// Hygiene and include order
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Force full winsock2 inclusion FIRST
#include <winsock2.h>
#include <ws2tcpip.h>

// EXPLICIT: Ensure WSAAPI is defined exactly as in WinSock2.h
#if !defined(WSAAPI)
#if !defined(FAR)
#define FAR
#endif
#if !defined(PASCAL)
#define PASCAL __stdcall
#endif
#define WSAAPI FAR PASCAL
#endif

// Verify it's defined
#ifndef WSAAPI
#error "WSAAPI still not defined after explicit setup"
#endif

#include <windows.h>
#include <psapi.h>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>   // std::memcmp, std::memcpy
#include <cstdlib>   // std::getenv
#include <sstream>   // std::ostringstream
#include <vector>
#include <cstdio>
#include "../Logger/Logger.h"
#include "../Hooking/hook_manager.h"

#include "PacketInjector.h"
#include "MinHook.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")

// Readable check (file-scope, before any uses)
static bool IsReadable(const void* ptr, size_t minLen) noexcept
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!ptr) return false;
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;

    const DWORD acc = mbi.Protect & 0xFF;
    const bool readable =
        acc == PAGE_READONLY || acc == PAGE_READWRITE ||
        acc == PAGE_EXECUTE_READ || acc == PAGE_EXECUTE_READWRITE ||
        acc == PAGE_WRITECOPY || acc == PAGE_EXECUTE_WRITECOPY;
    return readable && (mbi.RegionSize >= minLen);
}

// Make IPC detour/original visible at global scope (real namespace)
namespace SapphireHook {
    void __fastcall HookedHandleIPC(void* thisPtr, uint16_t opcode, void* data);
    extern void(__fastcall* originalHandleIPC)(void*, uint16_t, void*);
}

namespace { // helpers and learning (single definition, above usage)

    inline bool IsEnvEnabled(const char* name) noexcept
    {
        if (const char* v = std::getenv(name))
        {
            const char c = v[0];
            return c == '1' || c == 't' || c == 'T' || c == 'y' || c == 'Y';
        }
        return false;
    }

    static bool GetMainModuleRange(uintptr_t& base, size_t& size) noexcept
    {
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return false;
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
            return false;
        base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        size = static_cast<size_t>(mi.SizeOfImage);
        return true;
    }

    // Find .text section to filter frames
    static bool GetTextSectionRange(uintptr_t& textBase, uintptr_t& textEnd) noexcept
    {
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return false;
        auto base = reinterpret_cast<uintptr_t>(hMod);

        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        auto sect = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sect)
        {
            if (std::memcmp(sect->Name, ".text", 5) == 0)
            {
                textBase = base + sect->VirtualAddress;
                textEnd = textBase + sect->Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    // Very light function-start guess by scanning back for common prologues
    static uintptr_t FindFunctionStart(uintptr_t addr, uintptr_t textBase) noexcept
    {
        uintptr_t cursor = addr;
        const uintptr_t minAddr = (addr > textBase + 0x100) ? addr - 0x100 : textBase;
        while (cursor > minAddr)
        {
            --cursor;
            const uint8_t* p = reinterpret_cast<const uint8_t*>(cursor);

            // We only scan within .text range
            if (p[0] == 0x55) return cursor;                         // push rbp
            if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return cursor; // sub rsp, imm8
            if (p[0] >= 0x50 && p[0] <= 0x57) return cursor;         // push r?
            if (p[0] == 0x40 && p[1] >= 0x50 && p[1] <= 0x57) return cursor; // REX + push
        }
        return addr;
    }

    static std::unordered_map<uintptr_t, size_t> g_FrameHits;
    static std::mutex g_FrameHitsMutex;
    static std::atomic<size_t> g_Samples{ 0 };
    static std::atomic<uintptr_t> g_SelectedFrame{ 0 };

    static void LearnFramesFromWSASend()
    {
        if (!IsEnvEnabled("SAPPHIRE_AUTOFIND_IPC")) return;

        // Capture stack
        void* frames[32] = {};
        USHORT captured = RtlCaptureStackBackTrace(0, 32, frames, nullptr);

        uintptr_t textBase = 0, textEnd = 0;
        if (!GetTextSectionRange(textBase, textEnd)) return;

        size_t added = 0;
        for (USHORT i = 0; i < captured; ++i)
        {
            uintptr_t f = reinterpret_cast<uintptr_t>(frames[i]);
            if (f >= textBase && f < textEnd)
            {
                std::lock_guard<std::mutex> lock(g_FrameHitsMutex);
                g_FrameHits[f]++;
                added++;
            }
        }
        if (added > 0) g_Samples.fetch_add(1, std::memory_order_relaxed);

        // Report when enough samples gathered
        size_t minSamples = 50;
        if (const char* v = std::getenv("SAPPHIRE_AUTOFIND_MIN"))
        {
            minSamples = std::max<size_t>(10, std::strtoul(v, nullptr, 10));
        }

        if (g_Samples.load(std::memory_order_relaxed) >= minSamples && g_SelectedFrame.load() == 0)
        {
            std::pair<uintptr_t, size_t> best{ 0,0 };
            {
                std::lock_guard<std::mutex> lock(g_FrameHitsMutex);
                for (auto& kv : g_FrameHits)
                {
                    if (kv.second > best.second) best = kv;
                }
            }
            if (best.first != 0)
            {
                uintptr_t funcStart = FindFunctionStart(best.first, textBase);
                g_SelectedFrame.store(funcStart, std::memory_order_relaxed);

                std::ostringstream oss;
                oss << "[AutoFind] WSASend backtrace selected candidate frame: 0x" << std::hex << best.first
                    << " -> function start: 0x" << funcStart << " (samples=" << std::dec << best.second << ")";
                ::SapphireHook::LogInfo(oss.str());

                // Optional: auto-install IPC hook when asked
                if (IsEnvEnabled("SAPPHIRE_INSTALL_LEARNED_IPC"))
                {
                    void* target = reinterpret_cast<void*>(funcStart);
                    MH_STATUS cr = MH_CreateHook(
                        target,
                        reinterpret_cast<void*>(&::SapphireHook::HookedHandleIPC),
                        reinterpret_cast<void**>(&::SapphireHook::originalHandleIPC)
                    );
                    if (cr != MH_OK)
                    {
                        ::SapphireHook::LogError("[AutoFind] MH_CreateHook failed at learned address");
                    }
                    else
                    {
                        MH_STATUS en = MH_EnableHook(target);
                        if (en != MH_OK)
                        {
                            ::SapphireHook::LogError("[AutoFind] MH_EnableHook failed at learned address");
                            MH_RemoveHook(target);
                        }
                        else
                        {
                            ::SapphireHook::HookManager::RegisterHook("IPC_AutoFound", funcStart, ::SapphireHook::originalHandleIPC, "AutoFind");
                            ::SapphireHook::LogInfo("[AutoFind] Installed hook at learned address via MinHook");
                        }
                    }
                }
            }
        }
    }

    // Track last known valid sockets seen in traffic
    static std::atomic<uint32_t> g_localActorId{ 0 };
    static std::atomic<std::uintptr_t> g_lastZoneSock{ static_cast<std::uintptr_t>(INVALID_SOCKET) };
    static std::atomic<std::uintptr_t> g_lastChatSock{ static_cast<std::uintptr_t>(INVALID_SOCKET) };

    // Active socket discovery (used only as a fallback)
    static std::vector<SOCKET> FindActiveSockets()
    {
        std::vector<SOCKET> activeSockets;

        // Heuristic ranges observed in your logs
        std::vector<SOCKET> candidateRanges = { 7000, 7050, 7100, 6500, 6600, 6700 };

        for (SOCKET baseSocket : candidateRanges)
        {
            for (int offset = -100; offset <= 100; offset++)
            {
                SOCKET testSocket = baseSocket + offset;
                if (testSocket == INVALID_SOCKET || testSocket <= 0) continue;

                int optval = 0;
                int optlen = sizeof(optval);
                if (getsockopt(testSocket, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&optval), &optlen) == 0)
                {
                    if (optval == SOCK_STREAM)
                    {
                        activeSockets.push_back(testSocket);
                        std::printf("[PacketInjector] Found active TCP socket: %llu\n",
                            static_cast<unsigned long long>(testSocket));
                    }
                }
            }
        }

        std::sort(activeSockets.begin(), activeSockets.end());
        activeSockets.erase(std::unique(activeSockets.begin(), activeSockets.end()), activeSockets.end());

        std::printf("[PacketInjector] Found %zu total active sockets\n", activeSockets.size());
        return activeSockets;
    }

    // Read a little-endian POD from a buffer with bounds + readability checks
    template <typename T>
    static inline bool ReadLE(const uint8_t* data, size_t len, size_t off, T& out) noexcept
    {
        if (!data) return false;
        if (off + sizeof(T) > len) return false;
        if (!::IsReadable(data + off, sizeof(T))) return false;
        std::memcpy(&out, data + off, sizeof(T));
        return true;
    }

} // anonymous namespace

namespace SapphireHook {

    bool PacketInjector::s_installed = false;
    std::uintptr_t PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(INVALID_SOCKET);
    std::uintptr_t PacketInjector::s_chatSocket = static_cast<std::uintptr_t>(INVALID_SOCKET);

    // Real WSASend pointer (kept internal to this TU)
    using WSASend_t = int(__stdcall*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
        LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    static WSASend_t g_realWSASend = nullptr;

    // Add function pointers for send/recv APIs
    using send_t = int(__stdcall*)(SOCKET, const char*, int, int);
    using recv_t = int(__stdcall*)(SOCKET, char*, int, int);
    using sendto_t = int(__stdcall*)(SOCKET, const char*, int, int, const sockaddr*, int);
    using recvfrom_t = int(__stdcall*)(SOCKET, char*, int, int, sockaddr*, int*);

    static send_t g_realSend = nullptr;
    static recv_t g_realRecv = nullptr;
    static sendto_t g_realSendTo = nullptr;
    static recvfrom_t g_realRecvFrom = nullptr;

    // Forward declaration
    static int __stdcall WSASend_Detour(SOCKET s,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesSent,
        DWORD dwFlags,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

    // Export hook fallback using MinHook
    static bool InstallWSASendHookExport()
    {
        if (g_realWSASend) return true;

        HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
        if (!hWs2)
        {
            hWs2 = LoadLibraryA("ws2_32.dll");
        }
        if (!hWs2)
        {
            std::printf("[PacketInjector] ws2_32.dll not loaded and could not be loaded\n");
            return false;
        }

        auto pWSASend = reinterpret_cast<LPVOID>(GetProcAddress(hWs2, "WSASend"));
        if (!pWSASend)
        {
            std::printf("[PacketInjector] GetProcAddress(WSASend) failed\n");
            return false;
        }

        if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED)
        {
            std::printf("[PacketInjector] MH_Initialize failed\n");
            return false;
        }

        const MH_STATUS cr = MH_CreateHook(pWSASend, reinterpret_cast<LPVOID>(&WSASend_Detour),
            reinterpret_cast<LPVOID*>(&g_realWSASend));
        if (cr != MH_OK)
        {
            std::printf("[PacketInjector] MH_CreateHook failed: %d\n", cr);
            return false;
        }

        const MH_STATUS en = MH_EnableHook(pWSASend);
        if (en != MH_OK)
        {
            std::printf("[PacketInjector] MH_EnableHook failed: %d\n", en);
            return false;
        }

        std::printf("[PacketInjector] WSASend hooked via export. Real=0x%p\n", g_realWSASend);
        return true;
    }

    bool PacketInjector::InstallWSASendHook()
    {
        // TEMP: bypass IAT while stabilizing
        // if (InstallWSASendHookIAT()) return true;
        return InstallWSASendHookExport();
    }

    // Updated classifier supporting observed header layout
    bool PacketInjector::ClassifyPacket(const uint8_t* data, size_t len, bool& isChat)
    {
        isChat = false;
        if (!data || len < 0x3C) return false;

        auto read16 = [&](size_t off) -> uint16_t { return *reinterpret_cast<const uint16_t*>(data + off); };
        auto read32 = [&](size_t off) -> uint32_t { return *reinterpret_cast<const uint32_t*>(data + off); };

        // Primary check (observed layout)
        uint32_t segType32 = read32(0x34);
        uint16_t reserved16 = read16(0x38);
        uint16_t ipcType = read16(0x3A);
        if (segType32 == 3 && reserved16 == 0x0014)
        {
            switch (ipcType)
            {
            case 0x0067: // ChatHandler (Zone)
            case 0x0191: // Command (Zone)
            case 0x0197: // GMCommand (Zone)
                isChat = false; // explicitly Zone (not Chat socket)
                return true;
            default:
                isChat = false;
                return true;
            }
        }

        // Fallback older assumption (keep same semantics: default to Zone)
        if (len >= 0x38)
        {
            uint16_t segType = read16(0x30);
            uint16_t reserved = read16(0x34);
            uint16_t ipcTypeA = read16(0x36);
            if (segType == 3 && reserved == 0x0014)
            {
                switch (ipcTypeA)
                {
                case 0x0067:
                case 0x0191:
                case 0x0197:
                    isChat = false;
                    return true;
                default:
                    isChat = false;
                    return true;
                }
            }
        }

        return false;
    }

    // Detour: learn sockets and forward to the real WSASend
    static int __stdcall WSASend_Detour(SOCKET s,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesSent,
        DWORD dwFlags,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
    {
        static bool s_logged = false;
        if (!s_logged && IsEnvEnabled("SAPPHIRE_AUTOFIND_IPC"))
        {
            ::SapphireHook::LogInfo("[AutoFind] Learning enabled (SAPPHIRE_AUTOFIND_IPC=1). Collecting WSASend call stacks...");
            s_logged = true;
        }
        LearnFramesFromWSASend();

        if (lpBuffers && dwBufferCount > 0)
        {
            for (DWORD i = 0; i < dwBufferCount; ++i)
            {
                const uint8_t* buf = reinterpret_cast<const uint8_t*>(lpBuffers[i].buf);
                const size_t len = lpBuffers[i].len;
                if (!buf || len < 0x40 || !::IsReadable(buf, 0x40)) continue;

                uint16_t connType = 0;
                (void)ReadLE<uint16_t>(buf, len, 0x1C, connType);

                bool isChat = false;
                const bool looksZoneIpc = PacketInjector::ClassifyPacket(buf, len, isChat);

                if (connType == 1 || looksZoneIpc)
                {
                    if (PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET))
                    {
                        PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(s);
                        std::printf("[PacketInjector] Learned zone socket: 0x%llx\n", static_cast<unsigned long long>(s));
                    }
                    g_lastZoneSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
                }
                else if (connType == 2)
                {
                    if (PacketInjector::s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET))
                    {
                        PacketInjector::s_chatSocket = static_cast<std::uintptr_t>(s);
                        std::printf("[PacketInjector] Learned chat socket: 0x%llx\n", static_cast<unsigned long long>(s));
                    }
                    g_lastChatSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
                }
            }
        }

        return g_realWSASend
            ? g_realWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine)
            : SOCKET_ERROR;
    }

    // Replace the body of send_Detour with this version (adds LocalActorId learning)
    static int __stdcall send_Detour(SOCKET s, const char* buf, int len, int flags)
    {
        std::printf("[PacketInjector] *** send() called on socket %lld, len=%d ***\n",
            static_cast<long long>(s), len);

        if (buf && len >= 0x50 && ::IsReadable(buf, 0x50))
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(buf);

            // Learn LocalActorId from outbound ChatHandler (0x0067): payload originEntityId at 0x4C
            uint32_t segType32 = 0;
            uint16_t reserved16 = 0, ipcType = 0;
            (void)ReadLE<uint32_t>(p, static_cast<size_t>(len), 0x34, segType32);
            (void)ReadLE<uint16_t>(p, static_cast<size_t>(len), 0x38, reserved16);
            (void)ReadLE<uint16_t>(p, static_cast<size_t>(len), 0x3A, ipcType);
            if (segType32 == 3 && reserved16 == 0x0014)
            {
                if (ipcType == 0x0067)
                {
                    uint32_t originEntityId = 0;
                    if (ReadLE<uint32_t>(p, static_cast<size_t>(len), 0x4C, originEntityId))
                    {
                        if (originEntityId != 0 && originEntityId != 0xFFFFFFFF)
                        {
                            const uint32_t prev = g_localActorId.exchange(originEntityId, std::memory_order_relaxed);
                            if (prev != originEntityId)
                            {
                                std::printf("[PacketInjector] Learned LocalActorId from ChatHandler: 0x%X (%u)\n",
                                    originEntityId, originEntityId);
                            }
                        }
                    }
                }
            }

            // Existing classification and socket learning
            uint16_t connType = 0;
            (void)ReadLE<uint16_t>(p, static_cast<size_t>(len), 0x1C, connType);

            bool isChat = false;
            const bool looksZoneIpc = PacketInjector::ClassifyPacket(p, static_cast<size_t>(len), isChat);

            if (connType == 1 || looksZoneIpc)
            {
                if (PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET))
                {
                    PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(s);
                    std::printf("[PacketInjector] Learned zone socket (send): 0x%llx\n",
                        static_cast<unsigned long long>(s));
                }
                g_lastZoneSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
            }
            else if (connType == 2)
            {
                if (PacketInjector::s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET))
                {
                    PacketInjector::s_chatSocket = static_cast<std::uintptr_t>(s);
                    std::printf("[PacketInjector] Learned chat socket (send): 0x%llx\n",
                        static_cast<unsigned long long>(s));
                }
                g_lastChatSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
            }

            // Existing manual packet preview
            if (len > 40)
            {
                std::string sample(reinterpret_cast<const char*>(p), std::min(static_cast<size_t>(len), size_t(1024)));
                if (sample.find('!') != std::string::npos)
                {
                    std::printf("[PacketInjector] === MANUAL COMMAND PACKET (send) ===\n");
                    std::printf("[PacketInjector] Socket: 0x%llx, Length: %d\n",
                        static_cast<unsigned long long>(s), len);

                    uint16_t ctDump = 0;
                    if (ReadLE<uint16_t>(p, static_cast<size_t>(len), 0x1C, ctDump))
                    {
                        std::printf("[PacketInjector] Connection Type: %u\n", ctDump);
                    }

                    std::string preview;
                    preview.reserve(120);
                    for (char c : sample)
                    {
                        if (c == '\0') break;
                        preview.push_back(isprint(static_cast<unsigned char>(c)) ? c : '.');
                        if (preview.size() >= 100) break;
                    }
                    std::printf("[PacketInjector] Content preview: %s\n", preview.c_str());
                    std::printf("[PacketInjector] First 128 bytes:\n");
                    for (size_t j = 0; j < std::min(static_cast<size_t>(len), size_t(128)); ++j)
                    {
                        if (j % 16 == 0) std::printf("\n%04zx: ", j);
                        std::printf("%02X ", p[j]);
                    }
                    std::printf("\n===========================================\n");
                }
            }
        }

        return g_realSend ? g_realSend(s, buf, len, flags) : SOCKET_ERROR;
    }

    static int __stdcall recv_Detour(SOCKET s, char* buf, int len, int flags)
    {
        std::printf("[PacketInjector] *** recv() called on socket %lld, len=%d ***\n",
            static_cast<long long>(s), len);
        return g_realRecv ? g_realRecv(s, buf, len, flags) : SOCKET_ERROR;
    }

    static int __stdcall sendto_Detour(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
    {
        std::printf("[PacketInjector] *** sendto() called on socket %lld, len=%d ***\n",
            static_cast<long long>(s), len);
        if (PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET))
        {
            PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(s);
            std::printf("[PacketInjector] *** LEARNED ZONE SOCKET from sendto(): %lld ***\n",
                static_cast<long long>(s));
        }
        return g_realSendTo ? g_realSendTo(s, buf, len, flags, to, tolen) : SOCKET_ERROR;
    }

    static int __stdcall recvfrom_Detour(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
    {
        std::printf("[PacketInjector] *** recvfrom() called on socket %lld, len=%d ***\n",
            static_cast<long long>(s), len);
        return g_realRecvFrom ? g_realRecvFrom(s, buf, len, flags, from, fromlen) : SOCKET_ERROR;
    }

    // Send helper (prefers given socket; fallback to discovery if needed)
    static bool SendOnSocket(std::uintptr_t sockVal, const uint8_t* data, size_t len)
    {
        SOCKET sock = static_cast<SOCKET>(sockVal);

        // Try provided socket first if valid
        if (sock != INVALID_SOCKET)
        {
            int optval = 0, optlen = sizeof(optval);
            if (getsockopt(sock, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&optval), &optlen) == 0)
            {
                if (g_realSend)
                {
                    int rc = g_realSend(sock, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
                    if (rc == static_cast<int>(len))
                    {
                        std::printf("[PacketInjector] *** Injected %d bytes via send() on socket 0x%llx ***\n",
                            rc, static_cast<unsigned long long>(sock));
                        return true;
                    }
                    std::printf("[PacketInjector] send() failed: %d (WSAGetLastError=%d)\n", rc, WSAGetLastError());
                }
                if (g_realWSASend)
                {
                    WSABUF wsaBuf{};
                    wsaBuf.len = static_cast<ULONG>(len);
                    wsaBuf.buf = reinterpret_cast<char*>(const_cast<uint8_t*>(data));

                    DWORD sent = 0;
                    int rc = g_realWSASend(sock, &wsaBuf, 1, &sent, 0, nullptr, nullptr);
                    if (rc == 0 && sent == len)
                    {
                        std::printf("[PacketInjector] Injected %lu bytes via WSASend on socket 0x%llx\n",
                            sent, static_cast<unsigned long long>(sock));
                        return true;
                    }
                    std::printf("[PacketInjector] WSASend failed: %d (WSAGetLastError=%d)\n", rc, WSAGetLastError());
                }
            }
            else
            {
                std::printf("[PacketInjector] Socket 0x%llx is no longer valid (WSAGetLastError=%d)\n",
                    static_cast<unsigned long long>(sock), WSAGetLastError());
            }
        }

        // Fallback: try to find active sockets (this worked in your earlier logs)
        std::printf("[PacketInjector] Searching for active sockets...\n");
        auto activeSockets = FindActiveSockets();

        for (SOCKET activeSocket : activeSockets)
        {
            if (g_realSend)
            {
                int rc = g_realSend(activeSocket, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
                if (rc == static_cast<int>(len))
                {
                    std::printf("[PacketInjector] *** SUCCESS: Injected %d bytes on discovered socket 0x%llx ***\n",
                        rc, static_cast<unsigned long long>(activeSocket));
                    return true;
                }
                std::printf("[PacketInjector] Socket 0x%llx failed with error %d, trying next...\n",
                    static_cast<unsigned long long>(activeSocket), WSAGetLastError());
            }
        }

        std::printf("[PacketInjector] *** FAILED: No active sockets found for injection ***\n");
        return false;
    }

    // Replace the Initialize function to hook ALL socket APIs
    bool PacketInjector::Initialize()
    {
        if (s_installed) return true;

        std::printf("[PacketInjector] *** HOOKING ALL SOCKET APIs (send/recv/WSASend) ***\n");

        HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
        if (!hWs2)
        {
            hWs2 = LoadLibraryA("ws2_32.dll");
        }
        if (!hWs2)
        {
            std::printf("[PacketInjector] Failed to load ws2_32.dll\n");
            return false;
        }

        if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED)
        {
            std::printf("[PacketInjector] MH_Initialize failed\n");
            return false;
        }

        bool anySuccess = false;

        // Hook send() - This is what IDA shows the game using
        auto pSend = GetProcAddress(hWs2, "send");
        if (pSend)
        {
            if (MH_CreateHook(pSend, &send_Detour, reinterpret_cast<LPVOID*>(&g_realSend)) == MH_OK)
            {
                if (MH_EnableHook(pSend) == MH_OK)
                {
                    std::printf("[PacketInjector] *** HOOKED send() - GAME USES THIS! ***\n");
                    anySuccess = true;
                }
            }
        }

        // Hook recv()
        auto pRecv = GetProcAddress(hWs2, "recv");
        if (pRecv)
        {
            if (MH_CreateHook(pRecv, &recv_Detour, reinterpret_cast<LPVOID*>(&g_realRecv)) == MH_OK)
            {
                if (MH_EnableHook(pRecv) == MH_OK)
                {
                    std::printf("[PacketInjector] *** HOOKED recv() - GAME USES THIS! ***\n");
                    anySuccess = true;
                }
            }
        }

        // Hook sendto()
        auto pSendTo = GetProcAddress(hWs2, "sendto");
        if (pSendTo)
        {
            if (MH_CreateHook(pSendTo, &sendto_Detour, reinterpret_cast<LPVOID*>(&g_realSendTo)) == MH_OK)
            {
                if (MH_EnableHook(pSendTo) == MH_OK)
                {
                    std::printf("[PacketInjector] *** HOOKED sendto() ***\n");
                    anySuccess = true;
                }
            }
        }

        // Hook recvfrom()
        auto pRecvFrom = GetProcAddress(hWs2, "recvfrom");
        if (pRecvFrom)
        {
            if (MH_CreateHook(pRecvFrom, &recvfrom_Detour, reinterpret_cast<LPVOID*>(&g_realRecvFrom)) == MH_OK)
            {
                if (MH_EnableHook(pRecvFrom) == MH_OK)
                {
                    std::printf("[PacketInjector] *** HOOKED recvfrom() ***\n");
                    anySuccess = true;
                }
            }
        }

        // Keep WSASend hook as fallback
        if (InstallWSASendHook())
        {
            std::printf("[PacketInjector] *** HOOKED WSASend() (fallback) ***\n");
            anySuccess = true;
        }

        s_installed = anySuccess;
        if (s_installed)
        {
            std::printf("[PacketInjector] *** ALL SOCKET API HOOKS INSTALLED ***\n");
        }
        else
        {
            std::printf("[PacketInjector] *** FAILED TO HOOK ANY SOCKET APIs ***\n");
        }

        return s_installed;
    }

    // Send with socket discovery fallback
    bool PacketInjector::Send(const uint8_t* data, size_t len)
    {
        if (!data || len == 0)
        {
            std::printf("[PacketInjector] Send failed - data=%p, len=%zu\n", data, len);
            return false;
        }

        // Check if we have ANY send function hooked
        if (!g_realSend && !g_realWSASend)
        {
            std::printf("[PacketInjector] Send failed - no send functions hooked (send=%p, WSASend=%p)\n",
                g_realSend, g_realWSASend);
            return false;
        }

        // Learn sockets if still unknown (use last seen)
        if (s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET))
        {
            auto last = g_lastZoneSock.load(std::memory_order_relaxed);
            if (last != static_cast<std::uintptr_t>(INVALID_SOCKET)) s_zoneSocket = last;
        }
        if (s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET))
        {
            auto last = g_lastChatSock.load(std::memory_order_relaxed);
            if (last != static_cast<std::uintptr_t>(INVALID_SOCKET)) s_chatSocket = last;
        }

        bool isChat{};
        (void)ClassifyPacket(data, len, isChat);

        // Default to Zone if classification fails
        const std::uintptr_t targetSock = isChat ? s_chatSocket : s_zoneSocket;

        // Try learned socket, then discovery fallback
        if (SendOnSocket(targetSock, data, len)) return true;

        // If that failed, attempt discovery explicitly
        std::printf("[PacketInjector] No luck with learned socket; attempting discovery fallback\n");
        return SendOnSocket(static_cast<std::uintptr_t>(INVALID_SOCKET), data, len);
    }

    bool PacketInjector::SendZone(const uint8_t* data, size_t len)
    {
        return SendOnSocket(s_zoneSocket, data, len);
    }

    bool PacketInjector::SendChat(const uint8_t* data, size_t len)
    {
        return SendOnSocket(s_chatSocket, data, len);
    }

    // Expose learned actor id to other modules
    uint32_t GetLearnedLocalActorId()
    {
        return g_localActorId.load(std::memory_order_relaxed);
    }
} // namespace SapphireHook