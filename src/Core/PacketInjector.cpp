#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#if !defined(WSAAPI)
#if !defined(FAR)
#define FAR
#endif
#if !defined(PASCAL)
#define PASCAL __stdcall
#endif
#define WSAAPI FAR PASCAL
#endif

#ifndef WSAAPI
#error "WSAAPI still not defined after explicit setup"
#endif

#include <windows.h>
#include <psapi.h>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <string>
#include "../Logger/Logger.h"
#include "../Hooking/hook_manager.h"

#include "PacketInjector.h"
#include <MinHook.h>
#include "../Monitor/NetworkMonitor.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")

using namespace SapphireHook;

// -------------------------------------------------------------------------------------------------
// Packet log mode runtime state (persistence handled by SettingsManager)
// -------------------------------------------------------------------------------------------------
namespace SapphireHook {

    static std::atomic<PacketLogMode> g_packetLogMode{ PacketLogMode::Summary };

    // Helpers for log level checks
    static inline bool PacketLogSummary() { return PacketLogAtLeast(PacketLogMode::Summary); }  // Summary or Verbose
    static inline bool PacketLogVerbose() { return PacketLogAtLeast(PacketLogMode::Verbose); }  // Verbose only

    bool PacketLogAtLeast(PacketLogMode needed) {
        return static_cast<int>(g_packetLogMode.load(std::memory_order_relaxed)) >= static_cast<int>(needed);
    }

    void SetPacketLogMode(PacketLogMode mode) {
        g_packetLogMode.store(mode, std::memory_order_relaxed);
        // Note: Persistence is now handled by SettingsManager
    }

    PacketLogMode GetPacketLogMode() {
        return g_packetLogMode.load(std::memory_order_relaxed);
    }

} // namespace SapphireHook

// -------------------------------------------------------------------------------------------------
// Existing packet injector implementation
// -------------------------------------------------------------------------------------------------

static std::atomic<uint64_t> g_sendOk{ 0 }, g_sendFail{ 0 }, g_bytesSent{ 0 };
static std::atomic<uint64_t> g_recvOk{ 0 }, g_bytesRecv{ 0 };
static std::atomic<uint64_t> g_wsa10038{ 0 }, g_wsa10054{ 0 }, g_wsa10035{ 0 }, g_wsa10057{ 0 };

static inline void CountWsa(int wsa) {
    switch (wsa) {
    case WSAENOTSOCK: g_wsa10038.fetch_add(1, std::memory_order_relaxed); break;
    case WSAECONNRESET: g_wsa10054.fetch_add(1, std::memory_order_relaxed); break;
    case WSAEWOULDBLOCK: g_wsa10035.fetch_add(1, std::memory_order_relaxed); break;
    case WSAENOTCONN: g_wsa10057.fetch_add(1, std::memory_order_relaxed); break;
    default: break;
    }
}

namespace {
    std::atomic<SOCKET> g_zoneSocket{ INVALID_SOCKET };
    std::atomic<SOCKET> g_chatSocket{ INVALID_SOCKET };
    std::atomic<SOCKET> g_lastZoneCandidate{ INVALID_SOCKET };
    std::atomic<SOCKET> g_lastChatCandidate{ INVALID_SOCKET };

    // CHANGE NOTE (2025-12-15): Replace protocol “magic numbers” with named constants.
    // This makes packet classification easier to audit and reduces the chance of subtle offset mistakes.
    constexpr int kFfxivHeaderSize = 0x34;
    constexpr size_t kOpcodeOffset = 0x30;
    constexpr uint16_t kChatIpcOpcode = 0x0067;
    constexpr std::array<uint8_t, 4> kFfxivMagic = { 0x52, 0x52, 0xA0, 0x41 };
}

static inline bool IsFfxivHeader(const uint8_t* b, int len) {
    if (!b) return false;
    return len >= kFfxivHeaderSize && b[0] == kFfxivMagic[0] && b[1] == kFfxivMagic[1] && b[2] == kFfxivMagic[2] && b[3] == kFfxivMagic[3];
}
static inline uint16_t ReadOpcodeLE(const uint8_t* b) {
    return static_cast<uint16_t>(b[kOpcodeOffset] | (b[kOpcodeOffset + 1] << 8));
}
static inline bool IsChatOpcode(uint16_t op) { return op == kChatIpcOpcode; }

void ConfigurePacketLogger() {
    // Leave existing logger configuration unchanged (not gated; global setup).
    LoggerConfig config;
    config.enableAsyncLogging = true;
    config.enabledCategories = static_cast<uint32_t>(LogCategory::Network | LogCategory::Packets);
    config.minLevel = LogLevel::Information;
    Logger::Instance().ApplyConfig(config);
    Logger::Instance().EnableCategory(LogCategory::Network);
}

static void ObserveTrafficAndMaybeLearn(SOCKET s, const uint8_t* buf, int len)
{
	if (!buf || len < kFfxivHeaderSize || !IsFfxivHeader(buf, len)) return;

    const uint16_t op = ReadOpcodeLE(buf);
    if (IsChatOpcode(op)) {
        g_lastChatCandidate.store(s, std::memory_order_relaxed);
        if (g_chatSocket.load(std::memory_order_relaxed) == INVALID_SOCKET) {
            g_chatSocket.store(s, std::memory_order_relaxed);
            if (PacketLogSummary()) {
                LogInfoWithContext("Socket learned",
                    LogContext()
                    .Add("component", "PacketInjector")
                    .Add("socket_type", "chat")
                    .Add("socket_id", Logger::HexFormat(static_cast<uintptr_t>(s)))
                    .Add("opcode", Logger::HexFormat(op))
                    .Add("packet_len", len));
            }
        }
    }
    else {
        g_lastZoneCandidate.store(s, std::memory_order_relaxed);
        if (g_zoneSocket.load(std::memory_order_relaxed) == INVALID_SOCKET) {
            g_zoneSocket.store(s, std::memory_order_relaxed);
            if (PacketLogSummary()) {
                LogInfo("[PacketInjector] Learned zone socket (traffic): " + Logger::HexFormat(static_cast<uintptr_t>(s)));
            }
        }
    }
}

void LogPacketBinary(const uint8_t* data, size_t len, bool outgoing) {
    // Binary logging left alone (assume it is desired even if Off? If you want Off to suppress binary too, gate here.)
    if (!PacketLogAtLeast(PacketLogMode::Verbose)) return;
    if (Logger::Instance().IsEnabledCategory(LogCategory::Packets)) {
        struct PacketHeader {
            uint64_t timestamp;
            uint32_t length;
            uint8_t outgoing;
            uint8_t reserved[3];
        };
        PacketHeader header;
        header.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        header.length = static_cast<uint32_t>(len);
        header.outgoing = outgoing ? 1 : 0;
        Logger::Instance().GetBinaryLogger().LogBinary(&header, sizeof(header), 1);
        Logger::Instance().GetBinaryLogger().LogBinary(data, len, 2);
    }
}

int WSAAPI Hook_send(SOCKET s, const char* buf, int len, int flags) {
    ObserveTrafficAndMaybeLearn(s, reinterpret_cast<const uint8_t*>(buf), len);
    return ::send(s, buf, len, flags);
}
int WSAAPI Hook_recv(SOCKET s, char* buf, int len, int flags) {
    const int ret = ::recv(s, buf, len, flags);
    if (ret > 0) ObserveTrafficAndMaybeLearn(s, reinterpret_cast<const uint8_t*>(buf), ret);
    return ret;
}

static decltype(&::closesocket) Real_closesocket = ::closesocket;
static int WSAAPI Hook_closesocket(SOCKET s)
{
    if (s == g_zoneSocket.load()) {
        g_zoneSocket.store(INVALID_SOCKET);
        if (PacketLogVerbose()) LogInfo("[PacketInjector] Zone socket closed -> cleared");
    }
    if (s == g_chatSocket.load()) {
        g_chatSocket.store(INVALID_SOCKET);
        if (PacketLogVerbose()) LogInfo("[PacketInjector] Chat socket closed -> cleared");
    }
    if (s == g_lastZoneCandidate.load()) g_lastZoneCandidate.store(INVALID_SOCKET);
    if (s == g_lastChatCandidate.load()) g_lastChatCandidate.store(INVALID_SOCKET);
    return Real_closesocket(s);
}

static SOCKET PickSocketForPacket(const uint8_t* buf, size_t len)
{
	if (buf && len >= static_cast<size_t>(kFfxivHeaderSize) && IsFfxivHeader(buf, static_cast<int>(len)) && IsChatOpcode(ReadOpcodeLE(buf))) {
        SOCKET s = g_chatSocket.load();
        return (s != INVALID_SOCKET) ? s : g_lastChatCandidate.load();
    }
    else {
        SOCKET s = g_zoneSocket.load();
        return (s != INVALID_SOCKET) ? s : g_lastZoneCandidate.load();
    }
}

static bool SendHardenedInternal(const void* data, size_t bytes)
{
    if (!data || bytes == 0) return false;
    const uint8_t* buf = static_cast<const uint8_t*>(data);

    auto trySend = [&](SOCKET s) -> bool {
        if (s == INVALID_SOCKET) return false;
        int sent = ::send(s, reinterpret_cast<const char*>(buf), (int)bytes, 0);
        if (sent == SOCKET_ERROR) {
            const int wsa = WSAGetLastError();
            CountWsa(wsa);
            if (PacketLogSummary()) {
                LogError("[PacketInjector] Send failed on " + Logger::HexFormat(static_cast<uintptr_t>(s)) +
                    " (WSA=" + std::to_string(wsa) + ")");
            }
            if (wsa == WSAENOTSOCK) {
                if (s == g_zoneSocket.load()) g_zoneSocket.store(INVALID_SOCKET);
                if (s == g_chatSocket.load()) g_chatSocket.store(INVALID_SOCKET);
            }
            g_sendFail.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        g_sendOk.fetch_add(1, std::memory_order_relaxed);
        g_bytesSent.fetch_add(static_cast<uint64_t>(sent), std::memory_order_relaxed);
        return true;
        };

    SOCKET primary = PickSocketForPacket(buf, bytes);
    if (trySend(primary)) return true;

    const bool isChat = (buf && bytes >= 0x34 && IsFfxivHeader(buf, (int)bytes) && IsChatOpcode(ReadOpcodeLE(buf)));
    SOCKET fallback = isChat ? g_lastChatCandidate.load() : g_lastZoneCandidate.load();
    if (fallback != primary && trySend(fallback)) {
        if (PacketLogVerbose()) {
            LogInfo("[PacketInjector] Retried send via fallback socket " + Logger::HexFormat(static_cast<uintptr_t>(fallback)));
        }
        return true;
    }

    if (PacketLogSummary()) LogError("[PacketInjector] Aborted: no viable socket");
    return false;
}

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

namespace SapphireHook {
    void __fastcall HookedHandleIPC(void* thisPtr, uint16_t opcode, void* data);
    extern void(__fastcall* originalHandleIPC)(void*, uint16_t, void*);
}

using namespace SapphireHook;

namespace {
    inline bool IsEnvEnabled(const char* name) noexcept {
        if (const char* v = std::getenv(name)) {
            const char c = v[0];
            return c == '1' || c == 't' || c == 'T' || c == 'y' || c == 'Y';
        }
        return false;
    }
    static bool GetTextSectionRange(uintptr_t& textBase, uintptr_t& textEnd) noexcept {
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return false;
        auto base = reinterpret_cast<uintptr_t>(hMod);
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto sect = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sect) {
            if (std::memcmp(sect->Name, ".text", 5) == 0) {
                textBase = base + sect->VirtualAddress;
                textEnd = textBase + sect->Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }
    static uintptr_t FindFunctionStart(uintptr_t addr, uintptr_t textBase) noexcept {
        uintptr_t cursor = addr;
        const uintptr_t minAddr = (addr > textBase + 0x100) ? addr - 0x100 : textBase;
        while (cursor > minAddr) {
            --cursor;
            const uint8_t* p = reinterpret_cast<const uint8_t*>(cursor);
            if (p[0] == 0x55) return cursor;
            if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return cursor;
            if (p[0] >= 0x50 && p[0] <= 0x57) return cursor;
            if (p[0] == 0x40 && p[1] >= 0x50 && p[1] <= 0x57) return cursor;
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
        void* frames[32] = {};
        USHORT captured = RtlCaptureStackBackTrace(0, 32, frames, nullptr);
        uintptr_t textBase = 0, textEnd = 0;
        if (!GetTextSectionRange(textBase, textEnd)) return;
        size_t added = 0;
        for (USHORT i = 0; i < captured; ++i) {
            uintptr_t f = reinterpret_cast<uintptr_t>(frames[i]);
            if (f >= textBase && f < textEnd) {
                std::lock_guard<std::mutex> lock(g_FrameHitsMutex);
                g_FrameHits[f]++;
                added++;
            }
        }
        if (added > 0) g_Samples.fetch_add(1, std::memory_order_relaxed);
        size_t minSamples = 50;
        if (const char* v = std::getenv("SAPPHIRE_AUTOFIND_MIN"))
            minSamples = std::max<size_t>(10, std::strtoul(v, nullptr, 10));
        if (g_Samples.load(std::memory_order_relaxed) >= minSamples && g_SelectedFrame.load() == 0) {
            std::pair<uintptr_t, size_t> best{ 0,0 };
            {
                std::lock_guard<std::mutex> lock(g_FrameHitsMutex);
                for (auto& kv : g_FrameHits)
                    if (kv.second > best.second) best = kv;
            }
            if (best.first != 0) {
                uintptr_t funcStart = FindFunctionStart(best.first, textBase);
                g_SelectedFrame.store(funcStart, std::memory_order_relaxed);
                if (PacketLogVerbose()) {
                    std::ostringstream oss;
                    oss << "[AutoFind] WSASend backtrace selected candidate frame: 0x" << std::hex << best.first
                        << " -> function start: 0x" << funcStart << " (samples=" << std::dec << best.second << ")";
                    ::SapphireHook::LogInfo(oss.str());
                }
            }
        }
    }

    static std::atomic<uint32_t> g_localActorId{ 0 };
    static std::atomic<std::uintptr_t> g_lastZoneSock{ static_cast<std::uintptr_t>(INVALID_SOCKET) };
    static std::atomic<std::uintptr_t> g_lastChatSock{ static_cast<std::uintptr_t>(INVALID_SOCKET) };

    static std::vector<SOCKET> FindActiveSockets()
    {
        std::vector<SOCKET> activeSockets;
        std::vector<SOCKET> candidateRanges = { 7000, 7050, 7100, 6500, 6600, 6700 };
        for (SOCKET baseSocket : candidateRanges) {
            for (int offset = -100; offset <= 100; offset++) {
                SOCKET testSocket = baseSocket + offset;
                if (testSocket == INVALID_SOCKET || testSocket <= 0) continue;
                int optval = 0; int optlen = sizeof(optval);
                if (getsockopt(testSocket, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&optval), &optlen) == 0) {
                    if (optval == SOCK_STREAM) {
                        activeSockets.push_back(testSocket);
                        if (PacketLogVerbose()) {
                            LogInfo("[PacketInjector] Found active TCP socket: " + std::to_string(static_cast<unsigned long long>(testSocket)));
                        }
                    }
                }
            }
        }
        std::sort(activeSockets.begin(), activeSockets.end());
        activeSockets.erase(std::unique(activeSockets.begin(), activeSockets.end()), activeSockets.end());
        if (PacketLogVerbose()) {
            LogInfo("[PacketInjector] Found " + std::to_string(activeSockets.size()) + " total active sockets");
        }
        return activeSockets;
    }

    template <typename T>
    static inline bool ReadLE(const uint8_t* data, size_t len, size_t off, T& out) noexcept {
        if (!data) return false;
        if (off + sizeof(T) > len) return false;
        if (!::IsReadable(data + off, sizeof(T))) return false;
        std::memcpy(&out, data + off, sizeof(T));
        return true;
    }
}

bool PacketInjector::s_installed = false;
std::uintptr_t PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(INVALID_SOCKET);
std::uintptr_t PacketInjector::s_chatSocket = static_cast<std::uintptr_t>(INVALID_SOCKET);

using WSASend_t = int(__stdcall*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSASend_t g_realWSASend = nullptr;

using send_t = int(__stdcall*)(SOCKET, const char*, int, int);
using recv_t = int(__stdcall*)(SOCKET, char*, int, int);
using sendto_t = int(__stdcall*)(SOCKET, const char*, int, int, const sockaddr*, int);
using recvfrom_t = int(__stdcall*)(SOCKET, char*, int, int, sockaddr*, int*);

static send_t g_realSend = nullptr;
static recv_t g_realRecv = nullptr;
static sendto_t g_realSendTo = nullptr;
static recvfrom_t g_realRecvFrom = nullptr;

static int __stdcall WSASend_Detour(SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static bool InstallWSASendHookExport()
{
    if (g_realWSASend) return true;
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");
    if (!hWs2) { if (PacketLogSummary()) LogError("[PacketInjector] ws2_32.dll not loaded and could not be loaded"); return false; }
    auto pWSASend = reinterpret_cast<LPVOID>(GetProcAddress(hWs2, "WSASend"));
    if (!pWSASend) { if (PacketLogSummary()) LogError("[PacketInjector] GetProcAddress(WSASend) failed"); return false; }
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        if (PacketLogSummary()) LogError("[PacketInjector] MH_Initialize failed"); return false;
    }
    const MH_STATUS cr = MH_CreateHook(pWSASend, reinterpret_cast<LPVOID>(&WSASend_Detour),
        reinterpret_cast<LPVOID*>(&g_realWSASend));
    if (cr != MH_OK) { if (PacketLogSummary()) LogError("[PacketInjector] MH_CreateHook failed: " + std::to_string(cr)); return false; }
    const MH_STATUS en = MH_EnableHook(pWSASend);
    if (en != MH_OK) { if (PacketLogSummary()) LogError("[PacketInjector] MH_EnableHook failed: " + std::to_string(en)); return false; }
    if (PacketLogVerbose()) LogInfo("[PacketInjector] WSASend hooked via export. Real=" + Logger::HexFormat(reinterpret_cast<uintptr_t>(g_realWSASend)));
    return true;
}

bool PacketInjector::InstallWSASendHook() { return InstallWSASendHookExport(); }

bool PacketInjector::ClassifyPacket(const uint8_t* data, size_t len, bool& isChat)
{
    isChat = false;
    if (!data || len < 0x3C) return false;
    auto read16 = [&](size_t off) -> uint16_t { return *reinterpret_cast<const uint16_t*>(data + off); };
    auto read32 = [&](size_t off) -> uint32_t { return *reinterpret_cast<const uint32_t*>(data + off); };
    uint32_t segType32 = read32(0x34);
    uint16_t reserved16 = read16(0x38);
    uint16_t ipcType = read16(0x3A);
    if (segType32 == 3 && reserved16 == 0x0014) {
        (void)ipcType;
        return true;
    }
    if (len >= 0x38) {
        uint16_t segType = read16(0x30);
        uint16_t reserved = read16(0x34);
        uint16_t ipcTypeA = read16(0x36);
        (void)ipcTypeA;
        if (segType == 3 && reserved == 0x0014) return true;
    }
    return false;
}

static int __stdcall WSASend_Detour(SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    static bool s_logged = false;
    if (!s_logged && IsEnvEnabled("SAPPHIRE_AUTOFIND_IPC")) {
        if (PacketLogVerbose()) LogInfo("[AutoFind] Learning enabled (SAPPHIRE_AUTOFIND_IPC=1). Collecting WSASend call stacks...");
        s_logged = true;
    }
    LearnFramesFromWSASend();

    if (lpBuffers && dwBufferCount > 0) {
        for (DWORD i = 0; i < dwBufferCount; ++i) {
            const uint8_t* buf = reinterpret_cast<const uint8_t*>(lpBuffers[i].buf);
            const size_t len = lpBuffers[i].len;
            if (!buf || len == 0) continue;
            if (::IsReadable(buf, 1)) {
                if (PacketLogVerbose()) {
                    SafeHookLogger::Instance().TryEnqueueFromHook(buf, len, true, (uint64_t)s);
                }
            }
            if (len < 0x40 || !::IsReadable(buf, 0x40)) continue;
            uint16_t connType = 0;
            (void)ReadLE<uint16_t>(buf, len, 0x1C, connType);
            bool isChat = false;
            const bool looksZoneIpc = PacketInjector::ClassifyPacket(buf, len, isChat);
            if (connType == 1 || looksZoneIpc) {
                if (PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) {
                    PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(s);
                    if (PacketLogSummary()) {
                        LogInfoWithContext("Socket learned",
                            LogContext()
                            .Add("component", "PacketInjector")
                            .Add("socket_type", "zone")
                            .Add("socket_id", static_cast<uintptr_t>(s))
                            .Add("connection_type", connType));
                    }
                }
                g_lastZoneSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
            }
            else if (connType == 2) {
                if (PacketInjector::s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) {
                    PacketInjector::s_chatSocket = static_cast<std::uintptr_t>(s);
                    if (PacketLogSummary()) LogInfo("[PacketInjector] Learned chat socket: " + Logger::HexFormat(static_cast<uintptr_t>(s)));
                }
                g_lastChatSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
            }
        }
    }

    int rc = g_realWSASend
        ? g_realWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine)
        : SOCKET_ERROR;

    if (rc == SOCKET_ERROR) {
        CountWsa(WSAGetLastError());
        g_sendFail.fetch_add(1, std::memory_order_relaxed);
        if (PacketLogSummary()) LogError("[PacketInjector] WSASend() failed (detour)");
    }
    else {
        g_sendOk.fetch_add(1, std::memory_order_relaxed);
        uint64_t total = 0;
        if (lpNumberOfBytesSent) total = *lpNumberOfBytesSent;
        else if (lpBuffers && dwBufferCount > 0)
            for (DWORD i = 0; i < dwBufferCount; i++) total += lpBuffers[i].len;
        g_bytesSent.fetch_add(total, std::memory_order_relaxed);
    }
    return rc;
}

static int __stdcall send_Detour(SOCKET s, const char* buf, int len, int flags)
{
    if (PacketLogVerbose()) {
        LogInfo("[PacketInjector] send() called on socket " + std::to_string(static_cast<uint64_t>(s)) +
            ", len=" + std::to_string(len));
    }
    if (buf && len > 0 && ::IsReadable(buf, 1)) {
        if (PacketLogVerbose()) {
            SafeHookLogger::Instance().TryEnqueueFromHook(buf, static_cast<size_t>(len), true, (uint64_t)s);
        }
    }
    if (buf && len >= 0x50 && ::IsReadable(buf, 0x50)) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(buf);

        uint32_t segType32 = 0; uint16_t reserved16 = 0, ipcType = 0;
        (void)ReadLE<uint32_t>(p, static_cast<size_t>(len), 0x34, segType32);
        (void)ReadLE<uint16_t>(p, static_cast<size_t>(len), 0x38, reserved16);
        (void)ReadLE<uint16_t>(p, static_cast<size_t>(len), 0x3A, ipcType);
        if (segType32 == 3 && reserved16 == 0x0014 && ipcType == 0x0067) {
            uint32_t originEntityId = 0;
            if (ReadLE<uint32_t>(p, static_cast<size_t>(len), 0x4C, originEntityId)) {
                if (originEntityId != 0 && originEntityId != 0xFFFFFFFF) {
                    g_localActorId.store(originEntityId, std::memory_order_relaxed);
                    if (PacketLogVerbose()) {
                        LogInfo("[PacketInjector] Learned LocalActorId from ChatHandler: 0x" +
                            std::to_string(originEntityId) + " (" + std::to_string(originEntityId) + ")");
                    }
                }
            }

            uint16_t connType = 0;
            (void)ReadLE<uint16_t>(p, static_cast<size_t>(len), 0x1C, connType);
            bool isChat = false;
            const bool looksZoneIpc = PacketInjector::ClassifyPacket(p, static_cast<size_t>(len), isChat);

            if (connType == 1 || looksZoneIpc) {
                if (PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) {
                    PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(s);
                    if (PacketLogSummary()) {
                        LogInfoWithContext("Socket learned",
                            LogContext()
                            .Add("component", "PacketInjector")
                            .Add("socket_type", "zone")
                            .Add("socket_id", static_cast<uintptr_t>(s))
                            .Add("connection_type", connType));
                    }
                }
                g_lastZoneSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
            }
            else if (connType == 2) {
                if (PacketInjector::s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) {
                    PacketInjector::s_chatSocket = static_cast<std::uintptr_t>(s);
                    if (PacketLogSummary()) LogInfo("[PacketInjector] Learned chat socket: " + Logger::HexFormat(static_cast<uintptr_t>(s)));
                }
                g_lastChatSock.store(static_cast<std::uintptr_t>(s), std::memory_order_relaxed);
            }
        }
    }

    int rc = g_realSend ? g_realSend(s, buf, len, flags) : SOCKET_ERROR;
    if (rc == SOCKET_ERROR) {
        int w = WSAGetLastError();
        CountWsa(w);
        g_sendFail.fetch_add(1, std::memory_order_relaxed);
        if (PacketLogSummary()) LogError("[PacketInjector] send() failed (WSA=" + std::to_string(w) + ")");
    }
    else if (rc > 0) {
        g_sendOk.fetch_add(1, std::memory_order_relaxed);
        g_bytesSent.fetch_add(static_cast<uint64_t>(rc), std::memory_order_relaxed);
    }
    return rc;
}

static int __stdcall recv_Detour(SOCKET s, char* buf, int len, int flags)
{
    if (PacketLogVerbose()) {
        LogDebug("[PacketInjector] recv() called on socket " + std::to_string(static_cast<long long>(s)) +
            ", len=" + std::to_string(len));
    }
    int rc = g_realRecv ? g_realRecv(s, buf, len, flags) : SOCKET_ERROR;
    if (rc > 0) {
        if (buf && ::IsReadable(buf, 1) && PacketLogVerbose()) {
            SafeHookLogger::Instance().TryEnqueueFromHook(buf, static_cast<size_t>(rc), false, (uint64_t)s);
        }
        g_recvOk.fetch_add(1, std::memory_order_relaxed);
        g_bytesRecv.fetch_add(static_cast<uint64_t>(rc), std::memory_order_relaxed);
    }
    return rc;
}

static int __stdcall sendto_Detour(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (PacketLogVerbose()) {
        LogDebug("[PacketInjector] sendto() called on socket " + std::to_string(static_cast<long long>(s)) +
            ", len=" + std::to_string(len));
    }
    if (buf && len > 0 && ::IsReadable(buf, 1) && PacketLogVerbose()) {
        SafeHookLogger::Instance().TryEnqueueFromHook(buf, static_cast<size_t>(len), true, (uint64_t)s);
    }
    if (PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) {
        PacketInjector::s_zoneSocket = static_cast<std::uintptr_t>(s);
        if (PacketLogSummary()) LogInfo("[PacketInjector] Learned zone socket (sendto): " + std::to_string(static_cast<long long>(s)));
    }
    return g_realSendTo ? g_realSendTo(s, buf, len, flags, to, tolen) : SOCKET_ERROR;
}

static int __stdcall recvfrom_Detour(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
    if (PacketLogVerbose()) {
        LogDebug("[PacketInjector] recvfrom() called on socket " + std::to_string(static_cast<long long>(s)) +
            ", len=" + std::to_string(len));
    }
    int rc = g_realRecvFrom ? g_realRecvFrom(s, buf, len, flags, from, fromlen) : SOCKET_ERROR;
    if (rc > 0 && buf && ::IsReadable(buf, 1) && PacketLogVerbose()) {
        SafeHookLogger::Instance().TryEnqueueFromHook(buf, static_cast<size_t>(rc), false, (uint64_t)s);
    }
    return rc;
}

static bool SendOnSocket(std::uintptr_t sockVal, const uint8_t* data, size_t len)
{
    SOCKET sock = static_cast<SOCKET>(sockVal);
    if (sock != INVALID_SOCKET) {
        int optval = 0, optlen = sizeof(optval);
        if (getsockopt(sock, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&optval), &optlen) == 0) {
            if (g_realSend) {
                int rc = g_realSend(sock, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
                if (rc == static_cast<int>(len)) {
                    if (PacketLogVerbose()) {
                        LogInfo("[PacketInjector] Injected " + std::to_string(rc) + " bytes via send() on socket " + Logger::HexFormat(static_cast<unsigned long long>(sock)));
                    }
                    return true;
                }
                int wsa = WSAGetLastError();
                CountWsa(wsa);
                if (PacketLogSummary()) {
                    LogError("[PacketInjector] send() failed: " + std::to_string(rc) + " (WSAGetLastError=" + std::to_string(wsa) + ")");
                }
            }
            if (g_realWSASend) {
                WSABUF wsaBuf{};
                wsaBuf.len = static_cast<ULONG>(len);
                wsaBuf.buf = reinterpret_cast<char*>(const_cast<uint8_t*>(data));
                DWORD sent = 0;
                int rc = g_realWSASend(sock, &wsaBuf, 1, &sent, 0, nullptr, nullptr);
                if (rc == 0 && sent == len) {
                    if (PacketLogVerbose()) {
                        LogInfo("[PacketInjector] Injected " + std::to_string(sent) + " bytes via WSASend on socket " + Logger::HexFormat(static_cast<unsigned long long>(sock)));
                    }
                    g_sendOk.fetch_add(1, std::memory_order_relaxed);
                    g_bytesSent.fetch_add(static_cast<uint64_t>(sent), std::memory_order_relaxed);
                    return true;
                }
                int wsa = WSAGetLastError();
                CountWsa(wsa);
                if (PacketLogSummary()) {
                    LogError("[PacketInjector] WSASend failed: " + std::to_string(rc) + " (WSAGetLastError=" + std::to_string(wsa) + ")");
                }
                g_sendFail.fetch_add(1, std::memory_order_relaxed);
            }
        }
        else {
            if (PacketLogSummary()) {
                LogWarning("[PacketInjector] Socket " + Logger::HexFormat(static_cast<unsigned long long>(sock)) +
                    " is no longer valid (WSAGetLastError=" + std::to_string(WSAGetLastError()) + ")");
            }
        }
    }

    if (PacketLogVerbose()) LogInfo("[PacketInjector] Searching for active sockets...");
    auto activeSockets = FindActiveSockets();
    for (SOCKET activeSocket : activeSockets) {
        if (g_realSend) {
            int rc = g_realSend(activeSocket, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
            if (rc == static_cast<int>(len)) {
                if (PacketLogVerbose()) {
                    LogInfo("[PacketInjector] SUCCESS: Injected " + std::to_string(rc) + " bytes on discovered socket " +
                        Logger::HexFormat(static_cast<unsigned long long>(activeSocket)));
                }
                return true;
            }
            int wsa = WSAGetLastError();
            CountWsa(wsa);
            if (PacketLogVerbose()) {
                LogDebug("[PacketInjector] Socket " + Logger::HexFormat(static_cast<unsigned long long>(activeSocket)) +
                    " failed with error " + std::to_string(wsa) + ", trying next...");
            }
        }
    }
    if (PacketLogSummary()) LogError("[PacketInjector] FAILED: No active sockets found for injection");
    return false;
}

bool PacketInjector::Initialize()
{
    if (s_installed) return true;
    if (PacketLogVerbose()) LogInfo("[PacketInjector] HOOKING ALL SOCKET APIs (send/recv/WSASend)");
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");
    if (!hWs2) { if (PacketLogSummary()) LogError("[PacketInjector] Failed to load ws2_32.dll"); return false; }
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        if (PacketLogSummary()) LogError("[PacketInjector] MH_Initialize failed"); return false;
    }
    bool anySuccess = false;
    auto pSend = GetProcAddress(hWs2, "send");
    if (pSend && MH_CreateHook(pSend, &send_Detour, reinterpret_cast<LPVOID*>(&g_realSend)) == MH_OK &&
        MH_EnableHook(pSend) == MH_OK) {
        if (PacketLogVerbose()) LogInfo("[PacketInjector] HOOKED send() - GAME USES THIS!"); anySuccess = true;
    }
    auto pRecv = GetProcAddress(hWs2, "recv");
    if (pRecv && MH_CreateHook(pRecv, &recv_Detour, reinterpret_cast<LPVOID*>(&g_realRecv)) == MH_OK &&
        MH_EnableHook(pRecv) == MH_OK) {
        if (PacketLogVerbose()) LogInfo("[PacketInjector] HOOKED recv() - GAME USES THIS!"); anySuccess = true;
    }
    auto pSendTo = GetProcAddress(hWs2, "sendto");
    if (pSendTo && MH_CreateHook(pSendTo, &sendto_Detour, reinterpret_cast<LPVOID*>(&g_realSendTo)) == MH_OK &&
        MH_EnableHook(pSendTo) == MH_OK) {
        if (PacketLogVerbose()) LogInfo("[PacketInjector] HOOKED sendto()"); anySuccess = true;
    }
    auto pRecvFrom = GetProcAddress(hWs2, "recvfrom");
    if (pRecvFrom && MH_CreateHook(pRecvFrom, &recvfrom_Detour, reinterpret_cast<LPVOID*>(&g_realRecvFrom)) == MH_OK &&
        MH_EnableHook(pRecvFrom) == MH_OK) {
        if (PacketLogVerbose()) LogInfo("[PacketInjector] HOOKED recvfrom()"); anySuccess = true;
    }
    auto pClose = GetProcAddress(hWs2, "closesocket");
    if (pClose && MH_CreateHook(pClose, &Hook_closesocket, reinterpret_cast<LPVOID*>(&Real_closesocket)) == MH_OK &&
        MH_EnableHook(pClose) == MH_OK) {
        if (PacketLogVerbose()) LogInfo("[PacketInjector] HOOKED closesocket()"); anySuccess = true;
    }
    if (InstallWSASendHook()) { if (PacketLogVerbose()) LogInfo("[PacketInjector] HOOKED WSASend() (fallback)"); anySuccess = true; }
    s_installed = anySuccess;
    if (s_installed) {
        if (PacketLogVerbose()) LogInfo("[PacketInjector] ALL SOCKET API HOOKS INSTALLED");
    }
    else {
        if (PacketLogSummary()) LogError("[PacketInjector] FAILED TO HOOK ANY SOCKET APIs");
    }
    return s_installed;
}

bool PacketInjector::Send(const uint8_t* data, size_t len)
{
    if (!data || len == 0) {
        if (PacketLogSummary()) {
            LogError("[PacketInjector] Send failed - data=" + Logger::HexFormat(reinterpret_cast<uintptr_t>(data)) +
                ", len=" + std::to_string(len));
        }
        return false;
    }
    if (!g_realSend && !g_realWSASend) {
        if (PacketLogSummary()) {
            LogError("[PacketInjector] Send failed - no send functions hooked (send=" +
                Logger::HexFormat(reinterpret_cast<uintptr_t>(g_realSend)) +
                ", WSASend=" + Logger::HexFormat(reinterpret_cast<uintptr_t>(g_realWSASend)) + ")");
        }
        return false;
    }
    if (s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) {
        auto last = g_lastZoneSock.load(std::memory_order_relaxed);
        if (last != static_cast<std::uintptr_t>(INVALID_SOCKET)) s_zoneSocket = last;
    }
    if (s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) {
        auto last = g_lastChatSock.load(std::memory_order_relaxed);
        if (last != static_cast<std::uintptr_t>(INVALID_SOCKET)) s_chatSocket = last;
    }
    bool isChat{};
    (void)ClassifyPacket(data, len, isChat);
    const std::uintptr_t targetSock = isChat ? s_chatSocket : s_zoneSocket;
    if (SendOnSocket(targetSock, data, len)) return true;
    if (PacketLogVerbose()) LogInfo("[PacketInjector] No luck with learned socket; attempting discovery fallback");
    return SendOnSocket(static_cast<std::uintptr_t>(INVALID_SOCKET), data, len);
}

bool PacketInjector::SendZone(const uint8_t* data, size_t len) { return SendOnSocket(s_zoneSocket, data, len); }
bool PacketInjector::SendChat(const uint8_t* data, size_t len) { return SendOnSocket(s_chatSocket, data, len); }

namespace SapphireHook {
    uint32_t GetLearnedLocalActorId() {
        return g_localActorId.load(std::memory_order_relaxed);
    }
}

PacketInjector::MetricsSnapshot PacketInjector::GetMetricsSnapshot()
{
    MetricsSnapshot s{};
    s.t_ms = GetTickCount64();
    s.sendOk = g_sendOk.load(std::memory_order_relaxed);
    s.sendFail = g_sendFail.load(std::memory_order_relaxed);
    s.bytesSent = g_bytesSent.load(std::memory_order_relaxed);
    s.recvOk = g_recvOk.load(std::memory_order_relaxed);
    s.bytesRecv = g_bytesRecv.load(std::memory_order_relaxed);
    s.wsa10038 = g_wsa10038.load(std::memory_order_relaxed);
    s.wsa10054 = g_wsa10054.load(std::memory_order_relaxed);
    s.wsa10035 = g_wsa10035.load(std::memory_order_relaxed);
    s.wsa10057 = g_wsa10057.load(std::memory_order_relaxed);
    return s;
}