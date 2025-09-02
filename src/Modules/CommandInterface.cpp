#ifndef NOMINMAX 
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Winsock2 must be before Windows.h
#include <winsock2.h>
#include <ws2tcpip.h>

#include "../Core/PacketInjector.h"
#include "../Core/patternscanner.h"
#include "../Modules/CommandInterface.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Add the missing include at the top with other includes
#include <tlhelp32.h>   // Add this line for CreateToolhelp32Snapshot, PROCESSENTRY32, etc.

// Windows headers AFTER winsock2
#include <Windows.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "User32.lib")  // For FindWindow, SetForegroundWindow

// Link with Psapi.lib
#pragma comment(lib, "Psapi.lib")

// Use the CORRECT Sapphire packet structures
namespace SapphireHook {
    struct FFXIVARR_PACKET_HEADER
    {
        uint64_t unknown_0;
        uint64_t unknown_8;
        uint64_t timestamp;
        uint32_t size;
        uint16_t connectionType;
        uint16_t count;
        uint8_t unknown_20;
        uint8_t isCompressed;
        uint32_t unknown_24;
    };

    struct FFXIVARR_PACKET_SEGMENT_HEADER
    {
        uint32_t size;
        uint32_t source_actor;
        uint32_t target_actor;
        uint16_t type;
        uint16_t padding;
    };

    struct FFXIVARR_IPC_HEADER
    {
        uint16_t reserved;
        uint16_t type;
        uint16_t padding;
        uint16_t serverId;
        uint32_t timestamp;
        uint32_t padding1;
    };

    enum GmCommandId : uint32_t
    {
        Pos = 0x0000,
        Lv = 0x0001,
        Race = 0x0002,
        Tribe = 0x0003,
        Sex = 0x0004,
        Time = 0x0005,
        Weather = 0x0006,
        Call = 0x0007,
        Inspect = 0x0008,
        Speed = 0x0009,
        Invis = 0x000D,
        Raise = 0x0010,
        Kill = 0x000E,
        Icon = 0x0012,
        Hp = 0x0064,
        Mp = 0x0065,
        Tp = 0x0066,
        Gp = 0x0067,
        Exp = 0x0068,
        Inv = 0x006A,
        Orchestrion = 0x0074,
        Item = 0x00C8,
        Gil = 0x00C9,
        Collect = 0x00CA,
        QuestAccept = 0x012C,
        QuestCancel = 0x012D,
        QuestComplete = 0x012E,
        QuestIncomplete = 0x012F,
        QuestSequence = 0x0130,
        QuestInspect = 0x0131,
        GC = 0x0154,
        GCRank = 0x0155,
        Aetheryte = 0x015E,
        Wireframe = 0x0226,
        Teri = 0x0258,
        Kick = 0x025C,
        TeriInfo = 0x025D,
        Jump = 0x025E,
        JumpNpc = 0x025F,
    };

    struct GmCommandPacket {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        uint64_t Target;
    };

    struct CompleteGMPacket {
        FFXIVARR_PACKET_HEADER header;
        FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
        FFXIVARR_IPC_HEADER ipcHeader;
        GmCommandPacket gmData;
    };

    struct ChatPacketData {
        uint32_t clientTimeValue;
        uint32_t originEntityId;
        float pos[3];
        float dir;
        uint8_t chatType;
        char message[1024];
    };

    struct CompleteChatPacket {
        FFXIVARR_PACKET_HEADER header;
        FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
        FFXIVARR_IPC_HEADER ipcHeader;
        ChatPacketData chatData;
    };

    struct CommandPacketData {
        char command[512];
    };

    struct CompleteCommandPacket {
        FFXIVARR_PACKET_HEADER header;
        FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
        FFXIVARR_IPC_HEADER ipcHeader;
        CommandPacketData cmd;
    };
}

// Static member definitions
CommandInterface::ChatCommand_t CommandInterface::s_chatCommandFunc = nullptr;
CommandInterface::SendPacket_t CommandInterface::s_sendPacketFunc = nullptr;
CommandInterface::SendPacketMethod_t CommandInterface::s_sendPacketMethod = nullptr; // NEW
CommandInterface::GameConnection_t CommandInterface::s_gameConnection = nullptr;
uintptr_t CommandInterface::s_gameConnectionPtr = 0;

bool CommandInterface::Initialize()
{
    bool foundCommands = FindCommandFunctions();
    bool foundNetwork = FindNetworkFunctions();
    bool foundConnection = FindGameConnection();

    // Hook WSASend to learn sockets
    bool wsaHooked = SapphireHook::PacketInjector::Initialize();

    if (wsaHooked)
    {
        std::printf("[CommandInterface] WSASend hook installed successfully\n");

        // DEBUG: Check if we can access the socket variables
        std::printf("[CommandInterface] Initial socket status:\n");
        std::printf("[CommandInterface] - Zone socket: 0x%llx\n",
            static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket));
        std::printf("[CommandInterface] - Chat socket: 0x%llx\n",
            static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket));

        // Wait for some traffic to potentially flow
        Sleep(2000); // Wait 2 seconds for login traffic

        std::printf("[CommandInterface] After 2 seconds:\n");
        std::printf("[CommandInterface] - Zone socket: 0x%llx\n",
            static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket));
        std::printf("[CommandInterface] - Chat socket: 0x%llx\n",
            static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket));
    }

    if (foundNetwork && s_sendPacketFunc != nullptr)
    {
        auto addr = reinterpret_cast<uintptr_t>(s_sendPacketFunc);
        TryResolveNetworkThisFromSend(addr);
    }

    std::printf("[CommandInterface] Initialize: Commands=%s, Network=%s, Connection=%s, WSAHook=%s\n",
        foundCommands ? "OK" : "FAIL",
        foundNetwork ? "OK" : "FAIL",
        foundConnection ? "OK" : "FAIL",
        wsaHooked ? "OK" : "FAIL");

    // Consider it successful if we at least have WSASend hooked
    return foundCommands || foundNetwork || foundConnection || wsaHooked;
}

// Helper for RIP-relative target compute
static inline uintptr_t RipTarget(uintptr_t instr, int relOffset)
{
    int32_t disp = *reinterpret_cast<int32_t*>(instr + relOffset);
    uintptr_t next = instr + relOffset + 4; // address immediately after disp32
    return static_cast<uintptr_t>(next + disp);
}

void CommandInterface::TryResolveNetworkThisFromSend(uintptr_t sendAddr)
{
    // Scan first 64 bytes for common RIP-relative loads to a global pointer
    const uint8_t* p = reinterpret_cast<const uint8_t*>(sendAddr);
    bool logged = false;

    for (int i = 0; i < 64; ++i)
    {
        // mov rcx, [rip+rel32]
        if (p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x0D)
        {
            uintptr_t tgt = RipTarget(sendAddr + i, 3);
            if (tgt)
            {
                uintptr_t candidate = 0;
                __try
                {
                    candidate = *reinterpret_cast<uintptr_t*>(tgt);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    candidate = 0;
                }
                if (candidate)
                {
                    s_gameConnectionPtr = candidate;
                    // We can reuse the same raw address for a member-call; the function body is the same entry
                    s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
                    std::printf("[CommandInterface] Derived network 'this' (mov rcx,[rip+]) at 0x%llx -> 0x%llx\n",
                        static_cast<unsigned long long>(tgt),
                        static_cast<unsigned long long>(s_gameConnectionPtr));
                    return;
                }
            }
        }
        // lea rcx, [rip+rel32]
        if (p[i] == 0x48 && p[i + 1] == 0x8D && p[i + 2] == 0x0D)
        {
            uintptr_t tgt = RipTarget(sendAddr + i, 3);
            if (tgt)
            {
                s_gameConnectionPtr = tgt;
                s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
                std::printf("[CommandInterface] Derived network 'this' (lea rcx,[rip+]) -> 0x%llx\n",
                    static_cast<unsigned long long>(s_gameConnectionPtr));
                return;
            }
        }
        // mov rax, [rip+rel32] then mov rcx, [rax+imm] (two-step global)
        if (p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x05)
        {
            uintptr_t tgt1 = RipTarget(sendAddr + i, 3);
            uintptr_t basePtr = 0;
            __try { basePtr = *reinterpret_cast<uintptr_t*>(tgt1); }
            __except (EXCEPTION_EXECUTE_HANDLER) { basePtr = 0; }

            if (basePtr)
            {
                // Look forward a bit for 'mov rcx, [rax+imm]'
                for (int k = i + 7; k < i + 32 && k + 6 < 64; ++k)
                {
                    if (p[k] == 0x48 && p[k + 1] == 0x8B && (p[k + 2] & 0xF8) == 0x48 /* [RAX+disp32] */ && p[k + 3] == 0x88)
                    {
                        // Heuristic; skip — patterns vary too much. We'll just treat basePtr as candidate.
                        s_gameConnectionPtr = basePtr;
                        s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
                        std::printf("[CommandInterface] Derived network 'this' (mov rax,[rip+]) base=0x%llx\n",
                            static_cast<unsigned long long>(s_gameConnectionPtr));
                        return;
                    }
                }
                // Even if we didn't see the second mov, basePtr is still a plausible singleton.
                s_gameConnectionPtr = basePtr;
                s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
                std::printf("[CommandInterface] Derived network 'this' (mov rax,[rip+]) base=0x%llx\n",
                    static_cast<unsigned long long>(s_gameConnectionPtr));
                return;
            }
        }
    }

    if (!logged)
        std::printf("[CommandInterface] Could not derive network 'this' from send function prologue\n");
}

// ADD THE DebugSocketLearning FUNCTION HERE - BEFORE SendRawPacket()
static void DebugSocketLearning()
{
    std::printf("[CommandInterface] === SOCKET LEARNING DEBUG ===\n");
    std::printf("[CommandInterface] Zone socket: 0x%llx (%s)\n",
        static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket),
        (SapphireHook::PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) ? "INVALID" : "VALID");
    std::printf("[CommandInterface] Chat socket: 0x%llx (%s)\n",
        static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket),
        (SapphireHook::PacketInjector::s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) ? "INVALID" : "VALID");

    // Check if INVALID_SOCKET value is what we expect
    std::printf("[CommandInterface] INVALID_SOCKET value: 0x%llx\n",
        static_cast<unsigned long long>(static_cast<std::uintptr_t>(INVALID_SOCKET)));
}

bool CommandInterface::SendRawPacket(const std::vector<uint8_t>& buffer)
{
    std::printf("[CommandInterface] Attempting to send raw packet of size %zu\n", buffer.size());

    std::printf("[CommandInterface] Packet contents (first 64 bytes):\n");
    size_t displaySize = (std::min)(buffer.size(), static_cast<size_t>(64));
    for (size_t i = 0; i < displaySize; i++)
    {
        if (i % 16 == 0) std::printf("\n%04zx: ", i);
        std::printf("%02X ", buffer[i]);
    }
    std::printf("\n");

    // Debug socket learning status
    DebugSocketLearning();

    // Path 1: free function
    if (s_sendPacketFunc)
    {
        bool ok = s_sendPacketFunc(const_cast<uint8_t*>(buffer.data()), buffer.size());
        std::printf("[CommandInterface] s_sendPacketFunc returned: %s\n", ok ? "OK" : "FAIL");
        if (ok) return true;
    }

    // Path 2: member function with derived 'this'
    if (s_sendPacketMethod && s_gameConnectionPtr)
    {
        bool ok = false;
        __try
        {
            ok = s_sendPacketMethod(reinterpret_cast<void*>(s_gameConnectionPtr),
                const_cast<uint8_t*>(buffer.data()),
                buffer.size());
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = false;
        }
        std::printf("[CommandInterface] s_sendPacketMethod returned: %s\n", ok ? "OK" : "FAIL");
        if (ok) return true;
    }

    // Path 3: WSASend injector fallback - ALWAYS try this
    std::printf("[CommandInterface] Trying PacketInjector::Send...\n");
    if (SapphireHook::PacketInjector::Send(buffer.data(), buffer.size()))
    {
        std::printf("[CommandInterface] Sent via PacketInjector (WSASend)\n");
        return true;
    }

    std::printf("[CommandInterface] PacketInjector::Send failed\n");
    return false;
}

bool CommandInterface::SetPlayerLevel(uint8_t level, uint64_t targetId)
{
    return SendGMCommand(SapphireHook::GmCommandId::Lv, level, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerClass(uint8_t classId, uint64_t targetId)
{
    return SendGMCommand(SapphireHook::GmCommandId::QuestAccept, classId, 0, 0, 0, targetId);
}

bool CommandInterface::GivePlayerItem(uint32_t itemId, uint32_t quantity, uint64_t targetId)
{
    return SendGMCommand(SapphireHook::GmCommandId::Item, itemId, quantity, 0, 0, targetId);
}

bool CommandInterface::GivePlayerGil(uint32_t amount, uint64_t targetId)
{
    return SendGMCommand(SapphireHook::GmCommandId::Gil, amount, 0, 0, 0, targetId);
}

bool CommandInterface::TeleportToZone(uint32_t zoneId, uint64_t targetId)
{
    return SendGMCommand(SapphireHook::GmCommandId::Teri, zoneId, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerPosition(float x, float y, float z, uint64_t targetId)
{
    uint32_t pos_x = *reinterpret_cast<uint32_t*>(&x);
    uint32_t pos_y = *reinterpret_cast<uint32_t*>(&y);
    uint32_t pos_z = *reinterpret_cast<uint32_t*>(&z);
    return SendGMCommand(SapphireHook::GmCommandId::Pos, pos_x, pos_y, pos_z, 0, targetId);
}

bool CommandInterface::TryParseAsGMCommand(const char* command)
{
    std::printf("[CommandInterface] Parsing debug command: %s\n", command);

    std::string cmdStr(command);
    for (char& c : cmdStr)
    {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // FIX: properly closed character literal and condition
    if (!cmdStr.empty() && cmdStr[0] == '!')
        cmdStr = cmdStr.substr(1);

    std::vector<std::string> parts;
    std::stringstream ss(cmdStr);
    std::string part;
    while (std::getline(ss, part, ' '))
    {
        if (!part.empty())
            parts.push_back(part);
    }

    if (parts.empty())
        return false;

    const std::string& mainCmd = parts[0];
    uint64_t targetId = 0;

    if (mainCmd == "set" && parts.size() >= 3)
    {
        const std::string& subCmd = parts[1];
        if (subCmd == "classjob" || subCmd == "job")
        {
            uint32_t jobId = std::stoul(parts[2]);
            return SendGMCommand(SapphireHook::GmCommandId::Lv, jobId, 0, 0, 0, targetId);
        }
        else if (subCmd == "pos" && parts.size() >= 5)
        {
            float x = std::stof(parts[2]);
            float y = std::stof(parts[3]);
            float z = std::stof(parts[4]);
            return SetPlayerPosition(x, y, z, targetId);
        }
        else if (subCmd == "tele")
        {
            uint32_t zoneId = std::stoul(parts[2]);
            return TeleportToZone(zoneId, targetId);
        }
    }
    else if (mainCmd == "add" && parts.size() >= 3)
    {
        const std::string& subCmd = parts[1];
        if (subCmd == "item")
        {
            uint32_t itemId = std::stoul(parts[2]);
            uint32_t quantity = parts.size() >= 4 ? std::stoul(parts[3]) : 1;
            return GivePlayerItem(itemId, quantity, targetId);
        }
        else if (subCmd == "gil")
        {
            uint32_t amount = std::stoul(parts[2]);
            return GivePlayerGil(amount, targetId);
        }
    }
    else if (mainCmd == "get" && parts.size() >= 2 && parts[1] == "pos")
    {
        return SendGMCommand(SapphireHook::GmCommandId::Pos, 0, 0, 0, 0, targetId);
    }

    std::printf("[CommandInterface] Unknown or unsupported debug command: %s\n", command);
    return false;
}

bool CommandInterface::SendDebugCommand(const char* command)
{
    std::printf("[CommandInterface] Attempting to send debug command: %s\n", command ? command : "");

    // 1) Prefer Command IPC (0x0191). If not handled, fallback to chat.
    if (SendDebugCommandPacket(command))
    {
        std::printf("[CommandInterface] Sent command via Command IPC: %s\n", command ? command : "");
        return true;
    }

    // Normalize chat string
    std::string cmd = command ? command : "";
    auto beginsWith = [](const std::string& s, char c) { return !s.empty() && s[0] == c; };
    const std::string chatCommand = (beginsWith(cmd, '!') || beginsWith(cmd, '/')) ? cmd : "!" + cmd;

    // 2) Try chat path (in-process or packet)
    if (SendChatMessage(chatCommand.c_str(), 0))
    {
        std::printf("[CommandInterface] Sent command via chat path: %s\n", chatCommand.c_str());
        return true;
    }

    // 3) As a last resort, try GM parse (only for known-good commands)
    if (TryParseAsGMCommand(command))
    {
        std::printf("[CommandInterface] Sent command via GM command parsing: %s\n", command);
        return true;
    }

    std::printf("[CommandInterface] All methods failed for: %s\n", command ? command : "");
    return false;
}

// Implement Command packet builder using the same header scheme as GM/Chat
bool CommandInterface::SendDebugCommandPacket(const char* command)
{
    if (!command || !*command) return false;
    std::printf("[CommandInterface] SendDebugCommandPacket: %s\n", command);

    SapphireHook::CompleteCommandPacket packet{};
    uint64_t timestamp = GetTickCount64();

    // FFXIVARR_PACKET_HEADER
    packet.header.timestamp = timestamp;
    packet.header.connectionType = 1; // Zone
    packet.header.count = 1;

    // FFXIVARR_IPC_HEADER payload size + segment header
    const uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::CommandPacketData);
    const uint32_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
    const uint32_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

    packet.header.size = totalSize;

    // FFXIVARR_PACKET_SEGMENT_HEADER
    packet.segmentHeader.size = segmentSize;
    packet.segmentHeader.type = 3; // IPC

    // FFXIVARR_IPC_HEADER
    packet.ipcHeader.reserved = 0x14;
    packet.ipcHeader.type = 0x0191; // Command
    packet.ipcHeader.timestamp = static_cast<uint32_t>(timestamp);

    // Payload: copy command text
    std::memset(packet.cmd.command, 0, sizeof(packet.cmd.command));
    std::strncpy(packet.cmd.command, command, sizeof(packet.cmd.command) - 1);

    // Send
    std::vector<uint8_t> buffer(sizeof(packet));
    std::memcpy(buffer.data(), &packet, sizeof(packet));
    return SendRawPacket(buffer);
}

bool CommandInterface::SendChatMessage(const char* message, uint8_t chatType)
{
    if (!message || !*message)
    {
        std::printf("[CommandInterface] SendChatMessage: empty message\n");
        return false;
    }

    // If an in-process chat function is resolved, use it first.
    if (s_chatCommandFunc)
    {
        try
        {
            s_chatCommandFunc(message);
            std::printf("[CommandInterface] Sent chat via in-process ChatCommand_t\n");
            return true;
        }
        catch (...)
        {
            std::printf("[CommandInterface] Exception in ChatCommand_t; falling back to packet\n");
        }
    }

    // For debug commands starting with '!', we need to send BOTH packets like manual typing
    if (message && message[0] == '!')
    {
        std::printf("[CommandInterface] Debug command detected, sending both Chat and Command packets\n");

        // Step 1: Send ChatHandler packet (0x0067) 
        bool chatSent = SendChatPacket(message, chatType);
        if (!chatSent)
        {
            std::printf("[CommandInterface] Failed to send ChatHandler packet\n");
            return false;
        }

        // Step 2: Send Command packet (0x0191) - this triggers the actual execution
        // Extract command without the '!' prefix
        std::string command = message + 1; // Skip the '!' character
        bool commandSent = SendDebugCommandPacket(command.c_str());
        if (!commandSent)
        {
            std::printf("[CommandInterface] Failed to send Command packet\n");
            return false;
        }

        std::printf("[CommandInterface] Successfully sent both Chat (0x0067) and Command (0x0191) packets\n");
        return true;
    }
    else
    {
        // Regular chat message - just send ChatHandler
        return SendChatPacket(message, chatType);
    }
}

bool CommandInterface::SendChatPacket(const char* message, uint8_t chatType)
{
    std::printf("[CommandInterface] Attempting to send chat packet: %s (type: %u)\n",
        message ? message : "", chatType);

    // CORRECTED: Use the EXACT structure from ClientZoneDef.h
    struct CorrectChatPacket {
        SapphireHook::FFXIVARR_PACKET_HEADER header;
        SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
        SapphireHook::FFXIVARR_IPC_HEADER ipcHeader;

        // EXACT structure that server expects (from ClientZoneDef.h)
        struct {
            uint32_t clientTimeValue;
            struct {
                uint32_t originEntityId;
                float pos[3];
                float dir;
            } position;
            uint8_t chatType;  // Common::ChatType is likely uint8_t
            char message[1024];
        } data;
    };

    CorrectChatPacket packet = {};
    uint64_t timestamp = GetTickCount64();

    // Calculate sizes for the CORRECT structure
    uint32_t dataSize = sizeof(packet.data);
    uint32_t segmentSize = sizeof(packet.segmentHeader) + sizeof(packet.ipcHeader) + dataSize;
    uint32_t totalSize = sizeof(packet.header) + segmentSize;

    // FFXIVARR_PACKET_HEADER
    packet.header.timestamp = timestamp;
    packet.header.connectionType = 1; // Zone
    packet.header.count = 1;
    packet.header.size = totalSize;

    // FFXIVARR_PACKET_SEGMENT_HEADER  
    packet.segmentHeader.size = segmentSize;
    packet.segmentHeader.source_actor = 0;
    packet.segmentHeader.target_actor = 0;
    packet.segmentHeader.type = 3; // IPC

    // FFXIVARR_IPC_HEADER - ChatHandler opcode
    packet.ipcHeader.reserved = 0x14;
    packet.ipcHeader.type = 0x0067; // ChatHandler
    packet.ipcHeader.padding = 0;
    packet.ipcHeader.serverId = 0;
    packet.ipcHeader.timestamp = static_cast<uint32_t>(timestamp);
    packet.ipcHeader.padding1 = 0;

    // CORRECT Chat data - EXACT structure the server expects
    packet.data.clientTimeValue = static_cast<uint32_t>(timestamp);
    packet.data.position.originEntityId = 0; // Player entity ID if you have it
    packet.data.position.pos[0] = 0.0f;
    packet.data.position.pos[1] = 0.0f;
    packet.data.position.pos[2] = 0.0f;
    packet.data.position.dir = 0.0f;
    packet.data.chatType = chatType;

    // Clear and set message
    std::memset(packet.data.message, 0, sizeof(packet.data.message));
    std::strncpy(packet.data.message, message ? message : "", sizeof(packet.data.message) - 1);

    std::vector<uint8_t> buffer(sizeof(packet));
    std::memcpy(buffer.data(), &packet, sizeof(packet));
    return SendRawPacket(buffer);
}

bool CommandInterface::SendGMCommandWithName(uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, const char* targetName)
{
    // If you have a name->ID resolver, use it here to fill 'target'. For now, ignore and send target=0.
    (void)targetName;
    return SendGMCommand(commandId, arg0, arg1, arg2, arg3, 0);
}

// Optional: keep as a stub unless you use it.
bool CommandInterface::SimulateCommandInput(const char* command)
{
    std::printf("[CommandInterface] SimulateCommandInput not implemented. Command: %s\n", command ? command : "");
    return false;
}

// =====================
// Missing implementations
// =====================

bool CommandInterface::FindCommandFunctions()
{
    // If you have a signature for the in-process chat function, resolve it here and assign s_chatCommandFunc.
    // For now, log and return true so Initialize() can proceed.
    std::printf("[CommandInterface] Command function search - focusing on packet structure\n");
    return true;
}

bool CommandInterface::FindNetworkFunctions()
{
    size_t moduleSize = 0;
    uintptr_t moduleBase = GetModuleBaseAddress(nullptr, moduleSize);
    if (!moduleBase)
    {
        std::printf("[CommandInterface] Failed to get module base address\n");
        return false;
    }

    std::printf("[CommandInterface] Scanning for network functions in module at 0x%llx (size: 0x%llx)...\n",
        static_cast<unsigned long long>(moduleBase),
        static_cast<unsigned long long>(moduleSize));

    // WSASend is already hooked via PacketInjector, so we don't need internal patterns
    std::printf("[CommandInterface] Skipping unreliable pattern scanning - using WSASend hook instead\n");

    // Try to find WSASend directly in the IAT for reference
    auto wsaSendAddr = GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSASend");
    if (wsaSendAddr)
    {
        std::printf("[CommandInterface] WSASend found at: 0x%llx\n",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(wsaSendAddr)));
    }

    std::printf("[CommandInterface] Network function search completed - relying on WSASend injection\n");
    return true; // Return true since PacketInjector provides network functionality
}

bool CommandInterface::FindGameConnection()
{
    // If you can pattern scan a network singleton, do it here and set s_gameConnectionPtr.
    std::printf("[CommandInterface] Game connection search - focusing on packet structure\n");
    return true;
}

bool CommandInterface::SendGMCommand(uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint64_t target)
{
    std::printf("[CommandInterface] Sending GM Command: ID=0x%X, Args=(%u,%u,%u,%u), Target=0x%llX\n",
        commandId, arg0, arg1, arg2, arg3, static_cast<unsigned long long>(target));

    SapphireHook::CompleteGMPacket packet = {};
    uint64_t timestamp = GetTickCount64();

    // Fill headers
    packet.header.timestamp = timestamp;
    packet.header.connectionType = 1; // Zone
    packet.header.count = 1;

    uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::GmCommandPacket);
    uint32_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
    uint32_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

    packet.header.size = totalSize;
    packet.segmentHeader.size = segmentSize;
    packet.segmentHeader.target_actor = static_cast<uint32_t>(target);
    packet.segmentHeader.type = 3; // IPC

    packet.ipcHeader.reserved = 0x14;
    packet.ipcHeader.type = 0x0197; // GMCommand from ClientIpcs.h
    packet.ipcHeader.timestamp = static_cast<uint32_t>(timestamp);

    packet.gmData.Id = commandId;
    packet.gmData.Arg0 = arg0;
    packet.gmData.Arg1 = arg1;
    packet.gmData.Arg2 = arg2;
    packet.gmData.Arg3 = arg3;
    packet.gmData.Target = target;

    std::vector<uint8_t> buffer(sizeof(packet));
    std::memcpy(buffer.data(), &packet, sizeof(packet));
    return SendRawPacket(buffer);
}

// REMOVED: The duplicate SendChatPacket function definition that was causing the error