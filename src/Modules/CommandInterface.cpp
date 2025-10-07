#ifndef NOMINMAX 
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include "../Analysis/PatternScanner.h"
#include "../Core/PacketInjector.h"

#include "../Modules/CommandInterface.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <tlhelp32.h>          
#include <Psapi.h>
#include <Windows.h>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "User32.lib")     
#pragma comment(lib, "Psapi.lib")

namespace SapphireHook { uint32_t GetLearnedLocalActorId(); }

namespace {
    struct Position3 {
        float x, y, z;
    };

    static Position3* GetLocalPlayerPosition()
    {
        return nullptr;
    }

    static uint32_t GetLocalEntityId()
    {
        uint32_t learned = SapphireHook::GetLearnedLocalActorId();
        if (learned != 0 && learned != 0xFFFFFFFF)
        {
            return learned;
        }
        static uint32_t s_id = 0x200001;
        static bool s_inited = false;
        if (!s_inited)
        {
            s_inited = true;
            if (const char* v = std::getenv("SAPPHIRE_ENTITYID"))
            {
                if (std::strlen(v) > 2 && (v[0] == '0') && (v[1] == 'x' || v[1] == 'X'))
                {
                    s_id = static_cast<uint32_t>(std::strtoul(v + 2, nullptr, 16));
                }
                else
                {
                    s_id = static_cast<uint32_t>(std::strtoul(v, nullptr, 10));
                }
            }
            std::printf("[CommandInterface] LocalEntityId: 0x%X (%u)\n", s_id, s_id);
        }
        return s_id;
    }
}

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

    struct ClientTriggerPacketData {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        uint64_t Target;
    };

    struct CompleteClientTriggerPacket {
        FFXIVARR_PACKET_HEADER header;
        FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
        FFXIVARR_IPC_HEADER ipcHeader;
        ClientTriggerPacketData data;
    };
}

CommandInterface::ChatCommand_t CommandInterface::s_chatCommandFunc = nullptr;
CommandInterface::SendPacket_t CommandInterface::s_sendPacketFunc = nullptr;
CommandInterface::SendPacketMethod_t CommandInterface::s_sendPacketMethod = nullptr;
CommandInterface::GameConnection_t CommandInterface::s_gameConnection = nullptr;
uintptr_t CommandInterface::s_gameConnectionPtr = 0;

bool CommandInterface::Initialize()
{
    bool foundCommands = FindCommandFunctions();
    bool foundNetwork = FindNetworkFunctions();
    bool foundConnection = FindGameConnection();

    bool wsaHooked = SapphireHook::PacketInjector::Initialize();

    if (wsaHooked)
    {
        std::printf("[CommandInterface] WSASend hook installed successfully\n");

        std::printf("[CommandInterface] Initial socket status:\n");
        std::printf("[CommandInterface] - Zone socket: 0x%llx\n",
            static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket));
        std::printf("[CommandInterface] - Chat socket: 0x%llx\n",
            static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket));

        Sleep(2000);       

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

    return foundCommands || foundNetwork || foundConnection || wsaHooked;
}

static inline uintptr_t RipTarget(uintptr_t instr, int relOffset)
{
    int32_t disp = *reinterpret_cast<int32_t*>(instr + relOffset);
    uintptr_t next = instr + relOffset + 4;     
    return static_cast<uintptr_t>(next + disp);
}

void CommandInterface::TryResolveNetworkThisFromSend(uintptr_t sendAddr)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(sendAddr);
    bool logged = false;

    for (int i = 0; i < 64; ++i)
    {
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
                    s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
                    std::printf("[CommandInterface] Derived network 'this' (mov rcx,[rip+]) at 0x%llx -> 0x%llx\n",
                        static_cast<unsigned long long>(tgt),
                        static_cast<unsigned long long>(s_gameConnectionPtr));
                    return;
                }
            }
        }
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
        if (p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x05)
        {
            uintptr_t tgt1 = RipTarget(sendAddr + i, 3);
            uintptr_t basePtr = 0;
            __try { basePtr = *reinterpret_cast<uintptr_t*>(tgt1); }
            __except (EXCEPTION_EXECUTE_HANDLER) { basePtr = 0; }

            if (basePtr)
            {
                for (int k = i + 7; k < i + 32 && k + 6 < 64; ++k)
                {
                    if (p[k] == 0x48 && p[k + 1] == 0x8B && (p[k + 2] & 0xF8) == 0x48    && p[k + 3] == 0x88)
                    {
                        s_gameConnectionPtr = basePtr;
                        s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
                        std::printf("[CommandInterface] Derived network 'this' (mov rax,[rip+]) base=0x%llx\n",
                            static_cast<unsigned long long>(s_gameConnectionPtr));
                        return;
                    }
                }
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

static void DebugSocketLearning()
{
    std::printf("[CommandInterface] === SOCKET LEARNING DEBUG ===\n");
    std::printf("[CommandInterface] Zone socket: 0x%llx (%s)\n",
        static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket),
        (SapphireHook::PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) ? "INVALID" : "VALID");
    std::printf("[CommandInterface] Chat socket: 0x%llx (%s)\n",
        static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket),
        (SapphireHook::PacketInjector::s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) ? "INVALID" : "VALID");

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

    DebugSocketLearning();

    if (s_sendPacketFunc)
    {
        bool ok = s_sendPacketFunc(const_cast<uint8_t*>(buffer.data()), buffer.size());
        std::printf("[CommandInterface] s_sendPacketFunc returned: %s\n", ok ? "OK" : "FAIL");
        if (ok) return true;
    }

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

    std::string cmd = command ? command : "";
    auto beginsWith = [](const std::string& s, char c) { return !s.empty() && s[0] == c; };
    const std::string chatCommand = (beginsWith(cmd, '!') || beginsWith(cmd, '/')) ? cmd : "!" + cmd;

    if (SendChatMessage(chatCommand.c_str(), 0))
    {
        std::printf("[CommandInterface] Sent command via chat path: %s\n", chatCommand.c_str());
        return true;
    }

    if (TryParseAsGMCommand(command))
    {
        std::printf("[CommandInterface] Sent command via GM command parsing: %s\n", command);
        return true;
    }

    std::printf("[CommandInterface] All methods failed for: %s\n", command ? command : "");
    return false;
}

bool CommandInterface::SendDebugCommandPacket(const char* command)
{
    if (!command || !*command) return false;
    std::printf("[CommandInterface] SendDebugCommandPacket: %s\n", command);

    std::string cmd = command;
    if (!cmd.empty() && (cmd[0] == '!' || cmd[0] == '/')) cmd.erase(0, 1);
    std::vector<std::string> parts;
    { std::stringstream ss(cmd); std::string t; while (ss >> t) parts.push_back(t); }

    uint32_t id = 0, a0 = 0, a1 = 0, a2 = 0, a3 = 0;
    if (parts.size() >= 3 && parts[0] == "set" && (parts[1] == "classjob" || parts[1] == "job"))
    {
        id = 0x01BE;    
        a0 = 0;
    }

    SapphireHook::CompleteClientTriggerPacket packet{};
    const uint64_t ts = GetTickCount64();
    const uint32_t actorId = GetLocalEntityId();

    packet.header.timestamp = ts;
    packet.header.connectionType = 1;
    packet.header.count = 1;

    const uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::ClientTriggerPacketData);
    const uint32_t segSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
    const uint32_t total = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segSize;

    packet.header.size = total;

    packet.segmentHeader.size = segSize;
    packet.segmentHeader.source_actor = actorId;
    packet.segmentHeader.target_actor = 0;
    packet.segmentHeader.type = 3;

    packet.ipcHeader.reserved = 0x14;
    packet.ipcHeader.type = 0x0191;
    packet.ipcHeader.timestamp = static_cast<uint32_t>(ts);

    packet.data.Id = id;
    packet.data.Arg0 = a0; packet.data.Arg1 = a1; packet.data.Arg2 = a2; packet.data.Arg3 = a3;
    packet.data.Target = 0;

    std::printf("[CommandInterface] ClientTrigger: Id=0x%X Arg0=%u SourceActor=0x%X\n", id, a0, actorId);

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

    if (message && message[0] == '!')
    {
        std::printf("[CommandInterface] Debug command detected, sending ChatHandler then 0x0191\n");

        if (!SendChatPacket(message, static_cast<uint8_t>(10)))    
        {
            std::printf("[CommandInterface] Failed to send ChatHandler packet\n");
            return false;
        }

        Sleep(50);

        std::string command = message + 1;   
        if (!SendDebugCommandPacket(command.c_str()))
        {
            std::printf("[CommandInterface] Failed to send Command packet\n");
            return false;
        }

        std::printf("[CommandInterface] Successfully sent both Chat (0x0067) and Command (0x0191) packets\n");
        return true;
    }

    return SendChatPacket(message, chatType);
}

bool CommandInterface::SendChatPacket(const char* message, uint8_t chatType)
{
    if (!message || !*message)
    {
        std::printf("[CommandInterface] SendChatPacket: empty message\n");
        return false;
    }

    std::printf("[CommandInterface] Attempting to send chat packet: %s (type: %u)\n", message, chatType);

    struct FFXIVIpcChatHandler
    {
        uint32_t clientTimeValue;
        uint32_t originEntityId;
        float pos[3];
        float dir;
        uint16_t chatType;
        char message[1024];
    };

    FFXIVIpcChatHandler chatPacket = {};
    chatPacket.clientTimeValue = static_cast<uint32_t>(GetTickCount64());
    chatPacket.originEntityId = GetLocalEntityId();
    chatPacket.chatType = static_cast<uint16_t>(chatType);
    strncpy_s(chatPacket.message, sizeof(chatPacket.message), message, _TRUNCATE);

    auto pos = GetLocalPlayerPosition();
    if (pos)
    {
        chatPacket.pos[0] = pos->x;
        chatPacket.pos[1] = pos->y;
        chatPacket.pos[2] = pos->z;
        chatPacket.dir = 0.0f;       
    }
    else
    {
        chatPacket.pos[0] = 0.0f;
        chatPacket.pos[1] = 0.0f;
        chatPacket.pos[2] = 0.0f;
        chatPacket.dir = 0.0f;
    }

    const size_t chatDataSize = sizeof(FFXIVIpcChatHandler);
    const size_t ipcSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + chatDataSize;
    const size_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + ipcSize;
    const size_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

    std::vector<uint8_t> buffer(totalSize);
    auto* header = reinterpret_cast<SapphireHook::FFXIVARR_PACKET_HEADER*>(buffer.data());
    auto* segment = reinterpret_cast<SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER*>(buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER));
    auto* ipc = reinterpret_cast<SapphireHook::FFXIVARR_IPC_HEADER*>(buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER));
    auto* data = buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + sizeof(SapphireHook::FFXIVARR_IPC_HEADER);

    header->timestamp = GetTickCount64();
    header->size = static_cast<uint32_t>(totalSize);
    header->connectionType = 0;
    header->count = 1;

    segment->size = static_cast<uint32_t>(segmentSize);
    segment->source_actor = GetLocalEntityId();
    segment->target_actor = 0;
    segment->type = 3;

    ipc->reserved = 0x14;
    ipc->type = 0x0067;  
    ipc->timestamp = static_cast<uint32_t>(GetTickCount64());

    memcpy(data, &chatPacket, chatDataSize);

    return SendRawPacket(buffer);
}

bool CommandInterface::SendGMCommand(uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint64_t target)
{
    return SendGMCommandEx(0x0197   , commandId, arg0, arg1, arg2, arg3, target);
}

bool CommandInterface::SendGMCommandEx(uint16_t ipcOpcode, uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint64_t target)
{
    std::printf("[CommandInterface] Sending GM Command (EX): OPCODE=0x%X ID=0x%X, Args=(%u,%u,%u,%u), Target=0x%llX\n",
        ipcOpcode, commandId, arg0, arg1, arg2, arg3, static_cast<unsigned long long>(target));

    SapphireHook::CompleteGMPacket packet = {};
    const uint64_t timestamp = GetTickCount64();

    packet.header.timestamp = timestamp;
    packet.header.connectionType = 1;  
    packet.header.count = 1;

    const uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::GmCommandPacket);
    const uint32_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
    const uint32_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

    packet.header.size = totalSize;
    packet.segmentHeader.size = segmentSize;
    packet.segmentHeader.source_actor = GetLocalEntityId();
    packet.segmentHeader.target_actor = static_cast<uint32_t>(target);
    packet.segmentHeader.type = 3;  

    packet.ipcHeader.reserved = 0x14;
    packet.ipcHeader.type = ipcOpcode;     
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

bool CommandInterface::FindCommandFunctions()
{
    // Intentionally not resolved yet; rely on packet injection path.
    s_chatCommandFunc = nullptr;
    std::printf("[CommandInterface] FindCommandFunctions: not implemented; using packet path only\n");
    return false;
}

bool CommandInterface::FindNetworkFunctions()
{
    // Not resolved; leave pointers null and let WSASend injector handle sending.
    s_sendPacketFunc = nullptr;
    s_sendPacketMethod = nullptr;
    std::printf("[CommandInterface] FindNetworkFunctions: not implemented; using WSASend injector\n");
    return false;
}

bool CommandInterface::FindGameConnection()
{
    // Not resolved; TryResolveNetworkThisFromSend will attempt derivation if available.
    s_gameConnection = nullptr;
    s_gameConnectionPtr = 0;
    std::printf("[CommandInterface] FindGameConnection: not implemented; no game connection singleton\n");
    return false;
}
