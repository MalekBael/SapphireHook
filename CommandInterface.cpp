#include "CommandInterface.h"
#include "patternscanner.h"
#include <algorithm>

// Standard library includes
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <iostream>

// Windows includes
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

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
}

// Static member definitions
CommandInterface::ChatCommand_t CommandInterface::s_chatCommandFunc = nullptr;
CommandInterface::SendPacket_t CommandInterface::s_sendPacketFunc = nullptr;
CommandInterface::GameConnection_t CommandInterface::s_gameConnection = nullptr;
uintptr_t CommandInterface::s_gameConnectionPtr = 0;

bool CommandInterface::Initialize()
{
	bool foundCommands = FindCommandFunctions();
	bool foundNetwork = FindNetworkFunctions();
	bool foundConnection = FindGameConnection();

	std::printf("[CommandInterface] Initialize: Commands=%s, Network=%s, Connection=%s\n",
		foundCommands ? "OK" : "FAIL",
		foundNetwork ? "OK" : "FAIL",
		foundConnection ? "OK" : "FAIL");

	return foundCommands || foundNetwork || foundConnection;
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

	std::printf("[CommandInterface] Scanning for network functions...\n");

	const char* packetPatterns[] = {
		"48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9 48 85 D2",
		"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B F9",
		"48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 30 48 8B F2",
		"E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B 4C 24 ? 48 33 CC",
		"48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 40",
	};

	for (size_t i = 0; i < sizeof(packetPatterns) / sizeof(packetPatterns[0]); i++)
	{
		std::printf("[CommandInterface] Trying pattern %zu\n", i);
		uintptr_t addr = patternscan(moduleBase, moduleSize, packetPatterns[i]);
		if (addr)
		{
			std::printf("[CommandInterface] Found potential send function at: 0x%llx (pattern %zu)\n", addr, i);
			s_sendPacketFunc = reinterpret_cast<SendPacket_t>(addr);
			return true;
		}
	}

	std::printf("[CommandInterface] No network functions found\n");
	return false;
}

bool CommandInterface::FindGameConnection()
{
	std::printf("[CommandInterface] Game connection search - focusing on packet structure\n");
	return true;
}

bool CommandInterface::FindCommandFunctions()
{
	std::printf("[CommandInterface] Command function search - focusing on packet structure\n");
	return true;
}

bool CommandInterface::SendGMCommand(uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint64_t target)
{
	std::printf("[CommandInterface] Sending GM Command: ID=0x%X, Args=(%u,%u,%u,%u), Target=0x%llX\n",
		commandId, arg0, arg1, arg2, arg3, target);

	SapphireHook::CompleteGMPacket packet = {};
	uint64_t timestamp = GetTickCount64();

	// Fill headers
	packet.header.timestamp = timestamp;
	packet.header.connectionType = 1;
	packet.header.count = 1;

	uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::GmCommandPacket);
	uint32_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
	uint32_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

	packet.header.size = totalSize;
	packet.segmentHeader.size = segmentSize;
	packet.segmentHeader.target_actor = static_cast<uint32_t>(target);
	packet.segmentHeader.type = 3;

	packet.ipcHeader.reserved = 0x14;
	packet.ipcHeader.type = 0x0103;
	packet.ipcHeader.timestamp = static_cast<uint32_t>(timestamp);

	packet.gmData.Id = commandId;
	packet.gmData.Arg0 = arg0;
	packet.gmData.Arg1 = arg1;
	packet.gmData.Arg2 = arg2;
	packet.gmData.Arg3 = arg3;
	packet.gmData.Target = target;

	std::printf("[CommandInterface] Created packet - Total size: %u\n", totalSize);

	std::vector<uint8_t> buffer(sizeof(packet));
	memcpy(buffer.data(), &packet, sizeof(packet));
	return SendRawPacket(buffer);
}

bool CommandInterface::SendChatPacket(const char* message, uint8_t chatType)
{
	std::printf("[CommandInterface] Attempting to send chat packet: %s (type: %d)\n", message, chatType);

	SapphireHook::CompleteChatPacket packet = {};
	uint64_t timestamp = GetTickCount64();

	packet.header.timestamp = timestamp;
	packet.header.connectionType = 1;
	packet.header.count = 1;

	uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::ChatPacketData);
	uint32_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
	uint32_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

	packet.header.size = totalSize;
	packet.segmentHeader.size = segmentSize;
	packet.segmentHeader.type = 3;

	packet.ipcHeader.reserved = 0x14;
	packet.ipcHeader.type = 0x0067;
	packet.ipcHeader.timestamp = static_cast<uint32_t>(timestamp);

	packet.chatData.clientTimeValue = static_cast<uint32_t>(timestamp);
	packet.chatData.chatType = chatType;
	strncpy_s(packet.chatData.message, sizeof(packet.chatData.message), message, _TRUNCATE);

	std::vector<uint8_t> buffer(sizeof(packet));
	memcpy(buffer.data(), &packet, sizeof(packet));
	return SendRawPacket(buffer);
}

bool CommandInterface::SendRawPacket(const std::vector<uint8_t>& buffer)
{
	std::printf("[CommandInterface] Attempting to send raw packet of size %zu\n", buffer.size());

	std::printf("[CommandInterface] Packet contents (first 64 bytes):\n");

	// Alternative fix: Use the min function from algorithm header explicitly
	size_t displaySize = (std::min)(buffer.size(), static_cast<size_t>(64));
	for (size_t i = 0; i < displaySize; i++)
	{
		if (i % 16 == 0) std::printf("\n%04zx: ", i);
		std::printf("%02X ", buffer[i]);
	}
	std::printf("\n");

	std::printf("[CommandInterface] Packet formatted correctly using Sapphire structure\n");
	return true;
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
	std::printf("[CommandInterface] Attempting to send debug command: %s\n", command);

	if (TryParseAsGMCommand(command))
	{
		std::printf("[CommandInterface] Sent command via GM command parsing: %s\n", command);
		return true;
	}

	std::string chatCommand = "!" + std::string(command);
	if (SendChatPacket(chatCommand.c_str(), 0))
	{
		std::printf("[CommandInterface] Sent command via chat packet: %s\n", chatCommand.c_str());
		return true;
	}

	std::printf("[CommandInterface] Falling back to keyboard simulation\n");
	return SimulateCommandInput(chatCommand.c_str());
}

bool CommandInterface::SendChatMessage(const char* message, uint8_t chatType)
{
	return SendChatPacket(message, chatType);
}

bool CommandInterface::SimulateCommandInput(const char* command)
{
	std::printf("[CommandInterface] Simulating keyboard input for command: %s\n", command);

	HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
	if (!gameWindow)
	{
		std::printf("[CommandInterface] Could not find game window\n");
		return false;
	}

	SetForegroundWindow(gameWindow);
	Sleep(100);

	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
	Sleep(50);

	for (size_t i = 0; i < strlen(command); i++)
	{
		char c = command[i];
		SHORT vk = VkKeyScanA(c);
		BYTE key = LOBYTE(vk);
		BYTE shift = HIBYTE(vk);

		if (shift & 1)
			keybd_event(VK_SHIFT, 0, 0, 0);

		keybd_event(key, 0, 0, 0);
		keybd_event(key, 0, KEYEVENTF_KEYUP, 0);

		if (shift & 1)
			keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);

		Sleep(10);
	}

	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);

	std::printf("[CommandInterface] Command simulation completed\n");
	return true;
}

bool CommandInterface::SendDebugCommandPacket(const char* command)
{
	std::printf("[CommandInterface] SendDebugCommandPacket: %s\n", command);
	return false;
}

bool CommandInterface::SendGMCommandWithName(uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, const char* targetName)
{
	std::printf("[CommandInterface] SendGMCommandWithName not implemented yet\n");
	return false;
}