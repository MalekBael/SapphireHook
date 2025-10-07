#pragma once
#include <Windows.h>
#include <string>
#include <cstdint>
#include <vector>

class CommandInterface
{
private:
	// Function pointers for game's command system
	typedef void(*ChatCommand_t)(const char* command);
	typedef bool(*SendPacket_t)(void* packet, size_t size);
	// New: member-style sender (RCX = this)
	typedef bool(__fastcall* SendPacketMethod_t)(void* thisPtr, void* packet, size_t size);
	typedef bool(*GameConnection_t)(void* packet, size_t size);

	static ChatCommand_t s_chatCommandFunc;
	static SendPacket_t s_sendPacketFunc;
	// New: if the function is a method, this pointer and method entry are used
	static SendPacketMethod_t s_sendPacketMethod;
	static GameConnection_t s_gameConnection;
	static uintptr_t s_gameConnectionPtr;

	// Pattern scanning to find command functions
	static bool FindCommandFunctions();
	static bool FindNetworkFunctions();
	static bool FindGameConnection();

	// New: try to derive a plausible singleton "this" from the send function's prologue
	static void TryResolveNetworkThisFromSend(uintptr_t sendAddr);

	static bool SendDebugCommandPacket(const char* command);
	static bool SimulateCommandInput(const char* command);
	static bool TryParseAsGMCommand(const char* command);
	static bool SendRawPacket(const std::vector<uint8_t>& buffer);  // Fixed: moved here and corrected signature

public:
	static bool Initialize();
	static bool SendDebugCommand(const char* command);
	static bool SendChatMessage(const char* message, uint8_t chatType = 0);
	static bool SendChatPacket(const char* message, uint8_t chatType = 0);

	// GM Command packet sending (defaults to GM1)
	static bool SendGMCommand(uint32_t commandId, uint32_t arg0 = 0, uint32_t arg1 = 0, uint32_t arg2 = 0, uint32_t arg3 = 0, uint64_t target = 0);

	// New: explicit opcode variant for discovery (0x0197 GM1, 0x0198 GM2)
	static bool SendGMCommandEx(uint16_t ipcOpcode, uint32_t commandId, uint32_t arg0 = 0, uint32_t arg1 = 0, uint32_t arg2 = 0, uint32_t arg3 = 0, uint64_t target = 0);

	// ADD MISSING DECLARATIONS:
	static bool SendCommandPacket(uint32_t commandId, uint32_t arg0 = 0, uint32_t arg1 = 0, uint32_t arg2 = 0, uint32_t arg3 = 0, uint64_t target = 0);
	static bool ProcessCommand(const std::string& command);

	// Convenience methods for common GM commands
	static bool SetPlayerLevel(uint8_t level, uint64_t targetId = 0);
	static bool SetPlayerClass(uint8_t classId, uint64_t targetId = 0);
	static bool GivePlayerItem(uint32_t itemId, uint32_t quantity = 1, uint64_t targetId = 0);
	static bool GivePlayerGil(uint32_t amount, uint64_t targetId = 0);
	static bool TeleportToZone(uint32_t zoneId, uint64_t targetId = 0);
	static bool SetPlayerPosition(float x, float y, float z, uint64_t targetId = 0);
};