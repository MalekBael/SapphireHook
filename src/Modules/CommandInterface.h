#pragma once
#include <Windows.h>
#include <string>
#include <cstdint>
#include <vector>

class CommandInterface
{
private:
	typedef void(*ChatCommand_t)(const char* command);
	typedef bool(*SendPacket_t)(void* packet, size_t size);
	typedef bool(__fastcall* SendPacketMethod_t)(void* thisPtr, void* packet, size_t size);
	typedef bool(*GameConnection_t)(void* packet, size_t size);

	static ChatCommand_t        s_chatCommandFunc;
	static SendPacket_t         s_sendPacketFunc;
	static SendPacketMethod_t   s_sendPacketMethod;
	static GameConnection_t     s_gameConnection;
	static uintptr_t            s_gameConnectionPtr;

	static bool FindCommandFunctions();
	static bool FindNetworkFunctions();
	static bool FindGameConnection();
	static void TryResolveNetworkThisFromSend(uintptr_t sendAddr);

	static bool SendDebugCommandPacket(const char* command);
	static bool SimulateCommandInput(const char* command);
	static bool TryParseAsGMCommand(const char* command);
	static bool SendRawPacket(const std::vector<uint8_t>& buffer);

public:
	static bool Initialize();
	static bool SendDebugCommand(const char* command);
	static bool SendChatMessage(const char* message, uint8_t chatType = 0);
	static bool SendChatPacket(const char* message, uint8_t chatType = 0);

	// Generic GM senders
	static bool SendGMCommand(uint32_t commandId,
		uint32_t arg0 = 0,
		uint32_t arg1 = 0,
		uint32_t arg2 = 0,
		uint32_t arg3 = 0,
		uint64_t target = 0);
	static bool SendGMCommandEx(uint16_t ipcOpcode,
		uint32_t commandId,
		uint32_t arg0 = 0,
		uint32_t arg1 = 0,
		uint32_t arg2 = 0,
		uint32_t arg3 = 0,
		uint64_t target = 0);

	// Discovery/raw helpers
	static bool SendCommandPacket(uint32_t commandId,
		uint32_t arg0 = 0,
		uint32_t arg1 = 0,
		uint32_t arg2 = 0,
		uint32_t arg3 = 0,
		uint64_t target = 0);
	static bool ProcessCommand(const std::string& command);

	// Existing convenience (already implemented)
	static bool SetPlayerLevel(uint8_t level, uint64_t targetId = 0);
	static bool SetPlayerClass(uint8_t classId, uint64_t targetId = 0);
	static bool GivePlayerItem(uint32_t itemId, uint32_t quantity = 1, uint64_t targetId = 0);
	static bool GivePlayerGil(uint32_t amount, uint64_t targetId = 0);
	static bool TeleportToZone(uint32_t zoneId, uint64_t targetId = 0);
	static bool SetPlayerPosition(float x, float y, float z, uint64_t targetId = 0);

	// New wrapper methods (no enum exposure required externally)
	static bool SetPlayerRace(uint32_t raceId, uint64_t targetId = 0);
	static bool SetPlayerTribe(uint32_t tribeId, uint64_t targetId = 0);
	static bool SetPlayerGender(uint32_t gender, uint64_t targetId = 0);
	static bool SetPlayerHp(uint32_t hp, uint64_t targetId = 0);
	static bool SetPlayerMp(uint32_t mp, uint64_t targetId = 0);
	static bool SetPlayerGp(uint32_t gp, uint64_t targetId = 0);
	static bool AddPlayerExp(uint32_t amount, uint64_t targetId = 0); // additive (server dependent)
	static bool SetPlayerExp(uint32_t amount, uint64_t targetId = 0); // overwrite
	static bool SetPlayerIcon(uint32_t iconId, uint64_t targetId = 0);
	static bool SetInvincibility(uint32_t enabled, uint64_t targetId = 0);
	static bool SetInvisibility(uint32_t visibleFlag);                // 1 = visible, 0 = invisible (matches current usage)
	static bool SetWireframe(uint32_t enabled);
	static bool UnlockOrchestrion(uint32_t songId);                   // 0 = all
	static bool SetGrandCompany(uint32_t companyId, uint64_t targetId = 0);
	static bool SetGrandCompanyRank(uint32_t rank, uint64_t targetId = 0);

	// ============================================================================
	// Generic IPC Packet Builder & Sender
	// ============================================================================
	
	/**
	 * @brief Send a raw IPC packet with any payload struct
	 * @tparam T Payload struct type (e.g., FFXIVIpcActionRequest)
	 * @param opcode IPC opcode (e.g., 0x0196 for ActionRequest)
	 * @param payload Reference to the filled payload struct
	 * @param connectionType 1=Zone, 2=Chat, 3=Lobby (default: Zone)
	 * @param targetActorId Target actor ID (default: 0)
	 * @return true if packet was sent successfully
	 */
	template<typename T>
	static bool SendIpcPacket(uint16_t opcode, const T& payload, uint16_t connectionType = 1, uint32_t targetActorId = 0);

	/**
	 * @brief Send a raw IPC packet from a byte buffer
	 * @param opcode IPC opcode
	 * @param payloadData Pointer to payload bytes
	 * @param payloadSize Size of payload in bytes
	 * @param connectionType 1=Zone, 2=Chat, 3=Lobby (default: Zone)
	 * @param targetActorId Target actor ID (default: 0)
	 * @return true if packet was sent successfully
	 */
	static bool SendIpcPacketRaw(uint16_t opcode, const void* payloadData, size_t payloadSize, 
		uint16_t connectionType = 1, uint32_t targetActorId = 0);

	// ============================================================================
	// ContentFinder / Duty Finder Packets (Client-to-Server)
	// ============================================================================
	
	/**
	 * @brief Queue for up to 5 duties (ContentFinder)
	 * @param territoryTypes Array of up to 5 TerritoryType IDs (e.g., Sastasha=1036, Tam-Tara=1037)
	 * @param count Number of territory IDs (1-5)
	 * @param flags Unused for Find5Contents (use FindContent opcode for single duty with flags)
	 * @return true if packet was sent
	 */
	static bool QueueForDuties(const uint16_t* territoryTypes, uint8_t count, uint32_t flags = 0);

	/**
	 * @brief Accept a duty finder pop
	 * @param contentId The ContentFinderCondition ID
	 * @return true if packet was sent
	 */
	static bool AcceptDutyPop(uint32_t contentId);

	/**
	 * @brief Cancel duty finder queue
	 * @return true if packet was sent
	 */
	static bool CancelDutyQueue();

	// ============================================================================
	// Quest Packets (Client-to-Server)
	// ============================================================================
	
	/**
	 * @brief Accept a quest via EventHandlerTalk
	 * @param eventId Quest event ID
	 * @param actorId NPC actor ID to talk to
	 * @return true if packet was sent
	 */
	static bool SendEventTalk(uint32_t eventId, uint32_t actorId);

	// Get local player entity ID (helper)
	static uint32_t GetLocalEntityId();
};