#pragma once
#include "../UI/UIModule.h"
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <cstdint>

namespace SapphireHook {

/**
 * @brief UI Module for building and sending IPC packets
 * 
 * Provides a visual interface to construct and send client-to-server packets.
 * Shows expected syntax and parameters for each supported opcode.
 */
class PacketSenderModule : public UIModule {
public:
    PacketSenderModule();
    ~PacketSenderModule() override = default;

    const char* GetName() const override { return "packet_sender"; }
    const char* GetDisplayName() const override { return "Packet Sender"; }
    
    void RenderMenu() override;
    void RenderWindow() override;
    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    bool m_windowOpen = false;
    int m_selectedCategory = 0;
    int m_selectedPacket = 0;
    
    // Last send result
    bool m_lastSendResult = false;
    std::string m_lastSendMessage;
    
    // ContentFinder inputs
    uint16_t m_cfContentIds[5] = { 0 };
    int m_cfContentCount = 1;
    uint32_t m_cfFlags = 0;
    uint32_t m_cfAcceptContentId = 0;
    
    // Event inputs
    uint32_t m_eventId = 0;
    uint32_t m_eventActorId = 0;
    
    // Generic IPC inputs
    uint16_t m_genericOpcode = 0;
    uint8_t m_genericPayload[256] = { 0 };
    int m_genericPayloadSize = 0;
    std::string m_genericPayloadHex;
    
    // Retainer inputs
    uint32_t m_retainerHandlerId = 0x000B0009;  // RetainerDesk handler ID (720905) - cmndefretainerdesk_00009
    uint16_t m_retainerSceneId = 0;
    uint8_t m_retainerSubtype = 3;  // Default to LoadRetainerCreation
    uint8_t m_retainerSlotIndex = 0;
    bool m_retainerHookInstalled = false;
    uintptr_t m_loadRetainerCreationAddr = 0;
    uintptr_t m_sendEventPacketAddr = 0;
    uintptr_t m_playEventSceneAddr = 0;       // sub_14069AAA0 - PlayEventScene
    uintptr_t m_startEventSceneAddr = 0;      // sub_14068FEB0 - StartEventScene
    uintptr_t m_getOrCreateHandlerAddr = 0;   // sub_1406722E0 - GetOrCreateHandler (registers handler if needed)
    uintptr_t m_eventManagerPtr = 0;          // qword_1417C39D0 - Event manager global
    uintptr_t m_localPlayerPtr = 0;           // qword_1415F5A68 - Local player actor pointer
    uintptr_t m_currentTargetPtr = 0;         // qword_1415F1830 - Target Manager base
    uintptr_t m_actorLookupAddr = 0;          // sub_1405C1A10 - Look up actor pointer from actor ID
    
    // Render helpers
    void RenderContentFinderSection();
    void RenderDirectorSection();
    void RenderEventSection();
    void RenderGenericSection();
    void RenderRetainerSection();
    void RenderLastResult();
    void RenderServerToClientInjector(uint16_t opcode, const char* name);
    
    // Server→Client packet injection for testing
    bool InjectServerPacket(uint16_t opcode, const void* payload, size_t payloadSize);
    
    // Utility
    static std::string ToHexString(uint16_t value);
    
    // Packet info structure
    struct PacketInfo {
        uint16_t opcode;
        const char* name;
        const char* direction;  // "C→S" or "S→C"
        const char* description;
        const char* syntax;
    };
    
    static const std::vector<PacketInfo>& GetContentFinderPackets();
    static const std::vector<PacketInfo>& GetEventPackets();
    static const std::vector<PacketInfo>& GetDirectorPackets();
    static const std::vector<PacketInfo>& GetRetainerPackets();
    
    // Retainer helpers
    bool TryScanRetainerFunctions();
    bool CallSendEventPacket(int handlerId, int16_t sceneId, char subtype, uint32_t* data, uint8_t size);
    bool CallPlayEventScene(uintptr_t actorPtr, uint32_t handlerId, int16_t sceneId, int64_t delay, uint32_t* params, uint8_t paramCount);
    bool CallStartEventScene(uintptr_t actorPtr, uint32_t handlerId, int16_t sceneId, int64_t delay, uint32_t* params, uint8_t paramCount);
    uintptr_t GetOrCreateHandler(uint32_t handlerId, uintptr_t actorPtr = 0);  // Registers handler if not exists
    uintptr_t GetLocalPlayerActorPtr();
    uintptr_t GetCurrentTargetPtr();  // Gets current target actor pointer
    bool SendStartTalkEventPacket(uint64_t targetActorId, uint32_t eventId);  // Sends C→S talk event packet
    bool SendReturnEventScenePacket(uint32_t handlerId, uint16_t sceneId, uint32_t selection);  // Sends C→S scene return packet
};

} // namespace SapphireHook
