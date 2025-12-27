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
    
    // Render helpers
    void RenderContentFinderSection();
    void RenderDirectorSection();
    void RenderEventSection();
    void RenderGenericSection();
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
};

} // namespace SapphireHook
