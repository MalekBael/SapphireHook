#include "PacketSenderModule.h"
#include "CommandInterface.h"
#include "../Monitor/NetworkMonitor.h"
#include "../Hooking/hook_manager.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace SapphireHook {

// ============================================================================
// Packet Info Tables - Shows syntax expected for each opcode
// ============================================================================

const std::vector<PacketSenderModule::PacketInfo>& PacketSenderModule::GetContentFinderPackets() {
    static const std::vector<PacketInfo> packets = {
        // Client → Server (packets YOU send)
        { 0x01FD, "Find5Contents", "C→S", 
          "Queue for up to 5 duties",
          "contentIds[5]: u16 (ContentFinderCondition IDs)\n"
          "flags: u32 (queue options)\n"
          "count: u8 (1-5)" },
        { 0x01FB, "AcceptContent", "C→S",
          "Accept duty finder pop",
          "contentId: u32\n"
          "accepted: u8 (1=yes, 0=no)" },
        { 0x01FC, "CancelFindContent", "C→S",
          "Cancel duty queue",
          "reserved: u32" },
          
        // Server → Client (packets you RECEIVE / can inject for testing)
        { 0x0290, "CFNotify", "S→C",
          "ContentFinder notification base",
          "category: u16 (8=queue, 9=queueOp, 10=content, 11=state)\n"
          "state: u8\n"
          "padding: u8\n"
          "param1-4: u32 each" },
        { 0x0291, "CFNotifyPop", "S→C",
          "Duty finder match found",
          "category: u16 (should be 10)\n"
          "state: u8 (2+ triggers dialog)\n"
          "padding: u8\n"
          "contentId: u32\n"
          "param2-4: u32 each" },
        { 0x0292, "CFNotifyEnterReady", "S→C",
          "All players ready, entering instance",
          "category: u16\n"
          "state: u8\n"
          "padding: u8\n"
          "param1-4: u32 each" },
        { 0x0293, "CFNotifyMemberUpdate", "S→C",
          "Party member update in queue",
          "category: u16\n"
          "state: u8\n"
          "padding: u8\n"
          "param1-4: u32 each" },
        { 0x0294, "CFNotifyStatus", "S→C",
          "Queue/duty status update",
          "category: u16\n"
          "state: u8\n"
          "padding: u8\n"
          "param1-4: u32 each" },
    };
    return packets;
}

const std::vector<PacketSenderModule::PacketInfo>& PacketSenderModule::GetDirectorPackets() {
    static const std::vector<PacketInfo> packets = {
        { 0x0168, "Director7Init", "S→C",
          "Initialize instance director (triggers ContentsInfo UI)",
          "directorId: u16\n"
          "contentFlags: u8\n"
          "contentType: u8\n"
          "contentId: u8\n"
          "unknown[3]: u8\n"
          "directorData[32]: u8" },
        { 0x0169, "Director7Update", "S→C",
          "Update instance director state",
          "directorId: u16\n"
          "sequence: u8\n"
          "branch: u8\n"
          "data[variable]: u8" },
        { 0x016A, "Director7Result", "S→C",
          "Instance completion/result",
          "directorId: u16\n"
          "resultFlags: u8\n"
          "data[variable]: u8" },
    };
    return packets;
}

const std::vector<PacketSenderModule::PacketInfo>& PacketSenderModule::GetEventPackets() {
    static const std::vector<PacketInfo> packets = {
        // Client → Server
        { 0x01C2, "EventHandlerTalk", "C→S",
          "Talk to NPC / interact with event object",
          "actorId: u32 (target NPC)\n"
          "eventId: u32 (quest/event ID)\n"
          "unknown1: u32\n"
          "unknown2: u32" },
        { 0x01C3, "EventHandlerEmote", "C→S",
          "Emote at NPC",
          "actorId: u32\n"
          "eventId: u32\n"
          "emoteId: u16" },
        { 0x01C4, "EventHandlerWithinRange", "C→S",
          "Entered range of event trigger",
          "actorId: u32\n"
          "eventId: u32\n"
          "position: float[3]" },
        { 0x01C5, "EventHandlerOutsideRange", "C→S",
          "Left range of event trigger",
          "actorId: u32\n"
          "eventId: u32" },
        { 0x01C6, "EnterTerritoryHandler", "C→S",
          "Notify server of territory entry",
          "territoryType: u32\n"
          "unknown: u32" },
    };
    return packets;
}

// ============================================================================
// Constructor
// ============================================================================

PacketSenderModule::PacketSenderModule() {
    // Initialize with sensible defaults
    std::memset(m_cfContentIds, 0, sizeof(m_cfContentIds));
    std::memset(m_genericPayload, 0, sizeof(m_genericPayload));
}

// ============================================================================
// UI Rendering
// ============================================================================

void PacketSenderModule::RenderMenu() {
    if (ImGui::MenuItem("Packet Sender", nullptr, m_windowOpen)) {
        m_windowOpen = !m_windowOpen;
    }
}

void PacketSenderModule::RenderWindow() {
    if (!m_windowOpen) return;

    ImGui::SetNextWindowSize(ImVec2(650, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Packet Sender##PacketSender", &m_windowOpen)) {
        ImGui::End();
        return;
    }

    // IPC Handler status
    bool ipcReady = SapphireHook::IsIPCHandlerReady();
    if (ipcReady) {
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "● IPC Handler Ready");
        ImGui::SameLine();
        ImGui::TextDisabled("(S→C injection active)");
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.2f, 1.0f), "○ IPC Handler Not Hooked");
        ImGui::SameLine();
        ImGui::TextDisabled("(pattern not found - S→C display-only)");
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::TextWrapped(
                "The IPC handler signature was not found for this client version.\n\n"
                "C→S packets work normally (sent to server).\n\n"
                "S→C 'injection' will add packets to NetworkMonitor for testing "
                "decoder display, but won't trigger game client behavior.");
            ImGui::EndTooltip();
        }
    }
    ImGui::Separator();

    // Category tabs
    if (ImGui::BeginTabBar("PacketCategories")) {
        if (ImGui::BeginTabItem("ContentFinder")) {
            RenderContentFinderSection();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Director")) {
            RenderDirectorSection();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Events")) {
            RenderEventSection();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Generic IPC")) {
            RenderGenericSection();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::Separator();
    RenderLastResult();

    ImGui::End();
}

void PacketSenderModule::RenderLastResult() {
    if (!m_lastSendMessage.empty()) {
        ImVec4 color = m_lastSendResult ? ImVec4(0.2f, 0.8f, 0.2f, 1.0f) : ImVec4(0.9f, 0.3f, 0.3f, 1.0f);
        ImGui::TextColored(color, "%s", m_lastSendMessage.c_str());
    }
}

// ============================================================================
// ContentFinder Section
// ============================================================================

void PacketSenderModule::RenderContentFinderSection() {
    const auto& packets = GetContentFinderPackets();
    
    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "ContentFinder / Duty Finder Packets");
    ImGui::Separator();
    
    // Reference table
    if (ImGui::CollapsingHeader("Packet Reference", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::BeginChild("CFRef", ImVec2(0, 180), true);
        for (const auto& p : packets) {
            ImGui::PushID(p.opcode);
            bool isClientToServer = (p.direction[0] == 'C');
            ImVec4 dirColor = isClientToServer ? ImVec4(0.3f, 1.0f, 0.3f, 1.0f) : ImVec4(1.0f, 0.6f, 0.3f, 1.0f);
            
            if (ImGui::TreeNode("##pkt", "0x%04X %s", p.opcode, p.name)) {
                ImGui::TextColored(dirColor, "[%s]", p.direction);
                ImGui::SameLine();
                ImGui::TextWrapped("%s", p.description);
                ImGui::Separator();
                ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.5f, 1.0f), "Syntax:");
                ImGui::TextUnformatted(p.syntax);
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    
    ImGui::Spacing();
    
    // Client→Server senders
    if (ImGui::CollapsingHeader("Send Client→Server", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent();
        
        // Queue for Duties (Find5Contents)
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "Queue for Duties (0x01FD - Find5Contents)");
        ImGui::TextWrapped("Use TerritoryType IDs (e.g., Sastasha=157, Copperbell=161, Tam-Tara=164, Toto-Rak=169)");
        ImGui::InputScalar("Territory Count", ImGuiDataType_S32, &m_cfContentCount);
        m_cfContentCount = (m_cfContentCount < 1) ? 1 : (m_cfContentCount > 5) ? 5 : m_cfContentCount;
        
        for (int i = 0; i < m_cfContentCount; ++i) {
            char label[32];
            snprintf(label, sizeof(label), "Territory Type %d", i + 1);
            ImGui::InputScalar(label, ImGuiDataType_U16, &m_cfContentIds[i]);
        }
        ImGui::BeginDisabled();
        ImGui::InputScalar("Flags (unused)##CF", ImGuiDataType_U32, &m_cfFlags, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::EndDisabled();
        
        if (ImGui::Button("Queue for Duties##Send")) {
            m_lastSendResult = CommandInterface::QueueForDuties(m_cfContentIds, static_cast<uint8_t>(m_cfContentCount), m_cfFlags);
            m_lastSendMessage = m_lastSendResult ? "Sent: Find5Contents (0x01FD)" : "Failed to send Find5Contents";
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        
        // Accept Duty
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "Accept Duty Pop (0x01FB)");
        ImGui::InputScalar("Content ID##Accept", ImGuiDataType_U32, &m_cfAcceptContentId);
        if (ImGui::Button("Accept Duty##Send")) {
            m_lastSendResult = CommandInterface::AcceptDutyPop(m_cfAcceptContentId);
            m_lastSendMessage = m_lastSendResult ? "Sent: AcceptContent (0x01FB)" : "Failed to send AcceptContent";
        }
        
        ImGui::Spacing();
        
        // Cancel Queue
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "Cancel Queue (0x01FC)");
        if (ImGui::Button("Cancel Duty Queue##Send")) {
            m_lastSendResult = CommandInterface::CancelDutyQueue();
            m_lastSendMessage = m_lastSendResult ? "Sent: CancelFindContent (0x01FC)" : "Failed to send CancelFindContent";
        }
        
        ImGui::Unindent();
    }
    
    // Server→Client injectors
    if (ImGui::CollapsingHeader("Inject Server→Client (Testing)")) {
        ImGui::Indent();
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.3f, 1.0f), "Inject CFNotify packets as if received from server");
        ImGui::TextWrapped("These will appear in NetworkMonitor and trigger client-side handlers.");
        
        RenderServerToClientInjector(0x0290, "CFNotify");
        RenderServerToClientInjector(0x0291, "CFNotifyPop");
        RenderServerToClientInjector(0x0292, "CFNotifyEnterReady");
        
        ImGui::Unindent();
    }
}

// ============================================================================
// Director Section
// ============================================================================

void PacketSenderModule::RenderDirectorSection() {
    const auto& packets = GetDirectorPackets();
    
    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Director7 Packets (Instance Content)");
    ImGui::Separator();
    
    // Reference table
    if (ImGui::CollapsingHeader("Packet Reference", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::BeginChild("DirRef", ImVec2(0, 150), true);
        for (const auto& p : packets) {
            ImGui::PushID(p.opcode);
            ImVec4 dirColor = ImVec4(1.0f, 0.6f, 0.3f, 1.0f); // All S→C
            
            if (ImGui::TreeNode("##pkt", "0x%04X %s", p.opcode, p.name)) {
                ImGui::TextColored(dirColor, "[%s]", p.direction);
                ImGui::SameLine();
                ImGui::TextWrapped("%s", p.description);
                ImGui::Separator();
                ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.5f, 1.0f), "Syntax:");
                ImGui::TextUnformatted(p.syntax);
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    
    if (ImGui::CollapsingHeader("Inject Server→Client (Testing)")) {
        ImGui::Indent();
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.3f, 1.0f), "Inject Director7 packets for testing");
        
        RenderServerToClientInjector(0x0168, "Director7Init");
        RenderServerToClientInjector(0x0169, "Director7Update");
        RenderServerToClientInjector(0x016A, "Director7Result");
        
        ImGui::Unindent();
    }
}

// ============================================================================
// Event Section
// ============================================================================

void PacketSenderModule::RenderEventSection() {
    const auto& packets = GetEventPackets();
    
    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Event Handler Packets");
    ImGui::Separator();
    
    // Reference table
    if (ImGui::CollapsingHeader("Packet Reference", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::BeginChild("EvtRef", ImVec2(0, 180), true);
        for (const auto& p : packets) {
            ImGui::PushID(p.opcode);
            bool isClientToServer = (p.direction[0] == 'C');
            ImVec4 dirColor = isClientToServer ? ImVec4(0.3f, 1.0f, 0.3f, 1.0f) : ImVec4(1.0f, 0.6f, 0.3f, 1.0f);
            
            if (ImGui::TreeNode("##pkt", "0x%04X %s", p.opcode, p.name)) {
                ImGui::TextColored(dirColor, "[%s]", p.direction);
                ImGui::SameLine();
                ImGui::TextWrapped("%s", p.description);
                ImGui::Separator();
                ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.5f, 1.0f), "Syntax:");
                ImGui::TextUnformatted(p.syntax);
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    
    ImGui::Spacing();
    
    if (ImGui::CollapsingHeader("Send Client→Server", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent();
        
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "EventHandlerTalk (0x01C2)");
        ImGui::InputScalar("Event ID##Talk", ImGuiDataType_U32, &m_eventId, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::InputScalar("Actor ID##Talk", ImGuiDataType_U32, &m_eventActorId, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        
        if (ImGui::Button("Send EventTalk##Send")) {
            m_lastSendResult = CommandInterface::SendEventTalk(m_eventId, m_eventActorId);
            m_lastSendMessage = m_lastSendResult ? "Sent: EventHandlerTalk (0x01C2)" : "Failed to send EventHandlerTalk";
        }
        
        ImGui::Unindent();
    }
}

// ============================================================================
// Generic IPC Section
// ============================================================================

void PacketSenderModule::RenderGenericSection() {
    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Generic IPC Packet Builder");
    ImGui::Separator();
    
    ImGui::TextWrapped("Build and send any IPC packet with raw hex payload.");
    ImGui::Spacing();
    
    // Direction
    static int direction = 0; // 0 = C→S, 1 = S→C
    ImGui::RadioButton("Client → Server", &direction, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Server → Client (Inject)", &direction, 1);
    
    ImGui::Spacing();
    
    // Opcode
    ImGui::InputScalar("IPC Opcode", ImGuiDataType_U16, &m_genericOpcode, nullptr, nullptr, "0x%04X", ImGuiInputTextFlags_CharsHexadecimal);
    
    // Payload size
    ImGui::InputInt("Payload Size", &m_genericPayloadSize);
    m_genericPayloadSize = (m_genericPayloadSize < 0) ? 0 : (m_genericPayloadSize > 256) ? 256 : m_genericPayloadSize;
    
    // Hex input
    ImGui::InputTextMultiline("Payload (Hex)", &m_genericPayloadHex[0], m_genericPayloadHex.capacity() + 1,
        ImVec2(-1, 80), ImGuiInputTextFlags_CallbackResize,
        [](ImGuiInputTextCallbackData* data) -> int {
            if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
                auto* str = static_cast<std::string*>(data->UserData);
                str->resize(data->BufTextLen);
                data->Buf = &(*str)[0];
            }
            return 0;
        }, &m_genericPayloadHex);
    
    ImGui::TextDisabled("Enter hex bytes separated by spaces: 00 11 22 33 ...");
    
    // Parse hex string to payload
    if (ImGui::Button("Parse Hex")) {
        std::memset(m_genericPayload, 0, sizeof(m_genericPayload));
        std::istringstream iss(m_genericPayloadHex);
        std::string byte;
        int idx = 0;
        while (iss >> byte && idx < 256) {
            m_genericPayload[idx++] = static_cast<uint8_t>(std::stoul(byte, nullptr, 16));
        }
        m_genericPayloadSize = idx;
    }
    
    ImGui::SameLine();
    
    // Send button
    if (ImGui::Button("Send Packet##Generic")) {
        if (direction == 0) {
            // Client → Server
            m_lastSendResult = CommandInterface::SendIpcPacketRaw(
                m_genericOpcode, m_genericPayload, static_cast<size_t>(m_genericPayloadSize));
            m_lastSendMessage = m_lastSendResult 
                ? "Sent C→S: 0x" + ToHexString(m_genericOpcode) 
                : "Failed to send packet";
        } else {
            // Server → Client (inject)
            m_lastSendResult = InjectServerPacket(m_genericOpcode, m_genericPayload, static_cast<size_t>(m_genericPayloadSize));
            m_lastSendMessage = m_lastSendResult 
                ? "Injected S→C: 0x" + ToHexString(m_genericOpcode) 
                : "Failed to inject packet";
        }
    }
    
    // Show parsed payload
    if (m_genericPayloadSize > 0) {
        ImGui::Separator();
        ImGui::Text("Parsed Payload (%d bytes):", m_genericPayloadSize);
        std::ostringstream oss;
        for (int i = 0; i < m_genericPayloadSize; ++i) {
            oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') 
                << static_cast<int>(m_genericPayload[i]);
            if ((i + 1) % 16 == 0) oss << "\n";
            else oss << " ";
        }
        ImGui::TextUnformatted(oss.str().c_str());
    }
}

// ============================================================================
// Server→Client Injection Helpers
// ============================================================================

void PacketSenderModule::RenderServerToClientInjector(uint16_t opcode, const char* name) {
    ImGui::PushID(opcode);
    
    static std::unordered_map<uint16_t, std::array<uint32_t, 6>> s_params;
    auto& params = s_params[opcode]; // category, state, param1-4
    
    if (ImGui::TreeNode("##inject", "0x%04X %s", opcode, name)) {
        ImGui::InputScalar("category (u16)", ImGuiDataType_U32, &params[0]);
        ImGui::InputScalar("state (u8)", ImGuiDataType_U32, &params[1]);
        ImGui::InputScalar("param1", ImGuiDataType_U32, &params[2], nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::InputScalar("param2", ImGuiDataType_U32, &params[3], nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::InputScalar("param3", ImGuiDataType_U32, &params[4], nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::InputScalar("param4", ImGuiDataType_U32, &params[5], nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        
        if (ImGui::Button("Inject##btn")) {
            // Build CFNotify-style payload
            struct CFNotifyPayload {
                uint16_t category;
                uint8_t state;
                uint8_t padding;
                uint32_t param1;
                uint32_t param2;
                uint32_t param3;
                uint32_t param4;
            };
            
            CFNotifyPayload payload = {};
            payload.category = static_cast<uint16_t>(params[0]);
            payload.state = static_cast<uint8_t>(params[1]);
            payload.param1 = params[2];
            payload.param2 = params[3];
            payload.param3 = params[4];
            payload.param4 = params[5];
            
            m_lastSendResult = InjectServerPacket(opcode, &payload, sizeof(payload));
            m_lastSendMessage = m_lastSendResult 
                ? "Injected: " + std::string(name) 
                : "Failed to inject " + std::string(name);
        }
        
        ImGui::TreePop();
    }
    
    ImGui::PopID();
}

bool PacketSenderModule::InjectServerPacket(uint16_t opcode, const void* payload, size_t payloadSize) {
    // Check if IPC handler is ready
    if (!SapphireHook::IsIPCHandlerReady()) {
        Logger::Instance().WarningF("[PacketSender] IPC handler not ready - game needs to receive at least one packet first");
        return false;
    }
    
    // Use the real IPC handler injection - this will trigger actual game behavior
    bool ok = SapphireHook::InjectServerPacket(opcode, payload, payloadSize);
    
    if (ok) {
        // Also log to packet capture for visibility in NetworkMonitor
        constexpr size_t PACKET_HEADER_SIZE = 40;
        constexpr size_t SEGMENT_HEADER_SIZE = 16;
        constexpr size_t IPC_HEADER_SIZE = 16;
        
        const size_t totalSize = PACKET_HEADER_SIZE + SEGMENT_HEADER_SIZE + IPC_HEADER_SIZE + payloadSize;
        std::vector<uint8_t> buffer(totalSize, 0);
        
        // Build minimal packet structure for display
        auto* pktHdr = reinterpret_cast<uint64_t*>(buffer.data());
        pktHdr[0] = 0x5252415658494646; // "FFXIVARR" magic
        pktHdr[2] = static_cast<uint64_t>(GetTickCount64());
        
        uint32_t* pktSize = reinterpret_cast<uint32_t*>(buffer.data() + 24);
        *pktSize = static_cast<uint32_t>(totalSize);
        
        uint16_t* pktConnType = reinterpret_cast<uint16_t*>(buffer.data() + 28);
        *pktConnType = 1; // Zone
        
        uint16_t* pktCount = reinterpret_cast<uint16_t*>(buffer.data() + 30);
        *pktCount = 1;
        
        uint8_t* segBase = buffer.data() + PACKET_HEADER_SIZE;
        *reinterpret_cast<uint32_t*>(segBase) = static_cast<uint32_t>(SEGMENT_HEADER_SIZE + IPC_HEADER_SIZE + payloadSize);
        *reinterpret_cast<uint32_t*>(segBase + 8) = CommandInterface::GetLocalEntityId();
        *reinterpret_cast<uint16_t*>(segBase + 12) = 3; // IPC
        
        uint8_t* ipcBase = segBase + SEGMENT_HEADER_SIZE;
        *reinterpret_cast<uint16_t*>(ipcBase) = 0x14;
        *reinterpret_cast<uint16_t*>(ipcBase + 2) = opcode;
        *reinterpret_cast<uint32_t*>(ipcBase + 8) = static_cast<uint32_t>(GetTickCount64());
        
        if (payload && payloadSize > 0) {
            std::memcpy(ipcBase + IPC_HEADER_SIZE, payload, payloadSize);
        }
        
        // Add to capture for display (marked as injected)
        PacketCapture::Instance().TryEnqueueFromHook(buffer.data(), buffer.size(), false, 0);
        
        Logger::Instance().InformationF("[PacketSender] Injected S→C packet 0x%04X into game handler, %zu bytes", opcode, payloadSize);
    } else {
        Logger::Instance().WarningF("[PacketSender] Failed to inject S→C packet 0x%04X", opcode);
    }
    
    return ok;
}

std::string PacketSenderModule::ToHexString(uint16_t value) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << value;
    return oss.str();
}

} // namespace SapphireHook
