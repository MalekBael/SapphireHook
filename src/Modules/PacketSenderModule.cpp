#include "PacketSenderModule.h"
#include "CommandInterface.h"
#include "../Core/PacketInjector.h"
#include "../Monitor/NetworkMonitor.h"
#include "../Hooking/hook_manager.h"
#include "../Analysis/PatternScanner.h"
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

const std::vector<PacketSenderModule::PacketInfo>& PacketSenderModule::GetRetainerPackets() {
    static const std::vector<PacketInfo> packets = {
        // Server → Client (what the server needs to send)
        { 0x00E5, "EventStart", "S→C",
          "Initialize event context",
          "actorId: u32\n"
          "eventId: u32\n"
          "flags: u32" },
        { 0x00E6, "EventPlay", "S→C",
          "Trigger event scene/script",
          "actorId: u32\n"
          "handlerId: u32\n"
          "sceneId: u16\n"
          "padding: u16\n"
          "flags: u32\n"
          "params[8]: u32" },
        { 0x01EF, "RetainerInfo", "S→C",
          "Retainer status/flags",
          "retainerCount: u8\n"
          "padding: u8[3]\n"
          "reserved: u32[10]" },
        { 0x01F0, "RetainerList", "S→C",
          "List of retainers (up to 8)",
          "retainer[8]: {\n"
          "  retainerId: u64\n"
          "  name: char[32]\n"
          "  etc...\n"
          "}" },
        
        // Client → Server Event Subtypes (sent via EventPlay)
        { 0x01E0, "EventReply (480-487)", "C→S",
          "Event response packet (opcode varies by payload size)",
          "handlerId: u32\n"
          "sceneId: u16\n"
          "subtype: u8 (3=LoadRetainerCreation, etc.)\n"
          "data: variable" },
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
    
    // Try to scan for retainer functions
    TryScanRetainerFunctions();
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
        if (ImGui::BeginTabItem("Retainer")) {
            RenderRetainerSection();
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

// ============================================================================
// Retainer Section
// ============================================================================

bool PacketSenderModule::TryScanRetainerFunctions() {
    // Get module base for fallback address calculation
    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    
    // Scan for SendEventPacket (sub_140CC2CF0)
    // Signature: 40 55 48 8D AC 24 B0 F4 FF FF 48 81 EC 50 0C 00 00
    auto sendResult = PatternScanner::ScanMainModule("40 55 48 8D AC 24 B0 F4 FF FF 48 81 EC 50 0C 00 00");
    if (sendResult) {
        m_sendEventPacketAddr = sendResult->address;
        Logger::Instance().InformationF("[PacketSender] Found SendEventPacket at 0x%llX", m_sendEventPacketAddr);
    }
    
    // Scan for LoadRetainerCreation (sub_140633910)
    // Signature: 40 53 48 83 EC 60 48 8B D1 48 8D 4C 24 30
    auto loadResult = PatternScanner::ScanMainModule("40 53 48 83 EC 60 48 8B D1 48 8D 4C 24 30");
    if (loadResult) {
        m_loadRetainerCreationAddr = loadResult->address;
        Logger::Instance().InformationF("[PacketSender] Found LoadRetainerCreation at 0x%llX", m_loadRetainerCreationAddr);
    }
    
    // Scan for PlayEventScene (sub_14069AAA0)
    // Bytes at start: 48 89 5C 24 08 57 48 83 EC 40 8B 81 60 09 00 00
    auto playSceneResult = PatternScanner::ScanMainModule("48 89 5C 24 08 57 48 83 EC 40 8B 81 60 09 00 00");
    if (playSceneResult) {
        m_playEventSceneAddr = playSceneResult->address;
        Logger::Instance().InformationF("[PacketSender] Found PlayEventScene at 0x%llX", m_playEventSceneAddr);
    } else {
        // Fallback for 3.35 binary: offset 0x69AAA0 from module base
        m_playEventSceneAddr = moduleBase + 0x69AAA0;
        Logger::Instance().InformationF("[PacketSender] Using fallback PlayEventScene at 0x%llX (3.35 offset)", m_playEventSceneAddr);
    }
    
    // Scan for StartEventScene (sub_14068FEB0)
    // Bytes at start: 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54
    auto startSceneResult = PatternScanner::ScanMainModule("48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54");
    if (startSceneResult) {
        m_startEventSceneAddr = startSceneResult->address;
        Logger::Instance().InformationF("[PacketSender] Found StartEventScene at 0x%llX", m_startEventSceneAddr);
    } else {
        // Fallback for 3.35 binary: offset 0x68FEB0 from module base
        m_startEventSceneAddr = moduleBase + 0x68FEB0;
        Logger::Instance().InformationF("[PacketSender] Using fallback StartEventScene at 0x%llX (3.35 offset)", m_startEventSceneAddr);
    }
    
    // Scan for GetOrCreateHandler (sub_1406722E0)
    // Bytes at start: 40 53 55 56 41 55 48 83 EC 28 8B DA 4D 8B E8 8B F2
    auto getOrCreateResult = PatternScanner::ScanMainModule("40 53 55 56 41 55 48 83 EC 28 8B DA 4D 8B E8 8B F2");
    if (getOrCreateResult) {
        m_getOrCreateHandlerAddr = getOrCreateResult->address;
        Logger::Instance().InformationF("[PacketSender] Found GetOrCreateHandler at 0x%llX", m_getOrCreateHandlerAddr);
    } else {
        // Fallback for 3.35 binary: offset 0x6722E0 from module base
        m_getOrCreateHandlerAddr = moduleBase + 0x6722E0;
        Logger::Instance().InformationF("[PacketSender] Using fallback GetOrCreateHandler at 0x%llX (3.35 offset)", m_getOrCreateHandlerAddr);
    }
    
    // Scan for EventManager global (qword_1417C39D0)
    // This is stored at a fixed address. In 3.35, it's at offset 0x17C39D0 from image base.
    // We'll use the direct offset as fallback.
    // Try to find it by scanning for a mov instruction that references it near PlayEventScene calls
    // For now, use direct offset for 3.35
    m_eventManagerPtr = moduleBase + 0x17C39D0;
    Logger::Instance().InformationF("[PacketSender] Using EventManager at 0x%llX (3.35 offset)", m_eventManagerPtr);
    
    // Local player pointer global: qword_1415F5A68 - offset 0x15F5A68 from module base
    m_localPlayerPtr = moduleBase + 0x15F5A68;
    Logger::Instance().InformationF("[PacketSender] Using LocalPlayer ptr at 0x%llX (3.35 offset)", m_localPlayerPtr);
    
    // Target Manager base: qword_1415F1830 - offset 0x15F1830 from module base
    // The Target Manager has current target wrapper at +0x98, fallback at +0x90
    m_currentTargetPtr = moduleBase + 0x15F1830;
    Logger::Instance().InformationF("[PacketSender] Using TargetManager at 0x%llX (3.35 offset)", m_currentTargetPtr);
    
    // Actor lookup function: sub_1405C1A10 - converts actor ID to actor pointer
    // Offset 0x5C1A10 from module base
    m_actorLookupAddr = moduleBase + 0x5C1A10;
    Logger::Instance().InformationF("[PacketSender] Using ActorLookup at 0x%llX (3.35 offset)", m_actorLookupAddr);
    
    return m_sendEventPacketAddr != 0 || m_loadRetainerCreationAddr != 0 || 
           m_playEventSceneAddr != 0 || m_startEventSceneAddr != 0 || m_getOrCreateHandlerAddr != 0;
}

// Helper function with SEH - declared outside class methods with objects
static bool CallSendEventPacket_SEH(uintptr_t funcAddr, int handlerId, int16_t sceneId, char subtype, uint32_t* data, uint8_t size) {
    using SendEventPacket_t = char(__fastcall*)(int, int16_t, char, uint32_t*, uint8_t);
    auto SendEventPacket = reinterpret_cast<SendEventPacket_t>(funcAddr);
    
    __try {
        char result = SendEventPacket(handlerId, sceneId, subtype, data, size);
        return result != 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool PacketSenderModule::CallSendEventPacket(int handlerId, int16_t sceneId, char subtype, uint32_t* data, uint8_t size) {
    if (m_sendEventPacketAddr == 0) {
        Logger::Instance().Warning("[PacketSender] SendEventPacket not found");
        return false;
    }
    
    bool result = CallSendEventPacket_SEH(m_sendEventPacketAddr, handlerId, sceneId, subtype, data, size);
    
    if (result) {
        Logger::Instance().InformationF("[PacketSender] SendEventPacket called: handler=%d, scene=%d, subtype=%d",
            handlerId, sceneId, subtype);
    } else {
        Logger::Instance().Warning("[PacketSender] SendEventPacket failed or returned 0");
    }
    
    return result;
}

// SEH wrapper for PlayEventScene
// Signature: char __fastcall sub_14069AAA0(__int64 eventManager, _BYTE *actorPtr, signed int handlerId, __int16 sceneId, __int64 delay, _DWORD *params, unsigned __int8 paramCount)
static bool CallPlayEventScene_SEH(uintptr_t funcAddr, uintptr_t eventManager, uintptr_t actorPtr, 
                                    uint32_t handlerId, int16_t sceneId, int64_t delay, 
                                    uint32_t* params, uint8_t paramCount) {
    using PlayEventScene_t = char(__fastcall*)(int64_t, uint8_t*, int32_t, int16_t, int64_t, uint32_t*, uint8_t);
    auto PlayEventScene = reinterpret_cast<PlayEventScene_t>(funcAddr);
    
    __try {
        char result = PlayEventScene(
            static_cast<int64_t>(eventManager),
            reinterpret_cast<uint8_t*>(actorPtr),
            static_cast<int32_t>(handlerId),
            sceneId,
            delay,
            params,
            paramCount
        );
        return result != 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH helper to safely read EventManager instance
static uintptr_t ReadEventManagerInstance_SEH(uintptr_t ptrAddr) {
    __try {
        return *reinterpret_cast<uintptr_t*>(ptrAddr);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

bool PacketSenderModule::CallPlayEventScene(uintptr_t actorPtr, uint32_t handlerId, int16_t sceneId, 
                                             int64_t delay, uint32_t* params, uint8_t paramCount) {
    if (m_playEventSceneAddr == 0) {
        Logger::Instance().Warning("[PacketSender] PlayEventScene not found");
        return false;
    }
    if (m_eventManagerPtr == 0) {
        Logger::Instance().Warning("[PacketSender] EventManager pointer not found");
        return false;
    }
    
    // Dereference the global pointer to get the actual EventManager instance
    uintptr_t eventManagerInstance = ReadEventManagerInstance_SEH(m_eventManagerPtr);
    if (eventManagerInstance == 0) {
        Logger::Instance().Warning("[PacketSender] EventManager instance is null or read failed - no active event context");
        return false;
    }
    
    Logger::Instance().InformationF("[PacketSender] Calling PlayEventScene: manager=0x%llX, actor=0x%llX, handler=0x%X, scene=%d",
        eventManagerInstance, actorPtr, handlerId, sceneId);
    
    bool result = CallPlayEventScene_SEH(m_playEventSceneAddr, eventManagerInstance, actorPtr, 
                                          handlerId, sceneId, delay, params, paramCount);
    
    if (result) {
        Logger::Instance().Information("[PacketSender] PlayEventScene returned success");
    } else {
        Logger::Instance().Warning("[PacketSender] PlayEventScene failed or returned 0");
    }
    
    return result;
}

// SEH wrapper for StartEventScene
// Signature: char __fastcall sub_14068FEB0(_QWORD *eventManager, _BYTE *actorPtr, signed int handlerId, __int16 sceneId, __int64 delay, void *params, unsigned __int8 paramCount)
static bool CallStartEventScene_SEH(uintptr_t funcAddr, uintptr_t eventManager, uintptr_t actorPtr,
                                     uint32_t handlerId, int16_t sceneId, int64_t delay,
                                     uint32_t* params, uint8_t paramCount) {
    using StartEventScene_t = char(__fastcall*)(int64_t*, uint8_t*, int32_t, int16_t, int64_t, void*, uint8_t);
    auto StartEventScene = reinterpret_cast<StartEventScene_t>(funcAddr);
    
    __try {
        char result = StartEventScene(
            reinterpret_cast<int64_t*>(eventManager),
            reinterpret_cast<uint8_t*>(actorPtr),
            static_cast<int32_t>(handlerId),
            sceneId,
            delay,
            params,
            paramCount
        );
        return result != 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool PacketSenderModule::CallStartEventScene(uintptr_t actorPtr, uint32_t handlerId, int16_t sceneId,
                                              int64_t delay, uint32_t* params, uint8_t paramCount) {
    if (m_startEventSceneAddr == 0) {
        Logger::Instance().Warning("[PacketSender] StartEventScene not found");
        return false;
    }
    if (m_eventManagerPtr == 0) {
        Logger::Instance().Warning("[PacketSender] EventManager pointer not found");
        return false;
    }
    
    // Dereference the global pointer to get the actual EventManager instance
    uintptr_t eventManagerInstance = ReadEventManagerInstance_SEH(m_eventManagerPtr);
    if (eventManagerInstance == 0) {
        Logger::Instance().Warning("[PacketSender] EventManager instance is null or read failed - no active event context");
        return false;
    }
    
    // Pre-check: Verify handler lookup will succeed
    // The handler lookup function (sub_1406603C0) checks:
    // 1. If eventManager[79] is set, check the handler from sub_140533AE0
    // 2. If handlerId >= 0, call sub_140656ED0
    // 3. If handlerId < 0, search linked list at [40]-[41]
    if (SapphireHook::IsValidMemoryAddress(eventManagerInstance + 79 * 8, sizeof(uint64_t))) {
        uint64_t slot79 = *reinterpret_cast<uint64_t*>(eventManagerInstance + 79 * 8);
        Logger::Instance().InformationF("[PacketSender] Pre-check: EventManager[79] = 0x%llX", slot79);
    }
    
    Logger::Instance().InformationF("[PacketSender] Calling StartEventScene: manager=0x%llX, actor=0x%llX, handler=0x%X, scene=%d",
        eventManagerInstance, actorPtr, handlerId, sceneId);
    
    bool result = CallStartEventScene_SEH(m_startEventSceneAddr, eventManagerInstance, actorPtr,
                                           handlerId, sceneId, delay, params, paramCount);
    
    if (result) {
        Logger::Instance().Information("[PacketSender] StartEventScene returned success");
    } else {
        Logger::Instance().Warning("[PacketSender] StartEventScene failed or returned 0");
    }
    
    return result;
}

// SEH wrapper for GetOrCreateHandler
// Signature: __int64 __fastcall sub_1406722E0(_QWORD *eventManager, unsigned int handlerId, __int64 actorPtr)
// This function looks up an existing handler or creates a new one via the factory
static uintptr_t CallGetOrCreateHandler_SEH(uintptr_t funcAddr, uintptr_t eventManager, uint32_t handlerId, uintptr_t actorPtr) {
    using GetOrCreateHandler_t = int64_t(__fastcall*)(uint64_t*, uint32_t, int64_t);
    auto GetOrCreateHandler = reinterpret_cast<GetOrCreateHandler_t>(funcAddr);
    
    // Debug: Check if actor would be blocked by the game's validation
    // The game checks: (*(uint16_t*)(actor + 136) - 200) <= 0x2B
    // If true, GetOrCreateHandler returns 0 immediately
    if (actorPtr != 0 && SapphireHook::IsValidMemoryAddress(actorPtr + 136, sizeof(uint16_t))) {
        uint16_t actorField = *reinterpret_cast<uint16_t*>(actorPtr + 136);
        bool wouldBlock = ((actorField - 200) <= 0x2B);
        SapphireHook::Logger::Instance().InformationF(
            "[PacketSender] Actor validation: field@0x88=%u, blocked=%s",
            actorField, wouldBlock ? "YES (try NULL actor)" : "no");
    }
    
    __try {
        int64_t result = GetOrCreateHandler(
            reinterpret_cast<uint64_t*>(eventManager),
            handlerId,
            static_cast<int64_t>(actorPtr)
        );
        return static_cast<uintptr_t>(result);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

uintptr_t PacketSenderModule::GetOrCreateHandler(uint32_t handlerId, uintptr_t actorPtr) {
    if (m_getOrCreateHandlerAddr == 0) {
        Logger::Instance().Warning("[PacketSender] GetOrCreateHandler not found");
        return 0;
    }
    if (m_eventManagerPtr == 0) {
        Logger::Instance().Warning("[PacketSender] EventManager pointer not found");
        return 0;
    }
    
    // Dereference the global pointer to get the actual EventManager instance
    uintptr_t eventManagerInstance = ReadEventManagerInstance_SEH(m_eventManagerPtr);
    if (eventManagerInstance == 0) {
        Logger::Instance().Warning("[PacketSender] EventManager instance is null");
        return 0;
    }
    
    Logger::Instance().InformationF("[PacketSender] Calling GetOrCreateHandler: manager=0x%llX, handler=0x%X, actor=0x%llX",
        eventManagerInstance, handlerId, actorPtr);
    
    uintptr_t result = CallGetOrCreateHandler_SEH(m_getOrCreateHandlerAddr, eventManagerInstance, handlerId, actorPtr);
    
    if (result != 0) {
        Logger::Instance().InformationF("[PacketSender] GetOrCreateHandler returned handler at 0x%llX", result);
        
        // Verify handler storage: the lookup function checks *(handler + 48) == handlerId
        if (SapphireHook::IsValidMemoryAddress(result + 48, sizeof(uint32_t))) {
            uint32_t storedId = *reinterpret_cast<uint32_t*>(result + 48);
            Logger::Instance().InformationF("[PacketSender] Handler verification: stored ID at +48 = 0x%X (expected 0x%X)", 
                storedId, handlerId);
        }
        
        // Also log EventManager[79] which is checked in the lookup
        if (SapphireHook::IsValidMemoryAddress(eventManagerInstance + 79 * 8, sizeof(uint64_t))) {
            uint64_t slot79 = *reinterpret_cast<uint64_t*>(eventManagerInstance + 79 * 8);
            Logger::Instance().InformationF("[PacketSender] EventManager[79] = 0x%llX (used by handler lookup)", slot79);
        }
    } else {
        Logger::Instance().Warning("[PacketSender] GetOrCreateHandler returned 0 (handler not created)");
    }
    
    return result;
}

uintptr_t PacketSenderModule::GetLocalPlayerActorPtr() {
    // Read local player actor pointer from qword_1415F5A68
    if (m_localPlayerPtr == 0) {
        Logger::Instance().Warning("[PacketSender] LocalPlayer pointer address not set");
        return 0;
    }
    
    // Safely read the pointer (it's a pointer-to-pointer)
    uintptr_t actorPtr = ReadEventManagerInstance_SEH(m_localPlayerPtr);
    if (actorPtr == 0) {
        Logger::Instance().Warning("[PacketSender] LocalPlayer actor pointer is null");
        return 0;
    }
    
    Logger::Instance().InformationF("[PacketSender] LocalPlayer actor at 0x%llX", actorPtr);
    return actorPtr;
}

bool PacketSenderModule::SendStartTalkEventPacket(uint64_t targetActorId, uint32_t eventId) {
    // Build a StartTalkEvent packet (opcode 0x01C2 in 3.35)
    // This tells the server we want to talk to an NPC, and the server responds with event scene data
    
    const uint32_t localActorId = SapphireHook::GetLearnedLocalActorId();
    
    if (localActorId == 0 || localActorId == 0xFFFFFFFF) {
        Logger::Instance().Warning("[PacketSender] Cannot send StartTalkEvent - local actor ID unknown");
        return false;
    }
    
    // Use fixed sizes matching game's actual packet format
    constexpr size_t PACKET_HEADER_SIZE = 40;
    constexpr size_t SEGMENT_HEADER_SIZE = 16;
    constexpr size_t IPC_HEADER_SIZE = 16;
    constexpr size_t PAYLOAD_SIZE = 12;  // uint64_t actorId + uint32_t eventId
    
    const size_t totalSize = PACKET_HEADER_SIZE + SEGMENT_HEADER_SIZE + IPC_HEADER_SIZE + PAYLOAD_SIZE;
    std::vector<uint8_t> buffer(totalSize, 0);
    
    const uint64_t ts = GetTickCount64();
    
    // ===== PACKET HEADER (40 bytes) =====
    // Offset 0-7: Magic "FFXIVARR" (required!)
    // "FFXIVARR" = 0x46 0x46 0x58 0x49 0x56 0x41 0x52 0x52
    *reinterpret_cast<uint64_t*>(buffer.data() + 0) = 0x5252415649584646ULL;  // "FFXIVARR" in little-endian
    // Offset 8-15: Unknown (zeros)
    // Offset 16-23: Timestamp
    *reinterpret_cast<uint64_t*>(buffer.data() + 16) = ts;
    // Offset 24-27: Total size
    *reinterpret_cast<uint32_t*>(buffer.data() + 24) = static_cast<uint32_t>(totalSize);
    // Offset 28-29: Connection type (1 = Zone)
    *reinterpret_cast<uint16_t*>(buffer.data() + 28) = 1;
    // Offset 30-31: Segment count
    *reinterpret_cast<uint16_t*>(buffer.data() + 30) = 1;
    // Offset 32-39: Unknown/flags (zeros)
    
    // ===== SEGMENT HEADER (16 bytes) =====
    uint8_t* segBase = buffer.data() + PACKET_HEADER_SIZE;
    // Offset 0-3: Segment size
    *reinterpret_cast<uint32_t*>(segBase + 0) = static_cast<uint32_t>(SEGMENT_HEADER_SIZE + IPC_HEADER_SIZE + PAYLOAD_SIZE);
    // Offset 4-7: Source actor
    *reinterpret_cast<uint32_t*>(segBase + 4) = localActorId;
    // Offset 8-11: Target actor
    *reinterpret_cast<uint32_t*>(segBase + 8) = 0;
    // Offset 12-13: Type (3 = IPC)
    *reinterpret_cast<uint16_t*>(segBase + 12) = 3;
    // Offset 14-15: Padding
    
    // ===== IPC HEADER (16 bytes) =====
    uint8_t* ipcBase = segBase + SEGMENT_HEADER_SIZE;
    // Offset 0-1: Reserved (0x14)
    *reinterpret_cast<uint16_t*>(ipcBase + 0) = 0x14;
    // Offset 2-3: Opcode
    *reinterpret_cast<uint16_t*>(ipcBase + 2) = 0x01C2;  // StartTalkEvent / EventHandlerTalk
    // Offset 4-5: Padding
    // Offset 6-7: Server ID
    // Offset 8-11: Timestamp
    *reinterpret_cast<uint32_t*>(ipcBase + 8) = static_cast<uint32_t>(ts);
    // Offset 12-15: Padding
    
    // ===== PAYLOAD (12 bytes) =====
    uint8_t* payloadBase = ipcBase + IPC_HEADER_SIZE;
    // Offset 0-7: Target actor ID
    *reinterpret_cast<uint64_t*>(payloadBase + 0) = targetActorId;
    // Offset 8-11: Event ID
    *reinterpret_cast<uint32_t*>(payloadBase + 8) = eventId;
    
    Logger::Instance().InformationF("[PacketSender] Sending StartTalkEvent: targetActor=0x%llX, eventId=0x%X, localActor=0x%X, size=%zu",
        targetActorId, eventId, localActorId, totalSize);
    
    // Debug: Log hex dump of first 40 bytes (packet header) and segment info
    {
        std::string hexDump;
        for (size_t i = 0; i < (std::min)(totalSize, size_t(84)); i++) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02X ", buffer[i]);
            hexDump += hex;
            if ((i + 1) % 16 == 0) hexDump += "\n";
        }
        Logger::Instance().InformationF("[PacketSender] Packet hex dump:\n%s", hexDump.c_str());
    }
    
    // Send via PacketInjector
    bool result = SapphireHook::PacketInjector::SendZone(buffer.data(), buffer.size());
    
    if (result) {
        Logger::Instance().Information("[PacketSender] StartTalkEvent packet sent successfully");
    } else {
        Logger::Instance().Warning("[PacketSender] Failed to send StartTalkEvent packet");
    }
    
    return result;
}

bool PacketSenderModule::SendReturnEventScenePacket(uint32_t handlerId, uint16_t sceneId, uint32_t selection) {
    // Build a ReturnEventScene2 packet (opcode 0x01D7 in 3.35)
    // This simulates selecting an option from an event menu
    
    const uint32_t localActorId = SapphireHook::GetLearnedLocalActorId();
    
    if (localActorId == 0 || localActorId == 0xFFFFFFFF) {
        Logger::Instance().Warning("[PacketSender] Cannot send ReturnEventScene - local actor ID unknown");
        return false;
    }
    
    // ReturnEventScene2 payload: handlerId(4) + sceneId(2) + errorCode(1) + numResults(1) + results[2](8) = 16 bytes
    constexpr size_t PACKET_HEADER_SIZE = 40;
    constexpr size_t SEGMENT_HEADER_SIZE = 16;
    constexpr size_t IPC_HEADER_SIZE = 16;
    constexpr size_t PAYLOAD_SIZE = 16;  // ReturnEventScene2 payload
    
    const size_t totalSize = PACKET_HEADER_SIZE + SEGMENT_HEADER_SIZE + IPC_HEADER_SIZE + PAYLOAD_SIZE;
    std::vector<uint8_t> buffer(totalSize, 0);
    
    const uint64_t ts = GetTickCount64();
    
    // ===== PACKET HEADER (40 bytes) =====
    *reinterpret_cast<uint64_t*>(buffer.data() + 0) = 0x5252415649584646ULL;  // "FFXIVARR"
    *reinterpret_cast<uint64_t*>(buffer.data() + 16) = ts;
    *reinterpret_cast<uint32_t*>(buffer.data() + 24) = static_cast<uint32_t>(totalSize);
    *reinterpret_cast<uint16_t*>(buffer.data() + 28) = 1;  // Zone connection
    *reinterpret_cast<uint16_t*>(buffer.data() + 30) = 1;  // Segment count
    
    // ===== SEGMENT HEADER (16 bytes) =====
    uint8_t* segBase = buffer.data() + PACKET_HEADER_SIZE;
    *reinterpret_cast<uint32_t*>(segBase + 0) = static_cast<uint32_t>(SEGMENT_HEADER_SIZE + IPC_HEADER_SIZE + PAYLOAD_SIZE);
    *reinterpret_cast<uint32_t*>(segBase + 4) = localActorId;  // Source actor
    *reinterpret_cast<uint32_t*>(segBase + 8) = 0;             // Target actor
    *reinterpret_cast<uint16_t*>(segBase + 12) = 3;            // Type = IPC
    
    // ===== IPC HEADER (16 bytes) =====
    uint8_t* ipcBase = segBase + SEGMENT_HEADER_SIZE;
    *reinterpret_cast<uint16_t*>(ipcBase + 0) = 0x14;          // Reserved
    *reinterpret_cast<uint16_t*>(ipcBase + 2) = 0x01D7;        // ReturnEventScene2 opcode
    *reinterpret_cast<uint32_t*>(ipcBase + 8) = static_cast<uint32_t>(ts);
    
    // ===== PAYLOAD (16 bytes) - FFXIVIpcEventHandlerReturnN<2> =====
    uint8_t* payloadBase = ipcBase + IPC_HEADER_SIZE;
    *reinterpret_cast<uint32_t*>(payloadBase + 0) = handlerId;     // handlerId
    *reinterpret_cast<uint16_t*>(payloadBase + 4) = sceneId;       // sceneId (0 = main menu)
    *reinterpret_cast<uint8_t*>(payloadBase + 6) = 0;              // errorCode (0 = success)
    *reinterpret_cast<uint8_t*>(payloadBase + 7) = 1;              // numOfResults (1 result)
    *reinterpret_cast<uint32_t*>(payloadBase + 8) = selection;     // results[0] = user selection
    *reinterpret_cast<uint32_t*>(payloadBase + 12) = 0;            // results[1] = 0
    
    Logger::Instance().InformationF("[PacketSender] Sending ReturnEventScene2: handlerId=0x%X, sceneId=%d, selection=%d",
        handlerId, sceneId, selection);
    
    // Debug hex dump
    {
        std::string hexDump;
        for (size_t i = 0; i < totalSize; i++) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02X ", buffer[i]);
            hexDump += hex;
            if ((i + 1) % 16 == 0) hexDump += "\n";
        }
        Logger::Instance().InformationF("[PacketSender] ReturnEventScene2 hex dump:\n%s", hexDump.c_str());
    }
    
    bool result = SapphireHook::PacketInjector::SendZone(buffer.data(), buffer.size());
    
    if (result) {
        Logger::Instance().Information("[PacketSender] ReturnEventScene2 packet sent successfully");
    } else {
        Logger::Instance().Warning("[PacketSender] Failed to send ReturnEventScene2 packet");
    }
    
    return result;
}

// SEH helper for reading actor ID from actor pointer
// Returns the FULL 64-bit actor ID including object type prefix
static uint64_t ReadActorIdFromPtr_SEH(uintptr_t actorPtr) {
    __try {
        if (actorPtr == 0) return 0;
        
        // First try to read from offset +0x70 which may have the full 64-bit ID
        if (SapphireHook::IsValidMemoryAddress(actorPtr + 0x70, sizeof(uint64_t))) {
            uint64_t fullId = *reinterpret_cast<uint64_t*>(actorPtr + 0x70);
            // If the upper bits have the object type, use this
            if ((fullId & 0xFFFFFFFF00000000ULL) != 0) {
                return fullId;
            }
        }
        
        // Fallback: read 32-bit ID at +0x74 and check object type at +0x8C
        if (!SapphireHook::IsValidMemoryAddress(actorPtr + 0x74, sizeof(uint32_t))) {
            return 0;
        }
        uint32_t instanceId = *reinterpret_cast<uint32_t*>(actorPtr + 0x74);
        
        // Try to determine object type from +0x8C (ObjectKind field)
        uint8_t objectKind = 0;
        if (SapphireHook::IsValidMemoryAddress(actorPtr + 0x8C, sizeof(uint8_t))) {
            objectKind = *reinterpret_cast<uint8_t*>(actorPtr + 0x8C);
        }
        
        // Synthesize the full ID: (objectType << 32) | instanceId
        // ObjectKind 9 = EventNpc, but the type byte is usually 1 for all NPCs
        // For safety, always use 0x1 as the type prefix for ENpc
        uint64_t fullId = (1ULL << 32) | instanceId;
        return fullId;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// SEH helper for reading current target - must be outside member function to use __try
static uintptr_t GetCurrentTarget_SEH(uintptr_t targetManagerBase, uintptr_t actorLookupAddr) {
    __try {
        // Read the current target wrapper at offset +0x98 (152)
        uintptr_t targetWrapperPtr = 0;
        if (!SapphireHook::IsValidMemoryAddress(targetManagerBase + 152, sizeof(uintptr_t))) {
            return 0;
        }
        targetWrapperPtr = *reinterpret_cast<uintptr_t*>(targetManagerBase + 152);
        
        // If no wrapper at +0x98, try fallback at +0x90 (144)
        if (targetWrapperPtr == 0) {
            if (!SapphireHook::IsValidMemoryAddress(targetManagerBase + 144, sizeof(uintptr_t))) {
                return 0;
            }
            targetWrapperPtr = *reinterpret_cast<uintptr_t*>(targetManagerBase + 144);
        }
        
        if (targetWrapperPtr == 0) {
            return 0;  // No target selected
        }
        
        // The wrapper has a vtable - call vtable[0](wrapper) to get actor ID
        if (!SapphireHook::IsValidMemoryAddress(targetWrapperPtr, sizeof(uintptr_t))) {
            return 0;
        }
        
        uintptr_t vtable = *reinterpret_cast<uintptr_t*>(targetWrapperPtr);
        if (!SapphireHook::IsValidMemoryAddress(vtable, sizeof(uintptr_t))) {
            return 0;
        }
        
        // Get vtable[0] - the GetActorId function
        using GetActorId_t = uint64_t(__fastcall*)(uintptr_t wrapper);
        GetActorId_t GetActorId = reinterpret_cast<GetActorId_t>(*reinterpret_cast<uintptr_t*>(vtable));
        
        uint64_t actorId = GetActorId(targetWrapperPtr);
        
        // Check for invalid ID (0xE0000000 = no target)
        if (actorId == 0xE0000000 || actorId == 0) {
            return 0;
        }
        
        // Now look up the actor pointer using sub_1405C1A10
        using ActorLookup_t = uintptr_t(__fastcall*)(uint64_t actorId);
        ActorLookup_t ActorLookup = reinterpret_cast<ActorLookup_t>(actorLookupAddr);
        
        return ActorLookup(actorId);
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

uintptr_t PacketSenderModule::GetCurrentTargetPtr() {
    // The target system in FFXIV 3.35 uses a Target Manager at qword_1415F1830
    // Structure:
    //   +0x90 (144): fallback target wrapper pointer
    //   +0x98 (152): current target wrapper pointer  
    // Each wrapper has a vtable where vtable[0]() returns the actor ID
    // We then call sub_1405C1A10(actorId) to get the actor pointer
    
    if (m_currentTargetPtr == 0) {
        Logger::Instance().Warning("[PacketSender] TargetManager pointer address not set");
        return 0;
    }
    
    if (m_actorLookupAddr == 0) {
        Logger::Instance().Warning("[PacketSender] ActorLookup function address not set");
        return 0;
    }
    
    uintptr_t actorPtr = GetCurrentTarget_SEH(m_currentTargetPtr, m_actorLookupAddr);
    
    if (actorPtr == 0) {
        Logger::Instance().Debug("[PacketSender] No target or lookup failed");
        return 0;
    }
    
    Logger::Instance().InformationF("[PacketSender] Got target actor pointer: 0x%llX", actorPtr);
    return actorPtr;
}

void PacketSenderModule::RenderRetainerSection() {
    const auto& packets = GetRetainerPackets();
    
    ImGui::TextColored(ImVec4(0.9f, 0.7f, 1.0f, 1.0f), "Retainer System Packets");
    ImGui::Separator();
    
    // Status display
    ImGui::Text("Function Scan Status:");
    if (m_sendEventPacketAddr != 0) {
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "  SendEventPacket: 0x%llX", m_sendEventPacketAddr);
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  SendEventPacket: Not Found");
    }
    if (m_loadRetainerCreationAddr != 0) {
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "  LoadRetainerCreation: 0x%llX", m_loadRetainerCreationAddr);
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  LoadRetainerCreation: Not Found");
    }
    if (m_playEventSceneAddr != 0) {
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "  PlayEventScene: 0x%llX", m_playEventSceneAddr);
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  PlayEventScene: Not Found");
    }
    if (m_startEventSceneAddr != 0) {
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "  StartEventScene: 0x%llX", m_startEventSceneAddr);
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  StartEventScene: Not Found");
    }
    if (m_getOrCreateHandlerAddr != 0) {
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "  GetOrCreateHandler: 0x%llX", m_getOrCreateHandlerAddr);
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  GetOrCreateHandler: Not Found");
    }
    if (m_localPlayerPtr != 0) {
        uintptr_t playerActor = ReadEventManagerInstance_SEH(m_localPlayerPtr);
        if (playerActor != 0) {
            ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "  LocalPlayer: 0x%llX", playerActor);
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "  LocalPlayer: NULL (not logged in?)");
        }
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  LocalPlayer: Not Found");
    }
    if (m_currentTargetPtr != 0) {
        // Note: GetCurrentTargetPtr() is expensive (virtual calls + lookup), so only call on button click
        // For display purposes, just show that TargetManager is available
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.9f, 1.0f), "  TargetManager: 0x%llX (use 'Get Target' button)", m_currentTargetPtr);
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  TargetManager: Not Found");
    }
    if (m_actorLookupAddr != 0) {
        ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "  ActorLookup: 0x%llX", m_actorLookupAddr);
    }
    
    if (ImGui::Button("Rescan Functions")) {
        TryScanRetainerFunctions();
    }
    
    ImGui::Separator();
    
    // Reference table
    if (ImGui::CollapsingHeader("Packet Reference")) {
        ImGui::BeginChild("RetRef", ImVec2(0, 200), true);
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
    
    // ==========================================================================
    // Option 1: Inject Server→Client Packets (Forge EventPlay)
    // NOTE: This approach does NOT work! See warning below.
    // ==========================================================================
    if (ImGui::CollapsingHeader("Option 1: Inject Server Packets (EventPlay) [BROKEN]")) {
        ImGui::Indent();
        
        // Critical warning about why this doesn't work
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
        ImGui::TextWrapped(
            "WARNING: This approach DOES NOT WORK!\n\n"
            "Our investigation revealed:\n"
            "- Opcode 0xE5 calls Handle_Invite() - party system, NOT events!\n"
            "- Opcode 0xE6 (sub_140D16ED0) uses Handle_PhysicalBonus - also party-related!\n"
            "- Real EventPlay opcodes (0x12D-0x137) call nullsub_127 - an EMPTY function!\n\n"
            "The zone IPC handler (sub_140DD9430) that we hook has event packets STUBBED OUT.\n"
            "Events only work through the virtual dispatch handler path (vtable offsets 616-696).\n"
            "Injecting packets through our hook cannot trigger events.");
        ImGui::PopStyleColor();
        
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "(Controls disabled - use Option 3 instead)");
        
        ImGui::BeginDisabled(true);  // Disable all controls since this doesn't work
        
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.3f, 1.0f), "Simulate server sending EventPlay to start retainer event");
        ImGui::TextWrapped("This injects packets as if the server sent them. May trigger the Lua retainer script.");
        
        // Quick reference for handler IDs (0x000B prefix = CustomTalk)
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 1.0f, 1.0f), "Handler ID Reference:");
        ImGui::BulletText("0x000B0009 (720905) = RetainerDesk (create/manage)");
        ImGui::BulletText("0x000B000A (720906) = RetainerCall (summoning bell)");
        ImGui::Spacing();
        
        static uint32_t evtActorId = 0;
        static uint32_t evtHandlerId = 0x000B0009;  // RetainerDesk (720905) - cmndefretainerdesk_00009
        static uint16_t evtSceneId = 1;  // Scene 1 = Create new retainer
        static uint32_t evtFlags = 0;
        static uint32_t evtParams[8] = { 0 };
        
        ImGui::InputScalar("Actor ID (Player)##evt", ImGuiDataType_U32, &evtActorId, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Usually your player's entity ID. Leave 0 to auto-fill.");
        }
        
        ImGui::InputScalar("Handler ID##evt", ImGuiDataType_U32, &evtHandlerId, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("0x000B0009 = RetainerDesk (script 9)\n0x000B000A = RetainerCall (script 10)\nFormat: 0x000B0000 | scriptNumber");
        }
        
        // Scene ID dropdown with descriptions
        const char* sceneDescriptions[] = {
            "0 - Main Menu",
            "1 - Create New Retainer (LoadRetainerCreation)",
            "2 - Remove Retainer",
            "3 - Explanation Talk 1",
            "4 - Explanation Talk 2", 
            "5 - Explanation Menu",
            "6 - Register to Market",
            "7 - Check Cashback/Tax",
            "8 - Remake Retainer (LoadRetainerRemake)",
            "9 - Job Change Menu",
            "10 - (unused)",
            "11 - Creation Success"
        };
        static int sceneSelection = 1;  // Default to scene 1 (create)
        ImGui::Combo("Scene ID##evtcombo", &sceneSelection, sceneDescriptions, IM_ARRAYSIZE(sceneDescriptions));
        evtSceneId = static_cast<uint16_t>(sceneSelection);
        
        ImGui::InputScalar("Flags##evt", ImGuiDataType_U32, &evtFlags, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        
        if (ImGui::TreeNode("Parameters##evt")) {
            for (int i = 0; i < 8; ++i) {
                char label[32];
                snprintf(label, sizeof(label), "Param[%d]", i);
                ImGui::InputScalar(label, ImGuiDataType_U32, &evtParams[i], nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
            }
            ImGui::TreePop();
        }
        
        if (ImGui::Button("Inject EventPlay (0xE6)##evt")) {
            // Build EventPlay payload
            struct EventPlayPayload {
                uint32_t actorId;
                uint32_t handlerId;
                uint16_t sceneId;
                uint16_t padding;
                uint32_t flags;
                uint32_t params[8];
            };
            
            EventPlayPayload payload = {};
            payload.actorId = evtActorId != 0 ? evtActorId : CommandInterface::GetLocalEntityId();
            payload.handlerId = evtHandlerId;
            payload.sceneId = evtSceneId;
            payload.flags = evtFlags;
            std::memcpy(payload.params, evtParams, sizeof(evtParams));
            
            m_lastSendResult = InjectServerPacket(0x00E6, &payload, sizeof(payload));
            m_lastSendMessage = m_lastSendResult 
                ? "Injected EventPlay (0xE6)" 
                : "Failed to inject EventPlay";
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        
        // RetainerList injection
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.3f, 1.0f), "Inject RetainerList (0x1F0)");
        ImGui::TextWrapped("Send empty retainer list to trigger 'create new retainer' flow.");
        
        static uint8_t retainerCount = 0;
        ImGui::InputScalar("Retainer Count##list", ImGuiDataType_U8, &retainerCount);
        
        if (ImGui::Button("Inject RetainerList (0x1F0)##list")) {
            // Build minimal RetainerList payload (just count, rest zeroed)
            std::vector<uint8_t> payload(320, 0);  // Approximately 40 bytes per retainer * 8
            payload[0] = retainerCount;
            
            m_lastSendResult = InjectServerPacket(0x01F0, payload.data(), payload.size());
            m_lastSendMessage = m_lastSendResult 
                ? "Injected RetainerList (0x1F0)" 
                : "Failed to inject RetainerList";
        }
        
        ImGui::EndDisabled();  // End disabled section for broken Option 1
        ImGui::Unindent();
    }
    
    // ==========================================================================
    // Option 2: Call SendEventPacket Directly
    // ==========================================================================
    if (ImGui::CollapsingHeader("Option 2: Call SendEventPacket Directly", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent();
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "Call the client's SendEventPacket function directly");
        ImGui::TextWrapped(
            "This calls sub_140CC2CF0 which sends an event packet to the server.\n"
            "Requires valid Handler ID and Scene ID from an active event context.\n\n"
            "WARNING: Calling without valid context may crash or do nothing!");
        
        ImGui::Spacing();
        
        ImGui::InputScalar("Handler ID", ImGuiDataType_U32, &m_retainerHandlerId, nullptr, nullptr, "%d");
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Event handler ID from active event (v2+48)");
        }
        
        ImGui::InputScalar("Scene ID", ImGuiDataType_U16, &m_retainerSceneId);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Scene ID from active event (v2+136)");
        }
        
        // Subtype dropdown
        const char* subtypeNames[] = {
            "3 - LoadRetainerCreation",
            "4 - LoadRetainerRemake", 
            "7 - SelectRetainer",
            "8 - DepopRetainer",
            "12 - RetainerMainMenu",
            "17 - CallRetainer",
            "27 - SendRetainerCharaMake",
            "31 - CompleteRetainerTask",
            "32 - AcceptRetainerTask",
            "33 - CancelRetainerTask",
            "34 - RemoveRetainer",
        };
        static int subtypeSelection = 0;
        ImGui::Combo("Subtype", &subtypeSelection, subtypeNames, IM_ARRAYSIZE(subtypeNames));
        
        // Map selection to actual subtype value
        static const uint8_t subtypeValues[] = { 3, 4, 7, 8, 12, 17, 27, 31, 32, 33, 34 };
        m_retainerSubtype = subtypeValues[subtypeSelection];
        
        ImGui::Spacing();
        
        bool canCall = m_sendEventPacketAddr != 0;
        ImGui::BeginDisabled(!canCall);
        if (ImGui::Button("Call SendEventPacket##call")) {
            m_lastSendResult = CallSendEventPacket(
                static_cast<int>(m_retainerHandlerId),
                static_cast<int16_t>(m_retainerSceneId),
                static_cast<char>(m_retainerSubtype),
                nullptr,
                0
            );
            m_lastSendMessage = m_lastSendResult 
                ? "Called SendEventPacket successfully" 
                : "SendEventPacket returned 0 or failed";
        }
        ImGui::EndDisabled();
        
        if (!canCall) {
            ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.2f, 1.0f), "SendEventPacket not found - cannot call directly");
        }
        
        ImGui::Unindent();
    }
    
    // ==========================================================================
    // Option 3: Direct Scene Trigger (RECOMMENDED)
    // ==========================================================================
    if (ImGui::CollapsingHeader("Option 3: Direct Scene Trigger [RECOMMENDED]", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent();
        
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.8f, 1.0f), "Call scene trigger functions directly");
        ImGui::TextWrapped(
            "This bypasses the packet system entirely and calls the scene trigger functions directly.\n\n"
            "Technical details:\n"
            "- PlayEventScene (sub_14069AAA0): Triggers a scene on an already-registered handler\n"
            "- StartEventScene (sub_14068FEB0): Starts a new event scene from scratch\n\n"
            "These functions are what the virtual dispatch handler eventually calls.");
        
        ImGui::Spacing();
        
        // Scene function status
        bool hasPlayScene = m_playEventSceneAddr != 0;
        bool hasStartScene = m_startEventSceneAddr != 0;
        bool hasAnySceneFunc = hasPlayScene || hasStartScene;
        
        if (!hasAnySceneFunc) {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), 
                "Scene functions not found! Click 'Rescan Functions' above.");
            ImGui::Spacing();
        }
        
        static uint32_t directHandlerId = 0x000B0009;  // RetainerDesk
        static uint16_t directSceneId = 1;             // Create retainer scene
        static uint32_t directDelay = 0;
        static uint32_t directParams[8] = { 0 };
        static uint64_t directTargetActorPtr = 0;      // Target NPC actor POINTER in memory
        static bool useLocalPlayer = false;            // If true, use local player instead of target
        static bool useNullActor = false;              // If true, pass NULL for actor
        
        ImGui::InputScalar("Handler ID##direct", ImGuiDataType_U32, &directHandlerId, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Handler ID format: 0x000B0000 | scriptNumber\n"
                "0x000B0009 = RetainerDesk (cmndefretainerdesk_00009)\n"
                "0x000B000A = RetainerCall (cmndefretainercall_00010)");
        }
        
        // Target actor input
        ImGui::Text("Actor Selection:");
        ImGui::InputScalar("Target Actor Ptr##direct", ImGuiDataType_U64, &directTargetActorPtr, nullptr, nullptr, "%llX", ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "The NPC's actor POINTER (not ID!) in memory.\n"
                "Click 'Get Current Target' to auto-fill with your current target.");
        }
        ImGui::SameLine();
        if (ImGui::Button("Get Current Target##gettarget")) {
            uintptr_t target = GetCurrentTargetPtr();
            if (target != 0) {
                directTargetActorPtr = target;
                useLocalPlayer = false;
                useNullActor = false;
                Logger::Instance().InformationF("[PacketSender] Got current target: 0x%llX", target);
            } else {
                Logger::Instance().Warning("[PacketSender] No current target - select an NPC first");
            }
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Reads the current target's actor pointer from game memory.\nTarget an NPC first!");
        }
        
        ImGui::Checkbox("Use Local Player##direct", &useLocalPlayer);
        if (useLocalPlayer) {
            useNullActor = false;  // Mutually exclusive
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("If checked, uses the local player actor.\nFor NPC interactions, you usually want the NPC's pointer.");
        }
        ImGui::SameLine();
        ImGui::Checkbox("Pass NULL (skip actor)##direct", &useNullActor);
        if (useNullActor) {
            useLocalPlayer = false;  // Mutually exclusive
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("If checked, passes NULL for actor.\nThe handler may still work for some event types.");
        }
        
        // Scene ID dropdown
        const char* directSceneDescriptions[] = {
            "0 - Main Menu",
            "1 - Create New Retainer",
            "2 - Remove Retainer",
            "3 - Explanation Talk 1",
            "4 - Explanation Talk 2", 
            "5 - Explanation Menu",
            "6 - Register to Market",
            "7 - Check Cashback/Tax",
            "8 - Remake Retainer",
            "9 - Job Change Menu",
            "10 - (unused)",
            "11 - Creation Success"
        };
        static int directSceneSelection = 1;
        ImGui::Combo("Scene ID##directcombo", &directSceneSelection, directSceneDescriptions, IM_ARRAYSIZE(directSceneDescriptions));
        directSceneId = static_cast<uint16_t>(directSceneSelection);
        
        ImGui::InputScalar("Delay (frames)##direct", ImGuiDataType_U32, &directDelay);
        
        if (ImGui::TreeNode("Parameters##direct")) {
            for (int i = 0; i < 8; ++i) {
                char label[32];
                snprintf(label, sizeof(label), "Param[%d]", i);
                ImGui::InputScalar(label, ImGuiDataType_U32, &directParams[i], nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
            }
            ImGui::TreePop();
        }
        
        ImGui::Spacing();
        
        // Check EventManager status
        bool hasEventManager = m_eventManagerPtr != 0;
        uintptr_t eventManagerInstance = 0;
        if (hasEventManager) {
            eventManagerInstance = ReadEventManagerInstance_SEH(m_eventManagerPtr);
        }
        
        // Display status
        if (hasEventManager) {
            if (eventManagerInstance != 0) {
                ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "EventManager: 0x%llX (instance: 0x%llX)", 
                    m_eventManagerPtr, eventManagerInstance);
            } else {
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "EventManager: 0x%llX (instance is NULL - no active event)", 
                    m_eventManagerPtr);
            }
        } else {
            ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "EventManager: Not Found");
        }
        
        if (hasPlayScene) {
            ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "PlayEventScene: 0x%llX", m_playEventSceneAddr);
        }
        if (hasStartScene) {
            ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "StartEventScene: 0x%llX", m_startEventSceneAddr);
        }
        
        bool hasGetOrCreate = m_getOrCreateHandlerAddr != 0;
        if (hasGetOrCreate) {
            ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "GetOrCreateHandler: 0x%llX", m_getOrCreateHandlerAddr);
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        
        // ==========================================================================
        // Step 1: Register Handler (MUST be done BEFORE sending packet!)
        // ==========================================================================
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.5f, 1.0f), "Step 1: Register Handler (REQUIRED FIRST!)");
        ImGui::TextWrapped(
            "CRITICAL: You MUST register the handler BEFORE sending the StartTalkEvent packet!\n\n"
            "Why? The server will respond with EventPlay, and the client needs a handler ready\n"
            "to process it. Without a registered handler, the client returns BEFORE_PLAY error.");
        ImGui::Spacing();
        
        static uintptr_t registeredHandlerPtr = 0;  // Store the returned handler object
        
        // Helper lambda to get the actor pointer based on UI settings
        auto getSelectedActorPtr = [&]() -> uintptr_t {
            if (useNullActor) {
                return 0;  // Pass NULL explicitly
            } else if (useLocalPlayer) {
                return GetLocalPlayerActorPtr();
            } else {
                return directTargetActorPtr;  // Use the manually input pointer
            }
        };
        
        bool canRegister = hasGetOrCreate && hasEventManager && eventManagerInstance != 0;
        ImGui::BeginDisabled(!canRegister);
        if (ImGui::Button("Register Handler##register")) {
            uintptr_t actorPtr = getSelectedActorPtr();
            Logger::Instance().InformationF("[PacketSender] RegisterHandler: actorPtr=0x%llX, handlerId=0x%X", actorPtr, directHandlerId);
            registeredHandlerPtr = GetOrCreateHandler(directHandlerId, actorPtr);
            if (registeredHandlerPtr != 0) {
                m_lastSendResult = true;
                m_lastSendMessage = "Handler registered at 0x" + ToHexString(static_cast<uint16_t>(registeredHandlerPtr >> 16)) + 
                                    ToHexString(static_cast<uint16_t>(registeredHandlerPtr & 0xFFFF));
            } else {
                m_lastSendResult = false;
                m_lastSendMessage = "Failed to register handler (GetOrCreateHandler returned 0)";
            }
        }
        ImGui::EndDisabled();
        
        ImGui::SameLine();
        if (registeredHandlerPtr != 0) {
            ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "Handler: 0x%llX", registeredHandlerPtr);
        } else {
            ImGui::TextColored(ImVec4(0.9f, 0.5f, 0.2f, 1.0f), "Handler: Not Registered (do this first!)");
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        
        // ==========================================================================
        // Step 2: Send Talk Event Packet (AFTER handler is registered!)
        // ==========================================================================
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 1.0f, 1.0f), "Step 2: Send StartTalkEvent (C\xe2\x86\x92S Packet)");
        ImGui::TextWrapped(
            "After registering the handler, send the StartTalkEvent packet to the server.\n"
            "The server will call the event script and send EventPlay back to the client.");
        ImGui::Spacing();
        
        static uint64_t talkEventActorId = 0;  // NPC's event actor ID
        static uint32_t talkEventId = 0x000B0009;  // Event ID
        
        // Actor ID format explanation
        ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Actor ID Format (CRITICAL!):");
        ImGui::TextWrapped(
            "The actor ID MUST include the object type prefix!\n\n"
            "Format: (objectType << 32) | instanceId\n"
            "- objectType = 1 for ENpc actors\n"
            "- instanceId = the LGB instance ID\n\n"
            "From TARGET_DECIDE (p1:100116A01):\n"
            "  Use the FULL value: 0x100116A01 (NOT just 0x116A01!)\n\n"
            "The high byte 0x01 indicates ENpc object type.");
        ImGui::Spacing();
        
        ImGui::InputScalar("NPC Actor ID (FULL 64-bit!)##talkevent", ImGuiDataType_U64, &talkEventActorId, nullptr, nullptr, "%llX", ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "The NPC's FULL 64-bit actor ID (not memory pointer!).\n\n"
                "From server log TARGET_DECIDE (p1:100116A01):\n"
                "  Use the FULL value: 0x100116A01\n"
                "  This includes objectType (0x1) in upper bits\n\n"
                "If you only have the instance ID (e.g., 0x116A01),\n"
                "click 'Add ENpc Prefix' to add the 0x100000000 prefix.");
        }
        
        // Helper to add ENpc prefix (objectType = 1)
        ImGui::SameLine();
        if (ImGui::Button("Add ENpc Prefix##addprefix")) {
            // If the ID doesn't have the upper bits set, add the ENpc type (0x1 << 32)
            if ((talkEventActorId & 0xFFFFFFFF00000000ULL) == 0) {
                talkEventActorId |= 0x100000000ULL;  // Add ENpc object type
            }
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Add 0x100000000 prefix for ENpc object type.\nUse this if you only entered the instance ID.");
        }
        
        ImGui::InputScalar("Event ID##talkevent", ImGuiDataType_U32, &talkEventId, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("The event handler ID (e.g., 0x000B0009 for RetainerDesk)");
        }
        
        // Disable send button if handler not registered
        bool handlerReady = registeredHandlerPtr != 0;
        
        ImGui::BeginDisabled(!handlerReady);
        if (ImGui::Button("Send StartTalkEvent Packet##sendtalk")) {
            if (talkEventActorId == 0) {
                m_lastSendResult = false;
                m_lastSendMessage = "Set the NPC Actor ID first";
            } else {
                m_lastSendResult = SendStartTalkEventPacket(talkEventActorId, talkEventId);
                m_lastSendMessage = m_lastSendResult 
                    ? "StartTalkEvent packet sent - check server response!" 
                    : "Failed to send StartTalkEvent packet";
            }
        }
        ImGui::EndDisabled();
        
        if (!handlerReady) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "<-- Register handler first!");
        }
        
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Sends a C\xe2\x86\x92S StartTalkEvent (0x01C2) packet to the server.\n"
                "Make sure handler is registered first to avoid BEFORE_PLAY error!");
        }
        
        ImGui::Spacing();
        
        // Combined "Talk to NPC" button that does both steps
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "Quick Action:");
        
        bool canTalk = canRegister && (directTargetActorPtr != 0 || useLocalPlayer || useNullActor);
        ImGui::BeginDisabled(!canTalk);
        if (ImGui::Button("Talk to Target (Register + Send)##quicktalk", ImVec2(-1, 30))) {
            // Step 1: Register handler
            uintptr_t actorPtr = getSelectedActorPtr();
            Logger::Instance().InformationF("[PacketSender] QuickTalk: Registering handler...");
            registeredHandlerPtr = GetOrCreateHandler(directHandlerId, actorPtr);
            
            if (registeredHandlerPtr != 0) {
                // Step 2: Send packet
                // Use the actor ID from the target if available
                uint64_t actorIdToSend = talkEventActorId;
                if (actorIdToSend == 0 && directTargetActorPtr != 0) {
                    // Try to read actor ID from target pointer using SEH helper
                    actorIdToSend = ReadActorIdFromPtr_SEH(directTargetActorPtr);
                }
                
                if (actorIdToSend != 0) {
                    Logger::Instance().InformationF("[PacketSender] QuickTalk: Sending packet with actorId=0x%llX", actorIdToSend);
                    m_lastSendResult = SendStartTalkEventPacket(actorIdToSend, directHandlerId);
                    m_lastSendMessage = m_lastSendResult 
                        ? "Handler registered + packet sent!" 
                        : "Handler registered but packet send failed";
                } else {
                    m_lastSendResult = false;
                    m_lastSendMessage = "Handler registered, but no actor ID available for packet";
                }
            } else {
                m_lastSendResult = false;
                m_lastSendMessage = "Failed to register handler";
            }
        }
        ImGui::EndDisabled();
        
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Combined action:\n"
                "1. Registers the event handler locally\n"
                "2. Sends StartTalkEvent packet to server\n\n"
                "Make sure you have a target selected or actor ID set!");
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        
        // ==========================================================================
        // Step 2.5: Skip to Scene (send ReturnEventScene to select menu option)
        // ==========================================================================
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.5f, 1.0f), "Step 2.5: Skip to Scene (Menu Selection)");
        ImGui::TextWrapped(
            "After the menu appears, send a ReturnEventScene packet to simulate\n"
            "selecting a menu option. This skips straight to the desired scene.");
        ImGui::Spacing();
        
        static uint16_t returnSceneId = 0;      // Scene we're returning FROM (0 = main menu)
        static uint32_t returnSelection = 1;     // Selection to make (1 = Hire retainer)
        
        // Preset for common RetainerDesk selections (from cmndefretainerdesk_00009.luab)
        // The selection values are NOT sequential! Based on Lua script:
        //   1=Create/Hire, 2=Dispatch, 3=Remove, 4=Explanation, 5=Cashback, 6=Cancel, 7=Remake*, 8=JobChange*
        //   (* = conditional options, may not appear in menu)
        const uint32_t retainerMenuValues[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        const char* retainerMenuOptions[] = {
            "1 - Hire a retainer (MAIN_MENU_CREATE)",
            "2 - Dispatch a retainer (MAIN_MENU_REGISTER_*)",
            "3 - Release a retainer (MAIN_MENU_REMOVE)",
            "4 - Ask about retainers (MAIN_MENU_EXPLANATION)",
            "5 - View market tax rates (MAIN_MENU_CHECK_CASHBACK)",
            "6 - Cancel/Nothing (MAIN_MENU_CANCEL)",
            "7 - Remake retainer* (MAIN_MENU_REMAKE)",
            "8 - Job change* (MAIN_MENU_JOBCHANGE)"
        };
        static int retainerMenuSelection = 0;
        ImGui::Combo("RetainerDesk Menu##retainermenu", &retainerMenuSelection, retainerMenuOptions, IM_ARRAYSIZE(retainerMenuOptions));
        returnSelection = retainerMenuValues[retainerMenuSelection];
        
        ImGui::InputScalar("Scene ID (from)##returnscene", ImGuiDataType_U16, &returnSceneId);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("The scene we're returning FROM.\n0 = main menu, 1 = create retainer, etc.");
        }
        
        ImGui::InputScalar("Selection Value##returnsel", ImGuiDataType_U32, &returnSelection);
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("The menu option to select.\nFor RetainerDesk main menu: 1=Hire, 2=Dispatch, 3=Release, etc.");
        }
        
        // Button to send the return packet
        bool canSendReturn = handlerReady;
        ImGui::BeginDisabled(!canSendReturn);
        if (ImGui::Button("Send ReturnEventScene##sendreturn")) {
            m_lastSendResult = SendReturnEventScenePacket(directHandlerId, returnSceneId, returnSelection);
            m_lastSendMessage = m_lastSendResult 
                ? "ReturnEventScene sent - check for next scene!" 
                : "Failed to send ReturnEventScene";
        }
        ImGui::EndDisabled();
        
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Sends ReturnEventScene2 (0x01D7) to simulate menu selection.\n"
                "Use after StartTalkEvent to skip to a specific scene.");
        }
        
        // Quick combo button: Start Talk + Auto-select Hire Retainer
        ImGui::SameLine();
        ImGui::BeginDisabled(!canTalk);
        if (ImGui::Button("Talk + Hire Retainer##quickhire")) {
            // Step 1: Register handler
            uintptr_t actorPtr = getSelectedActorPtr();
            registeredHandlerPtr = GetOrCreateHandler(directHandlerId, actorPtr);
            
            if (registeredHandlerPtr != 0) {
                // Step 2: Send StartTalkEvent
                uint64_t actorIdToSend = talkEventActorId;
                if (actorIdToSend == 0 && directTargetActorPtr != 0) {
                    actorIdToSend = ReadActorIdFromPtr_SEH(directTargetActorPtr);
                }
                
                if (actorIdToSend != 0) {
                    bool talkSent = SendStartTalkEventPacket(actorIdToSend, directHandlerId);
                    if (talkSent) {
                        // Step 3: Wait a moment then send ReturnEventScene to select "Hire retainer"
                        // Note: We send immediately - the server should process in order
                        Sleep(100);  // Small delay to let server process StartTalkEvent
                        m_lastSendResult = SendReturnEventScenePacket(directHandlerId, 0, 1);  // Scene 0, select option 1
                        m_lastSendMessage = m_lastSendResult 
                            ? "Started talk + selected Hire Retainer!" 
                            : "Talk sent but ReturnEventScene failed";
                    } else {
                        m_lastSendResult = false;
                        m_lastSendMessage = "StartTalkEvent failed";
                    }
                } else {
                    m_lastSendResult = false;
                    m_lastSendMessage = "No actor ID available";
                }
            } else {
                m_lastSendResult = false;
                m_lastSendMessage = "Failed to register handler";
            }
        }
        ImGui::EndDisabled();
        
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip(
                "Combined action:\n"
                "1. Register handler\n"
                "2. Send StartTalkEvent\n"
                "3. Send ReturnEventScene with selection=1 (Hire retainer)\n\n"
                "This should skip straight to the Create Retainer scene!");
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        
        // ==========================================================================
        // Step 3: Direct Scene Functions (Alternative - bypasses server)
        // ==========================================================================
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Step 3: Direct Scene Trigger (Alternative)");
        ImGui::TextWrapped(
            "These call scene functions directly on the client.\n"
            "Use this if you want to bypass the server entirely (local-only scenes).");
        ImGui::Spacing();
        
        // Call buttons
        bool canCallPlay = hasPlayScene && hasEventManager && eventManagerInstance != 0;
        bool canCallStart = hasStartScene && hasEventManager && eventManagerInstance != 0;
        
        ImGui::BeginDisabled(!canCallPlay);
        if (ImGui::Button("Call PlayEventScene##play")) {
            uintptr_t actorPtr = getSelectedActorPtr();
            Logger::Instance().InformationF("[PacketSender] PlayEventScene: actorPtr=0x%llX, handlerId=0x%X, sceneId=%d", actorPtr, directHandlerId, directSceneId);
            m_lastSendResult = CallPlayEventScene(
                actorPtr,
                directHandlerId,
                static_cast<int16_t>(directSceneId),
                static_cast<int64_t>(directDelay),
                directParams,
                0  // param count
            );
            m_lastSendMessage = m_lastSendResult 
                ? "PlayEventScene called successfully" 
                : "PlayEventScene failed or returned 0";
        }
        ImGui::EndDisabled();
        
        ImGui::SameLine();
        
        ImGui::BeginDisabled(!canCallStart);
        if (ImGui::Button("Call StartEventScene##start")) {
            uintptr_t actorPtr = getSelectedActorPtr();
            Logger::Instance().InformationF("[PacketSender] StartEventScene: actorPtr=0x%llX, handlerId=0x%X, sceneId=%d", actorPtr, directHandlerId, directSceneId);
            m_lastSendResult = CallStartEventScene(
                actorPtr,
                directHandlerId,
                static_cast<int16_t>(directSceneId),
                static_cast<int64_t>(directDelay),
                directParams,
                0  // param count
            );
            m_lastSendMessage = m_lastSendResult 
                ? "StartEventScene called successfully" 
                : "StartEventScene failed or returned 0";
        }
        ImGui::EndDisabled();
        
        ImGui::Spacing();
        
        if (!canCallPlay && !canCallStart) {
            if (eventManagerInstance == 0) {
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), 
                    "EventManager instance is NULL. You may need to be in an active event context\n"
                    "(e.g., talking to an NPC) for these functions to work.");
            } else {
                ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.2f, 1.0f), 
                    "Scene functions not available. Click 'Rescan Functions' above.");
            }
        }
        
        ImGui::Unindent();
    }
    
    // ==========================================================================
    // Research Notes
    // ==========================================================================
    if (ImGui::CollapsingHeader("Research Notes")) {
        ImGui::Indent();
        
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 1.0f, 1.0f), "Why Packet Injection Doesn't Work");
        ImGui::Separator();
        ImGui::TextWrapped(
            "Investigation revealed that the zone IPC handler (sub_140DD9430) that we hook\n"
            "has EventPlay packets (opcodes 0x12D-0x137) calling nullsub_127 - an empty function.\n\n"
            "The real event processing happens through a separate virtual dispatch handler\n"
            "that uses vtable offsets (616-696) to dispatch to actual implementations.\n\n"
            "Opcodes 0xE5 and 0xE6 that we initially targeted are actually party invite\n"
            "handlers (Handle_Invite, Handle_PhysicalBonus), not event handlers!");
        
        ImGui::Spacing();
        
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 1.0f, 1.0f), "Handler System");
        ImGui::Separator();
        ImGui::TextWrapped(
            "Handler IDs have format: 0x000T0NNN\n"
            "  T = Type (0xB = cmndef/CustomTalk, 0xA = quest, 0xC = other)\n"
            "  NNN = Script number\n\n"
            "Examples:\n"
            "  0x000B0009 = cmndefretainerdesk_00009 (RetainerDesk)\n"
            "  0x000B000A = cmndefretainercall_00010 (RetainerCall/Bell)\n\n"
            "Factory registration (sub_140685030) maps type prefixes to handler creators.");
        
        ImGui::Spacing();
        
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 1.0f, 1.0f), "Scene Trigger Functions");
        ImGui::Separator();
        ImGui::TextWrapped(
            "StartEventScene (sub_14068FEB0):\n"
            "  Called to start a new event scene. Takes eventManager, targetActor,\n"
            "  handlerId, sceneId, delay, params, paramCount.\n\n"
            "PlayEventScene (sub_14069AAA0):\n"
            "  Called when handler is already registered. Triggers OnSceneXXXXX callback.\n\n"
            "Both eventually call scene callbacks like OnScene00001 for retainer creation.");
        
        ImGui::Unindent();
    }
}

} // namespace SapphireHook
