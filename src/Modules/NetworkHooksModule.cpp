/**
 * @file NetworkHooksModule.cpp
 * @brief UI Module for high-level network hooks
 */

#include "NetworkHooksModule.h"
#include "../Hooking/NetworkHooks.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"

namespace SapphireHook {

void NetworkHooksModule::Initialize() {
    Logger::Instance().Information("[NetworkHooksModule] Initialized");
}

void NetworkHooksModule::Shutdown() {
    // NetworkHooks singleton handles its own cleanup
    Logger::Instance().Information("[NetworkHooksModule] Shutdown");
}

void NetworkHooksModule::RenderMenu() {
    if (ImGui::MenuItem(GetDisplayName(), nullptr, m_windowOpen)) {
        m_windowOpen = !m_windowOpen;
    }
}

void NetworkHooksModule::RenderWindow() {
    if (!m_windowOpen) return;
    
    ImGui::SetNextWindowSize(ImVec2(450, 400), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(GetDisplayName(), &m_windowOpen)) {
        ImGui::End();
        return;
    }
    
    auto& hooks = NetworkHooks::GetInstance();
    const auto& stats = hooks.GetStats();
    const auto& addrs = hooks.GetHookAddresses();
    
    // Status section
    ImGui::TextColored(hooks.IsHooked() ? ImVec4(0.4f, 1.0f, 0.4f, 1.0f) : ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
        hooks.IsHooked() ? "STATUS: ACTIVE" : "STATUS: INACTIVE");
    
    ImGui::SameLine();
    if (!hooks.IsHooked()) {
        if (ImGui::Button("Initialize Hooks")) {
            if (!hooks.Initialize()) {
                Logger::Instance().Error("[NetworkHooksModule] Failed to initialize hooks");
            }
        }
    } else {
        if (ImGui::Button("Shutdown Hooks")) {
            hooks.Shutdown();
        }
    }
    
    ImGui::Separator();
    
    // Hook addresses
    if (ImGui::CollapsingHeader("Hook Addresses", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::BeginDisabled(!hooks.IsHooked());
        
        auto formatAddr = [](uintptr_t addr) -> const char* {
            static char buf[32];
            if (addr == 0) {
                snprintf(buf, sizeof(buf), "Not Found");
            } else {
                snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(addr));
            }
            return buf;
        };
        
        ImGui::Text("Socket Handler:    %s", formatAddr(addrs.socketHandler));
        ImGui::Text("IPC Dispatcher:    %s", formatAddr(addrs.ipcDispatcher));
        ImGui::Text("Recv Wrapper:      %s", formatAddr(addrs.recvWrapper));
        ImGui::Text("Send Wrapper:      %s", formatAddr(addrs.sendWrapper));
        ImGui::Text("Packet Queue:      %s", formatAddr(addrs.packetQueue));
        
        ImGui::EndDisabled();
    }
    
    // Statistics
    if (ImGui::CollapsingHeader("Statistics", ImGuiTreeNodeFlags_DefaultOpen)) {
        // Calculate packets per second
        float currentTime = ImGui::GetTime();
        if (currentTime - m_lastUpdateTime >= 1.0f) {
            uint64_t totalPackets = stats.packetsReceived.load() + stats.packetsSent.load();
            uint64_t lastTotal = m_lastPacketsRecv + m_lastPacketsSent;
            m_packetsPerSecond = static_cast<float>(totalPackets - lastTotal) / (currentTime - m_lastUpdateTime);
            m_lastPacketsRecv = stats.packetsReceived.load();
            m_lastPacketsSent = stats.packetsSent.load();
            m_lastIpcProcessed = stats.ipcPacketsProcessed.load();
            m_lastUpdateTime = currentTime;
        }
        
        ImGui::Text("Packets Received:  %llu", static_cast<unsigned long long>(stats.packetsReceived.load()));
        ImGui::Text("Packets Sent:      %llu", static_cast<unsigned long long>(stats.packetsSent.load()));
        ImGui::Text("IPC Processed:     %llu", static_cast<unsigned long long>(stats.ipcPacketsProcessed.load()));
        ImGui::Text("Bytes Received:    %llu", static_cast<unsigned long long>(stats.bytesReceived.load()));
        ImGui::Text("Bytes Sent:        %llu", static_cast<unsigned long long>(stats.bytesSent.load()));
        ImGui::Separator();
        ImGui::Text("Packets/sec:       %.1f", m_packetsPerSecond);
        
        if (ImGui::Button("Reset Stats")) {
            hooks.ResetStats();
            m_lastPacketsRecv = 0;
            m_lastPacketsSent = 0;
            m_lastIpcProcessed = 0;
            m_packetsPerSecond = 0.0f;
        }
    }
    
    // Connection state
    if (ImGui::CollapsingHeader("Connection State")) {
        if (hooks.IsHooked() && hooks.GetConnectionObject()) {
            ImGui::Text("Connection Object: 0x%llX", 
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(hooks.GetConnectionObject())));
            ImGui::Text("Socket Handle:     0x%llX", static_cast<unsigned long long>(hooks.GetSocket()));
            ImGui::Text("Connection State:  %u", hooks.GetConnectionState());
            ImGui::Text("Buffer Size:       %u bytes", hooks.GetBufferSize());
            ImGui::Text("Total Bytes Recv:  %llu", static_cast<unsigned long long>(hooks.GetBytesReceived()));
            
            const uint8_t* buffer = hooks.GetRecvBuffer();
            if (buffer) {
                ImGui::Text("Recv Buffer:       0x%llX", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(buffer)));
            } else {
                ImGui::Text("Recv Buffer:       (null)");
            }
        } else {
            ImGui::TextDisabled("No active connection");
        }
    }
    
    // Callback options
    if (ImGui::CollapsingHeader("Logging Options")) {
        if (ImGui::Checkbox("Log IPC Packets", &m_logIpcPackets)) {
            if (m_logIpcPackets) {
                hooks.SetIPCCallback([](uint16_t opcode, uint32_t actorId, std::span<const uint8_t> payload) {
                    Logger::Instance().DebugF("[NetworkHooks] IPC opcode=0x%04X actor=0x%08X size=%zu",
                        opcode, actorId, payload.size());
                    return true;
                });
            } else {
                hooks.SetIPCCallback(nullptr);
            }
        }
        ImGui::SameLine();
        ImGui::TextDisabled("(?)");
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Log all IPC packets to the debug log.\nWarning: High traffic!");
        }
        
        if (ImGui::Checkbox("Log Raw Packets", &m_logRawPackets)) {
            if (m_logRawPackets) {
                hooks.SetRawRecvCallback([](void* connObj, std::span<const uint8_t> buffer) {
                    Logger::Instance().DebugF("[NetworkHooks] Raw recv size=%zu", buffer.size());
                    return true;
                });
            } else {
                hooks.SetRawRecvCallback(nullptr);
            }
        }
    }
    
    // Signatures info
    if (ImGui::CollapsingHeader("Signature Patterns")) {
        ImGui::TextWrapped("These patterns work for FFXIV 3.35. Other versions may require updated signatures.");
        ImGui::Separator();
        
        ImGui::Text("SocketReceiveHandler:");
        ImGui::TextDisabled("48 89 74 24 10 57 48 83 EC 20 44 8B 81 00 01 00 00");
        
        ImGui::Text("IPCDispatcher:");
        ImGui::TextDisabled("48 89 5C 24 08 57 48 83 EC 60 8B FA 41 0F B7 50 02");
        
        ImGui::Text("RecvWrapper:");
        ImGui::TextDisabled("48 83 EC 28 48 8B 49 08 45 33 C9");
        
        ImGui::Text("SendWrapper:");
        ImGui::TextDisabled("48 83 EC 28 48 8B 49 08 45 33 C9 45 8B D0");
    }
    
    ImGui::End();
}

} // namespace SapphireHook
