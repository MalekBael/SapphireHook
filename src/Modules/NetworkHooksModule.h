#pragma once
/**
 * @file NetworkHooksModule.h
 * @brief UI Module for high-level network hooks
 * 
 * Provides a UI to control and monitor the internal network hooks
 * discovered via radare2 analysis.
 */

#include "../UI/UIModule.h"
#include <cstdint>

namespace SapphireHook {

class NetworkHooksModule final : public UIModule {
public:
    const char* GetName() const override { return "network_hooks"; }
    const char* GetDisplayName() const override { return "Network Hooks"; }
    
    void Initialize() override;
    void Shutdown() override;
    void RenderMenu() override;
    void RenderWindow() override;
    
    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    bool m_windowOpen = false;
    bool m_autoInitialize = false;
    bool m_logIpcPackets = false;
    bool m_logRawPackets = false;
    
    // Cached display state
    uint64_t m_lastPacketsRecv = 0;
    uint64_t m_lastPacketsSent = 0;
    uint64_t m_lastIpcProcessed = 0;
    float m_packetsPerSecond = 0.0f;
    float m_lastUpdateTime = 0.0f;
};

} // namespace SapphireHook
