#pragma once
#include "../UI/UIModule.h"

// Forward include the monitor API
#include "../Monitor/NetworkMonitor.h"

namespace SapphireHook {

class NetworkMonitorModule final : public UIModule {
public:
    const char* GetName() const override { return "network_monitor"; }
    const char* GetDisplayName() const override { return "Network Monitor"; }

    void Initialize() override {}
    void Shutdown() override {}

    void RenderMenu() override; // toggled from Tools; still provide a menu entry if needed
    void RenderWindow() override;

    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    bool m_windowOpen = false;
};

} // namespace SapphireHook
