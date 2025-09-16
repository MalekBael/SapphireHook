#pragma once
#include "../UI/UIModule.h"

namespace SapphireHook {

class NetDiagnosticsModule final : public UIModule {
public:
    const char* GetName() const override { return "net_diagnostics"; }
    const char* GetDisplayName() const override { return "Network Monitor"; }
    void Initialize() override {}
    void RenderMenu() override;     // toggled from Tools only
    void RenderWindow() override;   // merged UI

    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    bool m_windowOpen = false;
};

} // namespace SapphireHook
