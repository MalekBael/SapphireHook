#pragma once
#include "../UI/UIModule.h"

namespace SapphireHook {

class NetDiagnosticsModule final : public UIModule {
public:
    const char* GetName() const override { return "net_diagnostics"; }
    const char* GetDisplayName() const override { return "Net Diagnostics"; }
    void Initialize() override {}
    void RenderMenu() override;
    void RenderWindow() override;

    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    bool m_windowOpen = false;
};

} // namespace SapphireHook
