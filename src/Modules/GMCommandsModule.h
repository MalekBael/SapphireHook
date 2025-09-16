#pragma once
#include "../UI/UIModule.h"
#include "../vendor/imgui/imgui.h"
#include <cstdint>

class GMCommandsModule : public SapphireHook::UIModule
{
public:
    const char* GetName() const override { return "gm_commands"; }
    const char* GetDisplayName() const override { return "GM Commands"; }

    void Initialize() override;
    void Shutdown() override {}

    void RenderMenu() override;
    void RenderWindow() override;

    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    // UI state
    bool m_windowOpen = false;

    // Dropdown selection index into GMCommands::kList
    int m_selectedIndex = -1;

    // Opcode-only: Send by numeric ID (GMCommand 0x0197)
    int m_commandId = 0;
    int m_arg0 = 0;
    int m_arg1 = 0;
    int m_arg2 = 0;
    int m_arg3 = 0;
    unsigned long long m_targetId = 0ULL;
};