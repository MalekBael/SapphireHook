#pragma once
#include <string>
#include <cstdint>
#include "../UI/UIModule.h"
#include "../Core/PacketInjector.h"

namespace SapphireHook {

    class SettingsModule final : public UIModule {
    public:
        SettingsModule() = default;
        ~SettingsModule() override = default;

        // UIModule interface
        const char* GetName() const override { return "settings"; }
        const char* GetDisplayName() const override { return "Settings"; }
        void Initialize() override;  // Loads saved settings
        void RenderMenu() override;
        void RenderWindow() override;
        bool IsWindowOpen() const override { return m_windowOpen; }
        void SetWindowOpen(bool open) override { m_windowOpen = open; }

    private:
        bool m_windowOpen = false;

        void DrawPacketLoggingSection();
    };

} // namespace SapphireHook