#pragma once
#include "../vendor/imgui/imgui.h"

namespace SapphireHook
{
    class UIModule
    {
    public:
        virtual ~UIModule() = default;

        // Module identification
        virtual const char* GetName() const = 0;
        virtual const char* GetDisplayName() const = 0;

        // Module lifecycle
        virtual void Initialize() {}
        virtual void Shutdown() {}

        // UI rendering
        virtual void RenderMenu() = 0;  // For menu bar items
        virtual void RenderWindow() = 0; // For standalone windows

        // Module state
        virtual bool IsWindowOpen() const = 0;
        virtual void SetWindowOpen(bool open) = 0;

        // Module settings
        virtual bool IsEnabled() const { return true; }
        virtual void SetEnabled(bool enabled) {}
    };
}