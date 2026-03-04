#pragma once
#include "../vendor/imgui/imgui.h"

namespace SapphireHook
{
    class UIModule
    {
    public:
        virtual ~UIModule() = default;

        virtual const char* GetName() const = 0;
        virtual const char* GetDisplayName() const = 0;

        virtual void Initialize() {}
        virtual void Shutdown() {}

        virtual void RenderMenu() = 0;  
        virtual void RenderWindow() = 0; 

        virtual bool IsWindowOpen() const = 0;
        virtual void SetWindowOpen(bool open) = 0;

        virtual bool IsEnabled() const { return true; }
        virtual void SetEnabled(bool enabled) {}
    };
}