#include "NetworkMonitorModule.h"
#include "../vendor/imgui/imgui.h"

using namespace SapphireHook;

void NetworkMonitorModule::RenderMenu()
{
    // Intentionally no-op: this module is toggled from the Tools menu to avoid duplication in Features.
}

void NetworkMonitorModule::RenderWindow()
{
    if (!m_windowOpen) return;

    // The monitor draws its own window with Begin/End and supports close button
    SafeHookLogger::Instance().DrawImGuiSimple(&m_windowOpen);
}
