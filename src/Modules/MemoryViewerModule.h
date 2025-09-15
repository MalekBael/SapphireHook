#pragma once
#include "../UI/UIModule.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/hex_editor/imgui_hex.h"
#include "../Core/SafeMemory.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>

class MemoryViewerModule : public SapphireHook::UIModule
{
public:
    const char* GetName() const override { return "memory_viewer"; }
    const char* GetDisplayName() const override { return "Memory Viewer"; }

    void Initialize() override;
    void Shutdown() override {}

    void RenderMenu() override {}
    void RenderWindow() override;

    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    // Hex editor callbacks (match vendor/hex_editor/imgui_hex.h signatures)
    static int  StaticReadCallback(ImGuiHexEditorState* state, int offset, void* buf, int size);
    static int  StaticWriteCallback(ImGuiHexEditorState* state, int offset, void* buf, int size);
    static bool StaticGetAddressNameCallback(ImGuiHexEditorState* state, int offset, char* buf, int size);
    static ImGuiHexEditorHighlightFlags StaticSingleHighlightCallback(ImGuiHexEditorState* state, int offset, ImColor* color, ImColor* text_color, ImColor* border_color);

    // helpers
    static bool SafeRead(uintptr_t address, void* outBuf, size_t size);
    static bool SafeWrite(uintptr_t address, const void* inBuf, size_t size);

    void EnsureBufferSize(size_t size);
    void RefreshBuffer();

private:
    bool m_windowOpen = false;

    // View state
    uintptr_t m_viewAddress = 0;
    int m_viewSize = 0x400; // default 1KB
    bool m_readOnly = true;
    bool m_autoRefresh = false;
    float m_refreshInterval = 0.5f;
    float m_timeSinceLastRefresh = 0.0f;

    // UI inputs
    char m_addressInput[32] = "0x0";

    // Highlight options
    int   m_hlFrom = -1;
    int   m_hlTo = -1;
    ImVec4 m_hlColor = ImVec4(0.2f, 0.6f, 1.0f, 0.35f);
    bool  m_hlAscii = true;
    bool  m_hlBorder = true;
    bool  m_hlFullSized = true;

    // Hex editor state and mirror buffer (used for UI consistency on writes)
    ImGuiHexEditorState m_hexState{};
    std::vector<std::uint8_t> m_buffer;
};