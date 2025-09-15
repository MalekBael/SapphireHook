#include "MemoryViewerModule.h"
#include "../Logger/Logger.h"
#include <windows.h>
#include <cstdio>
#include <cstdlib>

void MemoryViewerModule::Initialize()
{
    SapphireHook::LogInfo("[MemoryViewer] Initialize");
    EnsureBufferSize(static_cast<size_t>(m_viewSize));

    // Configure hex editor defaults
    m_hexState.Bytes = reinterpret_cast<void*>(m_viewAddress); // use base VA
    m_hexState.MaxBytes = m_viewSize;
    m_hexState.ShowAddress = true;
    m_hexState.AddressChars = -1;     // auto
    m_hexState.ShowAscii = true;
    m_hexState.ReadOnly = m_readOnly;
    m_hexState.Separators = 8;
    m_hexState.RenderZeroesDisabled = false;
    m_hexState.EnableClipboard = true;
    m_hexState.UserData = this;

    // Wire callbacks (per README)
    m_hexState.ReadCallback = &MemoryViewerModule::StaticReadCallback;
    m_hexState.GetAddressNameCallback = &MemoryViewerModule::StaticGetAddressNameCallback;
    m_hexState.SingleHighlightCallback = &MemoryViewerModule::StaticSingleHighlightCallback;
    m_hexState.WriteCallback = m_readOnly ? nullptr : &MemoryViewerModule::StaticWriteCallback;

    RefreshBuffer();
}

void MemoryViewerModule::EnsureBufferSize(size_t size)
{
    if (m_buffer.size() != size)
        m_buffer.assign(size, 0x00);
}

bool MemoryViewerModule::SafeRead(uintptr_t address, void* outBuf, size_t size)
{
    if (address == 0 || !outBuf || size == 0) return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
        return false;

    if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
        return false;

    SIZE_T read = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), outBuf, static_cast<SIZE_T>(size), &read))
        return false;

    return read == size;
}

bool MemoryViewerModule::SafeWrite(uintptr_t address, const void* inBuf, size_t size)
{
    if (address == 0 || !inBuf || size == 0) return false;

    SapphireHook::SafeMemoryRegion region(address, size);
    if (!region.IsValid()) return false;

    SIZE_T written = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(address), inBuf, static_cast<SIZE_T>(size), &written))
        return false;

    return written == size;
}

void MemoryViewerModule::RefreshBuffer()
{
    if (m_viewSize <= 0) return;

    EnsureBufferSize(static_cast<size_t>(m_viewSize));

    if (m_viewAddress != 0)
    {
        // Fill mirror buffer (not strictly required for rendering when using ReadCallback)
        if (!SafeRead(m_viewAddress, m_buffer.data(), m_buffer.size()))
            SapphireHook::LogWarning("[MemoryViewer] SafeRead failed at address");
    }

    // Sync state with current view
    m_hexState.Bytes = reinterpret_cast<void*>(m_viewAddress);
    m_hexState.MaxBytes = m_viewSize;
    m_hexState.ReadOnly = m_readOnly;
    m_hexState.WriteCallback = m_readOnly ? nullptr : &MemoryViewerModule::StaticWriteCallback;
}

// === Hex editor callbacks ===

int MemoryViewerModule::StaticReadCallback(ImGuiHexEditorState* state, int offset, void* buf, int size)
{
    if (!state || !buf || size <= 0) return 0;
    const uintptr_t base = reinterpret_cast<uintptr_t>(state->Bytes);
    const uintptr_t addr = base + static_cast<uintptr_t>(offset);

    const int maxAvail = state->MaxBytes - offset;
    const int toRead = (maxAvail > 0) ? (maxAvail < size ? maxAvail : size) : 0;
    if (toRead <= 0) return 0;

    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), buf, static_cast<SIZE_T>(toRead), &read))
        return static_cast<int>(read);

    // fallback (all-or-nothing)
    if (SafeRead(addr, buf, static_cast<size_t>(toRead)))
        return toRead;

    return 0;
}

int MemoryViewerModule::StaticWriteCallback(ImGuiHexEditorState* state, int offset, void* buf, int size)
{
    if (!state || !state->UserData || !buf || size <= 0) return 0;
    auto* self = reinterpret_cast<MemoryViewerModule*>(state->UserData);

    const uintptr_t base = reinterpret_cast<uintptr_t>(state->Bytes);
    const uintptr_t target = base + static_cast<uintptr_t>(offset);

    const int maxAvail = state->MaxBytes - offset;
    const int toWrite = (maxAvail > 0) ? (maxAvail < size ? maxAvail : size) : 0;
    if (toWrite <= 0) return 0;

    // Temporarily ensure writable and write
    SapphireHook::SafeMemoryRegion region(target, static_cast<size_t>(toWrite));
    if (!region.IsValid())
        return 0;

    SIZE_T written = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(target), buf, static_cast<SIZE_T>(toWrite), &written))
    {
        // fallback
        if (!SafeWrite(target, buf, static_cast<size_t>(toWrite)))
            return 0;
        written = static_cast<SIZE_T>(toWrite);
    }

    // Mirror into local buffer if in range
    if (!self->m_buffer.empty())
    {
        const size_t off = static_cast<size_t>(offset);
        const size_t end = off + static_cast<size_t>(written);
        if (end <= self->m_buffer.size())
            std::memcpy(self->m_buffer.data() + off, buf, static_cast<size_t>(written));
    }

    return static_cast<int>(written);
}

bool MemoryViewerModule::StaticGetAddressNameCallback(ImGuiHexEditorState* state, int offset, char* buf, int size)
{
    if (!state || !buf || size <= 0) return false;
    const uintptr_t base = reinterpret_cast<uintptr_t>(state->Bytes);
    const uintptr_t absAddr = base + static_cast<uintptr_t>(offset);

#if defined(_MSC_VER)
    _snprintf_s(buf, size, _TRUNCATE, "0x%016llX", static_cast<unsigned long long>(absAddr));
#else
    std::snprintf(buf, static_cast<size_t>(size), "0x%016llX", static_cast<unsigned long long>(absAddr));
#endif
    return true;
}

ImGuiHexEditorHighlightFlags MemoryViewerModule::StaticSingleHighlightCallback(
    ImGuiHexEditorState* state, int offset, ImColor* color, ImColor* /*text_color*/, ImColor* /*border_color*/)
{
    if (!state || !state->UserData || !color) return ImGuiHexEditorHighlightFlags_None;
    auto* self = reinterpret_cast<MemoryViewerModule*>(state->UserData);

    if (self->m_hlFrom >= 0 && self->m_hlTo >= 0 && offset >= self->m_hlFrom && offset <= self->m_hlTo)
    {
        *color = ImColor(self->m_hlColor);
        ImGuiHexEditorHighlightFlags flags = ImGuiHexEditorHighlightFlags_Apply | ImGuiHexEditorHighlightFlags_TextAutomaticContrast;
        if (self->m_hlAscii)     flags = flags | ImGuiHexEditorHighlightFlags_Ascii;
        if (self->m_hlBorder)    flags = flags | ImGuiHexEditorHighlightFlags_Border | ImGuiHexEditorHighlightFlags_BorderAutomaticContrast;
        if (self->m_hlFullSized) flags = flags | ImGuiHexEditorHighlightFlags_FullSized;
        return flags;
    }

    return ImGuiHexEditorHighlightFlags_None;
}

void MemoryViewerModule::RenderWindow()
{
    if (!m_windowOpen) return;

    ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Memory Viewer", &m_windowOpen))
    {
        ImGui::End();
        return;
    }

    // Controls row
    ImGui::PushItemWidth(180.0f);
    ImGui::InputTextWithHint("##addr", "Address (hex, e.g. 0x140000000)", m_addressInput, sizeof(m_addressInput));
    ImGui::SameLine();
    ImGui::PopItemWidth();

    ImGui::PushItemWidth(120.0f);
    ImGui::InputInt("Size (bytes)", &m_viewSize);
    ImGui::PopItemWidth();

    ImGui::SameLine();
    if (ImGui::Button("Go"))
    {
        std::string s = m_addressInput;
        uintptr_t addr = static_cast<uintptr_t>(_strtoui64(s.c_str(), nullptr, 0));
        m_viewAddress = addr;
        if (m_viewSize < 0) m_viewSize = 0;
        RefreshBuffer();
    }

    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
    {
        RefreshBuffer();
    }

    ImGui::SameLine();
    if (ImGui::Checkbox("Auto Refresh", &m_autoRefresh))
    {
        m_timeSinceLastRefresh = 0.0f;
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputFloat("Interval (s)", &m_refreshInterval);

    ImGui::Separator();

    // Options row
    if (ImGui::Checkbox("Read Only", &m_readOnly))
    {
        RefreshBuffer();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Show ASCII", &m_hexState.ShowAscii);
    ImGui::SameLine();
    ImGui::Checkbox("Show Address", &m_hexState.ShowAddress);
    ImGui::SameLine();
    ImGui::Checkbox("Lowercase", &m_hexState.LowercaseBytes);

    // Highlight UI
    ImGui::Separator();
    ImGui::TextUnformatted("Highlight Range:");
    ImGui::PushItemWidth(120.0f);
    ImGui::InputInt("From (byte offset)", &m_hlFrom);
    ImGui::SameLine();
    ImGui::InputInt("To (byte offset)", &m_hlTo);
    ImGui::PopItemWidth();
    ImGui::ColorEdit4("Highlight Color", (float*)&m_hlColor, ImGuiColorEditFlags_NoInputs);
    ImGui::Checkbox("Highlight ASCII", &m_hlAscii);
    ImGui::SameLine();
    ImGui::Checkbox("Border", &m_hlBorder);
    ImGui::SameLine();
    ImGui::Checkbox("Full Sized", &m_hlFullSized);

    // Auto refresh logic
    if (m_autoRefresh && m_viewAddress != 0 && m_viewSize > 0 && m_refreshInterval > 0.01f)
    {
        m_timeSinceLastRefresh += ImGui::GetIO().DeltaTime;
        if (m_timeSinceLastRefresh >= m_refreshInterval)
        {
            m_timeSinceLastRefresh = 0.0f;
            RefreshBuffer();
        }
    }

    ImGui::Separator();

    // Keep state pointers up-to-date per-frame
    m_hexState.Bytes = reinterpret_cast<void*>(m_viewAddress);
    m_hexState.MaxBytes = m_viewSize;

    if (ImGui::BeginHexEditor("##HexView", &m_hexState, ImVec2(0, 0)))
    {
        ImGui::EndHexEditor();
    }

    ImGui::End();
}