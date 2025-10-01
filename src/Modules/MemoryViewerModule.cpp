#pragma comment(lib, "psapi.lib")  // For GetModuleInformation

#include "MemoryViewerModule.h"
#include "../Helper/CapstoneWrapper.h"

#include <../vendor/capstone/include/capstone.h>
#include <algorithm>
#include <windows.h>
#include "../src/Logger/Logger.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <regex>
#include <psapi.h>
#include <set>
#include <unordered_map>
#include <fstream>
#include <filesystem>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

/* ====================== Capstone Environment Logging ====================== */
static void LogCapstoneEnvironment() {
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    SapphireHook::LogInfo("[Capstone] version: " + std::to_string(major) + "." + std::to_string(minor));
    if (HMODULE h = GetModuleHandleA("capstone.dll")) {
        char path[MAX_PATH]{};
        if (GetModuleFileNameA(h, path, MAX_PATH))
            SapphireHook::LogInfo(std::string("[Capstone] loaded from: ") + path);
    }
    else {
        SapphireHook::LogInfo("[Capstone] (static link or not yet loaded)");
    }
}

/* ====================== CapstoneBackend ====================== */
CapstoneBackend::CapstoneBackend() {
    csh h{};
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
        m_handle = nullptr;
        return;
    }
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    m_handle = reinterpret_cast<void*>(h);
}

CapstoneBackend::~CapstoneBackend() {
    if (m_handle) {
        cs_close(reinterpret_cast<csh*>(&m_handle));
    }
}

bool CapstoneBackend::Disassemble(uintptr_t start, size_t maxBytes,
    std::vector<DisassembledInstr>& out,
    size_t& bytesConsumed) {
    out.clear();
    bytesConsumed = 0;
    if (maxBytes == 0) return false;

    constexpr size_t kMaxRead = 0x2000;
    size_t readLen = (std::min)(maxBytes, kMaxRead);

    std::vector<uint8_t> buf(readLen);
    if (!MemoryViewerModule::SafeStaticRead(start, buf.data(), readLen)) {
        SapphireHook::LogWarning("CapstoneBackend: SafeStaticRead failed");
        return false;
    }

    SapphireHook::CapstoneWrapper wrapper;
    if (!wrapper.valid()) {
        SapphireHook::LogError("CapstoneBackend: wrapper invalid");
        return false;
    }

    auto result = wrapper.DisassembleBuffer(buf.data(), readLen, start, 0);
    if (!result.ok()) {
        SapphireHook::LogError(std::string("CapstoneBackend: disassembly failed: ")
            + CapstoneErrorToString(result.error()));
        return false;
    }

    const auto& decoded = result.value();
    out.reserve(decoded.size());
    for (const auto& di : decoded) {
        DisassembledInstr d;
        d.address = di.address;
        for (uint8_t i = 0; i < di.size; ++i) {
            char tmp[4];
            std::snprintf(tmp, sizeof(tmp), "%02X", di.bytes[i]);
            d.bytes += tmp;
        }
        d.mnemonic = di.mnemonic;
        d.operands = di.operands;
        d.isRet = di.isRet;
        d.isCall = di.isCall;
        d.isBranch = di.isBranch;
        d.target = di.target;
        out.push_back(std::move(d));
        bytesConsumed += di.size;
    }
    return !out.empty();
}

/* ====================== Safe Static Read ====================== */
bool MemoryViewerModule::SafeStaticRead(uintptr_t addr, void* out, size_t sz) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS)) return false;
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), out, sz, &got))
        return false;
    return got == sz;
}

/* ====================== Backend Init / Shutdown ====================== */
void MemoryViewerModule::InitAnalysisBackends() {
    if (!m_disBackend)    m_disBackend = std::make_unique<CapstoneBackend>();
    if (!m_decompBackend) m_decompBackend = std::make_unique<PseudoDecompilerBackend>();
    m_workerRun = true;
    m_worker = std::thread(&MemoryViewerModule::WorkerLoop, this);
    LogCapstoneEnvironment();
}

void MemoryViewerModule::ShutdownAnalysisBackends() {
    if (!m_workerRun.exchange(false)) return;
    {
        std::lock_guard<std::mutex> lk(m_wqMutex);
    }
    if (m_worker.joinable()) m_worker.join();
    m_disBackend.reset();
    m_decompBackend.reset();
}

/* ====================== Worker Thread ====================== */
void MemoryViewerModule::WorkerLoop() {
    while (m_workerRun) {
        WorkItem item{};
        bool have = false;
        {
            std::lock_guard<std::mutex> lk(m_wqMutex);
            if (!m_workQueue.empty()) {
                item = m_workQueue.front();
                m_workQueue.pop_front();
                have = true;
            }
        }
        if (!have) {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            continue;
        }

        if (item.type == WorkItem::Decompile) {
            m_pseudoProgress = 0;
            m_abortDecompile = false;

            std::shared_ptr<PseudoCacheEntry> entry;
            {
                std::lock_guard<std::mutex> lk(m_pcMutex);
                auto it = m_pseudoCache.find(item.start);
                if (it == m_pseudoCache.end()) continue;
                entry = it->second;
            }

            auto startTime = std::chrono::steady_clock::now();
            std::string out;
            bool ok = m_decompBackend->Decompile(item.start, item.size, out);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();

            if (m_abortDecompile) {
                entry->error = "Aborted by user";
                SapphireHook::LogWarning("[PseudoGen] Aborted by user after " +
                    std::to_string(elapsed) + "ms");
            }
            else if (elapsed > m_pseudoTimeoutMs) {
                entry->error = "Timeout exceeded";
                SapphireHook::LogError("[PseudoGen] Timeout after " +
                    std::to_string(elapsed) + "ms");
            }
            else {
                entry->pseudocode = std::move(out);
                if (!ok) entry->error = "Decompile failed";
            }

            // Capture timing info if backend supports
            if (auto* backend = dynamic_cast<PseudoDecompilerBackend*>(m_decompBackend.get())) {
                const auto& tm = backend->GetLastTimings();
                entry->tDecodeMs = tm.disasmMs;
                entry->tIRMs = tm.analyzeMs;
                entry->tGenMs = tm.genMs;
                entry->tTotalMs = tm.totalMs;
            }

            entry->memoryVersion = m_memoryMutationCounter.load();
            m_pseudoProgress = 100;
            entry->ready = true;
        }
    }
}

/* ====================== Queue Decompile ====================== */
void MemoryViewerModule::QueueDecompile(uintptr_t start, size_t size) {
    std::lock_guard<std::mutex> lk(m_pcMutex);
    auto& slot = m_pseudoCache[start];
    if (!slot) {
        slot = std::make_shared<PseudoCacheEntry>();
        slot->codeSize = size;
        slot->buildHash = ComputeImageHash();
        slot->ready = false;
        slot->memoryVersion = m_memoryMutationCounter.load();
        {
            std::lock_guard<std::mutex> qlk(m_wqMutex);
            m_workQueue.push_back({ WorkItem::Decompile, start, size });
        }
    } else {
        // If stale or error and user requested again, enqueue anew
        if (slot->memoryVersion < m_memoryMutationCounter.load() || !slot->ready) {
            slot->ready = false;
            slot->error.clear();
            slot->memoryVersion = m_memoryMutationCounter.load();
            {
                std::lock_guard<std::mutex> qlk(m_wqMutex);
                m_workQueue.push_back({ WorkItem::Decompile, start, size });
            }
        }
    }
}

/* ====================== Disassembly ====================== */
bool MemoryViewerModule::BuildDisassembly(uintptr_t address) {
    uintptr_t target = address ? address : (m_lastFuncStart ? m_lastFuncStart : address);
    uintptr_t start = FindFunctionStartHeuristic(target);
    size_t size = DetermineFunctionSize(start);
    size = (std::min)(size, static_cast<size_t>(0x2000));
    size_t consumed = 0;
    if (!m_disBackend) return false;

    auto t0 = std::chrono::steady_clock::now();
    if (!m_disBackend->Disassemble(start, size, m_lastDisasm, consumed))
        return false;
    m_lastDecodeMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    m_lastFuncStart = start;
    m_lastFuncSize = consumed;
    m_disasmDirty = false;
    m_lastDisasmMemoryVersion = m_memoryMutationCounter.load();
    return true;
}

/* ====================== Toolbar ====================== */
void MemoryViewerModule::RenderAnalysisToolbar() {
    if (ImGui::Button("Decode Function")) {
        m_disasmDirty = true;
    }
    ImGui::SameLine();
    // Conditions requiring decode before pseudocode:
    bool disasmMissing = m_lastFuncStart == 0 || m_lastFuncSize == 0;
    bool disasmStale = m_lastDisasmMemoryVersion != m_memoryMutationCounter.load();
    bool needDecode = disasmMissing || m_disasmDirty || disasmStale;

    if (ImGui::Button("Pseudocode")) {
        if (needDecode) {
            m_pendingPseudoRequest = true;
            ImGui::OpenPopup("Decode Required");
        } else if (m_lastFuncStart && m_lastFuncSize) {
            QueueDecompile(m_lastFuncStart, m_lastFuncSize);
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("FuncStart: 0x%llX Size: 0x%zX",
        static_cast<unsigned long long>(m_lastFuncStart), m_lastFuncSize);

    ImGui::SameLine();
    if (disasmStale) {
        ImGui::TextColored(ImVec4(1, 0.4f, 0.3f, 1.f), "[Disassembly Stale]");
        ImGui::SameLine();
        if (ImGui::SmallButton("Re-decode")) {
            BuildDisassembly(m_viewAddress ? m_viewAddress : m_lastFuncStart);
        }
    } else if (m_disasmDirty) {
        ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1.f), "[Dirty]");
    } else if (m_lastDecodeMs > 0) {
        ImGui::TextDisabled("(Decode %.2f ms)", m_lastDecodeMs);
    }

    // Modal popup
    if (ImGui::BeginPopupModal("Decode Required", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("A (re)decode is recommended before generating pseudocode.\n\nReasons:\n%s%s%s",
            disasmMissing ? "- No disassembly yet.\n" : "",
            m_disasmDirty ? "- Marked dirty by user.\n" : "",
            disasmStale ? "- Underlying bytes changed since last decode.\n" : "");
        ImGui::Separator();
        if (ImGui::Button("Decode & Generate", ImVec2(160, 0))) {
            if (BuildDisassembly(m_viewAddress ? m_viewAddress : m_lastFuncStart)) {
                if (m_lastFuncStart && m_lastFuncSize)
                    QueueDecompile(m_lastFuncStart, m_lastFuncSize);
            }
            m_pendingPseudoRequest = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            m_pendingPseudoRequest = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

/* ====================== Disassembly Tab ====================== */
void MemoryViewerModule::RenderDisassemblyTab() {
    if (m_disasmDirty) {
        BuildDisassembly(m_viewAddress ? m_viewAddress : m_lastFuncStart);
    }
    RenderAnalysisToolbar();
    ImGui::Separator();
    if (ImGui::BeginTable("disasm_tbl", 5,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable,
        ImVec2(0, 0))) {

        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 110.f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 120.f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 90.f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 70.f);
        ImGui::TableHeadersRow();

        for (auto& ins : m_lastDisasm) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX", static_cast<unsigned long long>(ins.address));
            ImGui::TableNextColumn(); ImGui::TextUnformatted(ins.bytes.c_str());
            ImGui::TableNextColumn(); ImGui::TextUnformatted(ins.mnemonic.c_str());
            ImGui::TableNextColumn(); ImGui::TextUnformatted(ins.operands.c_str());
            ImGui::TableNextColumn();
            if (ins.isRet)       ImGui::TextColored(ImVec4(1, 0.6f, 0, 1), "RET");
            else if (ins.isCall) ImGui::TextColored(ImVec4(0.7f, 0.7f, 1, 1), "CALL");
            else if (ins.isBranch) ImGui::TextColored(ImVec4(0.6f, 1, 0.6f, 1), "JMP");
            else ImGui::TextUnformatted("");
        }
        ImGui::EndTable();
    }
}

/* ====================== Pseudocode Tab ====================== */
// REPLACE the entire existing RenderPseudocodeTab() implementation with this version:

void MemoryViewerModule::RenderPseudocodeTab()
{
    // Build disassembly first if needed for side-by-side
    if (m_showSideBySide && (m_disasmDirty || m_lastFuncStart == 0))
        BuildDisassembly(m_viewAddress ? m_viewAddress : m_lastFuncStart);

    RenderAnalysisToolbar();
    ImGui::Separator();

    // Top options (removed old "Selectable View" toggle – always selectable now)
    ImGui::Checkbox("Side-by-Side Disassembly", &m_showSideBySide);
    ImGui::SameLine();
    static bool showTimings = true;
    ImGui::Checkbox("Show Timings", &showTimings);

    // Fetch current entry
    std::shared_ptr<PseudoCacheEntry> entry;
    {
        std::lock_guard<std::mutex> lk(m_pcMutex);
        auto it = m_pseudoCache.find(m_lastFuncStart);
        if (it != m_pseudoCache.end())
            entry = it->second;
    }

    uint64_t memVer = m_memoryMutationCounter.load();

    // Stale notice
    if (entry && entry->ready && entry->memoryVersion < memVer)
    {
        ImGui::TextColored(ImVec4(1, 0.5f, 0.3f, 1.f), "Pseudocode stale (memory modified)");
        ImGui::SameLine();
        if (ImGui::SmallButton("Regenerate"))
        {
            if (m_lastDisasmMemoryVersion != memVer || m_disasmDirty)
                BuildDisassembly(m_viewAddress ? m_viewAddress : m_lastFuncStart);
            QueueDecompile(m_lastFuncStart, m_lastFuncSize);
        }
    }

    // Export
    if (ImGui::Button("Export..."))
    {
        if (entry && entry->ready && entry->error.empty())
        {
            std::snprintf(m_exportPath, sizeof(m_exportPath), "pseudo_0x%llX.txt",
                static_cast<unsigned long long>(m_lastFuncStart));
            m_lastExportStatus.clear();
            m_exportOverwriteConfirm = false;
            ImGui::OpenPopup("Export Pseudocode/Disassembly");
        }
        else
            ImGui::OpenPopup("Export Unavailable");
    }

    if (ImGui::BeginPopupModal("Export Unavailable", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::TextWrapped("Pseudocode not ready or has errors. Please generate it first.");
        if (ImGui::Button("OK", ImVec2(120, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    if (ImGui::BeginPopupModal("Export Pseudocode/Disassembly", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::Text("Export current function to text file:");
        ImGui::InputText("Path", m_exportPath, sizeof(m_exportPath));
        if (!m_lastExportStatus.empty())
            ImGui::TextWrapped("%s", m_lastExportStatus.c_str());

        bool fileExists = std::filesystem::exists(m_exportPath);
        if (fileExists && !m_exportOverwriteConfirm)
            ImGui::TextColored(ImVec4(1, 0.6f, 0.2f, 1), "File exists. Press Save again to overwrite.");

        if (ImGui::Button("Save", ImVec2(120, 0)))
        {
            if (!entry)                      m_lastExportStatus = "No entry.";
            else if (!entry->ready)          m_lastExportStatus = "Not ready.";
            else if (!entry->error.empty())  m_lastExportStatus = "Error: " + entry->error;
            else
            {
                if (fileExists && !m_exportOverwriteConfirm)
                    m_exportOverwriteConfirm = true;
                else
                {
                    auto text = BuildExportText(*entry);
                    std::string err;
                    if (WriteTextFileUTF8(m_exportPath, text, true, err))
                        m_lastExportStatus = "Saved successfully.";
                    else
                        m_lastExportStatus = "Save failed: " + err;
                    m_exportOverwriteConfirm = false;
                }
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Close", ImVec2(120, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // State checks
    if (!entry)
    {
        ImGui::TextDisabled("No pseudocode requested.");
        return;
    }
    if (!entry->ready)
    {
        ImGui::TextColored(ImVec4(1, 1, 0, 1), "Generating... (%d%%)", m_pseudoProgress.load());
        return;
    }
    if (!entry->error.empty())
    {
        ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "Error: %s", entry->error.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Retry"))
            QueueDecompile(m_lastFuncStart, m_lastFuncSize);
        return;
    }

    // Timings
    if (showTimings)
    {
        ImGui::TextDisabled("Timings: Decode %.2f ms | IR %.2f ms | Gen %.2f ms | Total %.2f ms",
            entry->tDecodeMs, entry->tIRMs, entry->tGenMs, entry->tTotalMs);
    }

    // Sync selectable buffer (defensive compare)
    if (entry->memoryVersion != m_pseudoDisplayBufferVersion ||
        m_pseudoDisplayBuffer != entry->pseudocode)
    {
        m_pseudoDisplayBuffer = entry->pseudocode;
        m_pseudoDisplayBufferVersion = entry->memoryVersion;
        m_pseudoSelectableBuffer.assign(m_pseudoDisplayBuffer.begin(), m_pseudoDisplayBuffer.end());
        m_pseudoSelectableBuffer.push_back('\0');
    }

    // Layout
    if (m_showSideBySide)
    {
        float avail = ImGui::GetContentRegionAvail().x;
        float leftWidth = avail * 0.48f;

        ImGui::BeginChild("disasm_side", ImVec2(leftWidth, 0), true);
        ImGui::TextDisabled("Disassembly");
        ImGui::Separator();
        if (!m_lastDisasm.empty())
        {
            for (auto& ins : m_lastDisasm)
                ImGui::Text("0x%llX  %-8s %-24s",
                    static_cast<unsigned long long>(ins.address),
                    ins.mnemonic.c_str(),
                    ins.operands.c_str());
        }
        else
            ImGui::TextDisabled("(No disassembly)");
        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild("pseudo_side", ImVec2(0, 0), true);
        ImGui::TextDisabled("Pseudocode");
        ImGui::Separator();
        RenderPseudoSelectable("##pseudo_side_box", m_pseudoDisplayBuffer, ImVec2(-FLT_MIN, 0));
        if (ImGui::Button("Copy"))
            ImGui::SetClipboardText(entry->pseudocode.c_str());
        ImGui::EndChild();
    }
    else
    {
        ImGui::BeginChild("pseudo_full", ImVec2(0, 0), true);
        RenderPseudoSelectable("##pseudo_full_box", m_pseudoDisplayBuffer, ImVec2(-FLT_MIN, -FLT_MIN));
        ImGui::EndChild();
        if (ImGui::Button("Copy"))
            ImGui::SetClipboardText(entry->pseudocode.c_str());
    }
}
