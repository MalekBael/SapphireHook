#pragma comment(lib, "psapi.lib")

#include "MemoryViewerModule.h"
#include "../Helper/CapstoneWrapper.h"

#include <capstone/capstone.h>
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
	}
	else {
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
		}
		else if (m_lastFuncStart && m_lastFuncSize) {
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
	}
	else if (m_disasmDirty) {
		ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1.f), "[Dirty]");
	}
	else if (m_lastDecodeMs > 0) {
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
void MemoryViewerModule::RenderPseudocodeTab() {
	if (m_showSideBySide && (m_disasmDirty || m_lastFuncStart == 0))
		BuildDisassembly(m_viewAddress ? m_viewAddress : m_lastFuncStart);

	RenderAnalysisToolbar();
	ImGui::Separator();

	ImGui::Checkbox("Side-by-Side Disassembly", &m_showSideBySide);
	ImGui::SameLine();
	bool showTimings = true;
	ImGui::Checkbox("Show Timings", &showTimings);
	// Removed: Selectable View toggle (and its UI overlay)

	std::shared_ptr<PseudoCacheEntry> entry;
	{
		std::lock_guard<std::mutex> lk(m_pcMutex);
		auto it = m_pseudoCache.find(m_lastFuncStart);
		if (it != m_pseudoCache.end())
			entry = it->second;
	}

	uint64_t memVer = m_memoryMutationCounter.load();

	if (entry && entry->ready && entry->memoryVersion < memVer) {
		ImGui::TextColored(ImVec4(1, 0.5f, 0.3f, 1.f),
			"Pseudocode stale (memory modified)");
		ImGui::SameLine();
		if (ImGui::SmallButton("Regenerate")) {
			if (m_lastDisasmMemoryVersion != memVer || m_disasmDirty)
				BuildDisassembly(m_viewAddress ? m_viewAddress : m_lastFuncStart);
			QueueDecompile(m_lastFuncStart, m_lastFuncSize);
		}
	}

	// Export button (only meaningful if we have disasm & entry)
	if (ImGui::Button("Export...")) {
		if (entry && entry->ready && entry->error.empty()) {
			std::snprintf(m_exportPath, sizeof(m_exportPath),
				"pseudo_0x%llX.txt",
				static_cast<unsigned long long>(m_lastFuncStart));
			m_lastExportStatus.clear();
			m_exportOverwriteConfirm = false;
			ImGui::OpenPopup("Export Pseudocode/Disassembly");
		}
		else {
			ImGui::OpenPopup("Export Unavailable");
		}
	}
	if (ImGui::BeginPopupModal("Export Unavailable", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
		ImGui::TextWrapped("Pseudocode not ready or has errors. Please generate it first.");
		if (ImGui::Button("OK", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
		ImGui::EndPopup();
	}

	// Export popup
	if (ImGui::BeginPopupModal("Export Pseudocode/Disassembly", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
		ImGui::Text("Export current function to text file:");
		ImGui::InputText("Path", m_exportPath, sizeof(m_exportPath));
		if (!m_lastExportStatus.empty()) {
			ImGui::TextWrapped("%s", m_lastExportStatus.c_str());
		}
		bool fileExists = std::filesystem::exists(m_exportPath);
		if (fileExists && !m_exportOverwriteConfirm) {
			ImGui::TextColored(ImVec4(1, 0.6f, 0.2f, 1), "File exists. Press Save again to overwrite.");
		}

		if (ImGui::Button("Save", ImVec2(120, 0))) {
			if (!entry) {
				m_lastExportStatus = "No entry.";
			}
			else if (!entry->ready) {
				m_lastExportStatus = "Not ready.";
			}
			else if (!entry->error.empty()) {
				m_lastExportStatus = "Error present: " + entry->error;
			}
			else {
				if (fileExists && !m_exportOverwriteConfirm) {
					m_exportOverwriteConfirm = true;
				}
				else {
					auto text = BuildExportText(*entry);
					std::string err;
					if (WriteTextFileUTF8(m_exportPath, text, true, err)) {
						m_lastExportStatus = "Saved successfully.";
					}
					else {
						m_lastExportStatus = std::string("Save failed: ") + err;
					}
					m_exportOverwriteConfirm = false;
				}
			}
		}
		ImGui::SameLine();
		if (ImGui::Button("Close", ImVec2(120, 0))) {
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}

	if (!entry) {
		ImGui::TextDisabled("No pseudocode requested.");
		return;
	}
	if (!entry->ready) {
		ImGui::TextColored(ImVec4(1, 1, 0, 1), "Generating... (%d%%)", m_pseudoProgress.load());
		return;
	}
	if (!entry->error.empty()) {
		ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "Error: %s", entry->error.c_str());
		ImGui::SameLine();
		if (ImGui::SmallButton("Retry")) {
			QueueDecompile(m_lastFuncStart, m_lastFuncSize);
		}
		return;
	}

	if (showTimings) {
		ImGui::TextDisabled("Timings: Decode %.2f ms | IR %.2f ms | Gen %.2f ms | Total %.2f ms",
			entry->tDecodeMs, entry->tIRMs, entry->tGenMs, entry->tTotalMs);
	}

	// Removed: selectable buffer sync and InputTextMultiline path
	// Always render plain text pseudocode + Copy

	if (m_showSideBySide) {
		float avail = ImGui::GetContentRegionAvail().x;
		float leftWidth = avail * 0.48f;
		ImGui::BeginChild("disasm_side", ImVec2(leftWidth, 0), true);
		ImGui::TextDisabled("Disassembly");
		ImGui::Separator();
		if (!m_lastDisasm.empty()) {
			for (auto& ins : m_lastDisasm) {
				ImGui::Text("0x%llX  %-8s %-24s",
					static_cast<unsigned long long>(ins.address),
					ins.mnemonic.c_str(),
					ins.operands.c_str());
			}
		}
		else {
			ImGui::TextDisabled("(No disassembly)");
		}
		ImGui::EndChild();
		ImGui::SameLine();
		ImGui::BeginChild("pseudo_side", ImVec2(0, 0), true);
		ImGui::TextDisabled("Pseudocode");
		ImGui::Separator();

		ImGui::PushTextWrapPos();
		ImGui::TextUnformatted(entry->pseudocode.c_str());
		ImGui::PopTextWrapPos();

		if (ImGui::Button("Copy")) {
			ImGui::SetClipboardText(entry->pseudocode.c_str());
		}
		ImGui::EndChild();
	}
	else {
		ImGui::BeginChild("pseudo_scroll");
		ImGui::PushTextWrapPos();
		ImGui::TextUnformatted(entry->pseudocode.c_str());
		ImGui::PopTextWrapPos();
		ImGui::EndChild();
		if (ImGui::Button("Copy")) {
			ImGui::SetClipboardText(entry->pseudocode.c_str());
		}
	}
}

/* ====================== Export Helpers ====================== */
std::string MemoryViewerModule::BuildExportText(const PseudoCacheEntry& entry) const {
	std::ostringstream oss;
	oss << "Function Start: 0x" << std::hex << m_lastFuncStart
		<< "  Size: 0x" << std::hex << m_lastFuncSize << "\n";
	oss << "Memory Version: " << entry.memoryVersion << "\n";
	oss << "Timings (ms): Decode=" << std::fixed << std::setprecision(2) << entry.tDecodeMs
		<< " IR=" << entry.tIRMs
		<< " Gen=" << entry.tGenMs
		<< " Total=" << entry.tTotalMs << "\n\n";

	oss << "[Disassembly]\n";
	oss << "Address, Bytes, Mnemonic, Operands\n";
	for (const auto& ins : m_lastDisasm) {
		oss << "0x" << std::hex << ins.address << ", "
			<< ins.bytes << ", "
			<< ins.mnemonic << ", "
			<< ins.operands << "\n";
	}
	oss << "\n[Pseudocode]\n";
	oss << entry.pseudocode;
	if (entry.pseudocode.back() != '\n')
		oss << '\n';
	return oss.str();
}

bool MemoryViewerModule::WriteTextFileUTF8(const char* path, const std::string& content, bool overwrite, std::string& err) {
	namespace fs = std::filesystem;
	try {
		fs::path p(path);
		if (p.empty()) {
			err = "Empty path";
			return false;
		}
		if (fs::exists(p) && !overwrite) {
			err = "File exists";
			return false;
		}
		std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
		if (!ofs) {
			err = "Open failed";
			return false;
		}
		ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
		if (!ofs) {
			err = "Write failed";
			return false;
		}
		return true;
	}
	catch (const std::exception& ex) {
		err = ex.what();
		return false;
	}
}

/* ====================== Lifecycle ====================== */
void MemoryViewerModule::Initialize() {
	SapphireHook::LogInfo("[MemoryViewer] Initialize");
	EnsureBufferSize(static_cast<size_t>(m_viewSize));

	m_hexState.Bytes = reinterpret_cast<void*>(m_viewAddress);
	m_hexState.MaxBytes = m_viewSize;
	m_hexState.UserData = this;
	m_hexState.ReadCallback = &MemoryViewerModule::StaticReadCallback;
	m_hexState.WriteCallback = m_readOnly ? nullptr : &MemoryViewerModule::StaticWriteCallback;
	m_hexState.GetAddressNameCallback = &MemoryViewerModule::StaticGetAddressNameCallback;
	m_hexState.SingleHighlightCallback = &MemoryViewerModule::StaticSingleHighlightCallback;

	RefreshBuffer();
	InitAnalysisBackends();
}

void MemoryViewerModule::Shutdown() {
	ShutdownAnalysisBackends();
}

MemoryViewerModule::~MemoryViewerModule() {
	ShutdownAnalysisBackends();
}

/* ====================== Pseudo Decompiler Backend ====================== */
bool PseudoDecompilerBackend::Decompile(uintptr_t start, size_t codeSize,
	std::string& pseudoC) {
	m_lastTimings = {};
	auto ts = std::chrono::steady_clock::now();

	auto tDisStart = ts;
	std::vector<DisassembledInstr> instructions;
	if (!DisassembleFunction(start, (std::min)(codeSize, size_t(0x4000)), instructions)) {
		SapphireHook::LogError("[PseudoGen] Disassembly failed");
		pseudoC = "// Disassembly failed at " + SapphireHook::Logger::HexFormat(start);
		return false;
	}
	auto tDisEnd = std::chrono::steady_clock::now();

	auto tIRStart = tDisEnd;
	PseudoFunctionIR ir = AnalyzeInstructions(instructions);
	ir.start = start;
	ir.size = codeSize;
	auto tIREnd = std::chrono::steady_clock::now();

	auto tGenStart = tIREnd;
	pseudoC = GeneratePseudocode(ir);
	auto tGenEnd = std::chrono::steady_clock::now();

	m_lastTimings.disasmMs = std::chrono::duration<double, std::milli>(tDisEnd - tDisStart).count();
	m_lastTimings.analyzeMs = std::chrono::duration<double, std::milli>(tIREnd - tIRStart).count();
	m_lastTimings.genMs = std::chrono::duration<double, std::milli>(tGenEnd - tGenStart).count();
	m_lastTimings.totalMs = std::chrono::duration<double, std::milli>(tGenEnd - tDisStart).count();

	SapphireHook::LogInfo("[PseudoGen] Done in " + std::to_string((int)m_lastTimings.totalMs) +
		"ms instructions=" + std::to_string(instructions.size()));
	return true;
}

bool PseudoDecompilerBackend::DisassembleFunction(uintptr_t start, size_t maxSize,
	std::vector<DisassembledInstr>& instructions) {
	CapstoneBackend disasm;
	size_t consumed = 0;
	return disasm.Disassemble(start, maxSize, instructions, consumed);
}

PseudoFunctionIR PseudoDecompilerBackend::AnalyzeInstructions(
	const std::vector<DisassembledInstr>& instructions) {
	PseudoFunctionIR ir;
	std::unordered_map<uintptr_t, std::string> labels;
	int labelCounter = 0;

	for (const auto& insn : instructions) {
		if ((insn.isBranch || insn.isCall) && insn.target) {
			if (!labels.count(insn.target)) {
				labels[insn.target] = "L" + std::to_string(labelCounter++);
			}
		}
	}

	for (const auto& insn : instructions) {
		if (labels.count(insn.address)) {
			PseudoStatement lbl(PseudoStatement::Label);
			lbl.label = labels[insn.address] + ":";
			ir.statements.push_back(lbl);
		}

		PseudoStatement cmt(PseudoStatement::Comment);
		cmt.comment = "// " + insn.mnemonic + " " + insn.operands;
		ir.statements.push_back(cmt);

		if (insn.mnemonic == "mov" || insn.mnemonic == "lea") {
			PseudoStatement st(PseudoStatement::Assign);
			auto ops = insn.operands;
			auto comma = ops.find(',');
			if (comma != std::string::npos) {
				st.lhs = NormalizeOperand(ops.substr(0, comma));
				st.rhs = NormalizeOperand(ops.substr(comma + 1));
				ir.statements.push_back(st);
			}
		}
		else if (insn.mnemonic == "push") {
			PseudoStatement st(PseudoStatement::Assign);
			st.lhs = "[rsp]";
			st.rhs = NormalizeOperand(insn.operands);
			ir.statements.push_back(st);
		}
		else if (insn.mnemonic == "pop") {
			PseudoStatement st(PseudoStatement::Assign);
			st.lhs = NormalizeOperand(insn.operands);
			st.rhs = "[rsp]";
			ir.statements.push_back(st);
		}
		else if (insn.mnemonic == "call") {
			PseudoStatement st(PseudoStatement::Call);
			if (insn.target) {
				std::stringstream ss;
				ss << "func_" << std::hex << insn.target << "()";
				st.rhs = ss.str();
			}
			else {
				st.rhs = "call(" + insn.operands + ")";
			}
			ir.statements.push_back(st);
		}
		else if (insn.mnemonic == "ret") {
			PseudoStatement st(PseudoStatement::Return);
			ir.statements.push_back(st);
		}
		else if (insn.isBranch) {
			if (insn.mnemonic == "jmp") {
				PseudoStatement st(PseudoStatement::Goto);
				if (labels.count(insn.target))
					st.label = labels[insn.target];
				else {
					std::stringstream ss;
					ss << "0x" << std::hex << insn.target;
					st.label = ss.str();
				}
				ir.statements.push_back(st);
			}
			else {
				PseudoStatement st(PseudoStatement::IfCond);
				st.condition = GetConditionFromJump(insn.mnemonic);
				if (labels.count(insn.target))
					st.label = labels[insn.target];
				else {
					std::stringstream ss;
					ss << "0x" << std::hex << insn.target;
					st.label = ss.str();
				}
				ir.statements.push_back(st);
			}
		}
		else if (insn.mnemonic == "add" || insn.mnemonic == "sub" ||
			insn.mnemonic == "xor" || insn.mnemonic == "and" ||
			insn.mnemonic == "or") {
			PseudoStatement st(PseudoStatement::Assign);
			auto ops = insn.operands;
			auto comma = ops.find(',');
			if (comma != std::string::npos) {
				std::string dest = NormalizeOperand(ops.substr(0, comma));
				std::string src = NormalizeOperand(ops.substr(comma + 1));
				st.lhs = dest;
				st.rhs = dest + " " + insn.mnemonic + " " + src;
				ir.statements.push_back(st);
			}
		}
	}
	return ir;
}

std::string PseudoDecompilerBackend::GeneratePseudocode(const PseudoFunctionIR& ir) {
	std::stringstream ss;
	ss << "// Function at 0x" << std::hex << ir.start
		<< " (size: 0x" << ir.size << ", statements: "
		<< std::dec << ir.statements.size() << ")\n";
	ss << "// Decompiled to C++ pseudocode\n";
	ss << "void sub_" << std::hex << ir.start << "() {\n";

	std::set<std::string> declared;
	std::vector<std::string> locals;
	for (auto& st : ir.statements) {
		if (st.type == PseudoStatement::Assign) {
			if ((st.lhs.rfind("local_", 0) == 0 || st.lhs.rfind("arg_", 0) == 0) &&
				declared.insert(st.lhs).second) {
				locals.push_back(st.lhs);
			}
		}
	}
	if (!locals.empty()) {
		ss << "\n    // Variable declarations\n";
		for (auto& v : locals) {
			if (v.rfind("local_", 0) == 0)
				ss << "    std::uint64_t " << v << "{};\n";
			else if (v.rfind("arg_", 0) == 0)
				ss << "    auto " << v << " = /* arg placeholder */ 0ULL;\n";
		}
		ss << "\n";
	}

	for (size_t i = 0; i < ir.statements.size(); ++i) {
		const auto& st = ir.statements[i];
		switch (st.type) {
		case PseudoStatement::Label:
			ss << "\n" << st.label << "\n";
			break;
		case PseudoStatement::Assign:
			ss << "    " << ConvertToCppStyle(st.lhs) << " = "
				<< ConvertToCppStyle(st.rhs) << ";\n";
			break;
		case PseudoStatement::IfCond: {
			std::string cond = ConvertConditionToCpp(st.condition);
			bool mergedElse = false;
			if (i + 1 < ir.statements.size() && ir.statements[i + 1].type == PseudoStatement::Goto) {
				const auto& g = ir.statements[i + 1];
				ss << "    if (" << cond << ") goto " << st.label
					<< "; else goto " << g.label << ";\n";
				mergedElse = true;
				++i;
			}
			if (!mergedElse)
				ss << "    if (" << cond << ") goto " << st.label << ";\n";
			break;
		}
		case PseudoStatement::Goto:
			ss << "    goto " << st.label << ";\n";
			break;
		case PseudoStatement::Call:
			ss << "    " << ConvertCallToCpp(st.rhs) << ";\n";
			break;
		case PseudoStatement::Return:
			ss << "    return;\n";
			break;
		case PseudoStatement::Comment:
			ss << "    " << st.comment << "\n";
			break;
		}
	}
	ss << "}\n";
	if (ir.truncated)
		ss << "\n// NOTE: Function truncated\n";
	return ss.str();
}

std::string PseudoDecompilerBackend::ConvertToCppStyle(const std::string& op) {
	static const std::unordered_map<std::string, std::string> regMap = {
		{"rax","rax_val"},{"rbx","rbx_val"},{"rcx","rcx_val"},{"rdx","rdx_val"},
		{"rsi","rsi_val"},{"rdi","rdi_val"},{"rbp","rbp_val"},{"rsp","rsp_val"},
		{"r8","r8_val"},{"r9","r9_val"},{"r10","r10_val"},{"r11","r11_val"},
		{"r12","r12_val"},{"r13","r13_val"},{"r14","r14_val"},{"r15","r15_val"},
		{"eax","eax_val"},{"ebx","ebx_val"},{"ecx","ecx_val"},{"edx","edx_val"}
	};
	auto it = regMap.find(op);
	if (it != regMap.end()) return it->second;
	if (!op.empty() && op.front() == '[' && op.back() == ']') {
		std::string inner = op.substr(1, op.size() - 2);
		return "*reinterpret_cast<std::uint64_t*>(" + inner + ")";
	}
	if (op.rfind("0x", 0) == 0) return op + "ULL";
	return op;
}

std::string PseudoDecompilerBackend::ConvertConditionToCpp(const std::string& c) {
	static const std::unordered_map<std::string, std::string> map{
		{"ZF == 1","zero_flag"},
		{"ZF == 0","!zero_flag"},
		{"CF == 1","carry_flag"},
		{"CF == 0","!carry_flag"},
		{"SF == 1","sign_flag"},
		{"SF == 0","!sign_flag"},
		{"OF == 1","overflow_flag"},
		{"OF == 0","!overflow_flag"},
		{"ZF == 0 && SF == OF","!zero_flag && (sign_flag == overflow_flag)"},
		{"SF == OF","sign_flag == overflow_flag"},
		{"SF != OF","sign_flag != overflow_flag"},
		{"ZF == 1 || SF != OF","zero_flag || (sign_flag != overflow_flag)"},
		{"CF == 0 && ZF == 0","!carry_flag && !zero_flag"},
		{"CF == 1 || ZF == 1","carry_flag || zero_flag"}
	};
	auto it = map.find(c);
	return it != map.end() ? it->second : c;
}

std::string PseudoDecompilerBackend::ConvertCallToCpp(const std::string& call) {
	if (call.rfind("func_", 0) == 0) {
		auto pos = call.find('(');
		if (pos != std::string::npos) {
			std::string addr = call.substr(5, pos - 5);
			return "reinterpret_cast<void(*)()>(0x" + addr + ")()";
		}
	}
	if (call.rfind("call(", 0) == 0) {
		auto inner = call.substr(5, call.size() - 6);
		return "reinterpret_cast<void(*)()>(" + ConvertToCppStyle(inner) + ")()";
	}
	return call;
}

std::string PseudoDecompilerBackend::NormalizeOperand(const std::string& operand) {
	std::string op = operand;
	while (!op.empty() && (op.front() == ' ' || op.front() == '\t')) op.erase(op.begin());
	while (!op.empty() && (op.back() == ' ' || op.back() == '\t')) op.pop_back();

	if (IsStackReference(op)) {
		std::regex re(R"(\[([er]bp)\s*([+-])\s*0x([0-9a-fA-F]+)\])");
		std::smatch m;
		if (std::regex_match(op, m, re)) {
			int off = std::stoi(m[3].str(), nullptr, 16);
			return (m[2] == "-") ? ("local_" + std::to_string(off))
				: ("arg_" + std::to_string(off));
		}
	}
	return op;
}

bool PseudoDecompilerBackend::IsStackReference(const std::string& operand) {
	return operand.find("[rbp") != std::string::npos ||
		operand.find("[ebp") != std::string::npos ||
		operand.find("[rsp") != std::string::npos ||
		operand.find("[esp") != std::string::npos;
}

std::string PseudoDecompilerBackend::GetConditionFromJump(const std::string& mnem) {
	static const std::unordered_map<std::string, std::string> map{
		{"je","ZF == 1"},
		{"jne","ZF == 0"},
		{"jg","ZF == 0 && SF == OF"},
		{"jge","SF == OF"},
		{"jl","SF != OF"},
		{"jle","ZF == 1 || SF != OF"},
		{"ja","CF == 0 && ZF == 0"},
		{"jae","CF == 0"},
		{"jb","CF == 1"},
		{"jbe","CF == 1 || ZF == 1"},
		{"js","SF == 1"},
		{"jns","SF == 0"},
		{"jp","PF == 1"},
		{"jnp","PF == 0"}
	};
	auto it = map.find(mnem);
	return it != map.end() ? it->second : "condition";
}

/* ====================== Hex Editor Callbacks ====================== */
int MemoryViewerModule::StaticReadCallback(ImGuiHexEditorState* state, int offset, void* buf, int size) {
	if (!state || !buf || size <= 0) return 0;
	auto base = reinterpret_cast<uintptr_t>(state->Bytes);
	auto addr = base + static_cast<uintptr_t>(offset);
	int remain = state->MaxBytes - offset;
	int toRead = (remain > 0) ? (std::min)(remain, size) : 0;
	if (toRead <= 0) return 0;
	SIZE_T got = 0;
	if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), buf, toRead, &got))
		return static_cast<int>(got);
	if (SafeStaticRead(addr, buf, static_cast<size_t>(toRead)))
		return toRead;
	return 0;
}

int MemoryViewerModule::StaticWriteCallback(ImGuiHexEditorState* state, int offset, void* buf, int size) {
	if (!state || !state->UserData || !buf || size <= 0) return 0;
	auto* self = reinterpret_cast<MemoryViewerModule*>(state->UserData);
	auto base = reinterpret_cast<uintptr_t>(state->Bytes);
	auto addr = base + static_cast<uintptr_t>(offset);
	int remain = state->MaxBytes - offset;
	int toWrite = (remain > 0) ? (std::min)(remain, size) : 0;
	if (toWrite <= 0) return 0;
	if (!SafeWrite(addr, buf, static_cast<size_t>(toWrite))) return 0;
	if (!self->m_buffer.empty()) {
		size_t off = static_cast<size_t>(offset);
		size_t end = off + static_cast<size_t>(toWrite);
		if (end <= self->m_buffer.size())
			std::memcpy(self->m_buffer.data() + off, buf, static_cast<size_t>(toWrite));
	}
	self->OnBytesModified(addr, static_cast<size_t>(toWrite));
	return toWrite;
}

bool MemoryViewerModule::StaticGetAddressNameCallback(ImGuiHexEditorState* state, int offset, char* buf, int size) {
	if (!state || !buf || size <= 0) return false;
	auto base = reinterpret_cast<uintptr_t>(state->Bytes);
	auto abs = base + static_cast<uintptr_t>(offset);
#if defined(_MSC_VER)
	_snprintf_s(buf, size, _TRUNCATE, "0x%016llX", static_cast<unsigned long long>(abs));
#else
	std::snprintf(buf, static_cast<size_t>(size), "0x%016llX", static_cast<unsigned long long>(abs));
#endif
	return true;
}

ImGuiHexEditorHighlightFlags MemoryViewerModule::StaticSingleHighlightCallback(
	ImGuiHexEditorState* state, int offset, ImColor* color, ImColor*, ImColor*) {
	if (!state || !state->UserData || !color) return ImGuiHexEditorHighlightFlags_None;
	auto* self = reinterpret_cast<MemoryViewerModule*>(state->UserData);
	if (self->m_hlFrom >= 0 && self->m_hlTo >= 0 &&
		offset >= self->m_hlFrom && offset <= self->m_hlTo) {
		*color = ImColor(self->m_hlColor);
		ImGuiHexEditorHighlightFlags flags =
			ImGuiHexEditorHighlightFlags_Apply |
			ImGuiHexEditorHighlightFlags_TextAutomaticContrast;
		if (self->m_hlAscii)     flags |= ImGuiHexEditorHighlightFlags_Ascii;
		if (self->m_hlBorder)    flags |= ImGuiHexEditorHighlightFlags_Border |
			ImGuiHexEditorHighlightFlags_BorderAutomaticContrast;
		if (self->m_hlFullSized) flags |= ImGuiHexEditorHighlightFlags_FullSized;
		return flags;
	}
	return ImGuiHexEditorHighlightFlags_None;
}

/* ====================== Safe Memory Ops ====================== */
bool MemoryViewerModule::SafeRead(uintptr_t address, void* outBuf, size_t size) {
	if (!address || !outBuf || !size) return false;
	MEMORY_BASIC_INFORMATION mbi{};
	if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
		return false;
	if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
		return false;
	SIZE_T got = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address),
		outBuf, size, &got))
		return false;
	return got == size;
}

bool MemoryViewerModule::SafeWrite(uintptr_t address, const void* inBuf, size_t size) {
	if (!address || !inBuf || !size) return false;
	SapphireHook::SafeMemoryRegion region(address, size);
	if (!region.IsValid()) return false;
	SIZE_T written = 0;
	if (!WriteProcessMemory(GetCurrentProcess(),
		reinterpret_cast<LPVOID>(address),
		inBuf, size, &written))
		return false;
	return written == size;
}

/* ====================== Buffer Helpers ====================== */
void MemoryViewerModule::EnsureBufferSize(size_t size) {
	if (m_buffer.size() != size)
		m_buffer.assign(size, 0);
}

void MemoryViewerModule::RefreshBuffer() {
	if (m_viewSize <= 0) return;
	EnsureBufferSize(static_cast<size_t>(m_viewSize));
	if (m_viewAddress) {
		if (!SafeRead(m_viewAddress, m_buffer.data(), m_buffer.size())) {
			SapphireHook::LogWarning("[MemoryViewer] SafeRead failed at 0x" +
				std::to_string(m_viewAddress));
		}
	}
	m_hexState.Bytes = reinterpret_cast<void*>(m_viewAddress);
	m_hexState.MaxBytes = m_viewSize;
	m_hexState.ReadOnly = m_readOnly;
	m_hexState.WriteCallback = m_readOnly ? nullptr : &MemoryViewerModule::StaticWriteCallback;
}

void MemoryViewerModule::OnBytesModified(uintptr_t address, size_t size) {
	(void)address;
	(void)size;
	m_memoryMutationCounter.fetch_add(1);
	// Mark disassembly dirty only if modified range overlaps last function
	if (m_lastFuncStart && m_lastFuncSize) {
		if (address + size >= m_lastFuncStart &&
			address <= (m_lastFuncStart + m_lastFuncSize)) {
			m_disasmDirty = true;
		}
	}
}

/* ====================== Function Heuristics ====================== */
uintptr_t MemoryViewerModule::FindFunctionStartHeuristic(uintptr_t addr) {
	if (!addr) return 0;
	constexpr size_t scanBack = 0x200;
	uintptr_t scanStart = (addr > scanBack) ? (addr - scanBack) : 0;
	std::vector<uint8_t> buf(scanBack + 16);
	if (!SafeStaticRead(scanStart, buf.data(), buf.size())) return addr;

	for (size_t i = 0; i + 4 < buf.size(); ++i) {
		uintptr_t candidate = scanStart + i;
		if (candidate >= addr) break;
		if (buf[i] == 0x55 && buf[i + 1] == 0x48 && buf[i + 2] == 0x89 && buf[i + 3] == 0xE5)
			return candidate;
		if (buf[i] == 0x48 && buf[i + 1] == 0x83 && buf[i + 2] == 0xEC)
			return candidate;
		if (buf[i] == 0x48 && buf[i + 1] == 0x89 && buf[i + 2] == 0x4C && buf[i + 3] == 0x24)
			return candidate;
	}
	return addr;
}

size_t MemoryViewerModule::DetermineFunctionSize(uintptr_t start) {
	if (!start) return 0;
	constexpr size_t kMax = 0x2000;
	std::vector<uint8_t> buf(kMax);
	if (!SafeStaticRead(start, buf.data(), buf.size()))
		return 0x100;

	for (size_t i = 8; i + 4 < buf.size(); ++i) {
		if (buf[i] == 0xC3) {
			if (i + 1 < buf.size()) {
				uint8_t next = buf[i + 1];
				if (next == 0xCC || next == 0x90 || next == 0x00)
					return i + 1;
				if (i + 5 < buf.size() &&
					buf[i + 1] == 0x55 && buf[i + 2] == 0x48 &&
					buf[i + 3] == 0x89 && buf[i + 4] == 0xE5)
					return i + 1;
			}
		}
		if (buf[i] == 0xC2 && i + 2 < buf.size())
			return i + 3;
	}
	return kMax;
}

uint64_t MemoryViewerModule::ComputeImageHash() const {
	HMODULE h = GetModuleHandleA(nullptr);
	if (!h) return 0;
	MODULEINFO mi{};
	if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi)))
		return 0;
	uint64_t hash = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
	hash ^= (static_cast<uint64_t>(mi.SizeOfImage) << 32);
	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(h);
	if (dos && dos->e_magic == IMAGE_DOS_SIGNATURE) {
		auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
			reinterpret_cast<uint8_t*>(h) + dos->e_lfanew);
		if (nt && nt->Signature == IMAGE_NT_SIGNATURE)
			hash ^= static_cast<uint64_t>(nt->FileHeader.TimeDateStamp);
	}
	return hash;
}

/* ====================== RenderWindow ====================== */
void MemoryViewerModule::RenderWindow() {
	if (!m_windowOpen) return;
	ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin("Memory Viewer", &m_windowOpen)) {
		ImGui::End();
		return;
	}

	ImGui::PushItemWidth(180.f);
	ImGui::InputTextWithHint("##addr", "Address (hex)", m_addressInput, sizeof(m_addressInput));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(120.f);
	ImGui::InputInt("Size (bytes)", &m_viewSize);
	ImGui::PopItemWidth();
	ImGui::SameLine();
	if (ImGui::Button("Go")) {
		uintptr_t addr = static_cast<uintptr_t>(_strtoui64(m_addressInput, nullptr, 0));
		m_viewAddress = addr;
		if (m_viewSize < 0) m_viewSize = 0;
		RefreshBuffer();
		m_disasmDirty = true;
	}
	ImGui::SameLine();
	if (ImGui::Button("Refresh")) RefreshBuffer();
	ImGui::SameLine();
	if (ImGui::Checkbox("Auto Refresh", &m_autoRefresh))
		m_timeSinceLastRefresh = 0.f;
	ImGui::SameLine();
	ImGui::SetNextItemWidth(120.f);
	ImGui::InputFloat("Interval (s)", &m_refreshInterval);

	ImGui::Separator();

	if (ImGui::Checkbox("Read Only", &m_readOnly))
		RefreshBuffer();
	ImGui::SameLine();
	ImGui::Checkbox("Show ASCII", &m_hexState.ShowAscii);
	ImGui::SameLine();
	ImGui::Checkbox("Show Address", &m_hexState.ShowAddress);

	ImGui::Separator();

	if (ImGui::BeginTabBar("MemViewerTabs")) {
		if (ImGui::BeginTabItem("Hex")) {
			if (ImGui::BeginHexEditor("##HexView", &m_hexState, ImVec2(0, 0)))
				ImGui::EndHexEditor();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Disasm")) {
			RenderDisassemblyTab();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Pseudocode")) {
			RenderPseudocodeTab();
			ImGui::EndTabItem();
		}
		ImGui::EndTabBar();
	}

	ImGui::End();
}