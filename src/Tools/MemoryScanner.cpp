#include "../Tools/MemoryScanner.h"
#include "../Logger/Logger.h"
#include "../Helper/CapstoneWrapper.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/imspinner.h"
#include "../Core/LibraryIntegration.h"
#include <sstream>
#include <fstream>
#include <iomanip>
#include <unordered_set>
#include <algorithm>

// Windows headers for VirtualQuery / MODULEINFO
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#undef min
#undef max
#pragma comment(lib, "psapi.lib")

// Real scanning via FunctionScanner
#include "../Analysis/FunctionScanner.h"
#include "../Hooking/hook_manager.h"

using namespace SapphireHook;

MemoryScanner::MemoryScanner() = default;
MemoryScanner::~MemoryScanner() = default;

void MemoryScanner::ResetScanState()
{
	// Do not assign; ScanState contains non-copyable members (mutex)
	if (m_scanState.scanFuture.valid()) {
		try { m_scanState.scanFuture.wait(); }
		catch (...) {}
	}
	if (m_scanState.prologueFuture.valid()) {
		try { m_scanState.prologueFuture.wait(); }
		catch (...) {}
	}
	if (m_scanState.stringFuture.valid()) {
		try { m_scanState.stringFuture.wait(); }
		catch (...) {}
	}

	m_scanState.running = false;
	m_scanState.cancelled = false;
	m_scanState.scanPrologues = false;
	m_scanState.scanStrings = false;
	m_scanState.anchorsRebuilt = false;
	m_scanState.prologueCompleted = false;
	m_scanState.stringCompleted = false;
	m_scanState.uiFreeze = false;
	m_scanState.rowsCacheDirty = false;
	m_scanState.lastStatusBuildTick = 0;
	m_scanState.status.clear();
	m_scanState.lastProloguePhase.clear();
	m_scanState.lastStringPhase.clear();
	m_scanState.targetStrings.clear();
	m_scanState.prologueFunctions.clear();
	m_scanState.stringHits.clear();
	m_scanState.rowCache.clear();
	m_scanState.prologueProcessed.store(0, std::memory_order_relaxed);
	m_scanState.prologueTotal.store(0, std::memory_order_relaxed);
	m_scanState.stringProcessed.store(0, std::memory_order_relaxed);
	m_scanState.stringTotal.store(0, std::memory_order_relaxed);
	m_scanState.totalRegions.store(0, std::memory_order_relaxed);
	m_scanState.regionsProcessed.store(0, std::memory_order_relaxed);
}

void MemoryScanner::StartScan(const std::vector<std::string>& targetStrings,
	bool scanPrologues, bool scanStrings)
{
	ResetScanState();
	m_scanState.running = true;
	m_scanState.scanPrologues = scanPrologues;
	m_scanState.scanStrings = scanStrings;
	m_scanState.startTime = std::chrono::steady_clock::now();
	m_scanState.targetStrings = targetStrings;
	m_scanState.status = "Initializing scan...";

	// Clear previous results (under lock)
	{
		std::lock_guard<std::mutex> lock(m_resultsMutex);
		m_mergedFunctions.clear();
		m_functionTags.clear();
	}

	LogInfo("Memory scan started with " + std::to_string(targetStrings.size()) + " target strings");

	// Drive the scan on a worker thread
	m_scanState.scanFuture = std::async(std::launch::async, [this]() {
		UpdateScanAsync();
		});
}

void MemoryScanner::StopScan()
{
	m_scanState.cancelled = true;
	m_scanState.running = false;

	// Signal the FunctionScanner to stop its internal loops
	if (m_scanner) {
		m_scanner->StopScan();
	}

	// Wait for the async task to finish (it should exit quickly now)
	if (m_scanState.scanFuture.valid()) {
		// Use wait_for with timeout to avoid indefinite blocking
		auto status = m_scanState.scanFuture.wait_for(std::chrono::seconds(2));
		if (status == std::future_status::timeout) {
			LogWarning("Scan stop timed out - scan thread may still be running");
		}
	}

	m_scanState.status = "Scan stopped by user";
	LogInfo("Memory scan cancelled");
}

void MemoryScanner::UpdateScanAsync()
{
	// Real implementation: delegate scanning to FunctionScanner
	if (!m_scanner) {
		m_scanState.status = "Scanner not initialized";
		m_scanState.running = false;
		return;
	}

	// For progress bar (coarse-grained)
	m_scanState.totalRegions.store(
		(m_scanState.scanPrologues ? 1 : 0) + (m_scanState.scanStrings ? 1 : 0),
		std::memory_order_relaxed);
	m_scanState.regionsProcessed.store(0, std::memory_order_relaxed);

	// Helper to safely add a result
	auto addResult = [this](uintptr_t addr, const std::string& tag) {
		std::lock_guard<std::mutex> lock(m_resultsMutex);
		// Check if already exists
		auto it = std::lower_bound(m_mergedFunctions.begin(), m_mergedFunctions.end(), addr);
		if (it == m_mergedFunctions.end() || *it != addr) {
			m_mergedFunctions.insert(it, addr);
		}
		m_functionTags[addr].push_back(tag);
	};

	try {
		if (m_scanState.scanPrologues && !m_scanState.cancelled) {
			m_scanState.status = "Scanning for prologues...";
			SapphireHook::FunctionScanner::ScanConfig cfg{};
			cfg.maxResults = 10000;

			// Use result callback to stream results as they're found
			m_scanner->ScanForAllInterestingFunctions(cfg, 
				[this](size_t processed, size_t total, const std::string&) {
					// Update status periodically
					if (processed % 0x10000 == 0) {
						std::lock_guard<std::mutex> lock(m_resultsMutex);
						m_scanState.status = "Prologue scan: " + std::to_string(processed * 100 / (std::max)(total, size_t(1))) + "% (" + std::to_string(m_mergedFunctions.size()) + " found)";
					}
				},
				[&addResult](uintptr_t addr) {
					// Stream each result as it's found
					addResult(addr, "prologue");
				});
			
			// Check cancellation before continuing
			if (m_scanState.cancelled) {
				m_scanState.running = false;
				return;
			}

			m_scanState.regionsProcessed.fetch_add(1, std::memory_order_relaxed);
		}

		// Check cancellation between phases
		if (m_scanState.cancelled) {
			m_scanState.running = false;
			return;
		}

		if (m_scanState.scanStrings && !m_scanState.cancelled) {
			m_scanState.status = "Scanning for string anchors...";
			
			// Build default anchors if empty
			std::vector<std::string> anchors = m_scanState.targetStrings;
			if (anchors.empty()) {
				anchors = {
					"Player","Actor","UI","Addon","Agent","Network","Packet","Ability","Render","Socket"
				};
			}

			// Scan with progress callback
			const auto stringHits = m_scanner->ScanMemoryForFunctionStrings(anchors);
			
			// Check cancellation before processing results
			if (m_scanState.cancelled) {
				m_scanState.running = false;
				return;
			}

			// Get module range for sanity checks
			uintptr_t base = 0; size_t imageSize = 0;
			(void)GetMainModuleInfo(base, imageSize);

			for (const auto& hit : stringHits) {
				if (m_scanState.cancelled) break;
				
				const uintptr_t fn = hit.nearbyFunctionAddress;
				if (!fn) continue;

				if (base != 0 && imageSize != 0) {
					if (fn < base || fn >= base + imageSize) continue;
				}

				addResult(fn, std::string("string:") + hit.foundString);
			}
			
			m_scanState.regionsProcessed.fetch_add(1, std::memory_order_relaxed);
		}

		if (!m_scanState.cancelled) {
			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - m_scanState.startTime).count();

			std::lock_guard<std::mutex> lock(m_resultsMutex);
			m_scanState.status = "Scan complete: " + std::to_string(m_mergedFunctions.size()) +
				" functions found in " + std::to_string(elapsed) + "ms";
		}
	}
	catch (const std::exception& e) {
		m_scanState.status = std::string("Scan error: ") + e.what();
		LogError(m_scanState.status);
	}
	catch (...) {
		m_scanState.status = "Scan error: unknown exception";
		LogError(m_scanState.status);
	}

	m_scanState.running = false;
}

void MemoryScanner::RebuildAnchorStringMatches()
{
	if (!m_scanner) return;

	// Build default anchors if empty
	std::vector<std::string> anchors = m_scanState.targetStrings;
	if (anchors.empty()) {
		anchors = {
			"Player","Actor","UI","Addon","Agent","Network","Packet","Ability","Render","Socket"
		};
	}

	// Scan memory for function-related strings
	const auto stringHits = m_scanner->ScanMemoryForFunctionStrings(anchors);

	// Get module range for sanity checks
	uintptr_t base = 0; size_t imageSize = 0;
	(void)GetMainModuleInfo(base, imageSize);

	std::unordered_set<uintptr_t> unique;
	unique.reserve(stringHits.size());

	size_t rawHits = 0;
	for (const auto& hit : stringHits) {
		rawHits++;
		const uintptr_t fn = hit.nearbyFunctionAddress;
		if (!fn) continue;

		if (base != 0 && imageSize != 0) {
			if (fn < base || fn >= base + imageSize) continue;
		}

		unique.insert(fn);
		// Tag this function with the matched string value
		m_functionTags[fn].push_back(std::string("string:") + hit.foundString);
	}

	// Merge into results
	for (auto addr : unique) {
		m_mergedFunctions.push_back(addr);
	}

	LogInfo("String scan complete: " + std::to_string(rawHits) +
		" raw hits; " + std::to_string(unique.size()) + " functions associated");
}

void MemoryScanner::RenderScanResults()
{
	// Take a snapshot of results under lock for thread safety
	std::vector<uintptr_t> resultsCopy;
	std::unordered_map<uintptr_t, std::vector<std::string>> tagsCopy;
	{
		std::lock_guard<std::mutex> lock(m_resultsMutex);
		resultsCopy = m_mergedFunctions;
		tagsCopy = m_functionTags;
	}

	ImGui::Text("Results: %zu functions discovered", resultsCopy.size());

	if (!resultsCopy.empty()) {
		if (ImGui::BeginTable("ScanResults", 3,
			ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
		{
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
			ImGui::TableSetupColumn("Tags", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 100.0f);
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableHeadersRow();

			for (const auto& addr : resultsCopy) {
				ImGui::TableNextRow();

				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%016llX", static_cast<unsigned long long>(addr));

				ImGui::TableSetColumnIndex(1);
				auto it = tagsCopy.find(addr);
				if (it != tagsCopy.end()) {
					std::string tags;
					tags.reserve(64);
					for (const auto& tag : it->second) {
						if (!tags.empty()) tags += ", ";
						tags += tag;
					}
					ImGui::Text("%s", tags.c_str());
				}

				ImGui::TableSetColumnIndex(2);
				ImGui::PushID(static_cast<int>(addr));
				if (ImGui::SmallButton("Analyze")) {
					SelectFunctionForAnalysis(addr);
				}
				ImGui::PopID();
			}

			ImGui::EndTable();
		}
	}
}

void MemoryScanner::RenderAnalysisPanel()
{
	ImGui::Text("Analysis for 0x%016llX", static_cast<unsigned long long>(m_selectedFunction));

	// Use remaining height for content (leave space for buttons)
	float availHeight = ImGui::GetContentRegionAvail().y - 30.0f;
	if (ImGui::BeginChild("AnalysisContent", ImVec2(0, availHeight), true)) {
		if (m_selectedAnalysis.empty()) {
			m_selectedAnalysis = GenerateFunctionAnalysis(m_selectedFunction);
		}
		ImGui::TextUnformatted(m_selectedAnalysis.c_str());
	}
	ImGui::EndChild();

	if (ImGui::Button("Export Analysis")) {
		std::string filename = "analysis_" +
			std::to_string(m_selectedFunction) + ".txt";
		if (ExportAnalysis(filename, m_selectedAnalysis)) {
			LogInfo("Analysis exported to " + filename);
		}
	}

	ImGui::SameLine();
	if (ImGui::Button("Copy to Clipboard")) {
		ImGui::SetClipboardText(m_selectedAnalysis.c_str());
	}
}

void SapphireHook::MemoryScanner::Initialize()
{
	LogInfo("MemoryScanner initialized");
	if (!m_scanner) {
		m_scanner = std::make_shared<SapphireHook::FunctionScanner>();
	}
}

void SapphireHook::MemoryScanner::RenderMenu()
{
	if (ImGui::MenuItem(GetDisplayName(), nullptr, m_windowOpen))
		m_windowOpen = !m_windowOpen;
}

void SapphireHook::MemoryScanner::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGui::SetNextWindowSize(ImVec2(1000, 700), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin(GetDisplayName(), &m_windowOpen)) {
		ImGui::End();
		return;
	}

	// Scan controls
	static bool scanPrologues = true;
	static bool scanStrings = true;
	static char targets[512] = "";

	ImGui::Text("Scan Options:");
	ImGui::Checkbox("Scan function prologues", &scanPrologues);
	ImGui::SameLine();
	ImGui::Checkbox("Scan string anchors", &scanStrings);

	ImGui::InputTextWithHint("##targets", "comma-separated strings (leave empty for all)",
		targets, sizeof(targets));

	ImGui::SameLine();
	if (ImGui::Button("Start Scan") && !m_scanState.running) {
		std::vector<std::string> list;
		if (targets[0] != '\0') {
			std::string s(targets);
			size_t p = 0;
			while (true) {
				size_t q = s.find(',', p);
				std::string t = s.substr(p, q == std::string::npos ? q : q - p);
				// trim
				size_t b = t.find_first_not_of(" \t");
				size_t e = t.find_last_not_of(" \t");
				if (b != std::string::npos) {
					list.emplace_back(t.substr(b, e - b + 1));
				}
				if (q == std::string::npos) break;
				p = q + 1;
			}
		}
		StartScan(list, scanPrologues, scanStrings);
	}

	ImGui::SameLine();
	if (ImGui::Button("Stop") && m_scanState.running) {
		StopScan();
	}

	// Progress bar with spinner if scanning
	if (m_scanState.running) {
		// Show animated spinner while scanning
		ImGui::SameLine();
		ImSpinner::SpinnerRotatingHeart("scanning", 16.0f, 3.0f, 
			ImGui::GetColorU32(ImGuiCol_Text), ImGui::GetColorU32(ImGuiCol_TextDisabled), 6.0f);
		
		float progress = (m_scanState.totalRegions > 0)
			? static_cast<float>(m_scanState.regionsProcessed) / m_scanState.totalRegions
			: 0.0f;
		ImGui::ProgressBar(progress, ImVec2(-1, 0), m_scanState.status.c_str());
	}
	else if (!m_scanState.status.empty()) {
		ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "%s", m_scanState.status.c_str());
	}

	ImGui::Separator();

	// Side-by-side layout: results on left, analysis on right
	float availWidth = ImGui::GetContentRegionAvail().x;
	float leftWidth = (m_selectedFunction != 0) ? availWidth * 0.55f : availWidth;
	float rightWidth = availWidth - leftWidth - 10.0f; // 10px gap

	// Left panel: Results
	if (ImGui::BeginChild("ResultsPanel", ImVec2(leftWidth, 0), false)) {
		RenderScanResults();
	}
	ImGui::EndChild();

	// Right panel: Analysis (only if a function is selected)
	if (m_selectedFunction != 0) {
		ImGui::SameLine(0, 10.0f);
		if (ImGui::BeginChild("AnalysisPanelContainer", ImVec2(rightWidth, 0), true)) {
			RenderAnalysisPanel();
		}
		ImGui::EndChild();
	}

	ImGui::End();
}

std::vector<uintptr_t> MemoryScanner::GetDiscoveredFunctions() const
{
	std::lock_guard<std::mutex> lock(m_resultsMutex);
	return m_mergedFunctions;
}

std::unordered_map<uintptr_t, std::vector<std::string>> MemoryScanner::GetFunctionTags() const
{
	std::lock_guard<std::mutex> lock(m_resultsMutex);
	return m_functionTags;
}

std::string MemoryScanner::GenerateFunctionAnalysis(uintptr_t address) const
{
	std::stringstream ss;
	ss << "Function Analysis Report\n";
	ss << "========================\n\n";
	ss << "Address: 0x" << std::hex << std::setw(16) << std::setfill('0') << address << "\n";

	// Tags (thread-safe access)
	{
		std::lock_guard<std::mutex> lock(m_resultsMutex);
		auto it = m_functionTags.find(address);
		if (it != m_functionTags.end()) {
			ss << "Tags: ";
			for (const auto& tag : it->second) {
				ss << tag << " ";
			}
			ss << "\n";
		}
	}

	ss << "\nPrologue Bytes:\n";
	ss << GetPrologueBytes(address, 16) << "\n";

	ss << "\nDisassembly:\n";
	std::string disasm;
	if (DisassembleSnippet(address, disasm, 10, 64)) {
		ss << disasm;
	}
	else {
		ss << "(Unable to disassemble)\n";
	}

	return ss.str();
}

void MemoryScanner::SelectFunctionForAnalysis(uintptr_t address)
{
	m_selectedFunction = address;
	m_selectedAnalysis = GenerateFunctionAnalysis(address);
}

bool MemoryScanner::ExportAnalysis(const std::string& filename, const std::string& content)
{
	std::ofstream file(filename);
	if (file.is_open()) {
		file << content;
		file.close();
		return true;
	}
	return false;
}

std::string MemoryScanner::BuildMultiDiffText(const std::vector<uintptr_t>& addrs)
{
	if (addrs.empty()) return "No addresses provided";

	std::stringstream ss;
	ss << "Multi-Function Comparison\n";
	ss << "==========================\n\n";

	for (const auto& addr : addrs) {
		ss << "Function at 0x" << std::hex << addr << ":\n";
		ss << GetPrologueBytes(addr, 32) << "\n\n";
	}

	return ss.str();
}

std::string MemoryScanner::GetPrologueBytes(uintptr_t address, size_t maxLen) const
{
	std::stringstream ss;

	if (!IsSafeToRead(reinterpret_cast<void*>(address), maxLen)) {
		return "(Invalid memory address)";
	}

	const uint8_t* bytes = reinterpret_cast<const uint8_t*>(address);
	for (size_t i = 0; i < maxLen; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0')
			<< static_cast<int>(bytes[i]) << " ";
		if ((i + 1) % 16 == 0) ss << "\n";
	}

	return ss.str();
}

bool MemoryScanner::DisassembleSnippet(uintptr_t address, std::string& out, int maxInstr, size_t maxBytes) const
{
	if (!IsSafeToRead(reinterpret_cast<void*>(address), maxBytes)) {
		out = "(Invalid memory address)";
		return false;
	}

	// Use CapstoneWrapper for actual disassembly
	CapstoneWrapper cs;
	if (!cs.valid()) {
		// Fallback to raw bytes if capstone failed to init
		std::stringstream ss;
		ss << "(Capstone init failed)\nBytes: ";
		ss << GetPrologueBytes(address, (std::min)(maxBytes, size_t(32)));
		out = ss.str();
		return false;
	}

	const uint8_t* code = reinterpret_cast<const uint8_t*>(address);
	auto result = cs.DisassembleBuffer(code, maxBytes, address, static_cast<size_t>(maxInstr));

	if (!result.ok()) {
		std::stringstream ss;
		ss << "(Disassembly failed: " << CapstoneErrorToString(result.error()) << ")\nBytes: ";
		ss << GetPrologueBytes(address, (std::min)(maxBytes, size_t(32)));
		out = ss.str();
		return false;
	}

	std::stringstream ss;
	for (const auto& insn : result.value()) {
		ss << std::hex << std::setw(16) << std::setfill('0') << insn.address << "  ";
		// Print bytes
		for (size_t i = 0; i < insn.size; ++i) {
			ss << std::setw(2) << static_cast<int>(insn.bytes[i]) << " ";
		}
		// Pad to align mnemonics (max 16 bytes * 3 chars = 48)
		for (size_t i = insn.size; i < 8; ++i) {
			ss << "   ";
		}
		ss << " " << insn.mnemonic << " " << insn.operands << "\n";
	}

	out = ss.str();
	return true;
}

bool MemoryScanner::IsSafeToRead(void* address, size_t size) const
{
	MEMORY_BASIC_INFORMATION mbi = {};
	if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
		return false;
	}

	if (mbi.State != MEM_COMMIT) {
		return false;
	}

	if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
		return false;
	}

	// Basic range check against region size
	auto regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	auto addr = reinterpret_cast<uintptr_t>(address);
	return (addr + size) <= regionEnd;
}