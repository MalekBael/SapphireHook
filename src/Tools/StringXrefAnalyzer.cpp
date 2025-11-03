#include "../Tools/StringXrefAnalyzer.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <future>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>

// Windows + psapi for module/sections
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

// Scanners
#include "../Analysis/FunctionScanner.h"
#include "../Analysis/PatternScanner.h"

using namespace SapphireHook;

namespace {
	// Load .rdata section range
	static bool GetSectionRange(HMODULE mod, const char* name, uint8_t*& begin, size_t& size) {
		auto base = reinterpret_cast<uint8_t*>(mod);
		auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
		auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
		auto sec = IMAGE_FIRST_SECTION(nt);
		for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
			if (std::memcmp(sec->Name, name, (std::min)(static_cast<size_t>(std::strlen(name)), size_t(8))) == 0) {
				begin = base + sec->VirtualAddress;
				size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
				return true;
			}
		}
		return false;
	}

	static void CollectAsciiStrings(uint8_t* rdata, size_t rdataSize, size_t minLen, size_t limit,
		std::vector<std::pair<uintptr_t, std::string>>& out) {
		out.reserve((std::min)(limit, size_t(20000)));
		std::string cur;
		for (size_t i = 0; i < rdataSize; ++i) {
			unsigned char c = rdata[i];
			if (c >= 32 && c <= 126) {
				cur.push_back(static_cast<char>(c));
			}
			else {
				if (cur.size() >= minLen) {
					uintptr_t addr = reinterpret_cast<uintptr_t>(rdata + i - cur.size());
					out.emplace_back(addr, cur);
					if (out.size() >= limit) return;
				}
				cur.clear();
			}
		}
		if (cur.size() >= minLen && out.size() < limit) {
			uintptr_t addr = reinterpret_cast<uintptr_t>(rdata + rdataSize - cur.size());
			out.emplace_back(addr, cur);
		}
	}

	static void CollectUtf16Strings(uint8_t* rdata, size_t rdataSize, size_t minLen, size_t limit,
		std::vector<std::pair<uintptr_t, std::string>>& out) {
		size_t added = 0;
		std::string cur;
		size_t i = 0;
		while (i + 1 < rdataSize && added < limit) {
			uint8_t lo = rdata[i];
			uint8_t hi = rdata[i + 1];
			if (hi == 0 && lo >= 32 && lo <= 126) {
				cur.push_back(static_cast<char>(lo));
				i += 2;
			}
			else {
				if (cur.size() >= minLen) {
					uintptr_t addr = reinterpret_cast<uintptr_t>(rdata + i - cur.size() * 2);
					out.emplace_back(addr, cur);
					++added;
				}
				cur.clear();
				i += 2;
			}
		}
		if (cur.size() >= minLen && added < limit) {
			uintptr_t addr = reinterpret_cast<uintptr_t>(rdata + i - cur.size() * 2);
			out.emplace_back(addr, cur);
		}
	}
} // anonymous

StringXrefAnalyzer::StringXrefAnalyzer() = default;
StringXrefAnalyzer::~StringXrefAnalyzer()
{
	CancelAnalysis();
}

void StringXrefAnalyzer::Initialize()
{
	LogInfo("StringXrefAnalyzer initialized");
}

void StringXrefAnalyzer::RenderMenu()
{
	if (ImGui::MenuItem(GetDisplayName(), nullptr, m_windowOpen))
		m_windowOpen = !m_windowOpen;
}

void StringXrefAnalyzer::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin(GetDisplayName(), &m_windowOpen)) {
		ImGui::End();
		return;
	}

	// Controls
	ImGui::Text("String → Function XREF analysis");
	ImGui::Separator();

	ImGui::SetNextItemWidth(120);
	ImGui::InputInt("Min string length", &m_state.minLen);
	if (m_state.minLen < 3) m_state.minLen = 3;

	ImGui::SameLine();
	ImGui::SetNextItemWidth(200);
	int maxPerFn = static_cast<int>(m_state.maxStringsPerFn);
	if (ImGui::InputInt("Max strings per function", &maxPerFn)) {
		if (maxPerFn < 1) maxPerFn = 1;
		if (maxPerFn > 16) maxPerFn = 16;
		m_state.maxStringsPerFn = static_cast<size_t>(maxPerFn);
	}

	if (!m_state.running) {
		if (ImGui::Button("Start Analysis")) {
			StartAnalysis(m_state.minLen, m_state.maxStringsPerFn);
		}
		ImGui::SameLine();
		if (!m_state.rows.empty()) {
			if (ImGui::Button("Export Results (.txt)")) {
				std::string path;
				if (ExportResultsToText(path)) {
					LogInfo(std::string("String XREF results exported to: ") + path);
				}
				else {
					LogError("Failed to export String XREF results");
				}
			}
		}
	}
	else {
		if (ImGui::Button("Cancel")) {
			CancelAnalysis();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("%s", m_state.status.c_str());
	}

	if (m_state.running) {
		float frac = (m_state.mapTotal > 0)
			? static_cast<float>(m_state.mapProcessed.load(std::memory_order_relaxed)) / static_cast<float>(m_state.mapTotal)
			: 0.0f;
		ImGui::ProgressBar(frac, ImVec2(-1, 0), m_state.status.c_str());
	}
	else if (!m_state.status.empty()) {
		ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "%s", m_state.status.c_str());
	}

	ImGui::Separator();
	ImGui::Text("ASCII strings: %zu | UTF-16 strings: %zu | Functions: %zu",
		m_state.totalAscii, m_state.totalUtf16, m_state.rows.size());

	// Results table
	if (!m_state.rows.empty()) {
		if (ImGui::BeginTable("xref_rows", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
			ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.f);
			ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Strings", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableHeadersRow();

			for (const auto& r : m_state.rows) {
				ImGui::TableNextRow();

				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%016llX", static_cast<unsigned long long>(r.addr));

				ImGui::TableSetColumnIndex(1);
				ImGui::TextUnformatted(r.name.c_str());

				ImGui::TableSetColumnIndex(2);
				std::string joined;
				for (size_t i = 0; i < r.strings.size(); ++i) {
					if (i) joined += " | ";
					joined += r.strings[i];
				}
				ImGui::TextWrapped("%s", joined.c_str());
			}

			ImGui::EndTable();
		}
	}

	ImGui::End();
}

void StringXrefAnalyzer::StartAnalysis(int minStringLength, size_t maxStringsPerFunc)
{
	CancelAnalysis();
	m_state.running = true;
	m_state.minLen = std::max(3, minStringLength);
	m_state.maxStringsPerFn = std::max<size_t>(1, maxStringsPerFunc);
	m_state.totalAscii = 0;
	m_state.totalUtf16 = 0;
	m_state.rows.clear();
	m_state.interimMap.clear(); // NEW: reset interim accumulation
	m_state.status = "Preparing...";
	m_state.cancel.store(false, std::memory_order_relaxed);
	m_state.started = std::chrono::steady_clock::now();
	m_state.mapProcessed.store(0, std::memory_order_relaxed);
	m_state.mapTotal = 0;

	m_state.task = std::async(std::launch::async, [this]() {
		HMODULE mod = ::GetModuleHandleW(nullptr);
		if (!mod) { m_state.status = "Failed: no module"; m_state.running = false; return; }

		uint8_t* rdata = nullptr; size_t rdataSize = 0;
		if (!GetSectionRange(mod, ".rdata", rdata, rdataSize) || !rdata || rdataSize < 1024) {
			m_state.status = "Failed: .rdata not found"; m_state.running = false; return;
		}

		m_state.status = "Collecting strings...";
		const size_t asciiLimit = 25000;
		const size_t utf16Limit = 8000;

		std::vector<std::pair<uintptr_t, std::string>> asciiStrings;
		std::vector<std::pair<uintptr_t, std::string>> utf16Strings;

		CollectAsciiStrings(rdata, rdataSize, static_cast<size_t>(m_state.minLen), asciiLimit, asciiStrings);
		CollectUtf16Strings(rdata, rdataSize, static_cast<size_t>(m_state.minLen), utf16Limit, utf16Strings);
		m_state.totalAscii = asciiStrings.size();
		m_state.totalUtf16 = utf16Strings.size();

		m_state.mapTotal = m_state.totalAscii + m_state.totalUtf16;
		m_state.mapProcessed.store(0, std::memory_order_relaxed);

		m_state.status = "Mapping string references...";

		auto scanner = std::make_shared<SapphireHook::FunctionScanner>();
		auto mapBatch = [&](const std::vector<std::pair<uintptr_t, std::string>>& list) {
			for (const auto& kv : list) {
				if (m_state.cancel.load(std::memory_order_relaxed)) return;

				const uintptr_t saddr = kv.first;
				const std::string& s = kv.second;

				auto refs = SapphireHook::PatternScanner::FindRipReferencesTo(mod, saddr);
				if (!refs.empty()) {
					size_t refCap = 4;
					size_t taken = 0;
					for (auto ref : refs) {
						if (taken >= refCap) break;
						uintptr_t fn = scanner->FindFunctionStart(ref);
						if (!fn) continue;

						auto& vec = m_state.interimMap[fn]; // NEW: accumulate partials
						if (std::find(vec.begin(), vec.end(), s) == vec.end()) {
							vec.push_back(s);
							++taken;
						}
					}
				}

				// Progress update
				m_state.mapProcessed.fetch_add(1, std::memory_order_relaxed);
				if ((m_state.mapProcessed.load(std::memory_order_relaxed) & 0x3FF) == 0) {
					size_t done = m_state.mapProcessed.load(std::memory_order_relaxed);
					size_t total = m_state.mapTotal;
					m_state.status = "Mapping string references... " + std::to_string(done) + "/" + std::to_string(total);
				}
			}
			};

		mapBatch(asciiStrings);
		if (!m_state.cancel.load(std::memory_order_relaxed))
			mapBatch(utf16Strings);

		// Build rows from whatever we have (complete or partial)
		auto finalizeRows = [this]() {
			m_state.rows.clear();
			m_state.rows.reserve(m_state.interimMap.size());
			for (auto& [fn, strs] : m_state.interimMap) {
				if (strs.size() > m_state.maxStringsPerFn)
					strs.resize(m_state.maxStringsPerFn);
				XrefRow r;
				r.addr = fn;
				r.name = "";
				r.strings = std::move(strs);
				m_state.rows.emplace_back(std::move(r));
			}
			std::sort(m_state.rows.begin(), m_state.rows.end(),
				[](const auto& a, const auto& b) { return a.strings.size() > b.strings.size(); });
			};

		if (m_state.cancel.load(std::memory_order_relaxed)) {
			finalizeRows(); // NEW: produce partial results on cancel
			const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - m_state.started).count();
			m_state.status = "Cancelled (" + std::to_string(m_state.rows.size()) + " funcs) in " + std::to_string(ms) + "ms";
			m_state.running = false;
			return;
		}

		finalizeRows(); // normal completion
		const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - m_state.started).count();
		m_state.status = "Done in " + std::to_string(ms) + "ms";
		m_state.running = false;
		});
}

void StringXrefAnalyzer::CancelAnalysis()
{
	m_state.cancel.store(true, std::memory_order_relaxed);
	if (m_state.task.valid()) {
		try { m_state.task.wait(); }
		catch (...) {}
	}
	// Do not clear results on cancel; they were finalized (partial) in the worker if any
	if (!m_state.running && !m_state.rows.empty() && m_state.status.rfind("Cancelled", 0) != 0) {
		m_state.status = "Cancelled (" + std::to_string(m_state.rows.size()) + " funcs)";
	}
	m_state.running = false;
}

std::vector<StringXrefAnalyzer::XrefRow> StringXrefAnalyzer::GetResults() const
{
	return m_state.rows;
}

bool StringXrefAnalyzer::ExportResultsToText(std::string& outPath) const
{
	using SapphireHook::Logger;

	if (m_state.rows.empty()) return false;

	// Build a filename in the SapphireHook temp directory
	std::filesystem::path baseDir = Logger::GetDefaultTempDir();
	std::error_code ec;
	std::filesystem::create_directories(baseDir, ec);

	const auto now = std::chrono::system_clock::now();
	const auto tt = std::chrono::system_clock::to_time_t(now);
	std::tm tm{};
#if defined(_WIN32)
	localtime_s(&tm, &tt);
#else
	tm = *std::localtime(&tt);
#endif
	std::ostringstream name;
	name << "xref_results." << std::put_time(&tm, "%Y%m%d.%H%M%S") << ".txt";

	std::filesystem::path out = baseDir / name.str();

	std::ofstream ofs(out, std::ios::out | std::ios::trunc);
	if (!ofs.is_open()) {
		LogError(std::string("Export failed: could not open file: ") + out.string());
		return false;
	}

	ofs << "String XREF Results\n";
	ofs << "====================\n\n";
	ofs << "Functions: " << m_state.rows.size()
		<< " | ASCII strings: " << m_state.totalAscii
		<< " | UTF-16 strings: " << m_state.totalUtf16 << "\n\n";

	for (const auto& r : m_state.rows) {
		ofs << "0x" << std::hex << std::setw(16) << std::setfill('0')
			<< static_cast<unsigned long long>(r.addr) << std::dec << "  ";
		ofs << (r.name.empty() ? "(unnamed)" : r.name) << "\n";
		for (const auto& s : r.strings) {
			ofs << "  - " << s << "\n";
		}
		ofs << "\n";
	}
	ofs.flush();
	ofs.close();

	outPath = out.string();
	return true;
}