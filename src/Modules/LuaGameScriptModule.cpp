#include "LuaGameScriptModule.h"
#include <iomanip>
#include <sstream>
#include <fstream>

#include "../vendor/imgui/imgui.h"
#include "../Logger/Logger.h"

namespace SapphireHook {
	// Helper: convert path to UTF-8 std::string from u8string()
	static std::string ToUtf8(const std::filesystem::path& p) {
		auto u8 = p.u8string();                // std::u8string
		return std::string(u8.begin(), u8.end()); // byte-wise copy
	}

	// Helper: escape quotes for CSV
	static std::string CsvEscape(const std::string& s) {
		bool needQuote = s.find_first_of(",\"\n\r") != std::string::npos;
		std::string out;
		if (needQuote) {
			out.reserve(s.size() + 2);
			out.push_back('"');
			for (char c : s) {
				if (c == '"') out += "\"\"";
				else out.push_back(c);
			}
			out.push_back('"');
			return out;
		}
		return s;
	}

	void LuaGameScriptModule::RenderMenu() {
		if (ImGui::MenuItem(GetDisplayName(), nullptr, m_open))
			m_open = !m_open;
	}

	void LuaGameScriptModule::StartScan(const std::filesystem::path& root) {
		Cancel();
		m_root = root;
		m_status = "Scanning...";
		m_running.store(true);
		m_cancel.store(false);

		m_task = std::async(std::launch::async, [this]() {
			if (m_cancel.load()) return std::optional<LuaScanSummary>{};
			return ScanGameScriptPacks(m_root, m_maxEntries, m_probeBytes);
			});
	}

	void LuaGameScriptModule::Cancel() {
		m_cancel.store(true);
		if (m_task.valid()) {
			try { m_task.wait(); }
			catch (...) {}
		}
		m_running.store(false);
	}

	void LuaGameScriptModule::Finalize() {
		if (!m_task.valid()) return;
		auto opt = m_task.get();
		if (opt) {
			m_results = *opt;
			m_status = "Done: hits=" + std::to_string(m_results.hits.size());
		}
		else {
			m_status = "Cancelled / failed";
		}
		m_running.store(false);
	}

	void LuaGameScriptModule::RenderWindow() {
		if (!m_open) return;
		ImGui::SetNextWindowSize(ImVec2(950, 600), ImGuiCond_FirstUseEver);
		if (!ImGui::Begin(GetDisplayName(), &m_open)) {
			ImGui::End();
			return;
		}

		static char rootBuf[512] = { 0 };
		ImGui::InputText("SqPack Root", rootBuf, sizeof(rootBuf));
		ImGui::SetItemTooltip("Directory containing 'ffxiv' (and possibly ex* folders)");

		ImGui::SliderInt("Max entries / index", reinterpret_cast<int*>(&m_maxEntries), 1000, 50000);
		ImGui::SliderInt("Probe bytes", reinterpret_cast<int*>(&m_probeBytes), 0x400, 0x8000);

		if (!m_running.load()) {
			if (ImGui::Button("Scan")) {
				std::filesystem::path p(rootBuf);
				if (!p.empty())
					StartScan(p);
				else
					m_status = "Root path empty";
			}
			ImGui::SameLine();
			if (!m_results.hits.empty()) {
				if (ImGui::Button("Export CSV")) {
					std::filesystem::path out = std::filesystem::temp_directory_path() / "lua_gamescript_hits.csv";
					std::ofstream ofs(out, std::ios::out | std::ios::trunc);
					if (ofs.is_open()) {
						ofs << "LuaPath,IndexPath,DatPath,Hash,DatId,Offset,Type\n";
						for (auto& h : m_results.hits) {
							std::string luaPath = CsvEscape(h.displayPath);
							std::string indexFile = CsvEscape(ToUtf8(h.indexPath));
							std::string datFile = CsvEscape(ToUtf8(h.datPath));
							std::ostringstream hexHash, hexOff;
							hexHash << "0x" << std::hex << std::uppercase << h.indexHash;
							hexOff << "0x" << std::hex << std::uppercase << h.fileOffset;

							ofs << luaPath << ','
								<< indexFile << ','
								<< datFile << ','
								<< hexHash.str() << ','
								<< h.dataFileId << ','
								<< hexOff.str() << ','
								<< (h.bytecode ? "bytecode" : (h.looksSource ? "source?" : "?"))
								<< '\n';
						}
						ofs.close();
						LogInfo("LuaGameScript export: " + out.string());
					}
					else {
						LogError("Failed to open export file");
					}
				}
			}
		}
		else {
			ImGui::TextDisabled("%s", m_status.c_str());
			ImGui::SameLine();
			if (ImGui::Button("Cancel")) Cancel();
			if (m_task.valid() && m_task.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
				Finalize();
		}

		ImGui::Separator();
		ImGui::Text("Status: %s", m_status.c_str());
		ImGui::Text("Indexes scanned: %zu | Entries scanned: %zu | Hits: %zu",
			m_results.indexesScanned, m_results.entriesScanned, m_results.hits.size());

		ImGui::Separator();
		if (!m_results.hits.empty()) {
			if (ImGui::BeginTable("lua_hits", 7,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
				ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.f);
				ImGui::TableSetupColumn("DatId", ImGuiTableColumnFlags_WidthFixed, 50.f);
				ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 120.f);
				ImGui::TableSetupColumn("Hash", ImGuiTableColumnFlags_WidthFixed, 140.f);
				ImGui::TableSetupColumn("LuaPath", ImGuiTableColumnFlags_WidthStretch);
				ImGui::TableSetupColumn("DatPath", ImGuiTableColumnFlags_WidthStretch);
				ImGui::TableSetupColumn("IndexFile", ImGuiTableColumnFlags_WidthStretch);
				ImGui::TableHeadersRow();

				const size_t maxShow = std::min<size_t>(m_results.hits.size(), 5000);
				for (size_t i = 0; i < maxShow; ++i) {
					const auto& h = m_results.hits[i];
					ImGui::TableNextRow();
					ImGui::TableSetColumnIndex(0);
					ImGui::TextUnformatted(h.bytecode ? "bytecode" : (h.looksSource ? "source?" : "?"));
					ImGui::TableSetColumnIndex(1);
					ImGui::Text("%u", h.dataFileId);
					ImGui::TableSetColumnIndex(2);
					ImGui::Text("0x%llX", static_cast<unsigned long long>(h.fileOffset));
					ImGui::TableSetColumnIndex(3);
					ImGui::Text("0x%llX", static_cast<unsigned long long>(h.indexHash));
					ImGui::TableSetColumnIndex(4);
					ImGui::TextWrapped("%s", h.displayPath.c_str());
					ImGui::TableSetColumnIndex(5);
					std::string datUtf8 = ToUtf8(h.datPath);
					ImGui::TextWrapped("%s", datUtf8.c_str());
					ImGui::TableSetColumnIndex(6);
					std::string idxUtf8 = ToUtf8(h.indexPath);
					ImGui::TextWrapped("%s", idxUtf8.c_str());
				}
				ImGui::EndTable();
			}
		}

		ImGui::End();
	}
} // namespace SapphireHook