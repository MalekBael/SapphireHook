#include "Weather.h"
#include "CommandInterface.h"
#include "../Core/PacketInjector.h"
#include "../vendor/imgui/imgui.h"
#include "../Logger/Logger.h"
#include <string>
#include <algorithm>
#include <cstdint>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>

using SapphireHook::LogInfo;

struct WeatherEntry {
	uint32_t id;       // GM weather id (Arg0 to 0x0006)
	const char* name;  // Display name
	const char* desc;  // Short description (tooltip)
};

// Full list from docs/Weather.csv (duplicates preserved; IDs are authoritative)
static constexpr WeatherEntry kWeatherMap[] = {
	{  1, "Clear Skies",       "clear" },
	{  2, "Fair Skies",        "fair" },
	{  3, "Clouds",            "overcast" },
	{  4, "Fog",               "foggy" },
	{  5, "Wind",              "windy" },
	{  6, "Gales",             "gusty" },
	{  7, "Rain",              "rainy" },
	{  8, "Showers",           "showery" },
	{  9, "Thunder",           "thundery" },
	{ 10, "Thunderstorms",     "experiencing thunderstorms" },
	{ 11, "Dust Storms",       "dusty" },
	{ 12, "Sandstorms",        "sandy" },
	{ 13, "Hot Spells",        "hot" },
	{ 14, "Heat Waves",        "blistering" },
	{ 15, "Snow",              "snowy" },
	{ 16, "Blizzards",         "blizzardy" },
	{ 17, "Gloom",             "gloomy" },
	{ 18, "Auroras",           "experiencing auroral activity" },
	{ 19, "Darkness",          "dark" },
	{ 20, "Tension",           "crackling with tension" },
	{ 21, "Clouds",            "overcast" },
	{ 22, "Storm Clouds",      "threatened by rain" },
	{ 23, "Rough Seas",        "experiencing rough seas" },
	{ 24, "Rough Seas",        "experiencing rough seas" },
	{ 25, "Louring",           "loury" },
	{ 26, "Heat Waves",        "blistering" },
	{ 27, "Gloom",             "gloomy" },
	{ 28, "Gales",             "gusty" },
	{ 29, "Eruptions",         "erupting" },
	{ 30, "Fair Skies",        "fair" },
	{ 31, "Fair Skies",        "fair" },
	{ 32, "Fair Skies",        "fair" },
	{ 33, "Fair Skies",        "fair" },
	{ 34, "Fair Skies",        "fair" },
	{ 35, "Irradiance",        "irradiant" },
	{ 36, "Core Radiation",    "radioactive" },
	{ 37, "Core Radiation",    "radioactive" },
	{ 38, "Core Radiation",    "radioactive" },
	{ 39, "Core Radiation",    "radioactive" },
	{ 40, "Shelf Clouds",      "unnaturally cloudy" },
	{ 41, "Shelf Clouds",      "unnaturally cloudy" },
	{ 42, "Shelf Clouds",      "unnaturally cloudy" },
	{ 43, "Shelf Clouds",      "unnaturally cloudy" },
	{ 44, "Oppression",        "oppressive" },
	{ 45, "Oppression",        "oppressive" },
	{ 46, "Oppression",        "oppressive" },
	{ 47, "Oppression",        "oppressive" },
	{ 48, "Oppression",        "oppressive" },
	{ 49, "Umbral Wind",       "experiencing umbral wind" },
	{ 50, "Umbral Static",     "experiencing umbral static" },
	{ 51, "Smoke",             "smoky" },
	{ 52, "Fair Skies",        "fair" },
	{ 53, "Royal Levin",       "experiencing royal levin" },
	{ 54, "Hyperelectricity",  "hyperelectric" },
	{ 55, "Royal Levin",       "experiencing royal levin" },
	{ 56, "Oppression",        "oppressive" },
	{ 57, "Thunder",           "thundery" },
	{ 58, "Thunder",           "thundery" },
	{ 59, "CutScene",          "CutScenery" },
	{ 60, "Multiplicity",      "experiencing multiplicity" },
	{ 61, "Multiplicity",      "experiencing multiplicity" },
	{ 62, "Rain",              "rainy" },
	{ 63, "Fair Skies",        "fair" },
	{ 64, "Rain",              "rainy" },
	{ 65, "Fair Skies",        "fair" },
	{ 66, "Dragonstorm",       "unnaturally stormy" },
	{ 67, "Dragonstorm",       "unnaturally stormy" },
	{ 68, "Fair Skies",        "fair" },
};
static constexpr int kWeatherCount = static_cast<int>(sizeof(kWeatherMap) / sizeof(kWeatherMap[0]));

// ---------- Simple persistence helpers (ini) ----------
namespace {
	const char* SettingsFile() { return "sapphirehook_settings.ini"; }

	std::string Trim(std::string s) {
		auto issp = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
		while (!s.empty() && issp((unsigned char)s.back())) s.pop_back();
		size_t i = 0; while (i < s.size() && issp((unsigned char)s[i])) ++i;
		if (i) s.erase(0, i);
		return s;
	}

	std::vector<uint32_t> g_favorites; // persisted as comma-separated list of ids

	void LoadFavoritesFromConfig() {
		std::ifstream f(SettingsFile(), std::ios::in);
		if (!f.is_open()) return;

		std::string line;
		while (std::getline(f, line)) {
			if (line.empty() || line[0] == '#' || line[0] == ';') continue;
			size_t eq = line.find('=');
			if (eq == std::string::npos) continue;
			std::string key = Trim(line.substr(0, eq));
			std::string val = Trim(line.substr(eq + 1));
			std::string lowerKey = key;
			for (auto& c : lowerKey) c = (char)tolower((unsigned char)c);
			if (lowerKey == "weatherfavorites") {
				g_favorites.clear();
				std::stringstream ss(val);
				std::string tok;
				while (std::getline(ss, tok, ',')) {
					tok = Trim(tok);
					if (tok.empty()) continue;
					uint32_t id = (uint32_t)std::strtoul(tok.c_str(), nullptr, 10);
					if (id != 0) {
						// Deduplicate
						if (std::find(g_favorites.begin(), g_favorites.end(), id) == g_favorites.end())
							g_favorites.push_back(id);
					}
				}
				break;
			}
		}
	}

	void SaveFavoritesToConfig() {
		// Read whole file (if exists), replace or append our key
		std::vector<std::string> lines;
		{
			std::ifstream in(SettingsFile(), std::ios::in);
			if (in.is_open()) {
				std::string l; while (std::getline(in, l)) lines.push_back(l);
			}
		}
		std::ostringstream value;
		for (size_t i = 0; i < g_favorites.size(); ++i) {
			if (i) value << ",";
			value << g_favorites[i];
		}

		bool replaced = false;
		for (auto& l : lines) {
			size_t eq = l.find('=');
			if (eq == std::string::npos) continue;
			std::string key = Trim(l.substr(0, eq));
			std::string lowerKey = key;
			for (auto& c : lowerKey) c = (char)tolower((unsigned char)c);
			if (lowerKey == "weatherfavorites") {
				l = "WeatherFavorites=" + value.str();
				replaced = true;
				break;
			}
		}
		if (!replaced) {
			if (!lines.empty() && !lines.back().empty()) lines.push_back("");
			lines.push_back("# Weather favorites (comma-separated GM weather IDs)");
			lines.push_back("WeatherFavorites=" + value.str());
		}

		std::ofstream out(SettingsFile(), std::ios::out | std::ios::trunc);
		if (!out.is_open()) return;
		for (auto& l : lines) out << l << "\n";
		out.flush();
	}

	int FindIndexById(uint32_t id) {
		for (int i = 0; i < kWeatherCount; ++i)
			if (kWeatherMap[i].id == id) return i;
		return 0; // default Clear Skies
	}

	const char* NameById(uint32_t id) {
		for (const auto& e : kWeatherMap) if (e.id == id) return e.name;
		return "Unknown";
	}

	// Last send status (for status area)
	struct LastStatus {
		bool ok = false;
		uint32_t weatherId = 0;
		uint64_t target = 0;
		uint16_t opcode = 0x0197;
		uint64_t t_ms = 0;
		std::string message;
	};
	LastStatus g_last;

	uint64_t NowMs() {
		return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count();
	}
} // anon

namespace SapphireHook {
	void WeatherModule::Initialize() {
		LogInfo("[Weather] Initialized");
		m_weatherIdx = 0; // Clear Skies
		LoadFavoritesFromConfig();
	}

	void WeatherModule::RenderMenu() {
		(void)ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen);
	}

	void WeatherModule::RenderWindow() {
		if (!m_windowOpen) return;

		ImGui::SetNextWindowSize(ImVec2(520, 480), ImGuiCond_FirstUseEver);
		if (!ImGui::Begin(GetDisplayName(), &m_windowOpen)) { ImGui::End(); return; }

		ImGui::TextDisabled("GM commands are sent via Packet Injection (GM1/0x0197).");
		ImGui::Separator();

		// Search/filter + weather combo (with unique IDs and disambiguation)
		m_weatherIdx = std::clamp(m_weatherIdx, 0, kWeatherCount - 1);

		static ImGuiTextFilter s_filter;
		char preview[96];
		std::snprintf(preview, sizeof(preview), "%s (ID %u)", kWeatherMap[m_weatherIdx].name, kWeatherMap[m_weatherIdx].id);
		if (ImGui::BeginCombo("Weather Type", preview)) {
			s_filter.Draw("Filter", 180.0f);
			ImGui::Separator();

			for (int i = 0; i < kWeatherCount; ++i) {
				if (!s_filter.PassFilter(kWeatherMap[i].name)) continue;

				ImGui::PushID(i); // avoid duplicate-label conflicts
				bool selected = (m_weatherIdx == i);

				char label[96];
				std::snprintf(label, sizeof(label), "%s (ID %u)", kWeatherMap[i].name, kWeatherMap[i].id);
				if (ImGui::Selectable(label, selected)) {
					m_weatherIdx = i;
				}
				if (selected) ImGui::SetItemDefaultFocus();
				if (ImGui::IsItemHovered() && kWeatherMap[i].desc && kWeatherMap[i].desc[0] != '\0') {
					ImGui::SetTooltip("%s", kWeatherMap[i].desc);
				}
				ImGui::PopID();
			}
			ImGui::EndCombo();
		}

		ImGui::SliderFloat("Intensity", &m_intensity, 0.0f, 1.0f, "%.2f"); // visual-only for now
		ImGui::Separator();
		ImGui::Checkbox("Lock Time of Day", &m_lockTime); // visual-only for now
		if (m_lockTime) {
			ImGui::SliderFloat("Time (hours)", &m_timeOfDay, 0.0f, 24.0f, "%.1f h");
		}

		ImGui::Separator();

		// Favorites section (persisted)
		ImGui::TextColored(ImVec4(0.9f, 0.8f, 0.4f, 1.0f), "Favorites");
		if (ImGui::Button("Add Current")) {
			uint32_t id = kWeatherMap[m_weatherIdx].id;
			if (std::find(g_favorites.begin(), g_favorites.end(), id) == g_favorites.end()) {
				g_favorites.push_back(id);
				SaveFavoritesToConfig();
			}
		}
		ImGui::SameLine();
		if (ImGui::Button("Clear Favorites")) {
			g_favorites.clear();
			SaveFavoritesToConfig();
		}

		if (!g_favorites.empty()) {
			ImGui::Spacing();
			ImGui::BeginChild("##favbar", ImVec2(0, 64), true);
			for (size_t i = 0; i < g_favorites.size(); ++i) {
				uint32_t id = g_favorites[i];
				ImGui::PushID((int)i);

				// Quick apply button
				std::string btn = std::string(NameById(id)) + " (ID " + std::to_string(id) + ")";
				if (ImGui::Button(btn.c_str())) {
					m_weatherIdx = FindIndexById(id);
					ApplyWeather();
				}
				ImGui::SameLine();

				// Remove small 'X'
				if (ImGui::SmallButton("X")) {
					g_favorites.erase(g_favorites.begin() + (long long)i);
					SaveFavoritesToConfig();
					ImGui::PopID();
					break; // layout recalculates next frame
				}

				ImGui::PopID();
				if ((i + 1) % 2 == 0) ImGui::NewLine();
				else ImGui::SameLine();
			}
			ImGui::EndChild();
		}

		ImGui::Separator();

		// Local actor id (required as GM command target)
		const uint32_t learned = SapphireHook::GetLearnedLocalActorId();
		const bool hasSelf = (learned != 0 && learned != 0xFFFFFFFF);

		char buf[128];
		if (hasSelf)
			std::snprintf(buf, sizeof(buf), "Target actor: 0x%X (%u)", learned, learned);
		else
			std::snprintf(buf, sizeof(buf), "Target actor: (learning...) Type any chat message once.");
		ImGui::TextDisabled("%s", buf);

		ImGui::Spacing();

		if (!hasSelf) ImGui::BeginDisabled(true);
		if (ImGui::Button("Apply Weather")) {
			ApplyWeather();
		}
		if (!hasSelf) ImGui::EndDisabled();

		ImGui::SameLine();
		if (ImGui::Button("Reset")) {
			ResetDefaults();
			ApplyWeather(); // Auto-apply after reset
		}

		ImGui::Spacing();
		ImGui::Separator();

		// Status area: last result and last sent packet info
		ImGui::TextDisabled("Last Action:");
		if (g_last.t_ms != 0) {
			const float ageSec = (float)((NowMs() - g_last.t_ms) / 1000.0);
			ImVec4 col = g_last.ok ? ImVec4(0.5f, 0.9f, 0.6f, 1.0f) : ImVec4(1.0f, 0.5f, 0.5f, 1.0f);
			ImGui::PushStyleColor(ImGuiCol_Text, col);
			ImGui::Text("%s", g_last.ok ? "OK" : "FAILED");
			ImGui::PopStyleColor();
			ImGui::SameLine();
			ImGui::TextDisabled("(%.1fs ago) Weather=%s (ID %u), Target=0x%llX, Opcode=0x%04X",
				ageSec, NameById(g_last.weatherId), g_last.weatherId,
				static_cast<unsigned long long>(g_last.target), g_last.opcode);
			if (!g_last.message.empty()) {
				ImGui::TextDisabled("%s", g_last.message.c_str());
			}
		}
		else {
			ImGui::TextDisabled("No actions yet.");
		}

		ImGui::End();
	}

	void WeatherModule::ApplyWeather() {
		const uint32_t self = SapphireHook::GetLearnedLocalActorId();
		if (self == 0 || self == 0xFFFFFFFF) {
			LogInfo("[Weather] Cannot apply: local actor id not learned yet (send any chat once).");
			g_last = { false, 0, 0, 0x0197, NowMs(), "Local actor id not learned" };
			return;
		}

		m_weatherIdx = std::clamp(m_weatherIdx, 0, kWeatherCount - 1);
		const uint32_t weatherId = kWeatherMap[m_weatherIdx].id;

		// GM Weather command (ID=0x0006), Arg0=weatherId, target=self
		const bool ok = CommandInterface::SendGMCommand(
			0x0006,                     // Weather
			weatherId,                  // Arg0
			0, 0, 0,                    // Arg1..Arg3
			static_cast<uint64_t>(self) // target actor (required)
		);

		g_last.ok = ok;
		g_last.weatherId = weatherId;
		g_last.target = self;
		g_last.opcode = 0x0197;
		g_last.t_ms = NowMs();
		g_last.message = ok
			? std::string("Applied '") + kWeatherMap[m_weatherIdx].name + "'"
			: "SendGMCommand returned false";

		if (ok) {
			LogInfo(std::string("[Weather] Applied: '") + kWeatherMap[m_weatherIdx].name +
				"' (id=" + std::to_string(weatherId) + "), target=0x" + std::to_string(self));
		}
		else {
			LogInfo("[Weather] Failed to send GM weather command");
		}
	}

	void WeatherModule::SetWeatherById(uint32_t weatherId) {
		m_weatherIdx = FindIndexById(weatherId);
		ApplyWeather();
	}

	void WeatherModule::ResetDefaults() {
		m_weatherIdx = 0; // Clear Skies
		m_intensity = 0.75f;
		m_lockTime = false;
		m_timeOfDay = 12.0f;
	}
} // namespace SapphireHook