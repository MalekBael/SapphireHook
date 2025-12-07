#include "Weather.h"
#include "CommandInterface.h"
#include "../Core/PacketInjector.h"
#include "../Core/SettingsManager.h"
#include "../vendor/imgui/imgui.h"
#include "../Logger/Logger.h"
#include <string>
#include <algorithm>
#include <cstdint>
#include <vector>
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

// ---------- Helper functions ----------
namespace {
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
		// Favorites are now managed by SettingsManager
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

		// Favorites section (persisted via SettingsManager)
		ImGui::TextColored(ImVec4(0.9f, 0.8f, 0.4f, 1.0f), "Favorites");
		if (ImGui::Button("Add Current")) {
			uint32_t id = kWeatherMap[m_weatherIdx].id;
			SettingsManager::Instance().AddWeatherFavorite(id);
		}
		ImGui::SameLine();
		if (ImGui::Button("Clear Favorites")) {
			SettingsManager::Instance().SetWeatherFavorites({});
		}

		const auto& favorites = SettingsManager::Instance().GetWeatherFavorites();
		if (!favorites.empty()) {
			ImGui::Spacing();
			ImGui::BeginChild("##favbar", ImVec2(0, 64), true);
			for (size_t i = 0; i < favorites.size(); ++i) {
				uint32_t id = favorites[i];
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
					SettingsManager::Instance().RemoveWeatherFavorite(id);
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