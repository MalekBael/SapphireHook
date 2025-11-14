#include "CharacterEdit.h"
#include "../vendor/imgui/imgui.h"
#include "../Logger/Logger.h"
#include <cstdlib>
#include <string>

using SapphireHook::LogInfo;

namespace SapphireHook {
	void CharacterEditModule::Initialize() {
		LogInfo("[CharacterEdit] Initialized");
	}

	void CharacterEditModule::RenderMenu() {
		if (ImGui::MenuItem(GetDisplayName(), nullptr, m_windowOpen)) {
			m_windowOpen = !m_windowOpen;
		}
	}

	void CharacterEditModule::RenderWindow() {
		if (!m_windowOpen) return;

		ImGui::SetNextWindowSize(ImVec2(520, 460), ImGuiCond_FirstUseEver);
		if (!ImGui::Begin(GetDisplayName(), &m_windowOpen)) { ImGui::End(); return; }

		static const char* kRaces[] = {
			"Hyur","Elezen","Lalafell","Miqo'te","Roegadyn","Au Ra","Hrothgar","Viera"
		};
		static const char* kGender[] = { "Male","Female" };

		static const char* kTribes_Hyur[] = { "Midlander","Highlander" };
		static const char* kTribes_Elezen[] = { "Wildwood","Duskwight" };
		static const char* kTribes_Lalafell[] = { "Plainsfolk","Dunesfolk" };
		static const char* kTribes_Miqote[] = { "Seeker of the Sun","Keeper of the Moon" };
		static const char* kTribes_Roegadyn[] = { "Sea Wolf","Hellsguard" };
		static const char* kTribes_AuRa[] = { "Raen","Xaela" };
		static const char* kTribes_Hrothgar[] = { "Helions","The Lost" };
		static const char* kTribes_Viera[] = { "Rava","Veena" };

		auto getTribes = [&](int race, const char*** list, int* count) {
			switch (race) {
			default:
			case 0: *list = kTribes_Hyur;     *count = (int)IM_ARRAYSIZE(kTribes_Hyur); break;
			case 1: *list = kTribes_Elezen;   *count = (int)IM_ARRAYSIZE(kTribes_Elezen); break;
			case 2: *list = kTribes_Lalafell; *count = (int)IM_ARRAYSIZE(kTribes_Lalafell); break;
			case 3: *list = kTribes_Miqote;   *count = (int)IM_ARRAYSIZE(kTribes_Miqote); break;
			case 4: *list = kTribes_Roegadyn; *count = (int)IM_ARRAYSIZE(kTribes_Roegadyn); break;
			case 5: *list = kTribes_AuRa;     *count = (int)IM_ARRAYSIZE(kTribes_AuRa); break;
			case 6: *list = kTribes_Hrothgar; *count = (int)IM_ARRAYSIZE(kTribes_Hrothgar); break;
			case 7: *list = kTribes_Viera;    *count = (int)IM_ARRAYSIZE(kTribes_Viera); break;
			}
			if (m_tribe >= *count) m_tribe = 0;
			};

		if (ImGui::BeginTable("char_edit_tbl", 2, ImGuiTableFlags_SizingStretchProp)) {
			ImGui::TableSetupColumn("L", ImGuiTableColumnFlags_WidthStretch, 0.5f);
			ImGui::TableSetupColumn("R", ImGuiTableColumnFlags_WidthStretch, 0.5f);

			ImGui::TableNextColumn();
			ImGui::TextDisabled("Identity");
			ImGui::Separator();

			if (ImGui::Combo("Race", &m_race, kRaces, (int)IM_ARRAYSIZE(kRaces))) {
				const char** tribes = nullptr; int count = 0; getTribes(m_race, &tribes, &count);
			}
			{
				const char** tribes = nullptr; int count = 0; getTribes(m_race, &tribes, &count);
				ImGui::Combo("Tribe", &m_tribe, tribes, count);
			}
			ImGui::Combo("Gender", &m_gender, kGender, (int)IM_ARRAYSIZE(kGender));
			ImGui::SliderInt("Height", &m_height, 0, 100, "%d");

			ImGui::TableNextColumn();
			ImGui::TextDisabled("Appearance");
			ImGui::Separator();
			ImGui::SliderInt("Face", &m_face, 0, 7, "%d");
			ImGui::SliderInt("Hair Style", &m_hairStyle, 0, 19, "%d");
			ImGui::ColorEdit3("Hair Color", m_hairColor, ImGuiColorEditFlags_NoInputs);

			ImGui::EndTable();
		}

		ImGui::Separator();
		if (ImGui::Button("Apply")) {
			const char* raceName = (m_race >= 0 && m_race < 8) ? kRaces[m_race] : "Race";
			LogInfo(std::string("[CharacterEdit] Apply: race=") + raceName +
				" gender=" + (m_gender == 0 ? "Male" : "Female") +
				" face=" + std::to_string(m_face) +
				" hair=" + std::to_string(m_hairStyle) +
				" height=" + std::to_string(m_height));
		}
		ImGui::SameLine();
		if (ImGui::Button("Reset")) ResetDefaults();
		ImGui::SameLine();
		if (ImGui::Button("Randomize")) Randomize();
		ImGui::SameLine();
		ImGui::TextDisabled("Prototype UI (no game writes yet).");

		ImGui::End();
	}

	void CharacterEditModule::ResetDefaults() {
		m_race = 0; m_tribe = 0; m_gender = 0; m_height = 50;
		m_face = 0; m_hairStyle = 0;
		m_hairColor[0] = 0.25f; m_hairColor[1] = 0.20f; m_hairColor[2] = 0.15f;
	}

	void CharacterEditModule::Randomize() {
		auto rng = [](int lo, int hi) { return lo + (int)(rand() % (hi - lo + 1)); };
		m_race = rng(0, 7);
		m_gender = rng(0, 1);
		m_height = rng(0, 100);
		m_face = rng(0, 7);
		m_hairStyle = rng(0, 19);
		m_hairColor[0] = (float)(rand() % 100) / 100.0f;
		m_hairColor[1] = (float)(rand() % 100) / 100.0f;
		m_hairColor[2] = (float)(rand() % 100) / 100.0f;
	}
} // namespace SapphireHook