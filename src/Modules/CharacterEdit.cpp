#include "CharacterEdit.h"
#include "CommandInterface.h"
#include "../vendor/imgui/imgui.h"
#include "../Logger/Logger.h"
#include <cstdio>
#include <cstdlib>
#include <string>

using SapphireHook::LogInfo;

namespace SapphireHook {
	// Forward declaration (provided by PacketInjector.cpp)
	uint32_t GetLearnedLocalActorId();

	// Helper: resolve UI target (0 = self) to an effective actor id
	static inline uint64_t ResolveTarget(uint64_t uiTarget)
	{
		if (uiTarget != 0ULL) return uiTarget;
		const uint32_t self = GetLearnedLocalActorId();
		return (self != 0 && self != 0xFFFFFFFFu) ? static_cast<uint64_t>(self) : 0ULL;
	}

	void CharacterEditModule::Initialize() {
		LogInfo("[CharacterEdit] Initialized");
		m_targetId = 0ULL;

		m_level = 1; m_exp = 0; m_hp = 100; m_mp = 100; m_gp = 0; m_gil = 0;
		m_race = 0; m_tribe = 0; m_gender = 0;

		m_selectedClassJob = 0; m_selectedGC = 0; m_gcRank = 0;
		m_onlineStatusIcon = 0;
		m_invisToggle = false; m_invincToggle = false; m_wireframeToggle = false;
		m_orchestrionSongId = 0; m_titleId = 0; m_discoveryZone = 0; m_discoveryId = 0;
	}

	void CharacterEditModule::RenderMenu() {
		if (ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen)) {
			m_windowOpen = !m_windowOpen;
		}
	}

	void CharacterEditModule::RenderWindow() {
		if (!m_windowOpen) return;

		ImGui::SetNextWindowSize(ImVec2(700, 720), ImGuiCond_FirstUseEver);
		if (!ImGui::Begin(GetDisplayName(), &m_windowOpen)) {
			ImGui::End();
			return;
		}

		ImGui::TextDisabled("Character modification via GM Commands (packet injection)");
		ImGui::Separator();

		// Target selection section
		DrawTargetSection();
		ImGui::Separator();

		// Tabs for different categories
		if (ImGui::BeginTabBar("CharacterEditTabs", ImGuiTabBarFlags_None)) {
			if (ImGui::BeginTabItem("Stats & Progression")) {
				DrawStatsTab();
				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Appearance")) {
				DrawAppearanceTab();
				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Grand Company")) {
				DrawGrandCompanyTab();
				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Unlocks & Misc")) {
				DrawUnlocksTab();
				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Toggles & Effects")) {
				DrawTogglesTab();
				ImGui::EndTabItem();
			}

			ImGui::EndTabBar();
		}

		ImGui::End();
	}

	void CharacterEditModule::DrawTargetSection() {
		ImGui::TextColored(ImVec4(0.9f, 0.85f, 0.3f, 1.0f), "Target Selection");

		const uint32_t learned = GetLearnedLocalActorId();
		char buf[96];
		if (learned != 0 && learned != 0xFFFFFFFF)
			std::snprintf(buf, sizeof(buf), "Local Actor ID: 0x%X (%u)", learned, learned);
		else
			std::snprintf(buf, sizeof(buf), "Local Actor ID: (learning...) Type a chat message once.");

		ImGui::InputText("##local_actor_status", buf, sizeof(buf), ImGuiInputTextFlags_ReadOnly);
		ImGui::SameLine();

		const bool canUseSelf = (learned != 0 && learned != 0xFFFFFFFF);
		if (!canUseSelf) ImGui::BeginDisabled(true);
		if (ImGui::Button("Use Self")) {
			m_targetId = static_cast<unsigned long long>(learned);
		}
		if (!canUseSelf) ImGui::EndDisabled();
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Set Target ID to your player actor ID");

		ImGui::InputScalar("Target ID (uint64)", ImGuiDataType_U64, &m_targetId);
		ImGui::TextDisabled("Leave as 0 for self, or enter a specific player actor ID");
	}

	void CharacterEditModule::DrawStatsTab() {
		ImGui::BeginChild("##stats_scroll", ImVec2(0, 0), false);

		// Level
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Level");
		ImGui::SliderInt("##level", &m_level, 1, 90, "Level: %d");
		if (ImGui::Button("Set Level", ImVec2(120, 0))) {
			SendGMCommand_Level();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm lv <level> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// Class/Job
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Class/Job");
		static const char* kClassJobs[] = {
			"Gladiator (1)", "Pugilist (2)", "Marauder (3)", "Lancer (4)", "Archer (5)",
			"Conjurer (6)", "Thaumaturge (7)", "Carpenter (8)", "Blacksmith (9)", "Armorer (10)",
			"Goldsmith (11)", "Leatherworker (12)", "Weaver (13)", "Alchemist (14)", "Culinarian (15)",
			"Miner (16)", "Botanist (17)", "Fisher (18)", "Paladin (19)", "Monk (20)",
			"Warrior (21)", "Dragoon (22)", "Bard (23)", "White Mage (24)", "Black Mage (25)",
			"Arcanist (26)", "Summoner (27)", "Scholar (28)", "Rogue (29)", "Ninja (30)",
			"Machinist (31)", "Dark Knight (32)", "Astrologian (33)", "Samurai (34)", "Red Mage (35)",
			"Blue Mage (36)", "Gunbreaker (37)", "Dancer (38)", "Reaper (39)", "Sage (40)"
		};
		ImGui::Combo("##classjob", &m_selectedClassJob, kClassJobs, IM_ARRAYSIZE(kClassJobs));
		if (ImGui::Button("Set Class/Job", ImVec2(120, 0))) {
			SendDebugCommand_ClassJob();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("!set classjob <Class/JobID>");

		ImGui::Spacing();
		ImGui::Separator();

		// Experience
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Experience");
		ImGui::InputInt("##exp", &m_exp);
		if (ImGui::Button("Add EXP", ImVec2(120, 0))) {
			SendGMCommand_Exp();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm exp <amount> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// HP
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Hit Points");
		ImGui::InputInt("##hp", &m_hp);
		if (ImGui::Button("Set HP", ImVec2(120, 0))) {
			SendGMCommand_HP();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm hp <amount> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// MP
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Magic Points");
		ImGui::InputInt("##mp", &m_mp);
		if (ImGui::Button("Set MP", ImVec2(120, 0))) {
			SendGMCommand_MP();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm mp <amount> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// GP
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Gathering Points");
		ImGui::InputInt("##gp", &m_gp);
		if (ImGui::Button("Set GP", ImVec2(120, 0))) {
			SendGMCommand_GP();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm gp <amount> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// Gil
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Gil (Currency)");
		ImGui::InputInt("##gil", &m_gil);
		if (ImGui::Button("Set Gil", ImVec2(120, 0))) {
			SendGMCommand_Gil();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm gil <value> <player>");

		ImGui::EndChild();
	}

	void CharacterEditModule::DrawAppearanceTab() {
		ImGui::BeginChild("##appearance_scroll", ImVec2(0, 0), false);

		static const char* kRaces[] = {
			"Hyur (1)", "Elezen (2)", "Lalafell (3)", "Miqo'te (4)",
			"Roegadyn (5)", "Au Ra (6)", "Hrothgar (7)", "Viera (8)"
		};
		static const char* kGenders[] = { "Male (0)", "Female (1)" };

		// Race
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Race");
		ImGui::Combo("##race", &m_race, kRaces, IM_ARRAYSIZE(kRaces));
		if (ImGui::Button("Set Race", ImVec2(120, 0))) {
			SendGMCommand_Race();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm race <raceid> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// Tribe
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Tribe");
		ImGui::SliderInt("##tribe", &m_tribe, 0, 15, "Tribe ID: %d");
		if (ImGui::Button("Set Tribe", ImVec2(120, 0))) {
			SendGMCommand_Tribe();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm tribe <tribeid> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// Gender
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Gender");
		ImGui::Combo("##gender", &m_gender, kGenders, IM_ARRAYSIZE(kGenders));
		if (ImGui::Button("Set Gender", ImVec2(120, 0))) {
			SendGMCommand_Gender();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm sex <male=0,female=1> <player>");

		ImGui::EndChild();
	}

	void CharacterEditModule::DrawGrandCompanyTab() {
		ImGui::BeginChild("##gc_scroll", ImVec2(0, 0), false);

		static const char* kGrandCompanies[] = {
			"None (0)",
			"Maelstrom (1)",
			"Order of the Twin Adder (2)",
			"Immortal Flames (3)"
		};

		// Grand Company
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Grand Company");
		ImGui::Combo("##gc", &m_selectedGC, kGrandCompanies, IM_ARRAYSIZE(kGrandCompanies));
		if (ImGui::Button("Set Grand Company", ImVec2(160, 0))) {
			SendGMCommand_GC();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm gc <gcid>");

		ImGui::Spacing();
		ImGui::Separator();

		// GC Rank
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Grand Company Rank");
		ImGui::SliderInt("##gcrank", &m_gcRank, 0, 15, "Rank: %d");
		ImGui::TextDisabled("Ranks: 0=None, 1-15=Increasing ranks");
		if (ImGui::Button("Set GC Rank", ImVec2(160, 0))) {
			SendGMCommand_GCRank();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm gcrank <rank>");

		ImGui::EndChild();
	}

	void CharacterEditModule::DrawUnlocksTab() {
		ImGui::BeginChild("##unlocks_scroll", ImVec2(0, 0), false);

		// Orchestrion
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Orchestrion Rolls");
		ImGui::InputInt("Song ID##orch", &m_orchestrionSongId);
		ImGui::TextDisabled("Enter 0 to unlock all songs, or a specific Song ID");
		if (ImGui::Button("Unlock Orchestrion", ImVec2(160, 0))) {
			SendGMCommand_Orchestrion();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm orchestrion 1 <songid>");

		ImGui::Spacing();
		ImGui::Separator();

		// Title
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Titles");
		ImGui::InputInt("Title ID##title", &m_titleId);
		if (ImGui::Button("Add Title", ImVec2(160, 0))) {
			SendDebugCommand_Title();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("!add title <TitleID>");

		ImGui::Spacing();
		ImGui::Separator();

		// Discovery
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Discovery Points");
		ImGui::InputInt("Zone ID##disc_zone", &m_discoveryZone);
		ImGui::InputInt("Discovery ID##disc_id", &m_discoveryId);
		if (ImGui::Button("Unlock Discovery", ImVec2(160, 0))) {
			SendDebugCommand_Discovery();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("!set discovery <ZoneID> <DiscoverID>");

		ImGui::EndChild();
	}

	void CharacterEditModule::DrawTogglesTab() {
		ImGui::BeginChild("##toggles_scroll", ImVec2(0, 0), false);

		// Online Status Icon
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Online Status Icon");
		ImGui::InputInt("##icon", &m_onlineStatusIcon);
		ImGui::TextDisabled("0=None, 12=AFK, 15=Busy, 17=Looking for Party, etc.");
		if (ImGui::Button("Set Icon", ImVec2(120, 0))) {
			SendGMCommand_Icon();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm icon <onlinestatusid> <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// Invisibility
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Invisibility");
		ImGui::Checkbox("Invisible##invis", &m_invisToggle);
		ImGui::TextDisabled("0 = invisible, 1 = visible");
		if (ImGui::Button("Toggle Invisibility", ImVec2(160, 0))) {
			SendGMCommand_Invis();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm invis");

		ImGui::Spacing();
		ImGui::Separator();

		// Invincibility
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Invincibility");
		ImGui::Checkbox("Invincible##inv", &m_invincToggle);
		if (ImGui::Button("Toggle Invincibility", ImVec2(160, 0))) {
			SendGMCommand_Inv();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm inv <player>");

		ImGui::Spacing();
		ImGui::Separator();

		// Wireframe
		ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Wireframe Rendering");
		ImGui::Checkbox("Wireframe##wire", &m_wireframeToggle);
		if (ImGui::Button("Toggle Wireframe", ImVec2(160, 0))) {
			SendGMCommand_Wireframe();
		}
		ImGui::SameLine();
		ImGui::TextDisabled("//gm wireframe");

		ImGui::EndChild();
	}

	// GM Command senders (now all resolve target locally when needed)
	void CharacterEditModule::SendGMCommand_Level() {
		CommandInterface::SetPlayerLevel(static_cast<uint8_t>(m_level), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: Level " + std::to_string(m_level));
	}

	void CharacterEditModule::SendGMCommand_Exp() {
		CommandInterface::SetPlayerExp(static_cast<uint32_t>(m_exp), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: EXP " + std::to_string(m_exp));
	}

	void CharacterEditModule::SendGMCommand_HP() {
		CommandInterface::SetPlayerHp(static_cast<uint32_t>(m_hp), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: HP " + std::to_string(m_hp));
	}

	void CharacterEditModule::SendGMCommand_MP() {
		CommandInterface::SetPlayerMp(static_cast<uint32_t>(m_mp), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: MP " + std::to_string(m_mp));
	}

	void CharacterEditModule::SendGMCommand_GP() {
		CommandInterface::SetPlayerGp(static_cast<uint32_t>(m_gp), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: GP " + std::to_string(m_gp));
	}

	void CharacterEditModule::SendGMCommand_Gil() {
		CommandInterface::GivePlayerGil(static_cast<uint32_t>(m_gil), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: Gil " + std::to_string(m_gil));
	}

	void CharacterEditModule::SendGMCommand_Race() {
		const uint32_t raceId = static_cast<uint32_t>(m_race + 1);
		CommandInterface::SetPlayerRace(raceId, ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: Race " + std::to_string(raceId));
	}

	void CharacterEditModule::SendGMCommand_Tribe() {
		CommandInterface::SetPlayerTribe(static_cast<uint32_t>(m_tribe), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: Tribe " + std::to_string(m_tribe));
	}

	void CharacterEditModule::SendGMCommand_Gender() {
		CommandInterface::SetPlayerGender(static_cast<uint32_t>(m_gender), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: Gender " + std::to_string(m_gender));
	}

	void CharacterEditModule::SendGMCommand_GC() {
		CommandInterface::SetGrandCompany(static_cast<uint32_t>(m_selectedGC), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: GC " + std::to_string(m_selectedGC));
	}

	void CharacterEditModule::SendGMCommand_GCRank() {
		CommandInterface::SetGrandCompanyRank(static_cast<uint32_t>(m_gcRank), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: GC Rank " + std::to_string(m_gcRank));
	}

	void CharacterEditModule::SendGMCommand_Icon() {
		CommandInterface::SetPlayerIcon(static_cast<uint32_t>(m_onlineStatusIcon), ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: Icon " + std::to_string(m_onlineStatusIcon));
	}

	void CharacterEditModule::SendGMCommand_Invis() {
		// Include target (UI value or self) so server logs reflect correct actor
		const uint64_t target = ResolveTarget(m_targetId);
		CommandInterface::SendGMCommand(
			/*Invis*/ 0x000D,
			m_invisToggle ? 1u : 0u, 0, 0, 0, target);
		LogInfo("[CharacterEdit] Sent: Invisibility toggle => " +
			std::string(m_invisToggle ? "VISIBLE" : "INVISIBLE") +
			" (target=" + Logger::HexFormat(target) + ")");
	}

	void CharacterEditModule::SendGMCommand_Inv() {
		CommandInterface::SetInvincibility(m_invincToggle ? 1u : 0u, ResolveTarget(m_targetId));
		LogInfo("[CharacterEdit] Sent: Invincibility => " + std::string(m_invincToggle ? "ON" : "OFF"));
	}

	void CharacterEditModule::SendGMCommand_Wireframe() {
		// Include target (UI value or self)
		const uint64_t target = ResolveTarget(m_targetId);
		CommandInterface::SendGMCommand(
			/*Wireframe*/ 0x0226,
			m_wireframeToggle ? 1u : 0u, 0, 0, 0, target);
		LogInfo("[CharacterEdit] Sent: Wireframe => " +
			std::string(m_wireframeToggle ? "ON" : "OFF") +
			" (target=" + Logger::HexFormat(target) + ")");
	}

	void CharacterEditModule::SendGMCommand_Orchestrion() {
		// Include target (UI value or self). Arg0=1 per command syntax, Arg1=songId (0=all)
		const uint64_t target = ResolveTarget(m_targetId);
		CommandInterface::SendGMCommand(
			/*Orchestrion*/ 0x0074,
			1u, static_cast<uint32_t>(m_orchestrionSongId), 0, 0, target);
		LogInfo("[CharacterEdit] Sent: Orchestrion unlock " +
			std::to_string(m_orchestrionSongId) +
			" (target=" + Logger::HexFormat(target) + ")");
	}

	// Debug senders (unchanged)
	void CharacterEditModule::SendDebugCommand_ClassJob() {
		const uint32_t jobId = static_cast<uint32_t>(m_selectedClassJob + 1);
		char cmd[128];
		std::snprintf(cmd, sizeof(cmd), "!set classjob %u", jobId);
		CommandInterface::SendChatMessage(cmd, 0);
		LogInfo("[CharacterEdit] Sent: Set ClassJob to " + std::to_string(jobId));
	}

	void CharacterEditModule::SendDebugCommand_Title() {
		char cmd[128];
		std::snprintf(cmd, sizeof(cmd), "!add title %d", m_titleId);
		CommandInterface::SendChatMessage(cmd, 0);
		LogInfo("[CharacterEdit] Sent: Add Title " + std::to_string(m_titleId));
	}

	void CharacterEditModule::SendDebugCommand_Discovery() {
		char cmd[128];
		std::snprintf(cmd, sizeof(cmd), "!set discovery %d %d", m_discoveryZone, m_discoveryId);
		CommandInterface::SendChatMessage(cmd, 0);
		LogInfo("[CharacterEdit] Sent: Unlock Discovery Zone=" + std::to_string(m_discoveryZone) +
			" ID=" + std::to_string(m_discoveryId));
	}
} // namespace SapphireHook