#pragma once
#include "../UI/UIModule.h"
#include <cstdint>

namespace SapphireHook {
	class CharacterEditModule : public UIModule {
	public:
		const char* GetName() const override { return "CharacterEdit"; }
		const char* GetDisplayName() const override { return "Character Editor"; }
		void Initialize() override;
		void RenderMenu() override;
		void RenderWindow() override;

		bool IsWindowOpen() const override { return m_windowOpen; }
		void SetWindowOpen(bool open) override { m_windowOpen = open; }

	private:
		bool m_windowOpen = false;

		// Target
		unsigned long long m_targetId;

		// Stats & Progression
		int m_level;
		int m_exp;
		int m_hp;
		int m_mp;
		int m_gp;
		int m_gil;
		int m_selectedClassJob;

		// Appearance
		int m_race;
		int m_tribe;
		int m_gender;

		// Grand Company
		int m_selectedGC;
		int m_gcRank;

		// Unlocks & Misc
		int m_orchestrionSongId;
		int m_titleId;
		int m_discoveryZone;
		int m_discoveryId;

		// Toggles
		int m_onlineStatusIcon;
		bool m_invisToggle;
		bool m_invincToggle;
		bool m_wireframeToggle;

		// UI Sections
		void DrawTargetSection();
		void DrawStatsTab();
		void DrawAppearanceTab();
		void DrawGrandCompanyTab();
		void DrawUnlocksTab();
		void DrawTogglesTab();

		// GM Command senders
		void SendGMCommand_Level();
		void SendGMCommand_Exp();
		void SendGMCommand_HP();
		void SendGMCommand_MP();
		void SendGMCommand_GP();
		void SendGMCommand_Gil();
		void SendGMCommand_Race();
		void SendGMCommand_Tribe();
		void SendGMCommand_Gender();
		void SendGMCommand_GC();
		void SendGMCommand_GCRank();
		void SendGMCommand_Icon();
		void SendGMCommand_Invis();
		void SendGMCommand_Inv();
		void SendGMCommand_Wireframe();
		void SendGMCommand_Orchestrion();

		// Debug command senders
		void SendDebugCommand_ClassJob();
		void SendDebugCommand_Title();
		void SendDebugCommand_Discovery();

		// Utility
		void ResetDefaults();
		void Randomize();
	};
} // namespace SapphireHook