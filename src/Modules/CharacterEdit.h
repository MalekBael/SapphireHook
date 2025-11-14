#pragma once
#include "../UI/UIModule.h"

namespace SapphireHook {
	class CharacterEditModule final : public UIModule {
	public:
		const char* GetName() const override { return "CharacterEdit"; }
		const char* GetDisplayName() const override { return "Character Edit"; }

		void Initialize() override;
		void RenderMenu() override;
		void RenderWindow() override;

		bool IsWindowOpen() const override { return m_windowOpen; }
		void SetWindowOpen(bool open) override { m_windowOpen = open; }

	private:
		void ResetDefaults();
		void Randomize();

		bool m_windowOpen = false;

		int   m_race = 0;
		int   m_tribe = 0;
		int   m_gender = 0;
		int   m_height = 50;

		int   m_face = 0;
		int   m_hairStyle = 0;
		float m_hairColor[3] = { 0.25f, 0.20f, 0.15f };
	};
} // namespace SapphireHook