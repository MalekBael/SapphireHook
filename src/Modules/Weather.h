#pragma once
#include "../UI/UIModule.h"
#include <cstdint>

namespace SapphireHook {
	class WeatherModule final : public UIModule {
	public:
		const char* GetName() const override { return "Weather"; }
		const char* GetDisplayName() const override { return "Weather"; }

		void Initialize() override;
		void RenderMenu() override;
		void RenderWindow() override;

		bool IsWindowOpen() const override { return m_windowOpen; }
		void SetWindowOpen(bool open) override { m_windowOpen = open; }

		// New: programmatic control via GM packet injection
		void ApplyWeather();                 // Sends GM command for the currently selected weather
		void SetWeatherById(uint32_t weatherId); // Sets weather by ID and applies it

	private:
		void ResetDefaults();

		bool  m_windowOpen = false;
		int   m_weatherIdx = 0;
		float m_intensity = 0.75f;
		bool  m_lockTime = false;
		float m_timeOfDay = 12.0f;
	};
} // namespace SapphireHook