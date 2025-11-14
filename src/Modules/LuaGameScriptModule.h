#pragma once
#include <atomic>
#include <future>
#include <filesystem>
#include <string>
#include <vector>

#include "../UI/UIModule.h"
#include "../Tools/LuaGameScriptScanner.h"

namespace SapphireHook {
	class LuaGameScriptModule : public UIModule {
	public:
		LuaGameScriptModule() = default;
		~LuaGameScriptModule() override = default;

		// UIModule interface
		const char* GetName() const override { return "LuaGameScriptModule"; }
		const char* GetDisplayName() const override { return "Lua GameScript Scanner"; }
		void Initialize() override {}
		void Shutdown() override { Cancel(); }
		void RenderMenu() override;
		void RenderWindow() override;
		bool IsEnabled() const override { return true; }

		bool IsWindowOpen() const override { return m_open; }
		void SetWindowOpen(bool v) override { m_open = v; }

	private:
		// Match implementation names used in .cpp
		void StartScan(const std::filesystem::path& root);
		void Cancel();
		void Finalize();

	private:
		bool m_open = false;

		std::atomic<bool> m_running{ false };
		std::atomic<bool> m_cancel{ false };
		std::future<std::optional<LuaScanSummary>> m_task;

		std::filesystem::path m_root;
		LuaScanSummary m_results{};
		std::string m_status;

		size_t m_maxEntries = 25000;
		size_t m_probeBytes = 0x2000;
	};
} // namespace SapphireHook