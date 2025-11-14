#include "SettingsModule.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include "../Core/PacketInjector.h"
#include <windows.h>
#include <shellapi.h>   // NEW: for ShellExecute
#include <filesystem>

using namespace SapphireHook;

void SettingsModule::RenderMenu()
{
	// Intentionally left empty
}

void SettingsModule::RenderWindow()
{
	if (!m_windowOpen)
		return;

	ImGui::SetNextWindowSize(ImVec2(640, 640), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin("SapphireHook Settings", &m_windowOpen,
		ImGuiWindowFlags_NoCollapse))
	{
		ImGui::End();
		return;
	}

	if (ImGui::CollapsingHeader("Packet Logging", ImGuiTreeNodeFlags_DefaultOpen))
	{
		DrawPacketLoggingSection();
	}

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::TextDisabled("Changes apply to newly produced log lines.");

	ImGui::End();
}

void SettingsModule::DrawPacketLoggingSection()
{
	ImGui::TextUnformatted("Packet Logging Verbosity");
	ImGui::Separator();

	const char* help =
		"Controls how many packet-related entries are written to the log:\n"
		"Off:     Only critical errors & socket learning\n"
		"Summary: Suppress per-packet send/recv spam; keep important events (default)\n"
		"Verbose: Log every send/recv, enqueue, previews, hex dumps";
	ImGui::PushTextWrapPos();
	ImGui::TextUnformatted(help);
	ImGui::PopTextWrapPos();

	PacketLogMode current = GetPacketLogMode();
	int mode = static_cast<int>(current);

	bool changed = false;
	ImGui::Spacing();
	changed |= ImGui::RadioButton("Off", &mode, 0); ImGui::SameLine();
	changed |= ImGui::RadioButton("Summary", &mode, 1); ImGui::SameLine();
	changed |= ImGui::RadioButton("Verbose", &mode, 2);

	if (changed)
	{
		SetPacketLogMode(static_cast<PacketLogMode>(mode));
		LogInfo(std::string("[Settings] PacketLogMode => ")
			+ (mode == 0 ? "Off" : mode == 1 ? "Summary" : "Verbose"));
	}

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::TextUnformatted("Logger Output");
	ImGui::Separator();

	{
		auto& logger = Logger::Instance();
		bool consoleEnabled = logger.IsConsoleOutputEnabled();
		if (ImGui::Checkbox("Mirror logs to Console", &consoleEnabled))
		{
			logger.SetConsoleOutput(consoleEnabled);
			LogInfo(std::string("[Settings] Console mirroring => ") + (consoleEnabled ? "ON" : "OFF"));
		}

		static const char* kLevels[] = { "Debug", "Info", "Warn", "Error", "Fatal" };
		int curLevel = static_cast<int>(logger.GetMinimumLevel());
		ImGui::SetNextItemWidth(120);
		if (ImGui::Combo("Minimum Level", &curLevel, kLevels, IM_ARRAYSIZE(kLevels)))
		{
			logger.SetMinimumLevel(static_cast<LogLevel>(curLevel));
			LogInfo(std::string("[Settings] Minimum log level => ") + kLevels[curLevel]);
		}

		ImGui::TextDisabled("Console mirroring lets you mute or enable live log spam.");

		ImGui::Spacing();
		ImGui::Separator();

		// NEW: Open Log Folder button
		const std::filesystem::path logFile = logger.GetLogFilePath();
		const std::filesystem::path logDir = logFile.parent_path();

		ImGui::TextUnformatted("Log Directory:");
		ImGui::SameLine();
		ImGui::TextDisabled("%s", logDir.string().c_str());

		if (ImGui::Button("Open Log Folder")) {
			if (!logDir.empty()) {
				// Use wide version for Unicode paths
				ShellExecuteW(nullptr, L"open", logDir.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
			}
		}
	}
}