#include "SettingsModule.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include "../Core/PacketInjector.h"
#include "../Core/SettingsManager.h"
#include "../Core/GameDataLookup.h"
#include <windows.h>
#include <shellapi.h>   // for ShellExecute
#include <shobjidl.h>   // for IFileDialog
#include <filesystem>

using namespace SapphireHook;

void SettingsModule::Initialize()
{
	// SettingsManager handles loading settings on first access
	// Just ensure it's initialized
	SettingsManager::Instance().Initialize();
}

void SettingsModule::RenderMenu()
{
	// Intentionally left empty
}

void SettingsModule::RenderWindow()
{
	if (!m_windowOpen)
		return;

	ImGui::SetNextWindowSize(ImVec2(640, 700), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin("SapphireHook Settings", &m_windowOpen,
		ImGuiWindowFlags_NoCollapse))
	{
		ImGui::End();
		return;
	}

	if (ImGui::CollapsingHeader("Game Data (sqpack)", ImGuiTreeNodeFlags_DefaultOpen))
	{
		DrawGameDataSection();
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
		// Use SettingsManager which handles both runtime update and persistence
		SettingsManager::Instance().SetPacketLogMode(mode);
		LogInfo(std::string("[Settings] PacketLogMode => ")
			+ (mode == 0 ? "Off" : mode == 1 ? "Summary" : "Verbose"));
	}

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::TextUnformatted("Logger Output");
	ImGui::Separator();

	{
		auto& logger = Logger::Instance();
		auto& settings = SettingsManager::Instance();
		
		bool consoleEnabled = logger.IsConsoleOutputEnabled();
		if (ImGui::Checkbox("Mirror logs to Console", &consoleEnabled))
		{
			settings.SetConsoleOutput(consoleEnabled);
			LogInfo(std::string("[Settings] Console mirroring => ") + (consoleEnabled ? "ON" : "OFF"));
		}

		static const char* kLevels[] = { "Debug", "Info", "Warn", "Error", "Fatal" };
		int curLevel = static_cast<int>(logger.GetMinimumLevel());
		ImGui::SetNextItemWidth(120);
		if (ImGui::Combo("Minimum Level", &curLevel, kLevels, IM_ARRAYSIZE(kLevels)))
		{
			settings.SetLogLevel(curLevel);
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

void SettingsModule::DrawGameDataSection()
{
	auto& settings = SettingsManager::Instance();
	
	ImGui::TextUnformatted("FFXIV sqpack Path");
	ImGui::Separator();
	
	ImGui::PushTextWrapPos();
	ImGui::TextUnformatted(
		"The sqpack folder contains game data files (items, actions, etc.).\n"
		"By default, the path is auto-detected from the game executable.\n"
		"If auto-detection fails, you can set a custom path here.");
	ImGui::PopTextWrapPos();
	ImGui::Spacing();
	
	// Show current status
	const auto& stats = GameData::GetLoadStats();
	if (stats.initialized)
	{
		ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Status: Loaded");
		ImGui::SameLine();
		ImGui::TextDisabled("(%zu items, %zu actions, %zu statuses)",
			stats.itemCount, stats.actionCount, stats.statusCount);
	}
	else
	{
		ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Status: Not loaded");
		ImGui::SameLine();
		ImGui::TextDisabled("(lookups will show IDs only)");
	}
	
	ImGui::Spacing();
	
	// Current path display
	std::filesystem::path currentPath = GameData::GetDataDirectory();
	ImGui::TextUnformatted("Current Path:");
	ImGui::SameLine();
	if (currentPath.empty())
	{
		ImGui::TextDisabled("(not set)");
	}
	else
	{
		ImGui::TextDisabled("%s", currentPath.string().c_str());
	}
	
	ImGui::Spacing();
	ImGui::Separator();
	
	// Custom path input
	static char s_pathBuffer[512] = {};
	static bool s_initialized = false;
	
	// Initialize buffer from settings on first render
	if (!s_initialized)
	{
		if (settings.HasCustomSqpackPath())
		{
			strncpy_s(s_pathBuffer, settings.GetSqpackPath().string().c_str(), sizeof(s_pathBuffer) - 1);
		}
		s_initialized = true;
	}
	
	ImGui::TextUnformatted("Custom sqpack Path:");
	ImGui::SetNextItemWidth(-120.0f);  // Leave room for buttons
	ImGui::InputText("##sqpackPath", s_pathBuffer, sizeof(s_pathBuffer));
	
	ImGui::SameLine();
	if (ImGui::Button("Browse..."))
	{
		// Use Windows folder picker
		COMDLG_FILTERSPEC filterSpec = {};
		IFileDialog* pFileDialog = nullptr;
		HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL,
			IID_IFileDialog, reinterpret_cast<void**>(&pFileDialog));
		
		if (SUCCEEDED(hr))
		{
			DWORD options;
			pFileDialog->GetOptions(&options);
			pFileDialog->SetOptions(options | FOS_PICKFOLDERS);
			pFileDialog->SetTitle(L"Select FFXIV sqpack folder");
			
			hr = pFileDialog->Show(nullptr);
			if (SUCCEEDED(hr))
			{
				IShellItem* pItem = nullptr;
				hr = pFileDialog->GetResult(&pItem);
				if (SUCCEEDED(hr))
				{
					LPWSTR pPath = nullptr;
					hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pPath);
					if (SUCCEEDED(hr) && pPath)
					{
						std::filesystem::path selectedPath(pPath);
						strncpy_s(s_pathBuffer, selectedPath.string().c_str(), sizeof(s_pathBuffer) - 1);
						CoTaskMemFree(pPath);
					}
					pItem->Release();
				}
			}
			pFileDialog->Release();
		}
	}
	
	ImGui::Spacing();
	
	// Apply button
	if (ImGui::Button("Apply & Reload"))
	{
		std::filesystem::path newPath(s_pathBuffer);
		if (!newPath.empty() && std::filesystem::exists(newPath))
		{
			settings.SetSqpackPath(newPath);
			
			// Reload game data with new path
			if (GameData::Initialize(newPath))
			{
				const auto& newStats = GameData::GetLoadStats();
				LogInfo("[Settings] GameData reloaded: " + std::to_string(newStats.itemCount) + " items");
			}
			else
			{
				LogWarning("[Settings] Failed to load GameData from: " + newPath.string());
			}
		}
		else if (newPath.empty())
		{
			LogWarning("[Settings] Path is empty");
		}
		else
		{
			LogWarning("[Settings] Path does not exist: " + newPath.string());
		}
	}
	
	ImGui::SameLine();
	if (ImGui::Button("Clear Custom Path"))
	{
		s_pathBuffer[0] = '\0';
		settings.SetSqpackPath(std::filesystem::path());
		LogInfo("[Settings] Custom sqpack path cleared. Will use auto-detection on next load.");
	}
	
	ImGui::Spacing();
	ImGui::TextDisabled("Example: K:\\Program Files\\SquareEnix\\FINAL FANTASY XIV - A Realm Reborn\\game\\sqpack");
	
	// Test/Diagnostic section
	if (stats.initialized)
	{
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::TextUnformatted("Test Lookups");
		ImGui::Separator();
		
		// Test with some well-known IDs
		static int s_testItemId = 4;       // Fire Shard
		static int s_testActionId = 7;     // Attack
		static int s_testStatusId = 2;     // Weakness
		static int s_testMountId = 1;      // Company Chocobo
		
		ImGui::SetNextItemWidth(100);
		ImGui::InputInt("Item ID", &s_testItemId);
		ImGui::SameLine();
		if (const char* name = GameData::LookupItemName(static_cast<uint32_t>(s_testItemId)))
			ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "-> %s", name);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "-> (not found)");
		
		ImGui::SetNextItemWidth(100);
		ImGui::InputInt("Action ID", &s_testActionId);
		ImGui::SameLine();
		if (const char* name = GameData::LookupActionName(static_cast<uint32_t>(s_testActionId)))
			ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "-> %s", name);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "-> (not found)");
		
		ImGui::SetNextItemWidth(100);
		ImGui::InputInt("Status ID", &s_testStatusId);
		ImGui::SameLine();
		if (const char* name = GameData::LookupStatusName(static_cast<uint32_t>(s_testStatusId)))
			ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "-> %s", name);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "-> (not found)");
		
		ImGui::SetNextItemWidth(100);
		ImGui::InputInt("Mount ID", &s_testMountId);
		ImGui::SameLine();
		if (const char* name = GameData::LookupMountName(static_cast<uint32_t>(s_testMountId)))
			ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "-> %s", name);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "-> (not found)");
		
		ImGui::Spacing();
		ImGui::TextDisabled("Try known IDs: Item 4=Fire Shard, Action 7=Attack, Status 2=Weakness");
	}
}