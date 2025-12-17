#include "SettingsModule.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include "../Core/PacketInjector.h"
#include "../Core/SettingsManager.h"
#include "../Core/GameDataLookup.h"
#include "../Core/NavMeshManager.h"
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

	if (ImGui::CollapsingHeader("EXD Test Lookups"))
	{
		DrawExdTestLookupsSection();
	}

	if (ImGui::CollapsingHeader("NavMesh (navi)", ImGuiTreeNodeFlags_DefaultOpen))
	{
		DrawNavMeshSection();
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
}

void SettingsModule::DrawExdTestLookupsSection()
{
	const auto& stats = GameData::GetLoadStats();
	
	if (!stats.initialized)
	{
		ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Game data not loaded. Configure sqpack path above.");
		return;
	}
	
	ImGui::TextDisabled("Test EXD sheet lookups by entering IDs. Green = found, Red = not found.");
	ImGui::Spacing();
	
	// Helper lambda for rendering a lookup row
	auto RenderLookup = [](const char* label, int& id, const char* (*lookupFn)(uint32_t)) {
		ImGui::SetNextItemWidth(80);
		ImGui::InputInt(label, &id);
		ImGui::SameLine();
		if (const char* name = lookupFn(static_cast<uint32_t>(id)))
			ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "-> %s", name);
		else
			ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "-> (not found)");
	};
	
	// Static test IDs for each sheet
	static int s_itemId = 4;            // Fire Shard
	static int s_actionId = 7;          // Attack
	static int s_statusId = 2;          // Stun
	static int s_classJobId = 1;        // Gladiator
	static int s_mountId = 1;           // Company Chocobo
	static int s_minionId = 1;          // Chocobo Chick
	static int s_emoteId = 1;           // /sit
	static int s_questId = 65575;       // First quest
	static int s_territoryId = 132;     // Limsa Lominsa Upper Decks
	static int s_weatherId = 1;         // Clear Skies
	static int s_worldId = 21;          // Hyperion
	static int s_aetheryteId = 8;       // Limsa Aetheryte
	static int s_instanceId = 1;        // First dungeon
	static int s_bnpcId = 1;            // First BNpc
	static int s_enpcId = 1002299;      // An NPC
	static int s_placeNameId = 30;      // PlaceName
	static int s_mapId = 1;             // Map
	
	if (ImGui::BeginTabBar("ExdLookupTabs"))
	{
		if (ImGui::BeginTabItem("Common"))
		{
			ImGui::Spacing();
			RenderLookup("Item", s_itemId, GameData::LookupItemName);
			RenderLookup("Action", s_actionId, GameData::LookupActionName);
			RenderLookup("Status", s_statusId, GameData::LookupStatusName);
			RenderLookup("ClassJob", s_classJobId, [](uint32_t id) { return GameData::LookupClassJobName(static_cast<uint8_t>(id)); });
			ImGui::Spacing();
			ImGui::TextDisabled("Item 4=Fire Shard, Action 7=Attack, Status 2=Stun, ClassJob 1=GLD");
			ImGui::EndTabItem();
		}
		
		if (ImGui::BeginTabItem("Entities"))
		{
			ImGui::Spacing();
			RenderLookup("Mount", s_mountId, GameData::LookupMountName);
			RenderLookup("Minion", s_minionId, GameData::LookupMinionName);
			RenderLookup("Emote", s_emoteId, GameData::LookupEmoteName);
			RenderLookup("Quest", s_questId, GameData::LookupQuestName);
			ImGui::Spacing();
			ImGui::TextDisabled("Mount 1=Company Chocobo, Emote 1=/sit");
			ImGui::EndTabItem();
		}
		
		if (ImGui::BeginTabItem("World"))
		{
			ImGui::Spacing();
			RenderLookup("Territory", s_territoryId, GameData::LookupTerritoryName);
			RenderLookup("Weather", s_weatherId, GameData::LookupWeatherName);
			RenderLookup("World", s_worldId, GameData::LookupWorldName);
			RenderLookup("Aetheryte", s_aetheryteId, GameData::LookupAetheryteName);
			RenderLookup("Instance", s_instanceId, GameData::LookupInstanceContentName);
			RenderLookup("Map", s_mapId, GameData::LookupMapPath);
			ImGui::Spacing();
			ImGui::TextDisabled("Territory 132=Limsa Upper, Weather 1=Clear, World 21=Hyperion");
			ImGui::EndTabItem();
		}
		
		if (ImGui::BeginTabItem("NPCs"))
		{
			ImGui::Spacing();
			RenderLookup("BNpcName", s_bnpcId, GameData::LookupBNpcName);
			RenderLookup("ENpcName", s_enpcId, GameData::LookupENpcName);
			RenderLookup("PlaceName", s_placeNameId, GameData::LookupPlaceName);
			ImGui::Spacing();
			ImGui::TextDisabled("ENpc IDs start around 1000000+");
			ImGui::EndTabItem();
		}
		
		ImGui::EndTabBar();
	}
}

void SettingsModule::DrawNavMeshSection()
{
	auto& settings = SettingsManager::Instance();
	auto& navMgr = NavMeshManager::GetInstance();
	
	ImGui::TextUnformatted("Sapphire Server NavMesh Path");
	ImGui::Separator();
	
	ImGui::PushTextWrapPos();
	ImGui::TextUnformatted(
		"Path to the Sapphire server's /navi/ folder containing zone NavMesh files.\n"
		"Structure: {navi_path}/{zone_bg_name}/*.nav\n"
		"Example: D:\\Sapphire\\navi\\a2d1\\mesh.nav");
	ImGui::PopTextWrapPos();
	ImGui::Spacing();
	
	// Show current status
	auto currentPath = navMgr.GetNavMeshBasePath();
	bool hasNavMesh = navMgr.HasNavMesh();
	
	if (!currentPath.empty() && std::filesystem::exists(currentPath))
	{
		ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Status: Path Set");
		if (hasNavMesh)
		{
			auto stats = navMgr.GetCurrentNavMeshStats();
			ImGui::SameLine();
			ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), " | NavMesh Loaded (%zu polys)", stats.totalPolygons);
		}
	}
	else if (!currentPath.empty())
	{
		ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Status: Path not found");
	}
	else
	{
		ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Status: Not configured");
	}
	
	ImGui::TextUnformatted("Current Path:");
	ImGui::SameLine();
	ImGui::TextDisabled("%s", currentPath.empty() ? "(none)" : currentPath.string().c_str());
	
	ImGui::Spacing();
	
	// Path input
	ImGui::TextUnformatted("NavMesh Path:");
	static char s_naviPathBuffer[512] = {};
	
	// Initialize buffer from current path on first frame
	static bool s_naviBufferInitialized = false;
	if (!s_naviBufferInitialized && !currentPath.empty())
	{
		strncpy_s(s_naviPathBuffer, currentPath.string().c_str(), sizeof(s_naviPathBuffer) - 1);
		s_naviBufferInitialized = true;
	}
	
	ImGui::SetNextItemWidth(-100);
	ImGui::InputText("##navipath", s_naviPathBuffer, sizeof(s_naviPathBuffer));
	
	ImGui::SameLine();
	if (ImGui::Button("Browse...##navi"))
	{
		// Open folder browser dialog
		IFileDialog* pFileDialog = nullptr;
		HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileDialog));
		if (SUCCEEDED(hr))
		{
			DWORD options;
			pFileDialog->GetOptions(&options);
			pFileDialog->SetOptions(options | FOS_PICKFOLDERS);
			pFileDialog->SetTitle(L"Select Sapphire Server /navi/ Folder");
			
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
						strncpy_s(s_naviPathBuffer, selectedPath.string().c_str(), sizeof(s_naviPathBuffer) - 1);
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
	if (ImGui::Button("Apply & Reload NavMesh"))
	{
		std::filesystem::path newPath(s_naviPathBuffer);
		if (!newPath.empty() && std::filesystem::exists(newPath))
		{
			navMgr.SetNavMeshBasePath(newPath);
			
			// Try to reload navmesh for current zone
			auto terrId = navMgr.GetCurrentTerritoryId();
			if (terrId != 0)
			{
				if (navMgr.LoadNavMeshForZone(terrId))
				{
					LogInfo("[Settings] NavMesh loaded for zone " + std::to_string(terrId));
				}
				else
				{
					LogInfo("[Settings] No NavMesh found for zone " + std::to_string(terrId));
				}
			}
		}
		else if (newPath.empty())
		{
			LogWarning("[Settings] NavMesh path is empty");
		}
		else
		{
			LogWarning("[Settings] NavMesh path does not exist: " + newPath.string());
		}
	}
	
	ImGui::SameLine();
	if (ImGui::Button("Clear NavMesh Path"))
	{
		s_naviPathBuffer[0] = '\0';
		settings.SetNavMeshPath(std::filesystem::path());
		navMgr.ClearNavMesh();
		LogInfo("[Settings] NavMesh path cleared.");
	}
	
	ImGui::Spacing();
	ImGui::TextDisabled("Example: D:\\Sapphire\\navi");
}