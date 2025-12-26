// Ensure Windows headers don't pollute std headers with macros
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Windows + PDH must be included before using PDH_* types
#include <Windows.h>
#include <Psapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>

#include "../vendor/imgui/imgui.h"
#include <algorithm>
#include <cstring>
#include <cmath>
#include <unordered_map>
#include <mutex>
#include <DirectXMath.h>

#include "../UI/UIManager.h"
#include "../UI/UIModule.h"
#include "../Logger/Logger.h"

// Feature modules
#include "../Modules/CharacterEdit.h"
#include "../Modules/Weather.h"
#include "../Modules/DebugCommandsModule.h"
#include "../Modules/FunctionCallMonitor.h"
#include "../Modules/MemoryViewerModule.h"
#include "../Modules/GMCommandsModule.h"
#include "../Modules/NetDiagnosticsModule.h"
#include "../Modules/SettingsModule.h"

// Tool modules (new)
#include "../Tools/MemoryScanner.h"
#include "../Tools/StringXrefAnalyzer.h"
#include "../Tools/LiveTraceMonitor.h"
// NEW: Lua GameScript scanner module
#include "../Modules/LuaGameScriptModule.h"
// NEW: Debug visualization module
#include "../Modules/DebugVisualsModule.h"
// NEW: Collision/NavMesh overlay module
#include "../Modules/CollisionOverlayModule.h"
// NEW: Zone Layout Viewer for LGB data inspection
#include "../Modules/ZoneLayoutViewerModule.h"
// NEW: World Overlay manager module
#include "../Modules/WorldOverlayModule.h"
// NEW: Signature Scanner module for async pattern scanning
#include "../Modules/SignatureScannerModule.h"
// NEW: Camera extractor for player position display
#include "../Tools/GameCameraExtractor.h"
// Territory detection for zone display
#include "../Core/TerritoryScanner.h"
#include "../Core/GameDataLookup.h"

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

using namespace SapphireHook;

UIManager* UIManager::s_instance = nullptr;
bool UIManager::s_unloadRequested = false;

// System monitoring helper class
class SystemMonitor
{
private:
	PDH_HQUERY m_cpuQuery = nullptr;
	PDH_HCOUNTER m_cpuCounter = nullptr;
	ULARGE_INTEGER m_lastCPU = { 0 };
	ULARGE_INTEGER m_lastSysCPU = { 0 };
	ULARGE_INTEGER m_lastUserCPU = { 0 };
	HANDLE m_self = nullptr;
	int m_numProcessors = 0;

	// Network monitoring
	DWORD m_lastBytesIn = 0;
	DWORD m_lastBytesOut = 0;
	DWORD m_lastTime = 0;
	float m_downloadSpeed = 0.0f;
	float m_uploadSpeed = 0.0f;

	// Cached CPU value for less frequent updates
	float m_cachedCPUUsage = 0.0f;

	bool m_initialized = false;

public:
	SystemMonitor()
	{
		Initialize();
	}

	~SystemMonitor()
	{
		if (m_cpuQuery)
		{
			PdhCloseQuery(m_cpuQuery);
		}
		if (m_self && m_self != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_self);
		}
	}

	void Initialize()
	{
		// Initialize CPU monitoring
		PdhOpenQuery(nullptr, NULL, &m_cpuQuery);
		PdhAddEnglishCounterA(m_cpuQuery, "\\Processor(_Total)\\% Processor Time", NULL, &m_cpuCounter);
		PdhCollectQueryData(m_cpuQuery);

		// Get process handle for memory monitoring
		m_self = GetCurrentProcess();

		// Get number of processors
		SYSTEM_INFO sysInfo;
		GetSystemInfo(&sysInfo);
		m_numProcessors = sysInfo.dwNumberOfProcessors;

		// Initialize network counters
		UpdateNetworkStats();

		m_initialized = true;
	}

	void UpdateCPUUsage()
	{
		if (!m_initialized || !m_cpuQuery) return;

		PDH_FMT_COUNTERVALUE counterVal;
		PdhCollectQueryData(m_cpuQuery);
		PdhGetFormattedCounterValue(m_cpuCounter, PDH_FMT_DOUBLE, nullptr, &counterVal);
		m_cachedCPUUsage = static_cast<float>(counterVal.doubleValue);
	}

	float GetCPUUsage() const
	{
		return m_cachedCPUUsage;
	}

	float GetMemoryUsageMB()
	{
		if (!m_initialized || !m_self) return 0.0f;

		PROCESS_MEMORY_COUNTERS_EX pmc;
		if (GetProcessMemoryInfo(m_self, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc)))
		{
			return static_cast<float>(pmc.WorkingSetSize) / (1024.0f * 1024.0f);
		}
		return 0.0f;
	}

	void UpdateNetworkStats()
	{
		if (!m_initialized) return;

		PMIB_IFTABLE pIfTable = nullptr;
		DWORD dwSize = 0;

		// Get table size
		if (GetIfTable(pIfTable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER)
		{
			pIfTable = static_cast<PMIB_IFTABLE>(malloc(dwSize));
			if (pIfTable && GetIfTable(pIfTable, &dwSize, FALSE) == NO_ERROR)
			{
				DWORD currentTime = GetTickCount64();
				DWORD totalBytesIn = 0;
				DWORD totalBytesOut = 0;

				// Sum up all active interfaces
				for (DWORD i = 0; i < pIfTable->dwNumEntries; i++)
				{
					MIB_IFROW& row = pIfTable->table[i];
					if (row.dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL)
					{
						totalBytesIn += row.dwInOctets;
						totalBytesOut += row.dwOutOctets;
					}
				}

				// Calculate speeds if we have previous data
				if (m_lastTime > 0)
				{
					DWORD timeDiff = currentTime - m_lastTime;
					if (timeDiff > 0)
					{
						m_downloadSpeed = static_cast<float>(totalBytesIn - m_lastBytesIn) / (timeDiff / 1000.0f);
						m_uploadSpeed = static_cast<float>(totalBytesOut - m_lastBytesOut) / (timeDiff / 1000.0f);
					}
				}

				m_lastBytesIn = totalBytesIn;
				m_lastBytesOut = totalBytesOut;
				m_lastTime = currentTime;
			}

			if (pIfTable) free(pIfTable);
		}
	}

	float GetDownloadSpeed() const { return m_downloadSpeed; }
	float GetUploadSpeed() const { return m_uploadSpeed; }

	std::string FormatNetworkSpeed(float bytesPerSec) const
	{
		if (bytesPerSec < 1024.0f)
			return std::to_string(static_cast<int>(bytesPerSec)) + " B/s";
		else if (bytesPerSec < 1024.0f * 1024.0f)
			return std::to_string(static_cast<int>(bytesPerSec / 1024.0f)) + " KB/s";
		else
			return std::to_string(static_cast<int>(bytesPerSec / (1024.0f * 1024.0f))) + " MB/s";
	}
};

// Static system monitor instance
static SystemMonitor s_systemMonitor;

UIManager::UIManager()
{
	LogInfo("UIManager constructor called - instance created at: " +
		std::to_string(reinterpret_cast<uintptr_t>(this)));
}

UIManager::~UIManager()
{
	LogInfo("UIManager destructor called");
	for (auto& module : m_modules)
	{
		if (module)
		{
			module->Shutdown();
		}
	}
}

UIManager& UIManager::GetInstance()
{
	if (!s_instance)
	{
		LogInfo("Creating NEW UIManager singleton instance");
		s_unloadRequested = false; // ensure clean state on new instance
		s_instance = new UIManager();
		LogInfo("UIManager singleton created at: " +
			std::to_string(reinterpret_cast<uintptr_t>(s_instance)));
	}
	return *s_instance;
}

bool UIManager::HasInstance()
{
	return s_instance != nullptr;
}

void UIManager::Initialize()
{
	LogInfo("UIManager::Initialize() called on instance: " +
		std::to_string(reinterpret_cast<uintptr_t>(this)));
}

void UIManager::Shutdown()
{
	LogInfo("UIManager::Shutdown() called");
	if (s_instance)
	{
		delete s_instance;
		s_instance = nullptr;
		s_unloadRequested = false; // clear latched unload requests
		LogInfo("UIManager singleton destroyed");
	}
}

void UIManager::Render()
{
	RenderMainMenu();
	RenderAllWindows();
}

void UIManager::RegisterModule(std::unique_ptr<UIModule> module)
{
	if (module)
	{
		LogInfo("RegisterModule called on UIManager instance: " +
			std::to_string(reinterpret_cast<uintptr_t>(this)));
		LogInfo("Registering UI module: " + std::string(module->GetDisplayName()) +
			" (ID: " + std::string(module->GetName()) + ")");

		module->Initialize();
		m_modules.push_back(std::move(module));

		LogInfo("UI module registered successfully. Total modules: " + std::to_string(m_modules.size()));
		LogInfo("UIManager instance " + std::to_string(reinterpret_cast<uintptr_t>(this)) +
			" now has " + std::to_string(m_modules.size()) + " modules");
	}
	else
	{
		LogError("Attempted to register nullptr module!");
	}
}

UIModule* UIManager::GetModule(const char* name)
{
	// Throttle logging per module name (log only first 3 times)
	static std::unordered_map<std::string, int> s_logCount;
	const std::string key = name ? std::string(name) : std::string();

	auto itCount = s_logCount.find(key);
	const bool shouldLog = (itCount == s_logCount.end()) || (itCount->second < 3);
	if (shouldLog)
	{
		LogDebug("GetModule('" + std::string(name ? name : "") + "') called on instance: " +
			std::to_string(reinterpret_cast<uintptr_t>(this)) +
			" with " + std::to_string(m_modules.size()) + " modules");
		s_logCount[key] = (itCount == s_logCount.end()) ? 1 : (itCount->second + 1);
	}

	auto it = std::find_if(m_modules.begin(), m_modules.end(),
		[name](const std::unique_ptr<UIModule>& module)
		{
			if (!module) return false;
			bool matches = strcmp(module->GetName(), name) == 0;
			return matches;
		});

	UIModule* result = (it != m_modules.end()) ? it->get() : nullptr;

	if (shouldLog)
	{
		LogDebug(std::string("GetModule result: ") + (result ? "FOUND" : "NOT FOUND"));
	}
	return result;
}

// Helper template to reduce boilerplate in RegisterDefaultModules
// Returns true if module was registered or already exists, false on error
template<typename T>
bool UIManager::TryRegisterModule(const char* moduleId, const char* displayName, int& successCount)
{
	try {
		if (GetModule(moduleId) == nullptr) {
			LogInfo(std::string("Creating ") + displayName + " module...");
			RegisterModule(std::make_unique<T>());
			LogInfo(std::string("[OK] ") + displayName + " module registered");
			successCount++;
		}
		else {
			LogInfo(std::string(displayName) + " module already exists");
			successCount++;
		}
		return true;
	}
	catch (const std::exception& e) {
		LogError(std::string("Failed to register ") + displayName + ": " + e.what());
		return false;
	}
	catch (...) {
		LogError(std::string("Failed to register ") + displayName + ": unknown exception");
		return false;
	}
}

void UIManager::RegisterDefaultModules()
{
	LogInfo("=== RegisterDefaultModules() called on instance: " +
		std::to_string(reinterpret_cast<uintptr_t>(this)) + " ===");
	LogInfo("Current module count before registration: " + std::to_string(m_modules.size()));

	int successCount = 0;

	// Core feature modules
	TryRegisterModule<DebugCommandsModule>("debug_commands", "Debug Commands", successCount);
	TryRegisterModule<FunctionCallMonitor>("function_monitor", "Function Call Monitor", successCount);
	TryRegisterModule<MemoryViewerModule>("memory_viewer", "Memory Viewer", successCount);
	TryRegisterModule<GMCommandsModule>("gm_commands", "GM Commands", successCount);
	TryRegisterModule<NetDiagnosticsModule>("net_diagnostics", "Net Diagnostics", successCount);
	TryRegisterModule<SettingsModule>("settings", "Settings", successCount);

	// Tool modules
	TryRegisterModule<SapphireHook::MemoryScanner>("MemoryScanner", "Memory Scanner", successCount);
	TryRegisterModule<SapphireHook::StringXrefAnalyzer>("StringXrefAnalyzer", "String XREF Analyzer", successCount);
	TryRegisterModule<SapphireHook::CharacterEditModule>("CharacterEdit", "Character Edit", successCount);
	TryRegisterModule<SapphireHook::WeatherModule>("Weather", "Weather", successCount);
	TryRegisterModule<SapphireHook::LiveTraceMonitor>("LiveTraceMonitor", "Live Trace Monitor", successCount);
	TryRegisterModule<SapphireHook::LuaGameScriptModule>("LuaGameScriptModule", "Lua GameScript", successCount);
	TryRegisterModule<SapphireHook::DebugVisualsModule>("debug_visuals", "Debug Visuals", successCount);
	TryRegisterModule<SapphireHook::CollisionOverlayModule>("collision_overlay", "Collision Overlay", successCount);
	TryRegisterModule<SapphireHook::ZoneLayoutViewerModule>("zone_layout_viewer", "Zone Layout Viewer", successCount);
	TryRegisterModule<SapphireHook::WorldOverlayModule>("world_overlay", "World Overlay", successCount);
	TryRegisterModule<SapphireHook::SignatureScannerModule>("signature_scanner", "Signature Scanner", successCount);

	LogInfo("=== MODULE REGISTRATION COMPLETE ===");
	LogInfo("Successfully registered: " + std::to_string(successCount) + " modules");
	LogInfo("Final module count on instance " + std::to_string(reinterpret_cast<uintptr_t>(this)) +
		": " + std::to_string(m_modules.size()));

	for (size_t i = 0; i < m_modules.size(); ++i)
	{
		if (m_modules[i])
		{
			LogInfo("  " + std::to_string(i + 1) + ". " +
				std::string(m_modules[i]->GetDisplayName()) +
				" (" + std::string(m_modules[i]->GetName()) + ")");
		}
		else
		{
			LogError("  " + std::to_string(i + 1) + ". NULL MODULE!");
		}
	}
}

void UIManager::VerifyDefaultModules()
{
	// Single source of truth for expected default modules
	static constexpr const char* kDefaultModules[] = {
		"debug_commands",
		"function_monitor",
		"memory_viewer",
		"gm_commands",
		"net_diagnostics",
		"settings",
		// Tool modules with original casing
		"MemoryScanner",
		"StringXrefAnalyzer",
		"LiveTraceMonitor",
		"LuaGameScriptModule",
		"debug_visuals",
		"collision_overlay",
		"zone_layout_viewer"
	};

	LogInfo("=== DEFAULT MODULE VERIFICATION START ===");
	size_t missing = 0;
	for (const char* name : kDefaultModules)
	{
		if (GetModule(name))
			LogInfo(std::string("[OK] ") + name);
		else
		{
			LogError(std::string("[MISSING] ") + name);
			++missing;
		}
	}
	if (missing == 0)
		LogInfo("All default modules present");
	else
		LogError(std::to_string(missing) + " default modules missing");
	LogInfo("=== DEFAULT MODULE VERIFICATION END ===");
}

void UIManager::LogModuleSummary() const
{
	LogInfo("=== MODULE SUMMARY (" + std::to_string(m_modules.size()) + ") ===");
	if (m_modules.empty())
	{
		LogError("No modules registered");
		return;
	}
	for (const auto& mod : m_modules)
	{
		if (mod)
			LogInfo(" - " + std::string(mod->GetDisplayName()) + " (" + mod->GetName() + ")");
		else
			LogError(" - NULL MODULE POINTER");
	}
}

void UIManager::RenderMainMenu()
{
	if (!m_showMenu) return;

	static int renderCount = 0;
	renderCount++;
	if (renderCount <= 5)
	{
		LogInfo("RenderMainMenu called on instance: " +
			std::to_string(reinterpret_cast<uintptr_t>(this)) +
			" with " + std::to_string(m_modules.size()) + " modules");
	}

	// Update system monitoring data periodically
	static DWORD lastNetworkUpdate = 0;
	static DWORD lastCPUUpdate = 0;
	DWORD currentTime = GetTickCount64(); // Use 64-bit version

	// Update network stats every second
	if (currentTime - lastNetworkUpdate > 1000)
	{
		s_systemMonitor.UpdateNetworkStats();
		lastNetworkUpdate = currentTime;
	}

	// Update CPU usage every 15 seconds to prevent "tripping"
	if (currentTime - lastCPUUpdate > 15000)
	{
		s_systemMonitor.UpdateCPUUsage();
		lastCPUUpdate = currentTime;
	}

	ImGuiViewport* viewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowPos(viewport->Pos);
	ImGui::SetNextWindowSize(ImVec2(viewport->Size.x, 50));

	// Add NoBackground flag to remove the light grey bar
	ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoBackground;

	ImGui::Begin("##MainMenuBar", nullptr, window_flags);

	if (ImGui::BeginMenuBar())
	{
		if (ImGui::BeginMenu("SapphireHook"))
		{
			// Enhanced unload option with confirmation
			if (ImGui::MenuItem("Unload DLL"))
			{
				ImGui::OpenPopup("Confirm Unload");
			}

			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("Features"))
		{
			static int menuRenderCount = 0;
			menuRenderCount++;
			if (menuRenderCount <= 3)
			{
				LogInfo("Rendering Features menu with " + std::to_string(m_modules.size()) +
					" modules on instance: " + std::to_string(reinterpret_cast<uintptr_t>(this)));
			}

			if (!m_modules.empty())
			{
				// Only show main feature modules in Features menu
				static const char* featureModules[] = {
					"debug_commands",
					"function_monitor",
					"gm_commands"
				};

				for (const char* modName : featureModules)
				{
					UIModule* module = GetModule(modName);
					if (module && module->IsEnabled())
					{
						try
						{
							module->RenderMenu();
						}
						catch (...)
						{
							LogError("Exception rendering menu for module: " + std::string(module->GetDisplayName()));
						}
					}
				}
			}

			ImGui::Separator();
			{
				static UIModule* s_charEdit = nullptr;
				if (!s_charEdit)
					s_charEdit = GetModule("CharacterEdit");
				if (s_charEdit) {
					bool open = s_charEdit->IsWindowOpen();
					if (ImGui::MenuItem("Character Edit", nullptr, open)) {
						s_charEdit->SetWindowOpen(!open);
					}
				}
				else {
					ImGui::MenuItem("Character Edit", nullptr, false, false); // disabled until module is registered
				}

				// Weather (module-driven; no UIManager globals)
				static UIModule* s_weather = nullptr;
				if (!s_weather)
					s_weather = GetModule("Weather");
				if (s_weather) {
					bool open = s_weather->IsWindowOpen();
					if (ImGui::MenuItem("Weather", nullptr, open)) {
						s_weather->SetWindowOpen(!open);
					}
				}
				else {
					ImGui::MenuItem("Weather", nullptr, false, false); // disabled until module is registered
				}
			}

			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("Tools"))
		{
			// Memory Viewer
			{
				static UIModule* s_memViewer = nullptr;
				if (!s_memViewer)
					s_memViewer = GetModule("memory_viewer");

				if (s_memViewer)
				{
					bool open = s_memViewer->IsWindowOpen();
					if (ImGui::MenuItem("Memory Viewer", nullptr, open))
					{
						s_memViewer->SetWindowOpen(!open);
					}
				}
				else
				{
					ImGui::MenuItem("Memory Viewer", nullptr, false, false);
				}
			}

			// Memory Scanner
			{
				static UIModule* s_memScanner = nullptr;
				if (!s_memScanner)
					s_memScanner = GetModule("MemoryScanner");  // Original casing
				if (s_memScanner)
				{
					bool open = s_memScanner->IsWindowOpen();
					if (ImGui::MenuItem(s_memScanner->GetDisplayName(), nullptr, open))
					{
						s_memScanner->SetWindowOpen(!open);
					}
				}
			}

			// String XREF Analyzer
			{
				static UIModule* s_stringAnalyzer = nullptr;
				if (!s_stringAnalyzer)
					s_stringAnalyzer = GetModule("StringXrefAnalyzer");  // Original casing
				if (s_stringAnalyzer)
				{
					bool open = s_stringAnalyzer->IsWindowOpen();
					if (ImGui::MenuItem(s_stringAnalyzer->GetDisplayName(), nullptr, open))
					{
						s_stringAnalyzer->SetWindowOpen(!open);
					}
				}
			}

			// Live Trace Monitor
			{
				static UIModule* s_liveMonitor = nullptr;
				if (!s_liveMonitor)
					s_liveMonitor = GetModule("LiveTraceMonitor");  // Original casing
				if (s_liveMonitor)
				{
					bool open = s_liveMonitor->IsWindowOpen();
					if (ImGui::MenuItem(s_liveMonitor->GetDisplayName(), nullptr, open))
					{
						s_liveMonitor->SetWindowOpen(!open);
					}
				}
			}

			// NEW: Lua GameScript Scanner
			{
				static UIModule* s_luaMod = nullptr;
				if (!s_luaMod)
					s_luaMod = GetModule("LuaGameScriptModule");  // Module name

				if (s_luaMod)
				{
					bool open = s_luaMod->IsWindowOpen();
					if (ImGui::MenuItem(s_luaMod->GetDisplayName(), nullptr, open))
					{
						s_luaMod->SetWindowOpen(!open);
					}
				}
			}

			// Debug Visuals (3D world debug rendering)
			{
				static UIModule* s_debugVisuals = nullptr;
				if (!s_debugVisuals)
					s_debugVisuals = GetModule("debug_visuals");

				if (s_debugVisuals)
				{
					bool open = s_debugVisuals->IsWindowOpen();
					if (ImGui::MenuItem(s_debugVisuals->GetDisplayName(), nullptr, open))
					{
						s_debugVisuals->SetWindowOpen(!open);
					}
				}
			}

			// Collision Overlay (collision mesh & navmesh visualization)
			{
				static UIModule* s_collisionOverlay = nullptr;
				if (!s_collisionOverlay)
					s_collisionOverlay = GetModule("collision_overlay");

				if (s_collisionOverlay)
				{
					bool open = s_collisionOverlay->IsWindowOpen();
					if (ImGui::MenuItem(s_collisionOverlay->GetDisplayName(), nullptr, open))
					{
						s_collisionOverlay->SetWindowOpen(!open);
					}
				}
			}

			// Zone Layout Viewer (LGB data inspection)
			{
				static UIModule* s_zoneLayoutViewer = nullptr;
				if (!s_zoneLayoutViewer)
					s_zoneLayoutViewer = GetModule("zone_layout_viewer");

				if (s_zoneLayoutViewer)
				{
					bool open = s_zoneLayoutViewer->IsWindowOpen();
					if (ImGui::MenuItem(s_zoneLayoutViewer->GetDisplayName(), nullptr, open))
					{
						s_zoneLayoutViewer->SetWindowOpen(!open);
					}
				}
			}

			// World Overlay (zone-aware 3D overlays, navmesh, pathfinding)
			{
				static UIModule* s_worldOverlay = nullptr;
				static bool s_worldOverlayLogged = false;
				if (!s_worldOverlay)
				{
					s_worldOverlay = GetModule("world_overlay");
					if (!s_worldOverlayLogged)
					{
						if (s_worldOverlay)
							LogInfo("[Menu] World Overlay module found");
						else
							LogError("[Menu] World Overlay module NOT found!");
						s_worldOverlayLogged = true;
					}
				}

				if (s_worldOverlay)
				{
					bool open = s_worldOverlay->IsWindowOpen();
					if (ImGui::MenuItem(s_worldOverlay->GetDisplayName(), nullptr, open))
					{
						s_worldOverlay->SetWindowOpen(!open);
					}
				}
				else
				{
					ImGui::MenuItem("World Overlay", nullptr, false, false);  // Show disabled if not found
				}
			}

			// Signature Scanner (async pattern discovery)
			{
				static UIModule* s_sigScanner = nullptr;
				if (!s_sigScanner)
					s_sigScanner = GetModule("signature_scanner");

				if (s_sigScanner)
				{
					bool open = s_sigScanner->IsWindowOpen();
					if (ImGui::MenuItem(s_sigScanner->GetDisplayName(), nullptr, open))
					{
						s_sigScanner->SetWindowOpen(!open);
					}
				}
				else
				{
					ImGui::MenuItem("Signature Scanner", nullptr, false, false);
				}
			}

			ImGui::Separator();

			// Unified Network Monitor toggle
			{
				static UIModule* sNetMod = nullptr;
				if (!sNetMod)
					sNetMod = GetModule("net_diagnostics");
				if (sNetMod)
				{
					bool open = sNetMod->IsWindowOpen();
					if (ImGui::MenuItem("Network Monitor", nullptr, open))
					{
						sNetMod->SetWindowOpen(!open);
					}
				}
				else
				{
					ImGui::MenuItem("Network Monitor", nullptr, false, false);
				}
			}

			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("Settings"))
		{
			static UIModule* s_settings = nullptr;
			if (!s_settings)
				s_settings = GetModule("settings");

			if (s_settings)
			{
				bool open = s_settings->IsWindowOpen();
				if (ImGui::MenuItem("Settings Window", nullptr, open))
					s_settings->SetWindowOpen(!open);
			}
			else
			{
				ImGui::MenuItem("Settings Window", nullptr, false, false);
			}
			ImGui::EndMenu();
		}

		// System monitoring display on the right side of the menu bar
		const float menuBarWidth = ImGui::GetWindowWidth();
		const float statusWidth = 650.0f; // Increased for player position display

		ImGui::SetCursorPosX(menuBarWidth - statusWidth);

		// Get system stats (CPU now uses cached value)
		float cpuUsage = s_systemMonitor.GetCPUUsage();
		float memUsage = s_systemMonitor.GetMemoryUsageMB();
		float downSpeed = s_systemMonitor.GetDownloadSpeed();
		float upSpeed = s_systemMonitor.GetUploadSpeed();
		float fps = ImGui::GetIO().Framerate;

		// Format network speeds
		std::string downSpeedStr = s_systemMonitor.FormatNetworkSpeed(downSpeed);
		std::string upSpeedStr = s_systemMonitor.FormatNetworkSpeed(upSpeed);
		
		// Get player position from camera extractor - use LIVE read for real-time updates
		DirectX::XMFLOAT3 playerPos = {0.0f, 0.0f, 0.0f};
		bool hasPlayerPos = false;
		auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
		if (cameraExtractor.IsInitialized()) {
			playerPos = cameraExtractor.GetPlayerPositionLive();
			// Consider valid if any component is non-zero
			hasPlayerPos = (std::abs(playerPos.x) > 0.1f || 
			                std::abs(playerPos.y) > 0.1f || 
			                std::abs(playerPos.z) > 0.1f);
		}

		// Display system stats with zone info, player position, and performance
		// Zone info from TerritoryScanner
		auto& terrScanner = TerritoryScanner::GetInstance();
		auto terrState = terrScanner.GetCurrentState();
		if (terrState.IsValid()) {
			const char* zoneName = GameData::LookupTerritoryName(terrState.TerritoryType);
			if (zoneName && zoneName[0]) {
				ImGui::Text("%s (%u)", zoneName, terrState.TerritoryType);
			} else {
				ImGui::Text("Zone %u", terrState.TerritoryType);
			}
			ImGui::SameLine();
			ImGui::Text(" | ");
			ImGui::SameLine();
		}
		
		// Player position
		if (hasPlayerPos) {
			ImGui::Text("Pos: (%.0f, %.0f, %.0f)", playerPos.x, playerPos.y, playerPos.z);
			ImGui::SameLine();
			ImGui::Text(" | ");
			ImGui::SameLine();
		}
		ImGui::Text("FPS: %.1f", fps);
		ImGui::SameLine();
		ImGui::Text(" | CPU: %.1f%%", cpuUsage);
		ImGui::SameLine();
		ImGui::Text(" | RAM: %.1f MB", memUsage);
		ImGui::SameLine();
		ImGui::Text(" | down %s up %s", downSpeedStr.c_str(), upSpeedStr.c_str());

		ImGui::EndMenuBar();
	}

	ImGui::End();

	// Confirmation popup for unload
	if (ImGui::BeginPopupModal("Confirm Unload", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Are you sure you want to unload SapphireHook?");
		ImGui::Text("This will safely remove all hooks and close all windows.");
		ImGui::Separator();

		if (ImGui::Button("Yes, Unload"))
		{
			RequestUnload();
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine();
		if (ImGui::Button("Cancel"))
		{
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}

void UIManager::RenderAllWindows()
{
	if (!m_showMenu) return;

	for (auto& module : m_modules)
	{
		if (module && module->IsEnabled())
		{
			try
			{
				module->RenderWindow();
			}
			catch (...)
			{
				LogError("Exception rendering window for module: " + std::string(module->GetDisplayName()));
			}
		}
	}
}

void UIManager::RequestUnload()
{
	LogInfo("DLL unload requested via menu");
	s_unloadRequested = true;
}

bool UIManager::IsUnloadRequested()
{
	return s_unloadRequested;
}

bool UIManager::EnsureBootstrapped()
{
	static std::once_flag s_once;
	std::call_once(s_once, []() {
		// Create singleton and register all modules once
		UIManager& ui = UIManager::GetInstance();
		ui.RegisterDefaultModules();
		ui.LogModuleSummary();
		});
	return true;
}