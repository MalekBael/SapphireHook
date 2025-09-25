#include "../UI/UIManager.h"
#include "../UI/UIModule.h"
#include "../Modules/DebugCommandsModule.h"
#include "../Modules/FunctionCallMonitor.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include "../Modules/MemoryViewerModule.h"
#include "../Modules/GMCommandsModule.h"
#include "../Modules/NetDiagnosticsModule.h"
#include <Windows.h>
#include <Psapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>

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
	ULARGE_INTEGER m_lastCPU = {0};
	ULARGE_INTEGER m_lastSysCPU = {0};
	ULARGE_INTEGER m_lastUserCPU = {0};
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

void UIManager::RegisterDefaultModules()
{
 LogInfo("=== RegisterDefaultModules() called on instance: " +
  std::to_string(reinterpret_cast<uintptr_t>(this)) + " ===");
 LogInfo("Current module count before registration: " + std::to_string(m_modules.size()));

 int successCount = 0;

 try
 {
  if (GetModule("debug_commands") == nullptr)
  {
   LogInfo("Creating Debug Commands module...");
   auto debugModule = std::make_unique<DebugCommandsModule>();
   RegisterModule(std::move(debugModule));
   LogInfo("[OK] Debug Commands module registered");
   successCount++;
  }
  else
  {
   LogInfo("Debug Commands module already exists");
   successCount++;
  }
 }
 catch (const std::exception& e)
 {
  LogError("Failed to register Debug Commands: " + std::string(e.what()));
 }
 catch (...)
 {
  LogError("Failed to register Debug Commands: unknown exception");
 }

 try
 {
  if (GetModule("function_monitor") == nullptr)
  {
   LogInfo("Creating Function Call Monitor module...");
   auto functionModule = std::make_unique<FunctionCallMonitor>();
   RegisterModule(std::move(functionModule));
   LogInfo("[OK] Function Call Monitor module registered");
   successCount++;
  }
  else
  {
   LogInfo("Function Call Monitor module already exists");
   successCount++;
  }
 }
 catch (const std::exception& e)
 {
  LogError("Failed to register Function Call Monitor: " + std::string(e.what()));
 }
 catch (...)
 {
  LogError("Failed to register Function Call Monitor: unknown exception");
 }

 try
 {
  if (GetModule("memory_viewer") == nullptr)
  {
   LogInfo("Creating Memory Viewer module...");
   auto memView = std::make_unique<MemoryViewerModule>();
   RegisterModule(std::move(memView));
   LogInfo("[OK] Memory Viewer module registered");
   successCount++;
  }
  else
  {
   LogInfo("Memory Viewer module already exists");
   successCount++;
  }
 }
 catch (const std::exception& e)
 {
  LogError("Failed to register Memory Viewer: " + std::string(e.what()));
 }
 catch (...)
 {
  LogError("Failed to register Memory Viewer: unknown exception");
 }

 try
 {
  if (GetModule("gm_commands") == nullptr)
  {
   LogInfo("Creating GM Commands module...");
   auto gm = std::make_unique<GMCommandsModule>();
   RegisterModule(std::move(gm));
   LogInfo("[OK] GM Commands module registered");
   successCount++;
  }
  else
  {
   LogInfo("GM Commands module already exists");
   successCount++;
  }
 }
 catch (const std::exception& e)
 {
  LogError("Failed to register GM Commands: " + std::string(e.what()));
 }
 catch (...)
 {
  LogError("Failed to register GM Commands: unknown exception");
 }

	// Unified Network Monitor (packets + graphs)
	try
	{
		if (GetModule("net_diagnostics") == nullptr)
		{
			LogInfo("Creating Net Diagnostics module...");
			auto net = std::make_unique<NetDiagnosticsModule>();
			RegisterModule(std::move(net));
			LogInfo("[OK] Net Diagnostics module registered");
			successCount++;
		}
		else
		{
			LogInfo("Net Diagnostics module already exists");
			successCount++;
		}
	}
	catch (const std::exception& e)
	{
		LogError("Failed to register Net Diagnostics: " + std::string(e.what()));
	}
	catch (...)
	{
		LogError("Failed to register Net Diagnostics: unknown exception");
	}

 LogInfo("=== MODULE REGISTRATION COMPLETE ===");
 LogInfo("Successfully registered: " + std::to_string(successCount) + "/5 modules");
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

			if (m_modules.empty())
			{
				if (menuRenderCount <= 3)
				{
					LogError("NO MODULES FOUND FOR RENDERING! Instance: " +
						std::to_string(reinterpret_cast<uintptr_t>(this)));
				}
			}
			else
			{
				for (size_t i = 0; i < m_modules.size(); ++i)
				{
					auto& module = m_modules[i];
					if (module && module->IsEnabled())
					{
						if (menuRenderCount <= 3)
						{
							LogInfo("Rendering menu for module #" + std::to_string(i + 1) + ": " +
								std::string(module->GetDisplayName()));
						}

						try
						{
							module->RenderMenu();
						}
						catch (...)
						{
							LogError("Exception rendering menu for module: " + std::string(module->GetDisplayName()));
						}
					}
					else if (module && !module->IsEnabled() && menuRenderCount <= 3)
					{
						LogInfo("Module " + std::string(module->GetDisplayName()) + " is disabled");
					}
					else if (!module && menuRenderCount <= 3)
					{
						LogError("Null module found at index " + std::to_string(i));
					}
				}
			}

			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("Tools"))
		{
			// Cache the module pointer once to avoid per-frame GetModule logging
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

			// Unified Network Monitor toggle
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

			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("Settings"))
		{
			ImGui::MenuItem("Configuration", nullptr, nullptr);
			ImGui::EndMenu();
		}

		// System monitoring display on the right side of the menu bar
		const float menuBarWidth = ImGui::GetWindowWidth();
		const float statusWidth = 500.0f; // Adjust as needed
		
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
		
		// Display system stats
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

 // Removed the demo window rendering since it's no longer needed
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