#include "../UI/UIManager.h"
#include "../UI/UIModule.h"
#include "../Modules/IPCCommandsModule.h"
#include "../Modules/DebugCommandsModule.h"
#include "../Core/FunctionCallMonitor.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include "../Modules/MemoryViewerModule.h"
#include "../Modules/GMCommandsModule.h"
#include "../Modules/NetDiagnosticsModule.h"

using namespace SapphireHook;

UIManager* UIManager::s_instance = nullptr;

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
		if (GetModule("ipc_commands") == nullptr)
		{
			LogInfo("Creating IPC Commands module...");
			auto ipcModule = std::make_unique<IPCCommandsModule>();
			RegisterModule(std::move(ipcModule));
			LogInfo("[OK] IPC Commands module registered");
			successCount++;
		}
		else
		{
			LogInfo("IPC Commands module already exists");
			successCount++;
		}
	}
	catch (const std::exception& e)
	{
		LogError("Failed to register IPC Commands: " + std::string(e.what()));
	}
	catch (...)
	{
		LogError("Failed to register IPC Commands: unknown exception");
	}

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
	LogInfo("Successfully registered: " + std::to_string(successCount) + "/6 modules");
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

	ImGuiViewport* viewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowPos(viewport->Pos);
	ImGui::SetNextWindowSize(ImVec2(viewport->Size.x, 50));

	ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoBringToFrontOnFocus;

	ImGui::Begin("##MainMenuBar", nullptr, window_flags);

	if (ImGui::BeginMenuBar())
	{
		if (ImGui::BeginMenu("SapphireHook"))
		{
			ImGui::MenuItem("Show Demo Window", nullptr, &m_showDemoWindow);
			ImGui::Separator();
			if (ImGui::MenuItem("Exit"))
			{
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

			ImGui::Separator();
			ImGui::MenuItem("ESP", nullptr, nullptr);
			ImGui::MenuItem("Teleport", nullptr, nullptr);
			ImGui::MenuItem("Speed Hack", nullptr, nullptr);
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

		ImGui::EndMenuBar();
	}

	ImGui::Text("Press INSERT to toggle menu");
	ImGui::SameLine(ImGui::GetWindowWidth() - 150);
	ImGui::Text("FPS: %.1f", ImGui::GetIO().Framerate);

	ImGui::End();
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

	if (m_showDemoWindow)
	{
		ImGui::ShowDemoWindow(&m_showDemoWindow);
	}
}

size_t UIManager::GetModuleCount() const
{
	return m_modules.size();
}