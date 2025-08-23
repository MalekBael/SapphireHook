#include "UIManager.h"
#include "IPCCommandsModule.h"
#include "DebugCommandsModule.h"
#include "FunctionCallMonitor.h"
#include "imgui.h"
#include <algorithm>

UIManager::UIManager()
{
	// Register all modules
	RegisterModule(std::make_unique<IPCCommandsModule>());
	RegisterModule(std::make_unique<DebugCommandsModule>());
	RegisterModule(std::make_unique<FunctionCallMonitor>());

	// Initialize all modules
	for (auto& module : m_modules)
	{
		module->Initialize();
	}
}

UIManager::~UIManager()
{
	// Shutdown all modules
	for (auto& module : m_modules)
	{
		module->Shutdown();
	}
}

void UIManager::RegisterModule(std::unique_ptr<UIModule> module)
{
	m_modules.push_back(std::move(module));
}

UIModule* UIManager::GetModule(const char* name)
{
	auto it = std::find_if(m_modules.begin(), m_modules.end(),
		[name](const std::unique_ptr<UIModule>& module)
		{
			return strcmp(module->GetName(), name) == 0;
		});

	return (it != m_modules.end()) ? it->get() : nullptr;
}

void UIManager::RenderMainMenu()
{
	if (!m_showMenu) return;

	// Create top toolbar
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
				// Cleanup code would go here
			}
			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("Features"))
		{
			// Render module menu items
			for (auto& module : m_modules)
			{
				if (module->IsEnabled())
				{
					module->RenderMenu();
				}
			}

			ImGui::Separator();
			ImGui::MenuItem("ESP", nullptr, nullptr);
			ImGui::MenuItem("Teleport", nullptr, nullptr);
			ImGui::MenuItem("Speed Hack", nullptr, nullptr);
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

	// Render all module windows
	for (auto& module : m_modules)
	{
		if (module->IsEnabled())
		{
			module->RenderWindow();
		}
	}

	// Show demo window if enabled
	if (m_showDemoWindow)
	{
		ImGui::ShowDemoWindow(&m_showDemoWindow);
	}
}