#pragma once
#include "UIModule.h"
#include <vector>
#include <memory>

class UIManager
{
private:
	std::vector<std::unique_ptr<UIModule>> m_modules;
	bool m_showMenu = true;
	bool m_showDemoWindow = false;

public:
	UIManager();
	~UIManager();

	// Module management
	void RegisterModule(std::unique_ptr<UIModule> module);
	UIModule* GetModule(const char* name);

	// UI rendering
	void RenderMainMenu();
	void RenderAllWindows();

	// Menu state
	bool IsMenuVisible() const { return m_showMenu; }
	void SetMenuVisible(bool visible) { m_showMenu = visible; }
	void ToggleMenu() { m_showMenu = !m_showMenu; }
};