#pragma once
#pragma once
#include "imgui.h"

class UIModule
{
public:
	virtual ~UIModule() = default;

	// Module identification
	virtual const char* GetName() const = 0;
	virtual const char* GetDisplayName() const = 0;

	// Module lifecycle
	virtual void Initialize() {}
	virtual void Shutdown() {}

	// UI rendering
	virtual void RenderMenu() {}  // For menu bar items
	virtual void RenderWindow() {} // For standalone windows

	// Module state
	virtual bool IsWindowOpen() const { return false; }
	virtual void SetWindowOpen(bool open) {}

	// Module settings
	virtual bool IsEnabled() const { return true; }
	virtual void SetEnabled(bool enabled) {}
};