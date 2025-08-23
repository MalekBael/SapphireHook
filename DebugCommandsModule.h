#pragma once
#include "UIModule.h"
#include <imgui.h>

class DebugCommandsModule : public UIModule
{
private:
	struct DebugCommandInfo
	{
		const char* name;
		const char* description;
		int gmLevel;
		const char* subCommands[20];
		const char* examples[20];
	};

	static DebugCommandInfo s_commands[];

	int m_selectedCommand = 0;
	int m_selectedSubCommand = -1;
	char m_commandParams[256] = {};
	bool m_windowOpen = false;  // Add this missing member variable

	// Command injection methods
	bool TryPacketInjection(const char* command);
	bool TryMemoryPatching(const char* command);
	bool TryKeyboardSimulation(const char* command);

public:
	const char* GetName() const override { return "DebugCommands"; }
	const char* GetDisplayName() const override { return "Debug Commands"; }

	void RenderMenu() override;
	void RenderWindow() override;
	void Initialize() override;

	// Override base class window state methods
	bool IsWindowOpen() const override { return m_windowOpen; }
	void SetWindowOpen(bool open) override { m_windowOpen = open; }

	void SendDebugCommand(const char* command, const char* subCommand, const char* params);
	void TryInjectChatCommand(const char* command);
};