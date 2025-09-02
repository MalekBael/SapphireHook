#pragma once
#include "../UI/UIModule.h"
#include <cstdint>

class IPCCommandsModule : public SapphireHook::UIModule  // FIXED
{
private:
	struct IPCCommandInfo {
		const char* name;
		uint16_t opcode;
		const char* description;
	};

	static IPCCommandInfo s_commands[];
	int m_selectedCommand = 0;
	bool m_windowOpen = false;

	void SendIPCCommand(uint16_t opcode, const char* commandName);

public:
	const char* GetName() const override { return "ipc_commands"; }
	const char* GetDisplayName() const override { return "IPC Commands"; }

	void RenderMenu() override;
	void RenderWindow() override;

	bool IsWindowOpen() const override { return m_windowOpen; }
	void SetWindowOpen(bool open) override { m_windowOpen = open; }
};