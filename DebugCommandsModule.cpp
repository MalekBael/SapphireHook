#include "DebugCommandsModule.h"
#include "CommandInterface.h"
#include <cstdio>
#include <cstring>
#include <string>

// Add these includes for game integration
#include <Windows.h>
#include "patternscanner.h"

void DebugCommandsModule::TryInjectChatCommand(const char* command)
{
	printf("[SapphireHook] Attempting to inject chat command: !%s\n", command);

	// Try different methods to inject the command

	// Method 1: Try to send via CommandInterface first
	std::string fullCommand = "!" + std::string(command);
	if (CommandInterface::SendChatMessage(fullCommand.c_str(), 0))
	{
		printf("[DebugCommandsModule] Successfully sent command via CommandInterface\n");
		return;
	}

	// Method 2: Try packet injection if we can find the network functions
	if (TryPacketInjection(command))
	{
		printf("[DebugCommandsModule] Successfully sent command via packet injection\n");
		return;
	}

	// Method 3: Try memory patching approach
	if (TryMemoryPatching(command))
	{
		printf("[DebugCommandsModule] Successfully sent command via memory patching\n");
		return;
	}

	// Method 4: Fallback to keyboard simulation
	if (TryKeyboardSimulation(command))
	{
		printf("[DebugCommandsModule] Successfully sent command via keyboard simulation\n");
		return;
	}

	printf("[DebugCommandsModule] All command injection methods failed\n");
}

bool DebugCommandsModule::TryPacketInjection(const char* command)
{
	printf("[DebugCommandsModule] Attempting packet injection for: %s\n", command);

	// This would involve finding the game's packet queue and injecting directly
	// For now, return false as this needs more implementation

	printf("[DebugCommandsModule] Packet injection not yet fully implemented\n");
	return false;
}

bool DebugCommandsModule::TryMemoryPatching(const char* command)
{
	printf("[DebugCommandsModule] Attempting memory patching for: %s\n", command);

	// This would involve finding the game's command buffer and writing directly
	// For now, return false as this needs more implementation

	printf("[DebugCommandsModule] Memory patching not yet fully implemented\n");
	return false;
}

bool DebugCommandsModule::TryKeyboardSimulation(const char* command)
{
	printf("[DebugCommandsModule] Attempting keyboard simulation for: %s\n", command);

	// Get the game window
	HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
	if (!gameWindow)
	{
		printf("[DebugCommandsModule] Could not find game window\n");
		return false;
	}

	// Check if the window is visible and active
	if (!IsWindowVisible(gameWindow))
	{
		printf("[DebugCommandsModule] Game window is not visible\n");
		return false;
	}

	// Focus the game window
	SetForegroundWindow(gameWindow);
	Sleep(100); // Give it time to focus

	// Verify we have focus
	if (GetForegroundWindow() != gameWindow)
	{
		printf("[DebugCommandsModule] Failed to focus game window\n");
		return false;
	}

	// Open chat (Enter key)
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
	Sleep(100); // Wait for chat to open

	// Type the command with "!" prefix
	std::string fullCommand = "!" + std::string(command);
	for (char c : fullCommand)
	{
		SHORT vk = VkKeyScanA(c);
		BYTE key = LOBYTE(vk);
		BYTE shift = HIBYTE(vk);

		if (shift & 1) // Shift needed
		{
			keybd_event(VK_SHIFT, 0, 0, 0);
		}

		keybd_event(key, 0, 0, 0);
		keybd_event(key, 0, KEYEVENTF_KEYUP, 0);

		if (shift & 1)
		{
			keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
		}

		Sleep(15); // Slightly longer delay for better reliability
	}

	// Send the command (Enter key)
	Sleep(50); // Small pause before sending
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);

	printf("[DebugCommandsModule] Keyboard simulation completed for: %s\n", fullCommand.c_str());
	return true;
}

// First, fix the commands array by properly terminating it
DebugCommandsModule::DebugCommandInfo DebugCommandsModule::s_commands[] = {
	{
		"set", "Executes SET commands.", 1,
		{"pos", "posr", "tele", "discovery", "discovery_reset", "classjob", "cfpenalty", "setMount", "weatheroverride", "festival", "BitFlag", "mobaggro", "recastreset", "freecompany", nullptr},
		{"set pos 100 20 50", "set tele 2", "set classjob 1", "set cfpenalty 30", "set setMount 1", "set weatheroverride 1", nullptr}
	},
	{
		"get", "Executes GET commands.", 1,
		{"pos", nullptr},
		{"get pos", nullptr}
	},
	{
		"add", "Executes ADD commands.", 1,
		{"status", "title", "op", "actrl", "actrls", "unlock", "unlockall", "effect", "achvGeneral", nullptr},
		{"add status 1 30 0", "add title 1", "add unlock 1", "add unlockall", nullptr}
	},
	{
		"inject", "Loads and injects a premade packet.", 1,
		{nullptr},
		{"inject packetname", nullptr}
	},
	{
		"nudge", "Nudges you forward/up/down.", 1,
		{nullptr},
		{"nudge 5", "nudge 5 u", "nudge 5 d", nullptr}
	},
	{
		"info", "Show server info.", 0,
		{nullptr},
		{"info", nullptr}
	},
	{
		"help", "Shows registered commands.", 0,
		{nullptr},
		{"help", nullptr}
	},
	{
		"script", "Server script utilities.", 1,
		{"unload", "find", "load", "queuereload", nullptr},
		{"script load test.lua", "script unload test", "script find npc", nullptr}
	},
	{
		"instance", "Instance utilities", 1,
		{"create", "bind", "unbind", "createzone", "remove", "return", "set", "objstate", "seq", "flags", nullptr},
		{"instance create 1", "instance bind 123", "instance set 1 5", nullptr}
	},
	{
		"questbattle", "Quest battle utilities", 1,
		{"create", "complete", "fail", "set", "objstate", "seq", "flags", nullptr},
		{"questbattle create 1", "questbattle complete", nullptr}
	},
	{
		"housing", "Housing utilities", 1,
		{nullptr},
		{"housing", nullptr}
	},
	{
		"linkshell", "Linkshell creation", 1,
		{nullptr},
		{"linkshell MyLinkshell", nullptr}
	},
	{
		"cf", "Content-Finder", 1,
		{"pop", nullptr},
		{"cf pop 123", nullptr}
	},
	{
		"ew", "Easy warping", 1,
		{"waking_sands", "rising_stones", "little_solace", "gridania_gc", "uldah_gc", "limsa_gc", "observatorium", nullptr},
		{"ew waking_sands", "ew rising_stones", nullptr}
	},
	{
		"reload", "Reloads a resource", 1,
		{"actions", nullptr},
		{"reload actions", nullptr}
	},
	{
		"facing", "Checks if you are facing an actor", 1,
		{nullptr},
		{"facing 0.95", nullptr}
	},
	{
		"rental", "Simulate finish of chocobo rental warp", 1,
		{nullptr},
		{"rental", nullptr}
	},
	{
		"pos", "Sends current position", 1,
		{nullptr},
		{"pos", nullptr}
	}
};

// Fix the RenderWindow method to handle array bounds properly
void DebugCommandsModule::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Debug Commands", &m_windowOpen))
	{
		ImGui::Text("Select a debug command to execute:");
		ImGui::Separator();

		// Calculate the actual number of commands safely
		const int numCommands = sizeof(s_commands) / sizeof(s_commands[0]);

		// Ensure selected command is within bounds
		if (m_selectedCommand >= numCommands)
		{
			m_selectedCommand = 0;
		}

		// Main command selector
		if (ImGui::BeginCombo("Debug Command", s_commands[m_selectedCommand].name))
		{
			for (int i = 0; i < numCommands; i++)
			{
				bool isSelected = (m_selectedCommand == i);
				if (ImGui::Selectable(s_commands[i].name, isSelected))
				{
					m_selectedCommand = i;
					m_selectedSubCommand = -1; // Reset subcommand selection to -1 (None)
				}
				if (isSelected)
				{
					ImGui::SetItemDefaultFocus();
				}
			}
			ImGui::EndCombo();
		}

		// Sub-command selector (if available) - with proper bounds checking
		auto& currentCmd = s_commands[m_selectedCommand];
		if (currentCmd.subCommands[0] != nullptr)
		{
			ImGui::Spacing();

			const char* currentSubCmd = "None";
			if (m_selectedSubCommand >= 0 && m_selectedSubCommand < 20 && currentCmd.subCommands[m_selectedSubCommand])
			{
				currentSubCmd = currentCmd.subCommands[m_selectedSubCommand];
			}

			if (ImGui::BeginCombo("Sub Command", currentSubCmd))
			{
				if (ImGui::Selectable("None", m_selectedSubCommand == -1))
				{
					m_selectedSubCommand = -1;
				}

				for (int i = 0; i < 20 && currentCmd.subCommands[i] != nullptr; i++)
				{
					bool isSelected = (m_selectedSubCommand == i);
					if (ImGui::Selectable(currentCmd.subCommands[i], isSelected))
					{
						m_selectedSubCommand = i;
					}
					if (isSelected)
					{
						ImGui::SetItemDefaultFocus();
					}
				}
				ImGui::EndCombo();
			}
		}
		else
		{
			// Reset subcommand if current command has no subcommands
			m_selectedSubCommand = -1;
		}

		// Parameters input
		ImGui::Spacing();
		ImGui::Text("Parameters:");
		ImGui::InputText("##params", m_commandParams, sizeof(m_commandParams));

		// Display command info
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Text("Command: %s", currentCmd.name);
		ImGui::Text("Description: %s", currentCmd.description);
		ImGui::Text("GM Level Required: %d", currentCmd.gmLevel);

		// Show examples if available - with proper null checking
		if (currentCmd.examples[0] != nullptr)
		{
			ImGui::Spacing();
			ImGui::Text("Examples:");
			for (int i = 0; i < 20 && currentCmd.examples[i] != nullptr; i++)
			{
				ImGui::BulletText("%s", currentCmd.examples[i]);
			}
		}

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		// Execute button
		if (ImGui::Button("Execute Command", ImVec2(150, 30)))
		{
			const char* subCmd = nullptr;
			if (m_selectedSubCommand >= 0 && m_selectedSubCommand < 20 && currentCmd.subCommands[m_selectedSubCommand])
			{
				subCmd = currentCmd.subCommands[m_selectedSubCommand];
			}

			SendDebugCommand(currentCmd.name, subCmd, m_commandParams);
		}

		ImGui::SameLine();
		if (ImGui::Button("Clear Params", ImVec2(100, 30)))
		{
			m_commandParams[0] = '\0';
		}

		ImGui::SameLine();
		if (ImGui::Button("Close", ImVec2(80, 30)))
		{
			m_windowOpen = false;
		}

		// Quick access section for common commands
		ImGui::Spacing();
		ImGui::Text("Quick Actions:");

		if (ImGui::Button("Get Position"))
		{
			SendDebugCommand("get", "pos", "");
		}
		ImGui::SameLine();

		if (ImGui::Button("Server Info"))
		{
			SendDebugCommand("info", nullptr, "");
		}
		ImGui::SameLine();

		if (ImGui::Button("Help"))
		{
			SendDebugCommand("help", nullptr, "");
		}
	}
	ImGui::End();
}

void DebugCommandsModule::Initialize()
{
	// Initialize the debug commands module
	printf("[DebugCommandsModule] Initializing...\n");
	// Add any initialization code here
}

// Add this method after the Initialize() method
void DebugCommandsModule::RenderMenu()
{
	ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen);
}

void DebugCommandsModule::SendDebugCommand(const char* command, const char* subCommand, const char* params)
{
	char fullCommand[512];

	if (subCommand && strlen(subCommand) > 0)
	{
		if (params && strlen(params) > 0)
			snprintf(fullCommand, sizeof(fullCommand), "%s %s %s", command, subCommand, params);
		else
			snprintf(fullCommand, sizeof(fullCommand), "%s %s", command, subCommand);
	}
	else
	{
		if (params && strlen(params) > 0)
			snprintf(fullCommand, sizeof(fullCommand), "%s %s", command, params);
		else
			snprintf(fullCommand, sizeof(fullCommand), "%s", command);
	}

	printf("[SapphireHook] Executing Debug Command: %s\n", fullCommand);

	// Try to send through the command interface
	if (!CommandInterface::SendDebugCommand(fullCommand))
	{
		printf("[SapphireHook] Failed to send command through interface\n");

		// Fallback: Try to use your existing hook system
		// You could hook the ChatHandler IPC and inject the command there
		TryInjectChatCommand(fullCommand);
	}
}