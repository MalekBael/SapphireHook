#include "DebugCommandsModule.h"
#include "CommandInterface.h"
#include "../vendor/imgui/imgui.h"      
#include <cstdio>
#include <cstring>
#include <string>

#include <Windows.h>
#include "../Core/FunctionDatabase.h"
#include "../Core/CommandInvoker.h"

// optional: small helper
static std::wstring ToWide(const char* s)
{
    if (!s) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (len <= 1) return {};
    std::wstring out(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), len);
    return out;
}

void DebugCommandsModule::Initialize()
{
    printf("[DebugCommandsModule] Initializing...\n");

    static bool s_invokerConfigured = false;
    if (!s_invokerConfigured)
    {
        SapphireHook::FunctionDatabase db;
        if (db.Load("data.json") || db.Load("data\\data.json"))
        {
            auto& inv = SapphireHook::CommandInvoker::Instance();
            int count = inv.ConfigureFromFunctionDB(db, "data\\command-targets.json");
            printf("[DebugCommandsModule] CommandInvoker configured (targets=%d)\n", count);
            s_invokerConfigured = (count > 0);
        }
        else
        {
            printf("[DebugCommandsModule] Warning: could not load data.json for CommandInvoker\n");
        }
    }

    // Ensure WSASend gets hooked (and logs appear)
    const bool initOK = CommandInterface::Initialize();
    printf("[DebugCommandsModule] CommandInterface::Initialize => %s\n", initOK ? "OK" : "FAIL");
}

void DebugCommandsModule::TryInjectChatCommand(const char* command)
{
    printf("[SapphireHook] Attempting to inject chat command: !%s\n", command);

    // First, try the real in-process chat path via CommandInvoker
    std::wstring wfull = L"!";
    wfull += ToWide(command);
    if (!wfull.empty())
    {
        if (SapphireHook::CommandInvoker::Instance().SendChat(wfull))
        {
            printf("[DebugCommandsModule] Successfully sent command via CommandInvoker\n");
            return;
        }
    }

    std::string fullCommand = "!" + std::string(command);
    if (CommandInterface::SendChatMessage(fullCommand.c_str(), 0))
    {
        printf("[DebugCommandsModule] Successfully sent command via CommandInterface\n");
        return;
    }

    if (TryPacketInjection(command))
    {
        printf("[DebugCommandsModule] Successfully sent command via packet injection\n");
        return;
    }

    if (TryMemoryPatching(command))
    {
        printf("[DebugCommandsModule] Successfully sent command via memory patching\n");
        return;
    }

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

	printf("[DebugCommandsModule] Packet injection not yet fully implemented\n");
	return false;
}

bool DebugCommandsModule::TryMemoryPatching(const char* command)
{
	printf("[DebugCommandsModule] Attempting memory patching for: %s\n", command);

	printf("[DebugCommandsModule] Memory patching not yet fully implemented\n");
	return false;
}

bool DebugCommandsModule::TryKeyboardSimulation(const char* command)
{
	printf("[DebugCommandsModule] Attempting keyboard simulation for: %s\n", command);

	HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
	if (!gameWindow)
	{
		printf("[DebugCommandsModule] Could not find game window\n");
		return false;
	}

	if (!IsWindowVisible(gameWindow))
	{
		printf("[DebugCommandsModule] Game window is not visible\n");
		return false;
	}

	SetForegroundWindow(gameWindow);
	Sleep(100);      

	if (GetForegroundWindow() != gameWindow)
	{
		printf("[DebugCommandsModule] Failed to focus game window\n");
		return false;
	}

	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
	Sleep(100);      

	std::string fullCommand = "!" + std::string(command);
	for (char c : fullCommand)
	{
		SHORT vk = VkKeyScanA(c);
		BYTE key = LOBYTE(vk);
		BYTE shift = HIBYTE(vk);

		if (shift & 1)   
		{
			keybd_event(VK_SHIFT, 0, 0, 0);
		}

		keybd_event(key, 0, 0, 0);
		keybd_event(key, 0, KEYEVENTF_KEYUP, 0);

		if (shift & 1)
		{
			keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
		}

		Sleep(15);       
	}

	Sleep(50);     
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);

	printf("[DebugCommandsModule] Keyboard simulation completed for: %s\n", fullCommand.c_str());
	return true;
}

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

void DebugCommandsModule::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Debug Commands", &m_windowOpen))
	{
		ImGui::Text("Select a debug command to execute:");
		ImGui::Separator();

		const int numCommands = sizeof(s_commands) / sizeof(s_commands[0]);

		if (m_selectedCommand >= numCommands)
		{
			m_selectedCommand = 0;
		}

		if (ImGui::BeginCombo("Debug Command", s_commands[m_selectedCommand].name))
		{
			for (int i = 0; i < numCommands; i++)
			{
				bool isSelected = (m_selectedCommand == i);
				if (ImGui::Selectable(s_commands[i].name, isSelected))
				{
					m_selectedCommand = i;
					m_selectedSubCommand = -1;       
				}
				if (isSelected)
				{
					ImGui::SetItemDefaultFocus();
				}
			}
			ImGui::EndCombo();
		}

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
			m_selectedSubCommand = -1;
		}

		ImGui::Spacing();
		ImGui::Text("Parameters:");
		ImGui::InputText("##params", m_commandParams, sizeof(m_commandParams));

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Text("Command: %s", currentCmd.name);
		ImGui::Text("Description: %s", currentCmd.description);
		ImGui::Text("GM Level Required: %d", currentCmd.gmLevel);

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

void DebugCommandsModule::RenderMenu()
{
	static int callCount = 0;
	callCount++;
	if (callCount <= 3)
	{
		printf("[DebugCommandsModule] RenderMenu() called #%d\n", callCount);
	}
	
	if (ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen))
	{
		printf("[DebugCommandsModule] Menu clicked! Window: %s\n", m_windowOpen ? "OPEN" : "CLOSED");
	}
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

    // Last-known-good path: send via ChatHandler (0x0067) with '!' prefix.
    std::string chatCmd = "!";
    chatCmd += fullCommand;
    if (CommandInterface::SendChatMessage(chatCmd.c_str(), 0))
    {
        printf("[SapphireHook] Successfully sent command via ChatHandler: %s\n", chatCmd.c_str());
        return;
    }

    // Fallbacks (optional)
    if (CommandInterface::SendDebugCommand(fullCommand))
    {
        printf("[SapphireHook] Successfully sent command via CommandInterface::SendDebugCommand\n");
        return;
    }

    TryInjectChatCommand(fullCommand);
}