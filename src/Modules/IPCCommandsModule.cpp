#include "IPCCommandsModule.h"
#include "../vendor/imgui/imgui.h"      
#include <cstdio>
#include "../Core/CommandInvoker.h"

namespace IPCCommands {
	constexpr uint16_t PcSearch = 0xEB;
	constexpr uint16_t CatalogSearch = 0x109;
	constexpr uint16_t ItemSearch = 0x104;
	constexpr uint16_t GetItemSearchList = 0x105;
	constexpr uint16_t ZoneJump = 0x0190;
	constexpr uint16_t ActionRequest = 0x196;
	constexpr uint16_t Move = 0x019A;
	constexpr uint16_t Command = 0x191;
}

IPCCommandsModule::IPCCommandInfo IPCCommandsModule::s_commands[] = {
	{"PcSearch", IPCCommands::PcSearch, "Player Character Search"},
	{"CatalogSearch", IPCCommands::CatalogSearch, "Market Board Catalog Search"},
	{"ItemSearch", IPCCommands::ItemSearch, "General Item Search"},
	{"GetItemSearchList", IPCCommands::GetItemSearchList, "Get Item Search Results"},
	{"ZoneJump", IPCCommands::ZoneJump, "Zone Transfer/Jump"},
	{"ActionRequest", IPCCommands::ActionRequest, "Action/Skill Request"},
	{"Move", IPCCommands::Move, "Character Movement"},
	{"Command", IPCCommands::Command, "General Command"}
};

void IPCCommandsModule::RenderMenu()
{
	static int callCount = 0;
	callCount++;
	if (callCount <= 3)
	{
		printf("[IPCCommandsModule] RenderMenu() called #%d\n", callCount);
	}
	
	if (ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen))
	{
		printf("[IPCCommandsModule] Menu clicked! Window: %s\n", m_windowOpen ? "OPEN" : "CLOSED");
	}
}

void IPCCommandsModule::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("IPC Commands", &m_windowOpen))
	{
		ImGui::Text("Select an IPC command to execute:");
		ImGui::Separator();

		if (ImGui::BeginCombo("IPC Command", s_commands[m_selectedCommand].name))
		{
			for (int i = 0; i < IM_ARRAYSIZE(s_commands); i++)
			{
				bool isSelected = (m_selectedCommand == i);
				if (ImGui::Selectable(s_commands[i].name, isSelected))
				{
					m_selectedCommand = i;
				}
				if (isSelected)
				{
					ImGui::SetItemDefaultFocus();
				}
			}
			ImGui::EndCombo();
		}

		ImGui::Spacing();
		ImGui::Text("Command: %s", s_commands[m_selectedCommand].name);
		ImGui::Text("Opcode: 0x%04X", s_commands[m_selectedCommand].opcode);
		ImGui::Text("Description: %s", s_commands[m_selectedCommand].description);

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		if (ImGui::Button("Execute Command", ImVec2(150, 30)))
		{
			SendIPCCommand(s_commands[m_selectedCommand].opcode,
				s_commands[m_selectedCommand].name);
		}

		ImGui::SameLine();
		if (ImGui::Button("Close", ImVec2(80, 30)))
		{
			m_windowOpen = false;
		}

		ImGui::Spacing();
		ImGui::Text("Quick Actions:");

		if (ImGui::Button("Player Search"))
		{
			SendIPCCommand(IPCCommands::PcSearch, "PcSearch");
		}
		ImGui::SameLine();

		if (ImGui::Button("Market Board"))
		{
			SendIPCCommand(IPCCommands::CatalogSearch, "CatalogSearch");
		}
		ImGui::SameLine();

		if (ImGui::Button("Item Search"))
		{
			SendIPCCommand(IPCCommands::ItemSearch, "ItemSearch");
		}
	}
	ImGui::End();
}

void IPCCommandsModule::SendIPCCommand(uint16_t opcode, const char* commandName)
{
    // Try real IPC send first
    uint8_t payload[32] = {0}; // adjust per opcode as needed
    if (SapphireHook::CommandInvoker::Instance().SendIPC(opcode, payload, sizeof(payload)))
    {
        printf("[SapphireHook] Sent IPC via CommandInvoker: %s (0x%04X)\n", commandName, opcode);
        return;
    }

    // Fallback: simulate as before
    printf("[SapphireHook] Simulating IPC Command: %s (0x%04X)\n", commandName, opcode);

    switch (opcode)
    {
    case IPCCommands::PcSearch:
        printf("[SapphireHook] Triggering Player Search interface...\n");
        break;
    case IPCCommands::CatalogSearch:
        printf("[SapphireHook] Triggering Market Board search...\n");
        break;
    case IPCCommands::ZoneJump:
        printf("[SapphireHook] Initiating zone transfer...\n");
        break;
    default:
        printf("[SapphireHook] Executing command: %s\n", commandName);
        break;
    }
}