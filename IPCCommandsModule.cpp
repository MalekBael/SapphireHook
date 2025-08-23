#include "IPCCommandsModule.h"
#include <cstdio>

// IPC Command definitions
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
	ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen);
}

void IPCCommandsModule::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("IPC Commands", &m_windowOpen))
	{
		ImGui::Text("Select an IPC command to execute:");
		ImGui::Separator();

		// Command selector
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

		// Display command info
		ImGui::Spacing();
		ImGui::Text("Command: %s", s_commands[m_selectedCommand].name);
		ImGui::Text("Opcode: 0x%04X", s_commands[m_selectedCommand].opcode);
		ImGui::Text("Description: %s", s_commands[m_selectedCommand].description);

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		// Execute button
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

		// Quick access buttons
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
	printf("[SapphireHook] Simulating IPC Command: %s (0x%04X)\n", commandName, opcode);

	// Here you would implement the actual IPC sending logic
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