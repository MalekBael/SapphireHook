#include "GMCommandsModule.h"
#include "CommandInterface.h"
#include "../vendor/imgui/imgui.h"
#include <cstdio>

void GMCommandsModule::Initialize()
{
    printf("[GMCommandsModule] Initializing...\n");
}

void GMCommandsModule::RenderMenu()
{
    static int callCount = 0;
    callCount++;
    if (callCount <= 3)
    {
        printf("[GMCommandsModule] RenderMenu() called #%d\n", callCount);
    }

    if (ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen))
    {
        printf("[GMCommandsModule] Menu clicked! Window: %s\n", m_windowOpen ? "OPEN" : "CLOSED");
    }
}

void GMCommandsModule::RenderWindow()
{
    if (!m_windowOpen) return;

    ImGui::SetNextWindowSize(ImVec2(560, 460), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("GM Commands", &m_windowOpen))
    {
        ImGui::TextDisabled("GM commands are sent via opcodes only (no chat text).");
        ImGui::Separator();

        if (ImGui::BeginTabBar("GMTabBar"))
        {
            // Send by numeric ID (GMCommand 0x0197)
            if (ImGui::BeginTabItem("Send by ID"))
            {
                ImGui::TextWrapped("Dispatch a GM command by numeric ID with up to 4 integer args and optional target object ID.");
                ImGui::Separator();

                ImGui::InputInt("Command ID", &m_commandId);
                ImGui::InputInt("Arg 0", &m_arg0);
                ImGui::InputInt("Arg 1", &m_arg1);
                ImGui::InputInt("Arg 2", &m_arg2);
                ImGui::InputInt("Arg 3", &m_arg3);
                ImGui::InputScalar("Target ID (uint64)", ImGuiDataType_U64, &m_targetId);

                ImGui::Spacing();

                if (ImGui::Button("Send", ImVec2(140, 28)))
                {
                    const uint32_t cmd = static_cast<uint32_t>(m_commandId);
                    const uint32_t a0 = static_cast<uint32_t>(m_arg0);
                    const uint32_t a1 = static_cast<uint32_t>(m_arg1);
                    const uint32_t a2 = static_cast<uint32_t>(m_arg2);
                    const uint32_t a3 = static_cast<uint32_t>(m_arg3);
                    const uint64_t tgt = static_cast<uint64_t>(m_targetId);

                    printf("[GMCommandsModule] SendGMCommand id=%u a0=%u a1=%u a2=%u a3=%u target=%llu\n",
                        cmd, a0, a1, a2, a3, static_cast<unsigned long long>(tgt));

                    if (CommandInterface::SendGMCommand(cmd, a0, a1, a2, a3, tgt))
                        printf("[GMCommandsModule] OK\n");
                    else
                        printf("[GMCommandsModule] FAILED\n");
                }

                ImGui::EndTabItem();
            }

            // Send to target by name (GMCommandName 0x0198)
            if (ImGui::BeginTabItem("Send by Name"))
            {
                ImGui::TextWrapped("Dispatch a GM command by numeric ID with args and a target by name.");
                ImGui::Separator();

                ImGui::InputInt("Command ID##name", &m_nameCommandId);
                ImGui::InputInt("Arg 0##name", &m_nameArg0);
                ImGui::InputInt("Arg 1##name", &m_nameArg1);
                ImGui::InputInt("Arg 2##name", &m_nameArg2);
                ImGui::InputInt("Arg 3##name", &m_nameArg3);
                ImGui::InputText("Target Name", m_targetName, sizeof(m_targetName));

                ImGui::Spacing();

                if (ImGui::Button("Send (Name)", ImVec2(140, 28)))
                {
                    const uint32_t cmd = static_cast<uint32_t>(m_nameCommandId);
                    const uint32_t a0 = static_cast<uint32_t>(m_nameArg0);
                    const uint32_t a1 = static_cast<uint32_t>(m_nameArg1);
                    const uint32_t a2 = static_cast<uint32_t>(m_nameArg2);
                    const uint32_t a3 = static_cast<uint32_t>(m_nameArg3);

                    printf("[GMCommandsModule] SendGMCommandWithName id=%u a0=%u a1=%u a2=%u a3=%u name='%s'\n",
                        cmd, a0, a1, a2, a3, m_targetName);

                    if (CommandInterface::SendGMCommandWithName(cmd, a0, a1, a2, a3, m_targetName))
                        printf("[GMCommandsModule] OK\n");
                    else
                        printf("[GMCommandsModule] FAILED\n");
                }

                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::Separator();
        ImGui::TextDisabled("Note: Debug commands use \"!\" in chat; GM commands use opcodes only.");
    }
    ImGui::End();
}