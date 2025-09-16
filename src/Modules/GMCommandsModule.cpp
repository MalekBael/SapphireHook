#include "GMCommandsModule.h"
#include "CommandInterface.h"
#include "GMCommandList.h"
#include "../vendor/imgui/imgui.h"
#include <cstdio>
#include "../Core/PacketInjector.h"

void GMCommandsModule::Initialize()
{
    printf("[GMCommandsModule] Initializing...\n");

    // Default: no selection; show blank preview
    m_selectedIndex = -1;
    m_commandId = 0;
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

static void DrawHintBox()
{
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.12f, 0.16f, 0.35f));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);
    ImGui::BeginChild("##gm_hint", ImVec2(0, 72), true);
    ImGui::TextColored(ImVec4(0.9f, 0.85f, 0.3f, 1.0f), "Syntax");
    ImGui::Separator();
    ImGui::TextWrapped("This command expects the arguments shown below. The '/gm ' prefix and the command name are added automatically when you click Send.");
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
}

void GMCommandsModule::RenderWindow()
{
    if (!m_windowOpen) return;

    ImGui::SetNextWindowSize(ImVec2(560, 420), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("GM Commands", &m_windowOpen))
    {
        ImGui::TextDisabled("GM commands are sent via opcodes only (no chat text).");
        ImGui::Separator();

        DrawHintBox();

        // Combo preview is blank until a selection is made
        const bool hasItems = !GMCommands::kList.empty();
        const char* currentPreview =
            (hasItems && m_selectedIndex >= 0 && m_selectedIndex < (int)GMCommands::kList.size())
                ? GMCommands::kList[m_selectedIndex].name
                : "";

        if (ImGui::BeginCombo("GM Command", currentPreview))
        {
            bool noneSelected = (m_selectedIndex == -1);
            if (ImGui::Selectable("(None)", noneSelected))
            {
                m_selectedIndex = -1;
                m_commandId = 0;
            }
            if (noneSelected) ImGui::SetItemDefaultFocus();

            for (int i = 0; i < (int)GMCommands::kList.size(); ++i)
            {
                bool selected = (m_selectedIndex == i);
                if (ImGui::Selectable(GMCommands::kList[i].name, selected))
                {
                    m_selectedIndex = i;
                    m_commandId = GMCommands::kList[i].id;
                }
                if (selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        // If a command is selected, show inline syntax help
        if (m_selectedIndex >= 0 && m_selectedIndex < (int)GMCommands::kList.size())
        {
            const auto& entry = GMCommands::kList[m_selectedIndex];
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.6f, 0.85f, 1.0f, 1.0f), "Syntax:");
            // Show only the argument portion (prefix implied by selection)
            ImGui::TextWrapped("%s", (entry.argsHint && entry.argsHint[0] != '\0') ? entry.argsHint : "<no args>");
            if (entry.description && entry.description[0] != '\0')
            {
                ImGui::TextDisabled("%s", entry.description);
            }
        }

        ImGui::Separator();

        ImGui::BeginDisabled(true);
        ImGui::InputInt("Command ID", &m_commandId);
        ImGui::EndDisabled();

        // Arguments
        ImGui::InputInt("Arg 0", &m_arg0);
        ImGui::InputInt("Arg 1", &m_arg1);
        ImGui::InputInt("Arg 2", &m_arg2);
        ImGui::InputInt("Arg 3", &m_arg3);
        ImGui::InputScalar("Target ID (uint64)", ImGuiDataType_U64, &m_targetId);

        // Show learned local actor id (only set on button press)
        {
            const uint32_t learned = SapphireHook::GetLearnedLocalActorId();
            ImGui::Spacing();

            char buf[96];
            if (learned != 0 && learned != 0xFFFFFFFF)
                std::snprintf(buf, sizeof(buf), "Local actor ID: 0x%X (%u)", learned, learned);
            else
                std::snprintf(buf, sizeof(buf), "Local actor ID: (learning...) Type any chat message once.");

            ImGui::InputText("##local_actor_status", buf, sizeof(buf), ImGuiInputTextFlags_ReadOnly);

            ImGui::SameLine();
            const bool canUseSelf = (learned != 0 && learned != 0xFFFFFFFF);
            if (!canUseSelf) ImGui::BeginDisabled(true);
            if (ImGui::Button("Use Self"))
            {
                m_targetId = static_cast<unsigned long long>(learned); // set once on button press
            }
            if (!canUseSelf) ImGui::EndDisabled();
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Set Target ID to your player actor ID");
        }

        ImGui::Spacing();

        // Disable Send until a command is selected
        const bool canSend = (m_selectedIndex >= 0 && m_commandId != 0);
        if (!canSend) ImGui::BeginDisabled(true);
        if (ImGui::Button("Send", ImVec2(140, 28)))
        {
            const uint32_t cmd = static_cast<uint32_t>(m_commandId);
            const uint32_t a0  = static_cast<uint32_t>(m_arg0);
            const uint32_t a1  = static_cast<uint32_t>(m_arg1);
            const uint32_t a2  = static_cast<uint32_t>(m_arg2);
            const uint32_t a3  = static_cast<uint32_t>(m_arg3);
            const uint64_t tgt = static_cast<uint64_t>(m_targetId);

            printf("[GMCommandsModule] SendGMCommand id=%u a0=%u a1=%u a2=%u a3=%u target=%llu\n",
                   cmd, a0, a1, a2, a3, static_cast<unsigned long long>(tgt));

            if (CommandInterface::SendGMCommand(cmd, a0, a1, a2, a3, tgt))
                printf("[GMCommandsModule] OK\n");
            else
                printf("[GMCommandsModule] FAILED\n");
        }
        if (!canSend) ImGui::EndDisabled();

        ImGui::Separator();
        ImGui::TextDisabled("Source: compiled command list in GMCommandList.h (enum + table). Add argsHint/description for better help.");
    }
    ImGui::End();
}