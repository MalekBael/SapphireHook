#include "ZoneLayoutViewerModule.h"
#include "../Core/GameDataLookup.h"
#include "../Logger/Logger.h"
#include "../Tools/DebugRenderer.h"
#include "../Tools/GameCameraExtractor.h"
#include "../vendor/imgui/imgui.h"
#include <algorithm>
#include <format>

namespace SapphireHook {

// ============================================================================
// Helper: Get all territories with names
// ============================================================================

static std::vector<TerritoryInfo> GatherTerritoryList() {
    std::vector<TerritoryInfo> result;
    
    // Iterate through common territory ID range (0-2000 covers most zones)
    // This is not elegant but works without exposing internal maps
    for (uint32_t id = 1; id <= 2000; ++id) {
        const char* name = GameData::LookupTerritoryName(id);
        const char* bgPath = GameData::LookupTerritoryBgPath(id);
        
        // Only include territories with both name and bgPath
        if (name && name[0] != '\0' && bgPath && bgPath[0] != '\0') {
            TerritoryInfo info;
            info.id = id;
            info.name = name;
            info.bgPath = bgPath;
            result.push_back(info);
        }
    }
    
    // Sort by name for easier browsing
    std::sort(result.begin(), result.end(), [](const TerritoryInfo& a, const TerritoryInfo& b) {
        return a.name < b.name;
    });
    
    return result;
}

// ============================================================================
// ZoneLayoutViewerModule Implementation
// ============================================================================

ZoneLayoutViewerModule::ZoneLayoutViewerModule() {
    m_filterText[0] = '\0';
}

void ZoneLayoutViewerModule::Initialize() {
    LogInfo("[ZoneLayoutViewer] Module initialized");
}

void ZoneLayoutViewerModule::Shutdown() {
    m_currentLayout.reset();
    m_territories.clear();
    LogInfo("[ZoneLayoutViewer] Module shutdown");
}

void ZoneLayoutViewerModule::RenderMenu() {
    if (ImGui::MenuItem("Zone Layout Viewer", nullptr, m_windowOpen)) {
        m_windowOpen = !m_windowOpen;
        if (m_windowOpen && m_territories.empty()) {
            LoadTerritoryList();
        }
    }
}

void ZoneLayoutViewerModule::RenderWindow() {
    if (!m_windowOpen) return;
    
    // Always render overlays if enabled (even if window minimized)
    if (m_overlayEnabled && m_currentLayout && m_currentLayout->IsLoaded()) {
        RenderOverlays();
    }
    
    ImGui::SetNextWindowSize(ImVec2(800, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Zone Layout Viewer", &m_windowOpen)) {
        ImGui::End();
        return;
    }
    
    // Check if GameData is available
    if (!GameData::IsInitialized()) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), 
            "GameData not initialized! Configure sqpack path in Settings.");
        ImGui::End();
        return;
    }
    
    // Check if ZoneLayoutManager can load
    auto& layoutMgr = GetZoneLayoutManager();
    if (!layoutMgr.CanLoadLayouts()) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), 
            "Zone layout loading not available.");
        ImGui::End();
        return;
    }
    
    // Territory selector on the left
    ImGui::BeginChild("TerritoryList", ImVec2(280, 0), true);
    RenderTerritorySelector();
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    // Layout details on the right
    ImGui::BeginChild("LayoutDetails", ImVec2(0, 0), true);
    
    if (m_currentLayout && m_currentLayout->IsLoaded()) {
        RenderLayoutSummary();
        ImGui::Separator();
        
        // Tab bar for different entry types
        if (ImGui::BeginTabBar("LayoutTabs")) {
            if (ImGui::BeginTabItem("BNpcs")) {
                RenderBNpcTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("ENpcs")) {
                RenderENpcTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("EObjs")) {
                RenderEventObjectsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("FATEs")) {
                RenderFateRangesTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Exits")) {
                RenderExitsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("PopRanges")) {
                RenderPopRangesTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Gathering")) {
                RenderGatheringTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Treasures")) {
                RenderTreasuresTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Aetherytes")) {
                RenderAetherytesTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Misc##")) {
                // Misc tab contains Collision, MapRanges, EventRanges, Markers
                ImGui::Text("Other Layout Data:");
                ImGui::Separator();
                
                if (ImGui::CollapsingHeader("Collision Boxes", ImGuiTreeNodeFlags_DefaultOpen)) {
                    RenderCollisionTab();
                }
                if (ImGui::CollapsingHeader("Map Ranges")) {
                    RenderMapRangesTab();
                }
                if (ImGui::CollapsingHeader("Event Ranges")) {
                    RenderEventRangesTab();
                }
                if (ImGui::CollapsingHeader("Markers")) {
                    RenderMarkersTab();
                }
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    else if (!m_lastError.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Error: %s", m_lastError.c_str());
    }
    else {
        ImGui::TextDisabled("Select a territory to view its layout data.");
    }
    
    ImGui::EndChild();
    
    ImGui::End();
}

void ZoneLayoutViewerModule::LoadTerritoryList() {
    LogInfo("[ZoneLayoutViewer] Loading territory list...");
    m_territories = GatherTerritoryList();
    UpdateFilter();
    LogInfo(std::format("[ZoneLayoutViewer] Found {} territories with layout paths", m_territories.size()));
}

void ZoneLayoutViewerModule::UpdateFilter() {
    m_filteredIndices.clear();
    
    std::string filter = m_filterText;
    // Convert filter to lowercase for case-insensitive search
    std::transform(filter.begin(), filter.end(), filter.begin(), ::tolower);
    
    for (size_t i = 0; i < m_territories.size(); ++i) {
        if (filter.empty()) {
            m_filteredIndices.push_back(static_cast<int>(i));
        }
        else {
            // Search in name, ID, and bgPath
            std::string name = m_territories[i].name;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            
            std::string bgPath = m_territories[i].bgPath;
            std::transform(bgPath.begin(), bgPath.end(), bgPath.begin(), ::tolower);
            
            std::string idStr = std::to_string(m_territories[i].id);
            
            if (name.find(filter) != std::string::npos ||
                bgPath.find(filter) != std::string::npos ||
                idStr.find(filter) != std::string::npos) {
                m_filteredIndices.push_back(static_cast<int>(i));
            }
        }
    }
}

void ZoneLayoutViewerModule::LoadSelectedTerritory() {
    if (m_selectedTerritoryIndex < 0 || m_selectedTerritoryIndex >= static_cast<int>(m_territories.size())) {
        m_currentLayout.reset();
        return;
    }
    
    const auto& territory = m_territories[m_selectedTerritoryIndex];
    LogInfo(std::format("[ZoneLayoutViewer] Loading layout for {} (ID: {})", territory.name, territory.id));
    
    auto& layoutMgr = GetZoneLayoutManager();
    m_currentLayout = layoutMgr.LoadZoneLayout(territory.id);
    
    if (!m_currentLayout) {
        m_lastError = layoutMgr.GetLastError();
        LogWarning(std::format("[ZoneLayoutViewer] Failed to load: {}", m_lastError));
    }
    else {
        m_lastError.clear();
        LogInfo(std::format("[ZoneLayoutViewer] Loaded {} entries", m_currentLayout->TotalEntryCount()));
    }
}

void ZoneLayoutViewerModule::RenderTerritorySelector() {
    ImGui::Text("Territories (%zu)", m_territories.size());
    ImGui::Separator();
    
    // Refresh button
    if (ImGui::Button("Refresh List")) {
        LoadTerritoryList();
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear Cache")) {
        GetZoneLayoutManager().ClearCache();
        m_currentLayout.reset();
        LogInfo("[ZoneLayoutViewer] Layout cache cleared");
    }
    
    // Filter input
    ImGui::SetNextItemWidth(-1);
    if (ImGui::InputTextWithHint("##Filter", "Filter...", m_filterText, sizeof(m_filterText))) {
        UpdateFilter();
    }
    
    ImGui::Separator();
    
    // Territory list
    ImGui::BeginChild("TerritoryScroll", ImVec2(0, 0));
    
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(m_filteredIndices.size()));
    
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            int actualIndex = m_filteredIndices[row];
            const auto& territory = m_territories[actualIndex];
            
            // Format: "Name (ID)"
            std::string label = std::format("{} ({})", territory.name, territory.id);
            
            bool isSelected = (m_selectedTerritoryIndex == actualIndex);
            if (ImGui::Selectable(label.c_str(), isSelected)) {
                m_selectedTerritoryIndex = actualIndex;
                LoadSelectedTerritory();
            }
            
            // Tooltip with bg path
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::Text("ID: %u", territory.id);
                ImGui::Text("BgPath: %s", territory.bgPath.c_str());
                ImGui::EndTooltip();
            }
        }
    }
    
    clipper.End();
    ImGui::EndChild();
}

void ZoneLayoutViewerModule::RenderLayoutSummary() {
    if (!m_currentLayout) return;
    
    const auto& territory = m_territories[m_selectedTerritoryIndex];
    
    ImGui::Text("Zone: %s (ID: %u)", territory.name.c_str(), territory.id);
    ImGui::TextDisabled("BgPath: %s", m_currentLayout->BgPath.c_str());
    
    // Show loaded LGB files
    if (!m_currentLayout->LoadedLgbFiles.empty()) {
        ImGui::TextDisabled("Loaded %zu LGB files", m_currentLayout->LoadedLgbFiles.size());
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            for (const auto& file : m_currentLayout->LoadedLgbFiles) {
                ImGui::Text("%s", file.c_str());
            }
            ImGui::EndTooltip();
        }
    }
    
    ImGui::Spacing();
    
    // Entry counts in columns - NPCs row
    ImGui::Columns(4, nullptr, false);
    ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "BNpcs: %zu", m_currentLayout->BattleNpcs.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "ENpcs: %zu", m_currentLayout->EventNpcs.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.4f, 1.0f), "EObjs: %zu", m_currentLayout->EventObjects.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "FATEs: %zu", m_currentLayout->FateRanges.size());
    
    // Ranges row
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Exits: %zu", m_currentLayout->Exits.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(0.8f, 0.4f, 1.0f, 1.0f), "PopRanges: %zu", m_currentLayout->PopRanges.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.4f, 1.0f), "Gathering: %zu", m_currentLayout->GatheringPoints.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(1.0f, 0.84f, 0.0f, 1.0f), "Treasures: %zu", m_currentLayout->Treasures.size());
    
    // More data row
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(0.5f, 0.7f, 1.0f, 1.0f), "Aetherytes: %zu", m_currentLayout->Aetherytes.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "MapRanges: %zu", m_currentLayout->MapRanges.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "Collision: %zu", m_currentLayout->CollisionBoxes.size());
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(0.4f, 1.0f, 1.0f, 1.0f), "EvRanges: %zu", m_currentLayout->EventRanges.size());
    ImGui::Columns(1);
    
    ImGui::Spacing();
    RenderOverlaySettings();
}

void ZoneLayoutViewerModule::RenderOverlaySettings() {
    ImGui::Separator();
    
    // Main overlay toggle
    ImGui::Checkbox("Enable 3D Overlay", &m_overlayEnabled);
    
    if (!m_overlayEnabled) {
        ImGui::TextDisabled("Enable overlay to show zone data in 3D world");
        return;
    }
    
    ImGui::SameLine();
    ImGui::Checkbox("Labels", &m_showLabels);
    
    // Overlay type toggles - Row 1: NPCs and objects
    ImGui::Text("Show:");
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
    ImGui::Checkbox("BNpcs##ov", &m_overlayBNpcs);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
    ImGui::Checkbox("ENpcs##ov", &m_overlayENpcs);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.4f, 1.0f));
    ImGui::Checkbox("EObjs##ov", &m_overlayEventObjects);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.6f, 0.2f, 1.0f));
    ImGui::Checkbox("FATEs##ov", &m_overlayFateRanges);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
    ImGui::Checkbox("Exits##ov", &m_overlayExits);
    ImGui::PopStyleColor();
    
    // Row 2: More overlays
    ImGui::Text("     ");
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.4f, 1.0f, 1.0f));
    ImGui::Checkbox("PopRanges##ov", &m_overlayPopRanges);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.8f, 0.4f, 1.0f));
    ImGui::Checkbox("Gathering##ov", &m_overlayGathering);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.84f, 0.0f, 1.0f));
    ImGui::Checkbox("Treasures##ov", &m_overlayTreasures);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.7f, 1.0f, 1.0f));
    ImGui::Checkbox("Aetherytes##ov", &m_overlayAetherytes);
    ImGui::PopStyleColor();
    
    // Row 3: Less common overlays
    ImGui::Text("     ");
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.4f, 1.0f));
    ImGui::Checkbox("Collision##ov", &m_overlayCollision);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
    ImGui::Checkbox("MapRanges##ov", &m_overlayMapRanges);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 1.0f, 1.0f));
    ImGui::Checkbox("EventRanges##ov", &m_overlayEventRanges);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.8f, 1.0f));
    ImGui::Checkbox("Markers##ov", &m_overlayMarkers);
    ImGui::PopStyleColor();
    
    // Settings
    if (ImGui::TreeNode("Overlay Settings")) {
        ImGui::SliderFloat("Alpha", &m_overlayAlpha, 0.1f, 1.0f, "%.2f");
        ImGui::SliderFloat("Scale", &m_overlayScale, 0.1f, 5.0f, "%.2f");
        ImGui::SliderFloat("Max Distance", &m_maxRenderDistance, 50.0f, 500.0f, "%.0f");
        ImGui::TreePop();
    }
}

void ZoneLayoutViewerModule::RenderBNpcTab() {
    if (!m_currentLayout) return;
    
    const auto& bnpcs = m_currentLayout->BattleNpcs;
    if (bnpcs.empty()) {
        ImGui::TextDisabled("No BNpc spawn points in this zone.");
        return;
    }
    
    ImGui::Text("%zu Battle NPC Spawn Points", bnpcs.size());
    ImGui::Separator();
    
    // Table header
    if (ImGui::BeginTable("BNpcTable", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("NameId");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("BaseId");
        ImGui::TableSetupColumn("Level");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(bnpcs.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& npc = bnpcs[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%u", npc.NameId);
                
                ImGui::TableNextColumn();
                const char* name = GameData::LookupBNpcName(npc.NameId);
                ImGui::Text("%s", name ? name : "???");
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", npc.BaseId);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", npc.Level);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", npc.Position.x, npc.Position.y, npc.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", npc.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderENpcTab() {
    if (!m_currentLayout) return;
    
    const auto& enpcs = m_currentLayout->EventNpcs;
    if (enpcs.empty()) {
        ImGui::TextDisabled("No ENpc spawn points in this zone.");
        return;
    }
    
    ImGui::Text("%zu Event NPC Spawn Points", enpcs.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("ENpcTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("ENpcId");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(enpcs.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& npc = enpcs[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%u", npc.ENpcId);
                
                ImGui::TableNextColumn();
                const char* name = GameData::LookupENpcName(npc.ENpcId);
                ImGui::Text("%s", name ? name : "???");
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", npc.Position.x, npc.Position.y, npc.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", npc.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderCollisionTab() {
    if (!m_currentLayout) return;
    
    const auto& boxes = m_currentLayout->CollisionBoxes;
    if (boxes.empty()) {
        ImGui::TextDisabled("No collision boxes in this zone.");
        return;
    }
    
    ImGui::Text("%zu Collision Boxes", boxes.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("CollisionTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale (X, Y, Z)");
        ImGui::TableSetupColumn("Rotation (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(boxes.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& box = boxes[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", box.Position.x, box.Position.y, box.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", box.Scale.x, box.Scale.y, box.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.2f, %.2f, %.2f", box.Rotation.x, box.Rotation.y, box.Rotation.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", box.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderExitsTab() {
    if (!m_currentLayout) return;
    
    const auto& exits = m_currentLayout->Exits;
    if (exits.empty()) {
        ImGui::TextDisabled("No exit ranges in this zone.");
        return;
    }
    
    ImGui::Text("%zu Exit Ranges (Zone Transitions)", exits.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("ExitTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("DestId");
        ImGui::TableSetupColumn("Destination Zone");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(exits.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& exit = exits[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%u", exit.DestTerritoryType);
                
                ImGui::TableNextColumn();
                const char* destName = GameData::LookupTerritoryName(exit.DestTerritoryType);
                ImGui::Text("%s", destName ? destName : "???");
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", exit.Position.x, exit.Position.y, exit.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", exit.Scale.x, exit.Scale.y, exit.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", exit.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderPopRangesTab() {
    if (!m_currentLayout) return;
    
    const auto& pops = m_currentLayout->PopRanges;
    if (pops.empty()) {
        ImGui::TextDisabled("No pop ranges in this zone.");
        return;
    }
    
    ImGui::Text("%zu Pop Ranges (Spawn Areas)", pops.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("PopTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(pops.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& pop = pops[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%d", row);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pop.Position.x, pop.Position.y, pop.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pop.Scale.x, pop.Scale.y, pop.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", pop.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderMapRangesTab() {
    if (!m_currentLayout) return;
    
    const auto& maps = m_currentLayout->MapRanges;
    if (maps.empty()) {
        ImGui::TextDisabled("No map ranges in this zone.");
        return;
    }
    
    ImGui::Text("%zu Map Ranges", maps.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("MapTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(maps.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& map = maps[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%d", row);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", map.Position.x, map.Position.y, map.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", map.Scale.x, map.Scale.y, map.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", map.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

// ============================================================================
// 3D Overlay Rendering
// ============================================================================

void ZoneLayoutViewerModule::RenderOverlays() {
    using namespace DebugVisuals;
    
    auto& renderer = DebugRenderer::GetInstance();
    if (!renderer.IsInitialized() || !renderer.IsEnabled()) return;
    
    auto& cameraExtractor = GameCameraExtractor::GetInstance();
    if (!cameraExtractor.IsInitialized()) return;
    
    // Render each enabled category
    if (m_overlayBNpcs) RenderBNpcOverlays();
    if (m_overlayENpcs) RenderENpcOverlays();
    if (m_overlayEventObjects) RenderEventObjectOverlays();
    if (m_overlayFateRanges) RenderFateRangeOverlays();
    if (m_overlayExits) RenderExitOverlays();
    if (m_overlayPopRanges) RenderPopRangeOverlays();
    if (m_overlayGathering) RenderGatheringOverlays();
    if (m_overlayTreasures) RenderTreasureOverlays();
    if (m_overlayAetherytes) RenderAetheryteOverlays();
    if (m_overlayCollision) RenderCollisionOverlays();
    if (m_overlayMapRanges) RenderMapRangeOverlays();
    if (m_overlayEventRanges) RenderEventRangeOverlays();
    if (m_overlayMarkers) RenderMarkerOverlays();
}

void ZoneLayoutViewerModule::RenderBNpcOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetBNpcColor();
    color.a *= m_overlayAlpha;
    
    for (const auto& npc : m_currentLayout->BattleNpcs) {
        // Distance check
        float dx = npc.Position.x - camPos.x;
        float dy = npc.Position.y - camPos.y;
        float dz = npc.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(npc.Position.x, npc.Position.y, npc.Position.z);
        
        // Draw filled sphere at spawn location
        renderer.DrawSphere(pos, 0.5f * m_overlayScale, color, true, 8);
        
        // Draw vertical cylinder to make it visible from above
        renderer.DrawCylinder(pos, 0.3f * m_overlayScale, 2.0f * m_overlayScale, color, 8, true);
        
        DebugVisuals::Vec3 top = pos;
        top.y += 2.0f * m_overlayScale;
        
        // Draw label
        if (m_showLabels) {
            const char* name = GameData::LookupBNpcName(npc.NameId);
            std::string label = name ? std::format("{} L{}", name, npc.Level) 
                                     : std::format("BNpc {} L{}", npc.NameId, npc.Level);
            renderer.DrawText3D(top, label, color, 0.8f);
        }
    }
}

void ZoneLayoutViewerModule::RenderENpcOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetENpcColor();
    color.a *= m_overlayAlpha;
    
    for (const auto& npc : m_currentLayout->EventNpcs) {
        float dx = npc.Position.x - camPos.x;
        float dy = npc.Position.y - camPos.y;
        float dz = npc.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(npc.Position.x, npc.Position.y, npc.Position.z);
        
        // Draw filled sphere for ENpc
        renderer.DrawSphere(pos, 0.5f * m_overlayScale, color, true, 8);
        
        // Draw vertical cylinder to make it visible from above
        renderer.DrawCylinder(pos, 0.25f * m_overlayScale, 2.5f * m_overlayScale, color, 8, true);
        
        DebugVisuals::Vec3 top = pos;
        top.y += 2.5f * m_overlayScale;
        
        if (m_showLabels) {
            const char* name = GameData::LookupENpcName(npc.ENpcId);
            std::string label = name ? name : std::format("ENpc {}", npc.ENpcId);
            renderer.DrawText3D(top, label, color, 0.8f);
        }
    }
}

void ZoneLayoutViewerModule::RenderCollisionOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetCollisionColor();
    color.a *= m_overlayAlpha;
    
    for (const auto& box : m_currentLayout->CollisionBoxes) {
        float dx = box.Position.x - camPos.x;
        float dy = box.Position.y - camPos.y;
        float dz = box.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(box.Position.x, box.Position.y, box.Position.z);
        DebugVisuals::Vec3 halfExtents(
            box.Scale.x * 0.5f * m_overlayScale,
            box.Scale.y * 0.5f * m_overlayScale,
            box.Scale.z * 0.5f * m_overlayScale
        );
        
        // Draw filled box for collision
        renderer.DrawBox(pos, halfExtents, color, true);
    }
}

void ZoneLayoutViewerModule::RenderExitOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetExitColor();
    color.a *= m_overlayAlpha;
    
    for (const auto& exit : m_currentLayout->Exits) {
        float dx = exit.Position.x - camPos.x;
        float dy = exit.Position.y - camPos.y;
        float dz = exit.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(exit.Position.x, exit.Position.y, exit.Position.z);
        
        // Use scale to determine the exit zone size
        float radius = (std::max)({exit.Scale.x, exit.Scale.y, exit.Scale.z}) * m_overlayScale;
        if (radius < 1.0f) radius = 2.0f;
        
        // Draw filled cylinder for exit zone
        float height = 3.0f * m_overlayScale;
        renderer.DrawCylinder(pos, radius, height, color, 24, true);
        
        // Label with destination
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 3.5f * m_overlayScale;
            const char* destName = GameData::LookupTerritoryName(exit.DestTerritoryType);
            std::string label = destName ? std::format("-> {}", destName) 
                                         : std::format("-> Zone {}", exit.DestTerritoryType);
            renderer.DrawText3D(labelPos, label, color, 1.0f);
        }
    }
}

void ZoneLayoutViewerModule::RenderPopRangeOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetPopRangeColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& pop : m_currentLayout->PopRanges) {
        float dx = pop.Position.x - camPos.x;
        float dy = pop.Position.y - camPos.y;
        float dz = pop.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pop.Position.x, pop.Position.y, pop.Position.z);
        
        // Use scale to determine spawn area size
        float radius = (std::max)({pop.Scale.x, pop.Scale.z}) * 0.5f * m_overlayScale;
        if (radius < 0.5f) radius = 1.0f;
        
        // Draw filled spawn area circle
        renderer.DrawCircle(pos, radius, color, 16, true);
        
        // Draw cross in the center with slightly brighter color for visibility
        DebugVisuals::Color crossColor = color;
        crossColor.a = (std::min)(1.0f, color.a * 2.0f);
        DebugVisuals::Vec3 left = pos; left.x -= radius * 0.5f;
        DebugVisuals::Vec3 right = pos; right.x += radius * 0.5f;
        DebugVisuals::Vec3 front = pos; front.z -= radius * 0.5f;
        DebugVisuals::Vec3 back = pos; back.z += radius * 0.5f;
        renderer.DrawLine(left, right, crossColor, 2.0f);
        renderer.DrawLine(front, back, crossColor, 2.0f);
        
        // Label
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.5f;
            renderer.DrawText3D(labelPos, std::format("Pop #{}", idx), color, 0.7f);
        }
        
        ++idx;
    }
}

void ZoneLayoutViewerModule::RenderMapRangeOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetMapRangeColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& map : m_currentLayout->MapRanges) {
        float dx = map.Position.x - camPos.x;
        float dy = map.Position.y - camPos.y;
        float dz = map.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(map.Position.x, map.Position.y, map.Position.z);
        DebugVisuals::Vec3 halfExtents(
            map.Scale.x * 0.5f * m_overlayScale,
            map.Scale.y * 0.5f * m_overlayScale,
            map.Scale.z * 0.5f * m_overlayScale
        );
        
        // Draw filled box for map range
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += halfExtents.y + 0.5f;
            renderer.DrawText3D(labelPos, std::format("Map #{}", idx), color, 0.6f);
        }
        
        ++idx;
    }
}

// ============================================================================
// New Tab Render Methods
// ============================================================================

void ZoneLayoutViewerModule::RenderEventObjectsTab() {
    if (!m_currentLayout) return;
    
    const auto& eobjs = m_currentLayout->EventObjects;
    if (eobjs.empty()) {
        ImGui::TextDisabled("No event objects (EObjs) in this zone.");
        return;
    }
    
    ImGui::Text("%zu Event Objects", eobjs.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("EObjTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("BaseId");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(eobjs.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& obj = eobjs[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%u", obj.BaseId);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", obj.Position.x, obj.Position.y, obj.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", obj.Scale.x, obj.Scale.y, obj.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", obj.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderFateRangesTab() {
    if (!m_currentLayout) return;
    
    const auto& fates = m_currentLayout->FateRanges;
    if (fates.empty()) {
        ImGui::TextDisabled("No FATE ranges in this zone.");
        return;
    }
    
    ImGui::Text("%zu FATE Ranges", fates.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("FateTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(fates.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& fate = fates[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%d", row);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", fate.Position.x, fate.Position.y, fate.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", fate.Scale.x, fate.Scale.y, fate.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", fate.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderGatheringTab() {
    if (!m_currentLayout) return;
    
    const auto& gathers = m_currentLayout->GatheringPoints;
    if (gathers.empty()) {
        ImGui::TextDisabled("No gathering points in this zone.");
        return;
    }
    
    ImGui::Text("%zu Gathering Points", gathers.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("GatherTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(gathers.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& pt = gathers[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%d", row);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pt.Position.x, pt.Position.y, pt.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pt.Scale.x, pt.Scale.y, pt.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", pt.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderTreasuresTab() {
    if (!m_currentLayout) return;
    
    const auto& treasures = m_currentLayout->Treasures;
    if (treasures.empty()) {
        ImGui::TextDisabled("No treasure points in this zone.");
        return;
    }
    
    ImGui::Text("%zu Treasure Points", treasures.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("TreasureTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(treasures.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& pt = treasures[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%d", row);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pt.Position.x, pt.Position.y, pt.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pt.Scale.x, pt.Scale.y, pt.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", pt.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderAetherytesTab() {
    if (!m_currentLayout) return;
    
    const auto& aetherytes = m_currentLayout->Aetherytes;
    if (aetherytes.empty()) {
        ImGui::TextDisabled("No aetherytes in this zone.");
        return;
    }
    
    ImGui::Text("%zu Aetherytes", aetherytes.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("AetheryteTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(aetherytes.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& pt = aetherytes[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%d", row);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pt.Position.x, pt.Position.y, pt.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", pt.Scale.x, pt.Scale.y, pt.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", pt.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderEventRangesTab() {
    if (!m_currentLayout) return;
    
    const auto& ranges = m_currentLayout->EventRanges;
    if (ranges.empty()) {
        ImGui::TextDisabled("No event ranges in this zone.");
        return;
    }
    
    ImGui::Text("%zu Event Ranges", ranges.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("EventRangeTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale (X, Y, Z)");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(ranges.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& r = ranges[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%d", row);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", r.Position.x, r.Position.y, r.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", r.Scale.x, r.Scale.y, r.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", r.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

void ZoneLayoutViewerModule::RenderMarkersTab() {
    if (!m_currentLayout) return;
    
    const auto& markers = m_currentLayout->Markers;
    if (markers.empty()) {
        ImGui::TextDisabled("No markers in this zone.");
        return;
    }
    
    ImGui::Text("%zu Markers", markers.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("MarkerTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Position (X, Y, Z)");
        ImGui::TableSetupColumn("Scale");
        ImGui::TableSetupColumn("LayerId");
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(markers.size()));
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& m = markers[row];
                
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%u", m.Type);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", m.Position.x, m.Position.y, m.Position.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%.1f, %.1f, %.1f", m.Scale.x, m.Scale.y, m.Scale.z);
                
                ImGui::TableNextColumn();
                ImGui::Text("%u", m.LayerId);
            }
        }
        clipper.End();
        
        ImGui::EndTable();
    }
}

// ============================================================================
// New Overlay Render Methods
// ============================================================================

void ZoneLayoutViewerModule::RenderEventObjectOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetEventObjectColor();
    color.a *= m_overlayAlpha;
    
    for (const auto& obj : m_currentLayout->EventObjects) {
        float dx = obj.Position.x - camPos.x;
        float dy = obj.Position.y - camPos.y;
        float dz = obj.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(obj.Position.x, obj.Position.y, obj.Position.z);
        
        // Draw filled box for event objects
        DebugVisuals::Vec3 halfExtents(0.4f * m_overlayScale, 0.4f * m_overlayScale, 0.4f * m_overlayScale);
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.5f * m_overlayScale;
            renderer.DrawText3D(labelPos, std::format("EObj {}", obj.BaseId), color, 0.7f);
        }
    }
}

void ZoneLayoutViewerModule::RenderFateRangeOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetFateRangeColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& fate : m_currentLayout->FateRanges) {
        float dx = fate.Position.x - camPos.x;
        float dy = fate.Position.y - camPos.y;
        float dz = fate.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(fate.Position.x, fate.Position.y, fate.Position.z);
        
        // FATE areas are typically large - use the scale as radius
        float radius = (std::max)({fate.Scale.x, fate.Scale.z}) * 0.5f * m_overlayScale;
        if (radius < 5.0f) radius = 10.0f;  // FATE areas are usually large
        
        // Draw filled outer circle with lower alpha for visibility
        DebugVisuals::Color outerColor = color;
        outerColor.a *= 0.3f;  // More transparent for large areas
        renderer.DrawCircle(pos, radius, outerColor, 32, true);
        
        // Draw ring outline for edge visibility
        renderer.DrawCircle(pos, radius, color, 32, false);
        renderer.DrawCircle(pos, radius * 0.5f, color, 24, false);
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 2.0f;
            renderer.DrawText3D(labelPos, std::format("FATE #{}", idx), color, 1.0f);
        }
        
        ++idx;
    }
}

void ZoneLayoutViewerModule::RenderGatheringOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetGatheringColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& pt : m_currentLayout->GatheringPoints) {
        float dx = pt.Position.x - camPos.x;
        float dy = pt.Position.y - camPos.y;
        float dz = pt.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
        
        // Draw filled circle at ground level for gathering points
        renderer.DrawCircle(pos, 0.8f * m_overlayScale, color, 12, true);
        
        // Vertical cylinder beam
        renderer.DrawCylinder(pos, 0.15f * m_overlayScale, 1.5f * m_overlayScale, color, 6, true);
        
        DebugVisuals::Vec3 top = pos;
        top.y += 1.5f * m_overlayScale;
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 2.0f * m_overlayScale;
            renderer.DrawText3D(labelPos, std::format("Gather #{}", idx), color, 0.6f);
        }
        
        ++idx;
    }
}

void ZoneLayoutViewerModule::RenderTreasureOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetTreasureColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& pt : m_currentLayout->Treasures) {
        float dx = pt.Position.x - camPos.x;
        float dy = pt.Position.y - camPos.y;
        float dz = pt.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
        
        // Draw filled box for treasure chests
        DebugVisuals::Vec3 halfExtents(0.4f * m_overlayScale, 0.3f * m_overlayScale, 0.3f * m_overlayScale);
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.0f * m_overlayScale;
            renderer.DrawText3D(labelPos, std::format("Chest #{}", idx), color, 0.6f);
        }
        
        ++idx;
    }
}

void ZoneLayoutViewerModule::RenderAetheryteOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetAetheryteColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& pt : m_currentLayout->Aetherytes) {
        float dx = pt.Position.x - camPos.x;
        float dy = pt.Position.y - camPos.y;
        float dz = pt.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
        
        // Draw filled sphere for aetheryte base
        renderer.DrawSphere(pos, 1.0f * m_overlayScale, color, true, 12);
        
        // Draw filled vertical beacon cylinder
        renderer.DrawCylinder(pos, 0.3f * m_overlayScale, 10.0f * m_overlayScale, color, 8, true);
        
        DebugVisuals::Vec3 top = pos;
        top.y += 10.0f * m_overlayScale;
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 5.0f * m_overlayScale;
            renderer.DrawText3D(labelPos, "Aetheryte", color, 1.0f);
        }
        
        ++idx;
    }
}

void ZoneLayoutViewerModule::RenderEventRangeOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetEventRangeColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& r : m_currentLayout->EventRanges) {
        float dx = r.Position.x - camPos.x;
        float dy = r.Position.y - camPos.y;
        float dz = r.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(r.Position.x, r.Position.y, r.Position.z);
        
        float radius = (std::max)({r.Scale.x, r.Scale.z}) * 0.5f * m_overlayScale;
        if (radius < 0.5f) radius = 1.0f;
        
        // Draw filled event range circle
        renderer.DrawCircle(pos, radius, color, 16, true);
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.0f;
            renderer.DrawText3D(labelPos, std::format("EvRange #{}", idx), color, 0.5f);
        }
        
        ++idx;
    }
}

void ZoneLayoutViewerModule::RenderMarkerOverlays() {
    if (!m_currentLayout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
    DebugVisuals::Color color = GetMarkerColor();
    color.a *= m_overlayAlpha;
    
    int idx = 0;
    for (const auto& m : m_currentLayout->Markers) {
        float dx = m.Position.x - camPos.x;
        float dy = m.Position.y - camPos.y;
        float dz = m.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(m.Position.x, m.Position.y, m.Position.z);
        
        // Draw filled sphere for markers
        renderer.DrawSphere(pos, 0.4f * m_overlayScale, color, true, 8);
        
        // Vertical cylinder above
        renderer.DrawCylinder(pos, 0.1f * m_overlayScale, 3.0f * m_overlayScale, color, 6, true);
        
        DebugVisuals::Vec3 top = pos;
        top.y += 3.0f * m_overlayScale;
        
        if (m_showLabels) {
            DebugVisuals::Vec3 labelPos = top;
            labelPos.y += 0.5f;
            renderer.DrawText3D(labelPos, std::format("Marker T{}", m.Type), color, 0.6f);
        }
        
        ++idx;
    }
}

} // namespace SapphireHook
