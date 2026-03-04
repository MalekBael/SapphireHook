#include "WorldOverlayModule.h"
#include "CommandInterface.h"
#include "../Core/WorldOverlayManager.h"
#include "../Core/TerritoryScanner.h"
#include "../Core/NavMeshManager.h"
#include "../Core/GameDataLookup.h"
#include "../Logger/Logger.h"
#include "../Tools/GameCameraExtractor.h"
#include "../vendor/imgui/imgui.h"
#include <format>
#include <chrono>
#include <algorithm>
#include <cctype>

namespace SapphireHook {

void WorldOverlayModule::Initialize() {
    // Initialize WorldOverlayManager if not already done
    WorldOverlayManager::GetInstance().Initialize();
    // Initialize NavMeshManager
    NavMeshManager::GetInstance().Initialize();
    LogInfo("[WorldOverlayModule] Initialized");
}

void WorldOverlayModule::Shutdown() {
    LogInfo("[WorldOverlayModule] Shutdown");
}

void WorldOverlayModule::RenderMenu() {
    auto& mgr = WorldOverlayManager::GetInstance();
    bool enabled = mgr.AreOverlaysEnabled();
    
    // Show zone name in menu
    std::string menuLabel = std::format("World Overlay ({})", mgr.GetCurrentZoneName());
    
    if (ImGui::MenuItem(menuLabel.c_str(), nullptr, m_windowOpen)) {
        m_windowOpen = !m_windowOpen;
    }
}

void WorldOverlayModule::RenderWindow() {
    if (!m_windowOpen) return;
    
    // Always render overlays through the manager (even if window is collapsed)
    WorldOverlayManager::GetInstance().RenderOverlays();
    
    ImGui::SetNextWindowSize(ImVec2(450, 700), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("World Overlay", &m_windowOpen)) {
        ImGui::End();
        return;
    }
    
    RenderZoneInfo();
    ImGui::Separator();
    RenderQuickToggles();
    ImGui::Separator();
    RenderOverlayToggles();
    ImGui::Separator();
    RenderMarkerBrowser();
    ImGui::Separator();
    RenderSelectedMarkerDetails();
    ImGui::Separator();
    RenderNavMeshSection();
    ImGui::Separator();
    RenderPathfindingSection();
    ImGui::Separator();
    RenderAppearanceSettings();
    ImGui::Separator();
    RenderZoneStats();
    
    ImGui::End();
}

void WorldOverlayModule::RenderZoneInfo() {
    auto& mgr = WorldOverlayManager::GetInstance();
    auto& scanner = TerritoryScanner::GetInstance();
    
    auto state = scanner.GetCurrentState();
    
    ImGui::Text("Current Zone:");
    ImGui::SameLine();
    
    if (state.IsValid()) {
        std::string zoneName = mgr.GetCurrentZoneName();
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", zoneName.c_str());
        
        ImGui::TextDisabled("Territory: %u | Zone ID: %u | Layout: 0x%X", 
            state.TerritoryType, state.ZoneId, state.LayoutId);
        ImGui::TextDisabled("Spawn: %.1f, %.1f, %.1f | Weather: %u",
            state.SpawnPos[0], state.SpawnPos[1], state.SpawnPos[2], state.WeatherId);
    } else {
        // Try memory-based detection once (expensive scan, don't repeat)
        static bool scanAttempted = false;
        if (!scanAttempted) {
            scanAttempted = true;
            scanner.TryScanMemory();
        }
        
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Not in a zone (use manual override or teleport)");
        
        // Manual territory input for testing when packet detection fails
        ImGui::TextDisabled("Manual override (for testing):");
        static int manualTerritory = 129;  // Default: Limsa Lominsa
        ImGui::SetNextItemWidth(100);
        ImGui::InputInt("##manualTerr", &manualTerritory);
        ImGui::SameLine();
        if (ImGui::SmallButton("Set Territory")) {
            if (manualTerritory > 0 && manualTerritory < 65535) {
                scanner.ForceSetTerritory(static_cast<uint16_t>(manualTerritory));
            }
        }
        ImGui::SameLine();
        ImGui::TextDisabled("(129=Limsa, 132=Gridania, 130=Uldah)");
    }
}

void WorldOverlayModule::RenderQuickToggles() {
    auto& mgr = WorldOverlayManager::GetInstance();
    
    // Master toggle
    bool enabled = mgr.AreOverlaysEnabled();
    if (ImGui::Checkbox("Enable World Overlays", &enabled)) {
        mgr.SetOverlaysEnabled(enabled);
    }
    
    if (!enabled) {
        ImGui::TextDisabled("Enable overlays to show zone data in 3D world");
        return;
    }
    
    ImGui::SameLine();
    
    // Quick preset buttons
    if (ImGui::SmallButton("All")) {
        auto& settings = mgr.GetSettings();
        settings.EnabledCategories = static_cast<uint32_t>(WorldOverlayManager::OverlayCategory::All);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("None")) {
        auto& settings = mgr.GetSettings();
        settings.EnabledCategories = 0;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Useful")) {
        auto& settings = mgr.GetSettings();
        settings.EnabledCategories = 
            static_cast<uint32_t>(WorldOverlayManager::OverlayCategory::Exits) |
            static_cast<uint32_t>(WorldOverlayManager::OverlayCategory::Aetherytes) |
            static_cast<uint32_t>(WorldOverlayManager::OverlayCategory::FateRanges) |
            static_cast<uint32_t>(WorldOverlayManager::OverlayCategory::Gathering);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("NPCs")) {
        auto& settings = mgr.GetSettings();
        settings.EnabledCategories = 
            static_cast<uint32_t>(WorldOverlayManager::OverlayCategory::BNpcs) |
            static_cast<uint32_t>(WorldOverlayManager::OverlayCategory::ENpcs);
    }
}

void WorldOverlayModule::RenderOverlayToggles() {
    auto& mgr = WorldOverlayManager::GetInstance();
    
    if (!mgr.AreOverlaysEnabled()) return;
    
    ImGui::Text("Overlay Categories:");
    
    // Helper lambda to create colored checkbox
    auto ColoredCheckbox = [&mgr](const char* label, WorldOverlayManager::OverlayCategory cat, ImVec4 color) {
        bool enabled = mgr.IsCategoryEnabled(cat);
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        if (ImGui::Checkbox(label, &enabled)) {
            mgr.SetCategoryEnabled(cat, enabled);
        }
        ImGui::PopStyleColor();
    };
    
    // Row 1: NPCs
    ColoredCheckbox("BNpcs", WorldOverlayManager::OverlayCategory::BNpcs, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("ENpcs", WorldOverlayManager::OverlayCategory::ENpcs, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Event Objects", WorldOverlayManager::OverlayCategory::EventObjects, ImVec4(1.0f, 1.0f, 0.4f, 1.0f));
    
    // Row 2: World features
    ColoredCheckbox("Aetherytes", WorldOverlayManager::OverlayCategory::Aetherytes, ImVec4(0.5f, 0.7f, 1.0f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Gathering", WorldOverlayManager::OverlayCategory::Gathering, ImVec4(0.2f, 0.8f, 0.4f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Treasures", WorldOverlayManager::OverlayCategory::Treasures, ImVec4(1.0f, 0.84f, 0.0f, 1.0f));
    
    // Row 3: Ranges
    ColoredCheckbox("FATEs", WorldOverlayManager::OverlayCategory::FateRanges, ImVec4(1.0f, 0.6f, 0.2f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Exits", WorldOverlayManager::OverlayCategory::Exits, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Pop Ranges", WorldOverlayManager::OverlayCategory::PopRanges, ImVec4(0.8f, 0.4f, 1.0f, 1.0f));
    
    // Row 4: Less common
    ColoredCheckbox("Collision", WorldOverlayManager::OverlayCategory::Collision, ImVec4(1.0f, 0.8f, 0.4f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Map Ranges", WorldOverlayManager::OverlayCategory::MapRanges, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Event Ranges", WorldOverlayManager::OverlayCategory::EventRanges, ImVec4(0.4f, 1.0f, 1.0f, 1.0f));
    
    // Row 5: Misc
    ColoredCheckbox("Markers", WorldOverlayManager::OverlayCategory::Markers, ImVec4(1.0f, 0.5f, 0.8f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Chairs", WorldOverlayManager::OverlayCategory::ChairMarkers, ImVec4(0.4f, 0.6f, 0.8f, 1.0f));
    
    // NEW: Environment section
    ImGui::Spacing();
    ImGui::TextDisabled("Environment:");
    ColoredCheckbox("BG Parts", WorldOverlayManager::OverlayCategory::BgParts, ImVec4(0.6f, 0.6f, 0.7f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("VFX", WorldOverlayManager::OverlayCategory::VfxLocations, ImVec4(1.0f, 0.6f, 1.0f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Sound", WorldOverlayManager::OverlayCategory::SoundLocations, ImVec4(0.6f, 1.0f, 0.6f, 1.0f));
    
    // NEW: Interactive ranges
    ImGui::Spacing();
    ImGui::TextDisabled("Interactive Ranges:");
    ColoredCheckbox("Doors", WorldOverlayManager::OverlayCategory::DoorRanges, ImVec4(0.8f, 0.5f, 0.2f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Gimmicks", WorldOverlayManager::OverlayCategory::GimmickRanges, ImVec4(0.9f, 0.3f, 0.9f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("NavMesh Ranges", WorldOverlayManager::OverlayCategory::NavMeshRanges, ImVec4(0.3f, 0.8f, 0.3f, 1.0f));
    
    ColoredCheckbox("Keep (PvP)", WorldOverlayManager::OverlayCategory::KeepRanges, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
    
    // NEW: Paths
    ImGui::Spacing();
    ImGui::TextDisabled("Paths:");
    ColoredCheckbox("Server Paths", WorldOverlayManager::OverlayCategory::ServerPaths, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Client Paths", WorldOverlayManager::OverlayCategory::ClientPaths, ImVec4(0.4f, 0.4f, 1.0f, 1.0f));
    
    // Row 6: Navigation
    ImGui::Spacing();
    ImGui::TextDisabled("Navigation:");
    ColoredCheckbox("NavMesh##overlay", WorldOverlayManager::OverlayCategory::NavMesh, ImVec4(0.3f, 0.6f, 0.3f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Path", WorldOverlayManager::OverlayCategory::NavMeshPath, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));
    ImGui::SameLine();
    ColoredCheckbox("Off-Mesh Links", WorldOverlayManager::OverlayCategory::OffMeshLinks, ImVec4(1.0f, 0.5f, 0.0f, 1.0f));
}

void WorldOverlayModule::RenderAppearanceSettings() {
    auto& mgr = WorldOverlayManager::GetInstance();
    
    if (!mgr.AreOverlaysEnabled()) return;
    
    if (ImGui::CollapsingHeader("Appearance Settings")) {
        auto& settings = mgr.GetSettings();
        
        ImGui::SliderFloat("Alpha", &settings.Alpha, 0.1f, 1.0f, "%.2f");
        ImGui::SliderFloat("Scale", &settings.Scale, 0.1f, 5.0f, "%.2f");
        ImGui::SliderFloat("Max Distance", &settings.MaxRenderDistance, 0.0f, 500.0f, "%.0f");
        ImGui::Checkbox("Show Labels", &settings.ShowLabels);
        if (settings.ShowLabels) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(120.0f);
            ImGui::SliderFloat("Label Scale", &settings.LabelScale, 0.5f, 5.0f, "%.1f");
        }
    }
}

void WorldOverlayModule::RenderZoneStats() {
    auto& mgr = WorldOverlayManager::GetInstance();
    auto layout = mgr.GetCurrentZoneLayout();
    
    if (!layout || !layout->IsLoaded()) {
        ImGui::TextDisabled("No zone data loaded");
        return;
    }
    
    if (ImGui::CollapsingHeader("Zone Statistics", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Text("Total Entries: %zu", layout->TotalEntryCount());
        
        ImGui::Columns(4, nullptr, false);
        
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "BNpcs: %zu", layout->BattleNpcs.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "ENpcs: %zu", layout->EventNpcs.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.4f, 1.0f), "EObjs: %zu", layout->EventObjects.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "FATEs: %zu", layout->FateRanges.size());
        
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Exits: %zu", layout->Exits.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(0.8f, 0.4f, 1.0f, 1.0f), "Pops: %zu", layout->PopRanges.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.4f, 1.0f), "Gather: %zu", layout->GatheringPoints.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(1.0f, 0.84f, 0.0f, 1.0f), "Chest: %zu", layout->Treasures.size());
        
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(0.5f, 0.7f, 1.0f, 1.0f), "Aether: %zu", layout->Aetherytes.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "Collision: %zu", layout->CollisionBoxes.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 1.0f, 1.0f), "EvRange: %zu", layout->EventRanges.size());
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.8f, 1.0f), "Markers: %zu", layout->Markers.size());
        
        ImGui::Columns(1);
        
        // NEW: Additional stats
        if (layout->BgParts.size() > 0 || layout->SharedGroups.size() > 0 || 
            layout->ServerPaths.size() > 0 || layout->ChairMarkers.size() > 0) {
            ImGui::Spacing();
            ImGui::TextDisabled("Extended Data:");
            ImGui::Columns(4, nullptr, false);
            
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, 1.0f), "BG Parts: %zu", layout->BgParts.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.5f, 1.0f), "SGBs: %zu", layout->SharedGroups.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "SvrPaths: %zu", layout->ServerPaths.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.4f, 0.4f, 1.0f, 1.0f), "CliPaths: %zu", layout->ClientPaths.size());
            
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.4f, 0.6f, 0.8f, 1.0f), "Chairs: %zu", layout->ChairMarkers.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.8f, 0.5f, 0.2f, 1.0f), "Doors: %zu", layout->DoorRanges.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.9f, 1.0f), "Gimmicks: %zu", layout->GimmickRanges.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f), "NavRanges: %zu", layout->NavMeshRanges.size());
            
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 1.0f, 1.0f), "VFX: %zu", layout->VfxLocations.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.6f, 1.0f, 0.6f, 1.0f), "Sound: %zu", layout->SoundLocations.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.8f, 1.0f), "PCB Mesh: %zu", layout->CollisionMeshes.size());
            ImGui::NextColumn();
            ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "Keeps: %zu", layout->KeepRanges.size());
            
            ImGui::Columns(1);
        }
        
        // Show layer info
        if (!layout->Layers.empty()) {
            ImGui::Spacing();
            ImGui::TextDisabled("Layers: %zu", layout->Layers.size());
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                for (const auto& layer : layout->Layers) {
                    std::string flags;
                    if (layer.FestivalId > 0) flags += std::format(" [Festival:{}]", layer.FestivalId);
                    if (layer.IsHousing) flags += " [Housing]";
                    if (layer.IsTemporary) flags += " [Temp]";
                    if (layer.IsBushLayer) flags += " [Bush]";
                    ImGui::Text("Layer %u: %s%s", layer.LayerId, layer.Name.c_str(), flags.c_str());
                }
                ImGui::EndTooltip();
            }
        }
        
        // Show LGB files loaded
        if (!layout->LoadedLgbFiles.empty()) {
            ImGui::Spacing();
            ImGui::TextDisabled("Loaded %zu LGB files", layout->LoadedLgbFiles.size());
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                for (const auto& file : layout->LoadedLgbFiles) {
                    ImGui::Text("%s", file.c_str());
                }
                ImGui::EndTooltip();
            }
        }
        
        // Show SGB files loaded
        if (!layout->LoadedSgbFiles.empty()) {
            ImGui::TextDisabled("Loaded %zu SGB files", layout->LoadedSgbFiles.size());
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                for (const auto& file : layout->LoadedSgbFiles) {
                    ImGui::Text("%s", file.c_str());
                }
                ImGui::EndTooltip();
            }
        }
        
        // Show timeline info
        if (!layout->Timelines.empty()) {
            ImGui::TextDisabled("Timelines: %zu", layout->Timelines.size());
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                for (const auto& tl : layout->Timelines) {
                    std::string info = tl.Name.empty() ? std::format("Timeline {}", tl.TimelineId) : tl.Name;
                    if (tl.AutoPlay) info += " [Auto]";
                    if (tl.LoopPlayback) info += " [Loop]";
                    ImGui::Text("%s", info.c_str());
                }
                ImGui::EndTooltip();
            }
        }
    }
}

void WorldOverlayModule::RenderNavMeshSection() {
    auto& navMgr = NavMeshManager::GetInstance();
    
    if (ImGui::CollapsingHeader("NavMesh", ImGuiTreeNodeFlags_DefaultOpen)) {
        // Status
        if (navMgr.IsLoading()) {
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Loading... %.0f%%", navMgr.GetLoadProgress() * 100.0f);
        } else if (navMgr.HasNavMesh()) {
            auto stats = navMgr.GetCurrentNavMeshStats();
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "NavMesh Loaded (%s)", stats.format.c_str());
            
            ImGui::TextDisabled("Tiles: %zu | Polys: %zu | Verts: %zu", 
                stats.totalTiles, stats.totalPolygons, stats.totalVertices);
            
            if (stats.totalOffMeshConnections > 0) {
                ImGui::TextDisabled("Off-mesh links: %zu", stats.totalOffMeshConnections);
            }
            
            if (stats.canPathfind) {
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Pathfinding: Available");
            } else {
                ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Pathfinding: Not Available (TESM format)");
            }
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "No NavMesh loaded for this zone");
        }
        
        // Show current path (read-only, configure in Settings)
        auto basePath = navMgr.GetNavMeshBasePath();
        if (!basePath.empty()) {
            ImGui::TextDisabled("Path: %s", basePath.string().c_str());
        } else {
            ImGui::TextDisabled("Path: (not configured - set in Settings)");
        }
        
        // Manual reload button
        if (ImGui::Button("Reload NavMesh")) {
            auto terrId = TerritoryScanner::GetInstance().GetCurrentTerritoryType();
            if (terrId != 0) {
                navMgr.LoadNavMeshForZone(terrId);
            }
        }
    }
}

void WorldOverlayModule::RenderPathfindingSection() {
    auto& navMgr = NavMeshManager::GetInstance();
    
    if (!navMgr.CanPathfind()) {
        return;  // Don't show pathfinding section if not available
    }
    
    if (ImGui::CollapsingHeader("Pathfinding")) {
        // Get player position
        auto& camera = DebugVisuals::GameCameraExtractor::GetInstance();
        DirectX::XMFLOAT3 playerPos = {0, 0, 0};
        if (camera.IsInitialized()) {
            playerPos = camera.GetPlayerPositionLive();
        }
        
        ImGui::TextDisabled("Player: %.1f, %.1f, %.1f", playerPos.x, playerPos.y, playerPos.z);
        
        // Target input
        ImGui::Text("Target Position:");
        ImGui::SetNextItemWidth(80);
        ImGui::InputFloat("X##pathX", &m_pathTargetX, 0, 0, "%.1f");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80);
        ImGui::InputFloat("Y##pathY", &m_pathTargetY, 0, 0, "%.1f");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80);
        ImGui::InputFloat("Z##pathZ", &m_pathTargetZ, 0, 0, "%.1f");
        
        // Quick set to player position
        if (ImGui::Button("Use Player Pos")) {
            m_pathTargetX = playerPos.x;
            m_pathTargetY = playerPos.y;
            m_pathTargetZ = playerPos.z;
        }
        
        ImGui::SameLine();
        
        // Find path button
        if (ImGui::Button("Find Path")) {
            DirectX::XMFLOAT3 target = {m_pathTargetX, m_pathTargetY, m_pathTargetZ};
            navMgr.SetPathTarget(target);
        }
        
        ImGui::SameLine();
        
        // Clear path button
        if (ImGui::Button("Clear Path")) {
            navMgr.ClearPathTarget();
        }
        
        // Show active path info
        if (navMgr.HasActivePath()) {
            const auto& path = navMgr.GetActivePath();
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Path: %zu waypoints", path.waypoints.size());
            
            // Calculate distance
            float totalDist = 0.0f;
            for (size_t i = 1; i < path.waypoints.size(); ++i) {
                float dx = path.waypoints[i].x - path.waypoints[i-1].x;
                float dy = path.waypoints[i].y - path.waypoints[i-1].y;
                float dz = path.waypoints[i].z - path.waypoints[i-1].z;
                totalDist += std::sqrt(dx*dx + dy*dy + dz*dz);
            }
            ImGui::TextDisabled("Distance: %.1f yalms", totalDist);
        }
    }
}

// ============================================================================
// Interactive Marker Browser
// ============================================================================

bool WorldOverlayModule::MatchesSearchFilter(const std::string& name, uint32_t id) const {
    if (m_searchFilter[0] == '\0') return true;  // No filter = match all
    
    std::string filter(m_searchFilter);
    std::string lowerName = name;
    
    // Convert to lowercase for case-insensitive search
    std::transform(filter.begin(), filter.end(), filter.begin(), 
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    
    // Check if name contains filter
    if (lowerName.find(filter) != std::string::npos) return true;
    
    // Check if ID matches
    std::string idStr = std::to_string(id);
    if (idStr.find(filter) != std::string::npos) return true;
    
    return false;
}

void WorldOverlayModule::RenderMarkerBrowser() {
    auto& mgr = WorldOverlayManager::GetInstance();
    auto layout = mgr.GetCurrentZoneLayout();
    
    if (ImGui::CollapsingHeader("Marker Browser", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (!layout || !layout->IsLoaded()) {
            ImGui::TextDisabled("No zone data loaded - teleport to a zone first");
            return;
        }
        // Search filter
        ImGui::SetNextItemWidth(-1);
        ImGui::InputTextWithHint("##markerSearch", "Search by name or ID...", m_searchFilter, sizeof(m_searchFilter));
        
        ImGui::BeginChild("##markerList", ImVec2(0, 200), true, ImGuiWindowFlags_HorizontalScrollbar);
        
        // Helper to add selectable marker row
        // Note: ZoneLayoutManager uses SapphireHook::Vec3, convert to XMFLOAT3 for storage
        auto AddMarkerRow = [this](SelectedMarker::Type type, uint32_t idx, uint32_t id, 
                                   const std::string& name, const Vec3& pos,
                                   const Vec3& scale, ImVec4 color) {
            if (!MatchesSearchFilter(name, id)) return;
            
            bool isSelected = (m_selectedMarker.type == type && m_selectedMarker.index == idx);
            std::string label = std::format("{} [{}]##{}{}", name, id, static_cast<int>(type), idx);
            
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            if (ImGui::Selectable(label.c_str(), isSelected)) {
                m_selectedMarker.type = type;
                m_selectedMarker.index = idx;
                m_selectedMarker.id = id;
                m_selectedMarker.name = name;
                m_selectedMarker.position = {pos.x, pos.y, pos.z};
                m_selectedMarker.scale = {scale.x, scale.y, scale.z};
            }
            ImGui::PopStyleColor();
        };
        
        // BNpcs
        if (!layout->BattleNpcs.empty() && ImGui::TreeNode("BNpcs")) {
            uint32_t idx = 0;
            for (const auto& npc : layout->BattleNpcs) {
                const char* name = GameData::LookupBNpcName(npc.NameId);
                std::string displayName = name ? std::format("{} L{}", name, npc.Level) 
                                               : std::format("BNpc_{} L{}", npc.NameId, npc.Level);
                AddMarkerRow(SelectedMarker::Type::BNpc, idx, npc.NameId, displayName, 
                             npc.Position, Vec3{1, 1, 1}, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // ENpcs
        if (!layout->EventNpcs.empty() && ImGui::TreeNode("ENpcs")) {
            uint32_t idx = 0;
            for (const auto& npc : layout->EventNpcs) {
                const char* name = GameData::LookupENpcName(npc.ENpcId);
                std::string displayName = name ? name : std::format("ENpc_{}", npc.ENpcId);
                AddMarkerRow(SelectedMarker::Type::ENpc, idx, npc.ENpcId, displayName,
                             npc.Position, Vec3{1, 1, 1}, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // Event Objects
        if (!layout->EventObjects.empty() && ImGui::TreeNode("Event Objects")) {
            uint32_t idx = 0;
            for (const auto& obj : layout->EventObjects) {
                std::string displayName = std::format("EObj_{}", obj.BaseId);
                AddMarkerRow(SelectedMarker::Type::EventObject, idx, obj.BaseId, displayName,
                             obj.Position, obj.Scale, ImVec4(1.0f, 1.0f, 0.4f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // Exits
        if (!layout->Exits.empty() && ImGui::TreeNode("Exits")) {
            uint32_t idx = 0;
            for (const auto& exit : layout->Exits) {
                const char* destName = GameData::LookupTerritoryName(exit.DestTerritoryType);
                std::string displayName = destName ? std::format("-> {}", destName)
                                                   : std::format("-> Zone {}", exit.DestTerritoryType);
                AddMarkerRow(SelectedMarker::Type::Exit, idx, exit.DestTerritoryType, displayName,
                             exit.Position, exit.Scale, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // Pop Ranges
        if (!layout->PopRanges.empty() && ImGui::TreeNode("Pop Ranges")) {
            uint32_t idx = 0;
            for (const auto& pop : layout->PopRanges) {
                std::string displayName = std::format("Pop #{}", idx);
                AddMarkerRow(SelectedMarker::Type::PopRange, idx, idx, displayName,
                             pop.Position, pop.Scale, ImVec4(0.8f, 0.4f, 1.0f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // Gathering
        if (!layout->GatheringPoints.empty() && ImGui::TreeNode("Gathering")) {
            uint32_t idx = 0;
            for (const auto& pt : layout->GatheringPoints) {
                std::string displayName = std::format("Gather #{}", idx);
                AddMarkerRow(SelectedMarker::Type::Gathering, idx, idx, displayName,
                             pt.Position, Vec3{1, 1, 1}, ImVec4(0.2f, 0.8f, 0.4f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // Treasures
        if (!layout->Treasures.empty() && ImGui::TreeNode("Treasures")) {
            uint32_t idx = 0;
            for (const auto& pt : layout->Treasures) {
                std::string displayName = std::format("Chest #{}", idx);
                AddMarkerRow(SelectedMarker::Type::Treasure, idx, idx, displayName,
                             pt.Position, Vec3{1, 1, 1}, ImVec4(1.0f, 0.84f, 0.0f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // Aetherytes
        if (!layout->Aetherytes.empty() && ImGui::TreeNode("Aetherytes")) {
            uint32_t idx = 0;
            for (const auto& pt : layout->Aetherytes) {
                std::string displayName = std::format("Aetheryte #{}", idx);
                AddMarkerRow(SelectedMarker::Type::Aetheryte, idx, idx, displayName,
                             pt.Position, Vec3{1, 1, 1}, ImVec4(0.5f, 0.7f, 1.0f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        // FATEs
        if (!layout->FateRanges.empty() && ImGui::TreeNode("FATEs")) {
            uint32_t idx = 0;
            for (const auto& fate : layout->FateRanges) {
                std::string displayName = std::format("FATE #{}", idx);
                AddMarkerRow(SelectedMarker::Type::FateRange, idx, idx, displayName,
                             fate.Position, fate.Scale, ImVec4(1.0f, 0.6f, 0.2f, 1.0f));
                ++idx;
            }
            ImGui::TreePop();
        }
        
        ImGui::EndChild();
    }
}

void WorldOverlayModule::RenderSelectedMarkerDetails() {
    if (!m_selectedMarker.IsValid()) return;
    
    if (ImGui::CollapsingHeader("Selected Marker", ImGuiTreeNodeFlags_DefaultOpen)) {
        // Type and name
        const char* typeNames[] = {"None", "BNpc", "ENpc", "EObj", "Exit", "PopRange", 
                                   "Gather", "Treasure", "Aetheryte", "Marker", "FATE"};
        ImGui::Text("Type: %s", typeNames[static_cast<int>(m_selectedMarker.type)]);
        ImGui::Text("Name: %s", m_selectedMarker.name.c_str());
        ImGui::Text("ID: %u", m_selectedMarker.id);
        
        ImGui::Spacing();
        
        // Position
        ImGui::Text("Position:");
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "  X: %.2f  Y: %.2f  Z: %.2f",
                          m_selectedMarker.position.x, 
                          m_selectedMarker.position.y, 
                          m_selectedMarker.position.z);
        
        ImGui::Spacing();
        
        // Action buttons
        if (ImGui::Button("Teleport Here")) {
            TeleportToSelectedMarker();
        }
        
        ImGui::SameLine();
        
        if (ImGui::Button("Copy Position")) {
            CopyPositionToClipboard();
        }
        
        ImGui::SameLine();
        
        if (ImGui::Button("Clear Selection")) {
            m_selectedMarker.Clear();
        }
        
        // Set as pathfinding target
        ImGui::SameLine();
        if (ImGui::Button("Path To")) {
            m_pathTargetX = m_selectedMarker.position.x;
            m_pathTargetY = m_selectedMarker.position.y;
            m_pathTargetZ = m_selectedMarker.position.z;
            
            auto& navMgr = NavMeshManager::GetInstance();
            if (navMgr.CanPathfind()) {
                DirectX::XMFLOAT3 target = {m_pathTargetX, m_pathTargetY, m_pathTargetZ};
                navMgr.SetPathTarget(target);
            }
        }
    }
}

void WorldOverlayModule::TeleportToSelectedMarker() {
    if (!m_selectedMarker.IsValid()) return;
    
    // Server's !set pos command takes RAW world coordinates (X, Y, Z)
    // X = world X, Y = world Y (altitude), Z = world Z
    float worldX = m_selectedMarker.position.x;
    float worldY = m_selectedMarker.position.y;  // Height/altitude
    float worldZ = m_selectedMarker.position.z;
    
    std::string cmd = std::format("!set pos {:.0f} {:.0f} {:.0f}", worldX, worldY, worldZ);
    
    bool success = CommandInterface::SendChatMessage(cmd.c_str(), 0);
    
    if (success) {
        LogInfo(std::format("[WorldOverlay] Teleporting to {} - World ({:.1f}, {:.1f}, {:.1f})",
                           m_selectedMarker.name,
                           worldX, worldY, worldZ));
    } else {
        LogWarning("[WorldOverlay] Failed to send teleport command");
    }
}

void WorldOverlayModule::CopyPositionToClipboard() {
    if (!m_selectedMarker.IsValid()) return;
    
    std::string posStr = std::format("{:.2f}, {:.2f}, {:.2f}",
                                     m_selectedMarker.position.x,
                                     m_selectedMarker.position.y,
                                     m_selectedMarker.position.z);
    
    // Copy to Windows clipboard
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, posStr.size() + 1);
        if (hMem) {
            char* pMem = static_cast<char*>(GlobalLock(hMem));
            if (pMem) {
                memcpy(pMem, posStr.c_str(), posStr.size() + 1);
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
            }
        }
        
        CloseClipboard();
        LogInfo(std::format("[WorldOverlay] Copied position to clipboard: {}", posStr));
    }
}

} // namespace SapphireHook
