#include "CollisionOverlayModule.h"
#include "../Tools/DebugRenderer.h"
#include "../Tools/GameCameraExtractor.h"
#include "../Logger/Logger.h"
#include <imgui.h>
#include <algorithm>
#include <format>
#include <cmath>
#include <chrono>

namespace SapphireHook {

    CollisionOverlayModule::CollisionOverlayModule() {
        // Initialize all categories as visible
        m_categoryVisible.fill(true);
        m_areaVisible.fill(true);
        
        // Subscribe to PlayerSpawn events for initial positions (REAL float coords)
        m_playerSpawnSubId = PacketEventDispatcher::Instance().SubscribePlayerSpawn(
            [this](const PlayerSpawnEvent& event) {
                OnPlayerSpawn(event);
            });
        
        // Subscribe to ActorMove events for movement tracking
        m_actorMoveSubId = PacketEventDispatcher::Instance().SubscribeActorMove(
            [this](const ActorMoveEvent& event) {
                OnActorMove(event);
            });
    }

    CollisionOverlayModule::~CollisionOverlayModule() {
        // Unsubscribe from packet events
        if (m_playerSpawnSubId != 0) {
            PacketEventDispatcher::Instance().UnsubscribePlayerSpawn(m_playerSpawnSubId);
        }
        if (m_actorMoveSubId != 0) {
            PacketEventDispatcher::Instance().UnsubscribeActorMove(m_actorMoveSubId);
        }
        
        // Cleanup navmesh
        if (m_loadedNavMesh) {
            Navigation::NavMeshLoader::GetInstance().UnloadNavMesh(*m_loadedNavMesh);
        }
    }

    void CollisionOverlayModule::RenderMenu() {
        if (ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen)) {
            // Toggle handled by ImGui
        }
    }

    void CollisionOverlayModule::RenderWindow() {
        // Render 3D overlays even when window is closed (uses DirectX, not ImGui)
        Render3DOverlay();
        
        if (!m_windowOpen) return;

        ImGui::SetNextWindowSize(ImVec2(500, 600), ImGuiCond_FirstUseEver);
        if (!ImGui::Begin("Collision Overlay", &m_windowOpen)) {
            ImGui::End();
            return;
        }

        // Main tabs
        if (ImGui::BeginTabBar("CollisionTabs")) {
            if (ImGui::BeginTabItem("Collision Mesh")) {
                m_selectedTab = 0;
                RenderCollisionTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("NavMesh")) {
                m_selectedTab = 1;
                RenderNavMeshTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("BNPC Paths")) {
                m_selectedTab = 3;
                RenderBNPCPathsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Settings")) {
                m_selectedTab = 2;
                RenderSettingsTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::Separator();
        RenderStatistics();

        ImGui::End();
    }

    // ============================================
    // Collision Mesh Tab
    // ============================================
    void CollisionOverlayModule::RenderCollisionTab() {
        ImGui::Checkbox("Show Collision Mesh", &m_showCollisionMesh);

        ImGui::Separator();
        ImGui::TextUnformatted("Load OBJ File:");
        
        ImGui::SetNextItemWidth(-100);
        ImGui::InputText("##collisionpath", m_filePathBuffer, sizeof(m_filePathBuffer));
        ImGui::SameLine();
        
        if (m_loadingCollision) {
            ImGui::BeginDisabled();
            ImGui::Button("Loading...");
            ImGui::EndDisabled();
            
            // Progress bar
            float progress = static_cast<float>(m_collisionProgress.linesProcessed) / 
                             (std::max)(m_collisionProgress.totalLines, size_t(1));
            ImGui::ProgressBar(progress, ImVec2(-1, 0), 
                              (std::to_string(m_collisionProgress.objectsLoaded) + " objects").c_str());
        } else {
            if (ImGui::Button("Load")) {
                LoadCollisionFile(m_filePathBuffer);
            }
        }

        if (m_loadedCollision) {
            ImGui::Separator();
            ImGui::Text("Loaded: %s", m_loadedCollision->name.c_str());
            ImGui::Text("Objects: %zu | Triangles: %zu | Vertices: %zu",
                        m_loadedCollision->objects.size(),
                        m_loadedCollision->totalTriangles,
                        m_loadedCollision->totalVertices);

            ImGui::Separator();
            ImGui::TextUnformatted("Category Visibility:");
            
            ImGui::Columns(2, "CategoryCols", false);
            for (size_t i = 0; i < static_cast<size_t>(CollisionCategory::COUNT); ++i) {
                auto cat = static_cast<CollisionCategory>(i);
                const char* name = GetCategoryName(cat);
                auto color = GetDefaultCategoryColor(cat);
                
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(color.x, color.y, color.z, 1.0f));
                ImGui::Checkbox(name, &m_categoryVisible[i]);
                ImGui::PopStyleColor();
                
                ImGui::NextColumn();
            }
            ImGui::Columns(1);

            ImGui::Separator();
            ImGui::TextUnformatted("Display Options:");
            ImGui::Checkbox("Wireframe", &m_showCollisionWireframe);
            ImGui::SameLine();
            ImGui::Checkbox("Filled", &m_showCollisionFilled);
            ImGui::SliderFloat("Alpha##collision", &m_collisionAlpha, 0.0f, 1.0f);

            if (ImGui::Button("Unload Collision Mesh")) {
                m_loadedCollision.reset();
                m_collisionFilePath.clear();
            }
        }
    }

    // ============================================
    // NavMesh Tab
    // ============================================
    void CollisionOverlayModule::RenderNavMeshTab() {
        ImGui::Checkbox("Show NavMesh", &m_showNavMesh);

        ImGui::Separator();
        ImGui::TextUnformatted("Load NavMesh File (.nav):");
        
        ImGui::SetNextItemWidth(-100);
        static char navPathBuffer[512] = {};
        ImGui::InputText("##navmeshpath", navPathBuffer, sizeof(navPathBuffer));
        ImGui::SameLine();
        
        if (m_loadingNavMesh) {
            ImGui::BeginDisabled();
            ImGui::Button("Loading...");
            ImGui::EndDisabled();
            
            float progress = m_navMeshProgress.percentage / 100.0f;
            ImGui::ProgressBar(progress, ImVec2(-1, 0),
                              (std::to_string(m_navMeshProgress.tilesLoaded) + "/" +
                               std::to_string(m_navMeshProgress.totalTiles) + " tiles").c_str());
        } else {
            if (ImGui::Button("Load##nav")) {
                LoadNavMeshFile(navPathBuffer);
            }
        }

        if (m_loadedNavMesh && m_loadedNavMesh->IsValid()) {
            ImGui::Separator();
            ImGui::Text("Loaded: %s", m_loadedNavMesh->sourcePath.c_str());
            ImGui::Text("Tiles: %zu | Polygons: %zu | Off-mesh: %zu",
                        m_loadedNavMesh->tileCount,
                        m_loadedNavMesh->totalPolygons,
                        m_loadedNavMesh->totalOffMeshConnections);

            ImGui::Separator();
            ImGui::TextUnformatted("Display Options:");
            ImGui::Checkbox("Wireframe##nav", &m_showNavMeshWireframe);
            ImGui::SameLine();
            ImGui::Checkbox("Filled##nav", &m_showNavMeshFilled);
            ImGui::Checkbox("Off-mesh Connections", &m_showOffMeshConnections);
            ImGui::Checkbox("Color by Area Type", &m_colorByArea);
            ImGui::SliderFloat("Alpha##nav", &m_navMeshAlpha, 0.0f, 1.0f);
            
            ImGui::Separator();
            ImGui::TextUnformatted("Position Adjustment:");
            ImGui::SliderFloat("Y Offset", &m_navMeshYOffset, -50.0f, 50.0f, "%.1f");
            ImGui::SameLine();
            if (ImGui::Button("Reset##yoffset")) {
                m_navMeshYOffset = 0.0f;
            }
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Adjust if navmesh appears floating");

            if (m_colorByArea && ImGui::TreeNode("Area Visibility")) {
                for (const auto& [area, count] : m_loadedNavMesh->areaStats) {
                    auto areaType = static_cast<Navigation::NavAreaType>(area);
                    const char* areaName = Navigation::GetAreaTypeName(areaType);
                    auto color = Navigation::GetAreaColor(areaType);
                    
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(color.x, color.y, color.z, 1.0f));
                    std::string label = std::string(areaName) + " (" + std::to_string(count) + ")";
                    ImGui::Checkbox(label.c_str(), &m_areaVisible[area]);
                    ImGui::PopStyleColor();
                }
                ImGui::TreePop();
            }

            if (ImGui::Button("Unload NavMesh")) {
                Navigation::NavMeshLoader::GetInstance().UnloadNavMesh(*m_loadedNavMesh);
                m_loadedNavMesh.reset();
                m_navMeshFilePath.clear();
            }
        }
    }

    // ============================================
    // Settings Tab
    // ============================================
    void CollisionOverlayModule::RenderSettingsTab() {
        ImGui::TextUnformatted("Rendering Settings");
        ImGui::Separator();

        ImGui::SliderFloat("Max Render Distance", &m_maxRenderDistance, 10.0f, 1000.0f, "%.0f");
        ImGui::Checkbox("Depth Test", &m_depthTest);
        ImGui::Checkbox("Cull Backfaces", &m_cullBackfaces);

        ImGui::Separator();
        ImGui::TextUnformatted("Performance Tips:");
        ImGui::BulletText("Reduce render distance for better FPS");
        ImGui::BulletText("Disable filled rendering, use wireframe only");
        ImGui::BulletText("Hide categories you don't need");
    }

    // ============================================
    // BNPC Paths Tab
    // ============================================
    void CollisionOverlayModule::RenderBNPCPathsTab() {
        ImGui::Checkbox("Show BNPC Paths", &m_showBNPCPaths);
        
        ImGui::Separator();
        ImGui::TextUnformatted("Path Visualization Options:");
        
        ImGui::SliderFloat("Track Distance", &m_bnpcMaxTrackDistance, 10.0f, 200.0f, "%.0f");
        ImGui::SliderFloat("Update Interval", &m_bnpcPathUpdateInterval, 0.1f, 2.0f, "%.1f sec");
        
        ImGui::Checkbox("Show Position History", &m_showBNPCPositionHistory);
        if (m_showBNPCPositionHistory) {
            ImGui::SliderInt("History Length", &m_bnpcHistoryLength, 5, 50);
        }
        
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "Auto-Calibration:");
        ImGui::TextWrapped("Position is auto-calibrated when NPCs spawn. "
            "PlayerSpawn gives ground-truth coordinates, used to correct ActorMove offsets.");
        ImGui::Checkbox("Show Calibration Status", &m_showCalibrationStatus);
        
        ImGui::Separator();
        ImGui::TextUnformatted("Path Colors:");
        ImGui::BulletText("Red = Hostile NPCs");
        ImGui::BulletText("Green = Friendly NPCs");
        ImGui::BulletText("Yellow = Neutral NPCs / Uncalibrated");
        ImGui::BulletText("Cyan = Current position marker");
        
        ImGui::Separator();
        ImGui::Checkbox("Track Player Path (for testing)", &m_trackPlayerPath);
        
        if (!m_trackedEntities.empty()) {
            ImGui::Separator();
            ImGui::Text("Tracked entities: %zu", m_trackedEntities.size());
            
            // Show details for each tracked entity
            if (ImGui::CollapsingHeader("Entity Details")) {
                std::lock_guard<std::mutex> lock(m_trackedEntitiesMutex);
                for (const auto& entity : m_trackedEntities) {
                    const char* calStatus = entity.isCalibrated ? "calibrated" : 
                                           (entity.hasSpawnPosition ? "pending" : "uncalibrated");
                    if (m_showCalibrationStatus) {
                        ImGui::Text("  0x%08X [%s]: %zu pts @ (%.1f,%.1f,%.1f) off=(%.1f,%.1f,%.1f)", 
                            entity.id, calStatus,
                            entity.positionHistory.size(),
                            entity.lastPosition.x, entity.lastPosition.y, entity.lastPosition.z,
                            entity.calibrationOffset.x, entity.calibrationOffset.y, entity.calibrationOffset.z);
                    } else {
                        ImGui::Text("  0x%08X [%s]: %zu positions @ (%.1f, %.1f, %.1f)", 
                            entity.id, calStatus,
                            entity.positionHistory.size(),
                            entity.lastPosition.x, entity.lastPosition.y, entity.lastPosition.z);
                    }
                }
            }
            
            if (ImGui::Button("Clear All Paths")) {
                std::lock_guard<std::mutex> lock(m_trackedEntitiesMutex);
                m_trackedEntities.clear();
            }
        }
    }
    
    // ============================================
    // PlayerSpawn Event Callback
    // Called when entities spawn - gives us REAL float world coordinates
    // This is our ground truth for position calibration!
    // ============================================
    void CollisionOverlayModule::OnPlayerSpawn(const PlayerSpawnEvent& event) {
        if (!m_showBNPCPaths) return;  // Early exit if not tracking
        
        // Only track BattleNpcs (objKind=2) for now
        // ObjKind: 1=PC, 2=BattleNpc, 3=EventNpc, 4=Treasure, 5=Aetheryte, etc.
        if (event.objKind != 2) return;
        
        LogDebug(std::format("OnPlayerSpawn: actor=0x{:08X} pos=({:.2f},{:.2f},{:.2f}) objKind={} npcId={}",
            event.actorId, event.position.x, event.position.y, event.position.z,
            event.objKind, event.npcId));
        
        std::lock_guard<std::mutex> lock(m_trackedEntitiesMutex);
        
        // Check if entity already tracked
        for (auto& e : m_trackedEntities) {
            if (e.id == event.actorId) {
                // Update existing entry with spawn position (ground truth)
                e.spawnPosition = event.position;
                e.hasSpawnPosition = true;
                e.isCalibrated = false;  // Re-calibrate on next ActorMove
                e.positionHistory.clear();
                e.positionHistory.push_back(event.position);
                e.lastPosition = event.position;
                e.lastDirection = event.direction;
                e.lastUpdateTime = event.timestamp;
                return;
            }
        }
        
        // Create new tracked entity with spawn position (ground truth)
        TrackedEntity entity{};
        entity.id = event.actorId;
        entity.name = std::format("BNPC 0x{:08X} (NPC:{})", event.actorId, event.npcId);
        entity.type = 1;  // BattleNpc = hostile
        entity.spawnPosition = event.position;  // Ground truth!
        entity.hasSpawnPosition = true;
        entity.isCalibrated = false;  // Will calibrate on first ActorMove
        entity.positionHistory.push_back(event.position);
        entity.lastPosition = event.position;
        entity.lastDirection = event.direction;
        entity.lastUpdateTime = event.timestamp;
        
        m_trackedEntities.push_back(std::move(entity));
    }
    
    // ============================================
    // ActorMove Event Callback
    // Called from packet processing thread when BNPC movement detected
    // Uses per-entity calibration: offset = spawnPosition - firstActorMovePosition
    // ============================================
    void CollisionOverlayModule::OnActorMove(const ActorMoveEvent& event) {
        if (!m_showBNPCPaths) return;  // Early exit if not tracking
        
        std::lock_guard<std::mutex> lock(m_trackedEntitiesMutex);
        
        // Find or create entity entry
        TrackedEntity* entity = nullptr;
        for (auto& e : m_trackedEntities) {
            if (e.id == event.sourceActorId) {
                entity = &e;
                break;
            }
        }
        
        if (!entity) {
            // New entity from ActorMove (didn't see spawn) - create uncalibrated
            m_trackedEntities.push_back({});
            entity = &m_trackedEntities.back();
            entity->id = event.sourceActorId;
            entity->name = std::format("Actor 0x{:08X} (uncalibrated)", event.sourceActorId);
            entity->type = 1;  // Assume BNPC
            entity->hasSpawnPosition = false;
            entity->isCalibrated = false;
        }
        
        // Calculate final position with calibration
        DirectX::XMFLOAT3 finalPos = event.position;
        
        if (entity->hasSpawnPosition && !entity->isCalibrated) {
            // First ActorMove after spawn - calculate calibration offset
            // offset = spawnPosition - rawActorMovePosition
            entity->calibrationOffset.x = entity->spawnPosition.x - event.position.x;
            entity->calibrationOffset.y = entity->spawnPosition.y - event.position.y;
            entity->calibrationOffset.z = entity->spawnPosition.z - event.position.z;
            entity->isCalibrated = true;
            
            LogDebug(std::format("Calibrated actor 0x{:08X}: offset=({:.2f},{:.2f},{:.2f})",
                event.sourceActorId, 
                entity->calibrationOffset.x, entity->calibrationOffset.y, entity->calibrationOffset.z));
        }
        
        if (entity->isCalibrated) {
            // Apply calibration offset
            finalPos.x += entity->calibrationOffset.x;
            finalPos.y += entity->calibrationOffset.y;
            finalPos.z += entity->calibrationOffset.z;
        }
        // Else: uncalibrated, use raw position (will be wrong but shows something)
        
        // Only add to history if position changed significantly
        float dx = finalPos.x - entity->lastPosition.x;
        float dy = finalPos.y - entity->lastPosition.y;
        float dz = finalPos.z - entity->lastPosition.z;
        float distSq = dx*dx + dy*dy + dz*dz;
        
        if (distSq > 0.25f || entity->positionHistory.empty()) {  // 0.5^2 threshold
            entity->positionHistory.push_back(finalPos);
            entity->lastPosition = finalPos;
            entity->lastDirection = event.direction;
            entity->lastUpdateTime = event.timestamp;
            
            // Limit history length
            while (entity->positionHistory.size() > static_cast<size_t>(m_bnpcHistoryLength)) {
                entity->positionHistory.erase(entity->positionHistory.begin());
            }
        }
        
        // Cleanup: remove entities with very old data (no updates in 60 seconds)
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        m_trackedEntities.erase(
            std::remove_if(m_trackedEntities.begin(), m_trackedEntities.end(),
                [now](const TrackedEntity& e) {
                    return e.id != 0 && e.lastUpdateTime != 0 && 
                           (now - e.lastUpdateTime) > 60000;  // 60 second timeout
                }),
            m_trackedEntities.end());
    }
    
    // ============================================
    // BNPC Path 3D Rendering
    // ============================================
    void CollisionOverlayModule::RenderBNPCPaths() {
        auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
        if (!renderer.IsInitialized()) return;
        
        auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
        if (!cameraExtractor.IsInitialized()) return;
        
        // Update paths at the configured interval
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<float>(now - m_lastPathUpdate).count();
        
        if (elapsed >= m_bnpcPathUpdateInterval) {
            m_lastPathUpdate = now;
            
            // Track player path for testing/proof of concept
            if (m_trackPlayerPath) {
                std::lock_guard<std::mutex> lock(m_trackedEntitiesMutex);
                
                DirectX::XMFLOAT3 playerPos = cameraExtractor.GetPlayerPositionLive();
                
                // Find or create player entry
                TrackedEntity* playerEntity = nullptr;
                for (auto& entity : m_trackedEntities) {
                    if (entity.id == 0 && entity.name == "Player") {
                        playerEntity = &entity;
                        break;
                    }
                }
                
                if (!playerEntity) {
                    m_trackedEntities.push_back({});
                    playerEntity = &m_trackedEntities.back();
                    playerEntity->id = 0;
                    playerEntity->name = "Player";
                    playerEntity->type = 0;
                }
                
                // Only add if position changed significantly (more than 0.5 units)
                float dx = playerPos.x - playerEntity->lastPosition.x;
                float dy = playerPos.y - playerEntity->lastPosition.y;
                float dz = playerPos.z - playerEntity->lastPosition.z;
                float distSq = dx*dx + dy*dy + dz*dz;
                
                if (distSq > 0.25f) {  // 0.5^2
                    playerEntity->positionHistory.push_back(playerPos);
                    playerEntity->lastPosition = playerPos;
                    
                    // Limit history length
                    while (playerEntity->positionHistory.size() > static_cast<size_t>(m_bnpcHistoryLength)) {
                        playerEntity->positionHistory.erase(playerEntity->positionHistory.begin());
                    }
                }
            }
            
            // BNPC tracking is now handled via ActorMove packet events (see OnActorMove)
        }
        
        // Lock and render all tracked entity paths
        std::lock_guard<std::mutex> lock(m_trackedEntitiesMutex);
        for (const auto& entity : m_trackedEntities) {
            if (entity.positionHistory.size() < 2) continue;
            
            // Choose color based on entity type
            DebugVisuals::Color pathColor;
            switch (entity.type) {
                case 0: pathColor = {0.2f, 0.8f, 1.0f, 0.8f}; break;  // Cyan for player
                case 1: pathColor = {1.0f, 0.3f, 0.3f, 0.8f}; break;  // Red for hostile
                case 2: pathColor = {0.3f, 1.0f, 0.3f, 0.8f}; break;  // Green for friendly
                case 3: pathColor = {1.0f, 1.0f, 0.3f, 0.8f}; break;  // Yellow for neutral
                default: pathColor = {0.8f, 0.8f, 0.8f, 0.8f}; break; // Gray
            }
            
            // Draw path as connected lines using thick quads (solid color, no fading)
            for (size_t i = 0; i < entity.positionHistory.size() - 1; ++i) {
                const auto& p1 = entity.positionHistory[i];
                const auto& p2 = entity.positionHistory[i + 1];
                
                DebugVisuals::Vec3 start = {p1.x, p1.y + 0.1f, p1.z};  // Slight Y offset to avoid z-fighting
                DebugVisuals::Vec3 end = {p2.x, p2.y + 0.1f, p2.z};
                
                renderer.DrawThickLine(start, end, pathColor, 0.3f);  // 0.3 world units thick
            }
            
            // Draw current position marker as a small crosshair
            if (!entity.positionHistory.empty()) {
                const auto& currentPos = entity.positionHistory.back();
                DebugVisuals::Vec3 pos = {currentPos.x, currentPos.y + 0.2f, currentPos.z};
                
                // Draw small crosshair at current position (thin lines)
                float markerSize = 0.5f;
                DebugVisuals::Color markerColor = {0.0f, 1.0f, 1.0f, 1.0f};  // Bright cyan
                
                renderer.DrawLine(
                    {pos.x - markerSize, pos.y, pos.z},
                    {pos.x + markerSize, pos.y, pos.z},
                    markerColor);
                renderer.DrawLine(
                    {pos.x, pos.y, pos.z - markerSize},
                    {pos.x, pos.y, pos.z + markerSize},
                    markerColor);
                renderer.DrawLine(
                    {pos.x, pos.y - markerSize, pos.z},
                    {pos.x, pos.y + markerSize, pos.z},
                    markerColor);
            }
        }
    }

    // ============================================
    // Statistics
    // ============================================
    void CollisionOverlayModule::RenderStatistics() {
        ImGui::TextUnformatted("Statistics");
        
        size_t totalTris = 0;
        if (m_showCollisionMesh && m_loadedCollision) {
            totalTris += m_loadedCollision->totalTriangles;
        }
        if (m_showNavMesh && m_loadedNavMesh) {
            totalTris += m_loadedNavMesh->totalPolygons;  // Polygons, not all tris
        }
        
        ImGui::Text("Active triangles/polygons: %zu", totalTris);
        ImGui::Text("Render distance: %.0f", m_maxRenderDistance);
    }

    // ============================================
    // File Loading
    // ============================================
    void CollisionOverlayModule::LoadCollisionFile(const std::string& path) {
        if (path.empty()) {
            LogWarning("No collision file path specified");
            return;
        }

        m_loadingCollision = true;
        m_collisionProgress = {};
        
        CollisionMeshLoader::GetInstance().LoadOBJAsync(
            path,
            [this](std::optional<CollisionMesh> mesh) {
                m_loadingCollision = false;
                if (mesh) {
                    m_loadedCollision = std::move(mesh);
                    m_collisionFilePath = m_loadedCollision->sourcePath;
                    LogInfo(std::format("Loaded collision mesh: {} objects, {} triangles",
                            m_loadedCollision->objects.size(),
                            m_loadedCollision->totalTriangles));
                } else {
                    LogError("Failed to load collision mesh");
                }
            },
            [this](const CollisionLoadProgress& progress) {
                m_collisionProgress = progress;
            }
        );
    }

    void CollisionOverlayModule::LoadNavMeshFile(const std::string& path) {
        if (path.empty()) {
            LogWarning("No navmesh file path specified");
            return;
        }

        m_loadingNavMesh = true;
        m_navMeshProgress = {};

        Navigation::NavMeshLoader::GetInstance().LoadNavMeshAsync(
            path,
            [this](std::optional<Navigation::LoadedNavMesh> mesh) {
                m_loadingNavMesh = false;
                if (mesh) {
                    m_loadedNavMesh = std::move(mesh);
                    m_navMeshFilePath = m_loadedNavMesh->sourcePath;
                    LogInfo(std::format("Loaded navmesh: {} tiles, {} polygons",
                            m_loadedNavMesh->tileCount,
                            m_loadedNavMesh->totalPolygons));
                } else {
                    LogError("Failed to load navmesh: " +
                             Navigation::NavMeshLoader::GetInstance().GetLastError());
                }
            },
            [this](const Navigation::NavLoadProgress& progress) {
                m_navMeshProgress = progress;
            }
        );
    }

    // ============================================
    // 3D Overlay Rendering
    // ============================================
    void CollisionOverlayModule::Render3DOverlay() {
        auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
        if (!renderer.IsInitialized() || !renderer.IsEnabled()) {
            return;
        }

        // Configure depth test based on settings
        renderer.SetDepthTestEnabled(m_depthTest);

        if (m_showCollisionMesh && m_loadedCollision) {
            RenderCollisionMesh();
        }

        if (m_showNavMesh && m_loadedNavMesh) {
            RenderNavMesh();
        }
        
        if (m_showBNPCPaths) {
            RenderBNPCPaths();
        }
    }

    void CollisionOverlayModule::RenderCollisionMesh() {
        if (!m_loadedCollision) return;

        auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
        
        // Get camera position for distance culling
        DirectX::XMFLOAT3 cameraPos = { 0, 0, 0 };
        auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
        if (cameraExtractor.IsInitialized()) {
            const auto& camera = cameraExtractor.GetCachedCamera();
            if (camera.valid) {
                cameraPos = camera.position;
            }
        }
        
        const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
        size_t trianglesRendered = 0;
        const size_t maxTrianglesPerFrame = 50000;  // Limit to prevent FPS drop
        
        // Build list of visible objects with their distances for priority sorting
        struct ObjectWithDist {
            const CollisionObject* obj;
            float distSq;
        };
        std::vector<ObjectWithDist> visibleObjects;
        visibleObjects.reserve(m_loadedCollision->objects.size());

        for (const auto& obj : m_loadedCollision->objects) {
            // Check category visibility
            size_t catIndex = static_cast<size_t>(obj.category);
            if (catIndex >= m_categoryVisible.size() || !m_categoryVisible[catIndex]) {
                continue;
            }

            // Distance cull the entire object using its center
            float dx = obj.center.x - cameraPos.x;
            float dy = obj.center.y - cameraPos.y;
            float dz = obj.center.z - cameraPos.z;
            float distSq = dx*dx + dy*dy + dz*dz;
            
            // Compute radius from bounding box
            float objRadiusX = (obj.boundsMax.x - obj.boundsMin.x) * 0.5f;
            float objRadiusY = (obj.boundsMax.y - obj.boundsMin.y) * 0.5f;
            float objRadiusZ = (obj.boundsMax.z - obj.boundsMin.z) * 0.5f;
            float objRadius = std::sqrt(objRadiusX*objRadiusX + objRadiusY*objRadiusY + objRadiusZ*objRadiusZ);
            
            // Use object radius + render distance for culling
            float cullDistSq = (m_maxRenderDistance + objRadius) * (m_maxRenderDistance + objRadius);
            if (distSq > cullDistSq) {
                continue;
            }
            
            visibleObjects.push_back({ &obj, distSq });
        }
        
        // Sort by distance (nearest first) to prioritize nearby objects
        std::sort(visibleObjects.begin(), visibleObjects.end(),
                  [](const ObjectWithDist& a, const ObjectWithDist& b) { return a.distSq < b.distSq; });
        
        // Render sorted objects
        for (const auto& [objPtr, objDistSq] : visibleObjects) {
            if (trianglesRendered >= maxTrianglesPerFrame) break;
            
            const auto& obj = *objPtr;
            auto color = GetCollisionCategoryColor(obj.category);
            color.w = m_collisionAlpha;

            for (const auto& tri : obj.triangles) {
                if (trianglesRendered >= maxTrianglesPerFrame) break;
                
                // Per-triangle distance check for large objects
                if (obj.triangles.size() > 100) {
                    float cx = (tri.v0.x + tri.v1.x + tri.v2.x) / 3.0f;
                    float cy = (tri.v0.y + tri.v1.y + tri.v2.y) / 3.0f;
                    float cz = (tri.v0.z + tri.v1.z + tri.v2.z) / 3.0f;
                    float tdx = cx - cameraPos.x;
                    float tdy = cy - cameraPos.y;
                    float tdz = cz - cameraPos.z;
                    if (tdx*tdx + tdy*tdy + tdz*tdz > maxDistSq) {
                        continue;
                    }
                }
                
                DirectX::XMFLOAT3 v0 = { tri.v0.x, tri.v0.y, tri.v0.z };
                DirectX::XMFLOAT3 v1 = { tri.v1.x, tri.v1.y, tri.v1.z };
                DirectX::XMFLOAT3 v2 = { tri.v2.x, tri.v2.y, tri.v2.z };
                
                DrawTriangle(v0, v1, v2, color, m_showCollisionFilled, m_showCollisionWireframe);
                ++trianglesRendered;
            }
        }
    }

    void CollisionOverlayModule::RenderNavMesh() {
        if (!m_loadedNavMesh) return;

        auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
        
        // Get camera position for distance culling
        DirectX::XMFLOAT3 cameraPos = { 0, 0, 0 };
        auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
        if (cameraExtractor.IsInitialized()) {
            const auto& camera = cameraExtractor.GetCachedCamera();
            if (camera.valid) {
                cameraPos = camera.position;
            }
        }
        
        const float maxDistSq = m_maxRenderDistance * m_maxRenderDistance;
        size_t polysRendered = 0;
        const size_t maxPolysPerFrame = 50000;

        for (const auto& tile : m_loadedNavMesh->tiles) {
            if (!tile.visible) continue;
            if (polysRendered >= maxPolysPerFrame) break;
            
            // Quick tile distance check using tile bounds
            float tileCenterX = (tile.boundsMin.x + tile.boundsMax.x) * 0.5f;
            float tileCenterY = (tile.boundsMin.y + tile.boundsMax.y) * 0.5f + m_navMeshYOffset;
            float tileCenterZ = (tile.boundsMin.z + tile.boundsMax.z) * 0.5f;
            
            float tileRadius = std::sqrt(
                std::pow(tile.boundsMax.x - tile.boundsMin.x, 2) +
                std::pow(tile.boundsMax.z - tile.boundsMin.z, 2)) * 0.5f;
            
            float tdx = tileCenterX - cameraPos.x;
            float tdz = tileCenterZ - cameraPos.z;
            float tileDistSq = tdx*tdx + tdz*tdz;
            
            // Skip entire tile if too far
            float tileCullDist = m_maxRenderDistance + tileRadius;
            if (tileDistSq > tileCullDist * tileCullDist) {
                continue;
            }

            for (const auto& poly : tile.polygons) {
                if (polysRendered >= maxPolysPerFrame) break;
                
                // Check area visibility
                if (!m_areaVisible[poly.area]) {
                    continue;
                }
                
                // Distance check per polygon
                float dx = poly.center.x - cameraPos.x;
                float dz = poly.center.z - cameraPos.z;
                if (dx*dx + dz*dz > maxDistSq) {
                    continue;
                }

                auto color = GetNavAreaColor(poly.area);
                color.w = m_navMeshAlpha;

                // Draw polygon as triangle fan from center
                // For convex polygons, we triangulate from vertex 0
                if (poly.vertices.size() >= 3) {
                    for (size_t i = 1; i < poly.vertices.size() - 1; ++i) {
                        // Apply Y offset to all vertices
                        DirectX::XMFLOAT3 v0 = poly.vertices[0];
                        DirectX::XMFLOAT3 v1 = poly.vertices[i];
                        DirectX::XMFLOAT3 v2 = poly.vertices[i + 1];
                        
                        v0.y += m_navMeshYOffset;
                        v1.y += m_navMeshYOffset;
                        v2.y += m_navMeshYOffset;
                        
                        DrawTriangle(v0, v1, v2, color, m_showNavMeshFilled, m_showNavMeshWireframe);
                    }
                    ++polysRendered;
                }
            }

            // Draw off-mesh connections
            if (m_showOffMeshConnections) {
                for (const auto& conn : tile.offMeshConnections) {
                    // Apply Y offset
                    DebugVisuals::Vec3 start = { conn.startPos.x, conn.startPos.y + m_navMeshYOffset, conn.startPos.z };
                    DebugVisuals::Vec3 end = { conn.endPos.x, conn.endPos.y + m_navMeshYOffset, conn.endPos.z };
                    DebugVisuals::Color lineColor = { 1.0f, 0.8f, 0.0f, 1.0f };  // Yellow/orange
                    
                    renderer.DrawArrow(start, end, lineColor, 2.0f, 0.3f);
                }
            }
        }
    }

    void CollisionOverlayModule::DrawTriangle(
        const DirectX::XMFLOAT3& v0,
        const DirectX::XMFLOAT3& v1,
        const DirectX::XMFLOAT3& v2,
        const DirectX::XMFLOAT4& color,
        bool filled,
        bool wireframe)
    {
        auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
        
        DebugVisuals::Vec3 p0 = { v0.x, v0.y, v0.z };
        DebugVisuals::Vec3 p1 = { v1.x, v1.y, v1.z };
        DebugVisuals::Vec3 p2 = { v2.x, v2.y, v2.z };
        DebugVisuals::Color col = { color.x, color.y, color.z, color.w };

        if (filled) {
            // For filled triangles, we need to batch these properly
            // DebugRenderer doesn't have DrawTriangle, so we use DrawPath for now
            // This is inefficient - a proper implementation would batch triangles
            std::vector<DebugVisuals::Vec3> triPath = { p0, p1, p2 };
            renderer.DrawPath(triPath, col, 1.0f, true);
        }

        if (wireframe) {
            DebugVisuals::Color wireCol = col;
            wireCol.a = (std::min)(1.0f, col.a * 2.0f);  // Slightly more visible wireframe
            
            renderer.DrawLine(p0, p1, wireCol, 1.0f);
            renderer.DrawLine(p1, p2, wireCol, 1.0f);
            renderer.DrawLine(p2, p0, wireCol, 1.0f);
        }
    }

    DirectX::XMFLOAT4 CollisionOverlayModule::GetCollisionCategoryColor(CollisionCategory cat) const {
        auto color = GetDefaultCategoryColor(cat);
        
        // Apply override if set
        if (m_categoryColorOverride[0] >= 0) {
            return {
                m_categoryColorOverride[0],
                m_categoryColorOverride[1],
                m_categoryColorOverride[2],
                m_categoryColorOverride[3]
            };
        }
        
        return color;
    }

    DirectX::XMFLOAT4 CollisionOverlayModule::GetNavAreaColor(uint8_t area) const {
        if (m_colorByArea) {
            return Navigation::GetAreaColor(static_cast<Navigation::NavAreaType>(area));
        }
        // Default greenish color
        return { 0.3f, 0.8f, 0.3f, m_navMeshAlpha };
    }

} // namespace SapphireHook
