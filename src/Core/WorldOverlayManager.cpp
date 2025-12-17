#include "WorldOverlayManager.h"
#include "GameDataLookup.h"
#include "ZoneLayoutManager.h"
#include "NavMeshManager.h"
#include "../Logger/Logger.h"
#include "../Tools/DebugRenderer.h"
#include "../Tools/GameCameraExtractor.h"
#include <algorithm>
#include <format>

namespace SapphireHook {

WorldOverlayManager& WorldOverlayManager::GetInstance() {
    static WorldOverlayManager instance;
    return instance;
}

void WorldOverlayManager::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return;
    }
    
    // Initialize TerritoryScanner if not already
    TerritoryScanner::GetInstance().Initialize();
    
    // Register for territory changes
    m_territoryCallbackHandle = TerritoryScanner::GetInstance().RegisterCallback(
        [this](uint16_t newTerr, uint16_t oldTerr, const std::string& name) {
            OnTerritoryChanged(newTerr, oldTerr, name);
        }
    );
    
    // Set default enabled categories
    m_settings.EnabledCategories = 
        static_cast<uint32_t>(OverlayCategory::Exits) |
        static_cast<uint32_t>(OverlayCategory::Aetherytes) |
        static_cast<uint32_t>(OverlayCategory::FateRanges);
    
    m_initialized = true;
    
    LogInfo("[WorldOverlayManager] Initialized - listening for zone changes");
    
    // If we already have a territory (e.g., late initialization), load it
    auto state = TerritoryScanner::GetInstance().GetCurrentState();
    if (state.IsValid()) {
        LoadZone(state.TerritoryType);
    }
}

void WorldOverlayManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_territoryCallbackHandle != 0) {
        TerritoryScanner::GetInstance().UnregisterCallback(m_territoryCallbackHandle);
        m_territoryCallbackHandle = 0;
    }
    
    {
        std::lock_guard<std::mutex> cbLock(m_callbackMutex);
        m_zoneLoadedCallbacks.clear();
    }
    
    m_currentLayout.reset();
    m_currentTerritoryId = 0;
    m_initialized = false;
    
    LogInfo("[WorldOverlayManager] Shutdown");
}

std::shared_ptr<ZoneLayoutData> WorldOverlayManager::GetCurrentZoneLayout() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentLayout;
}

uint16_t WorldOverlayManager::GetCurrentTerritoryId() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentTerritoryId;
}

std::string WorldOverlayManager::GetCurrentZoneName() const {
    uint16_t terrId;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        terrId = m_currentTerritoryId;
    }
    
    if (terrId == 0) return "None";
    
    const char* name = GameData::LookupTerritoryName(terrId);
    return name ? name : std::format("Zone_{}", terrId);
}

bool WorldOverlayManager::LoadZone(uint16_t territoryId) {
    if (territoryId == 0) {
        ClearCurrentZone();
        return true;
    }
    
    LogInfo(std::format("[WorldOverlayManager] Loading zone {} layout...", territoryId));
    
    auto& layoutMgr = GetZoneLayoutManager();
    auto layout = layoutMgr.LoadZoneLayout(territoryId);
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentTerritoryId = territoryId;
        m_currentLayout = layout;
    }
    
    if (layout && layout->IsLoaded()) {
        LogInfo(std::format("[WorldOverlayManager] Loaded {} entries for zone {}", 
            layout->TotalEntryCount(), territoryId));
        NotifyZoneLoaded(territoryId, layout);
        return true;
    } else {
        LogWarning(std::format("[WorldOverlayManager] Failed to load zone {}: {}", 
            territoryId, layoutMgr.GetLastError()));
        return false;
    }
}

void WorldOverlayManager::ClearCurrentZone() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentLayout.reset();
    m_currentTerritoryId = 0;
}

void WorldOverlayManager::SetCategoryEnabled(OverlayCategory category, bool enabled) {
    if (enabled) {
        m_settings.EnabledCategories |= static_cast<uint32_t>(category);
    } else {
        m_settings.EnabledCategories &= ~static_cast<uint32_t>(category);
    }
}

bool WorldOverlayManager::IsCategoryEnabled(OverlayCategory category) const {
    return (m_settings.EnabledCategories & static_cast<uint32_t>(category)) != 0;
}

void WorldOverlayManager::SetOverlaysEnabled(bool enabled) {
    m_overlaysEnabled = enabled;
}

WorldOverlayManager::CallbackHandle WorldOverlayManager::RegisterZoneLoadedCallback(ZoneLoadedCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    CallbackHandle handle = m_nextCallbackHandle++;
    m_zoneLoadedCallbacks.emplace_back(handle, std::move(callback));
    return handle;
}

void WorldOverlayManager::UnregisterZoneLoadedCallback(CallbackHandle handle) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    auto it = std::remove_if(m_zoneLoadedCallbacks.begin(), m_zoneLoadedCallbacks.end(),
        [handle](const auto& pair) { return pair.first == handle; });
    m_zoneLoadedCallbacks.erase(it, m_zoneLoadedCallbacks.end());
}

void WorldOverlayManager::OnTerritoryChanged(uint16_t newTerritory, uint16_t oldTerritory, const std::string& zoneName) {
    LogInfo(std::format("[WorldOverlayManager] Territory changed: {} -> {} ({})", 
        oldTerritory, newTerritory, zoneName));
    
    // Load the new zone's layout
    LoadZone(newTerritory);
}

void WorldOverlayManager::NotifyZoneLoaded(uint16_t territoryId, std::shared_ptr<ZoneLayoutData> layout) {
    // Copy callbacks to avoid holding lock during invocation
    std::vector<ZoneLoadedCallback> callbacksCopy;
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        callbacksCopy.reserve(m_zoneLoadedCallbacks.size());
        for (const auto& pair : m_zoneLoadedCallbacks) {
            callbacksCopy.push_back(pair.second);
        }
    }
    
    for (const auto& callback : callbacksCopy) {
        try {
            callback(territoryId, layout);
        } catch (const std::exception& e) {
            LogError(std::format("[WorldOverlayManager] Callback exception: {}", e.what()));
        }
    }
}

void WorldOverlayManager::RenderOverlays() {
    if (!m_overlaysEnabled) return;
    
    std::shared_ptr<ZoneLayoutData> layout;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        layout = m_currentLayout;
    }
    
    if (!layout || !layout->IsLoaded()) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    if (!renderer.IsInitialized() || !renderer.IsEnabled()) return;
    
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    if (!cameraExtractor.IsInitialized()) return;
    
    // Render each enabled category
    if (IsCategoryEnabled(OverlayCategory::BNpcs)) RenderBNpcOverlays();
    if (IsCategoryEnabled(OverlayCategory::ENpcs)) RenderENpcOverlays();
    if (IsCategoryEnabled(OverlayCategory::EventObjects)) RenderEventObjectOverlays();
    if (IsCategoryEnabled(OverlayCategory::FateRanges)) RenderFateRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::Exits)) RenderExitOverlays();
    if (IsCategoryEnabled(OverlayCategory::PopRanges)) RenderPopRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::Gathering)) RenderGatheringOverlays();
    if (IsCategoryEnabled(OverlayCategory::Treasures)) RenderTreasureOverlays();
    if (IsCategoryEnabled(OverlayCategory::Aetherytes)) RenderAetheryteOverlays();
    if (IsCategoryEnabled(OverlayCategory::Collision)) RenderCollisionOverlays();
    if (IsCategoryEnabled(OverlayCategory::MapRanges)) RenderMapRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::EventRanges)) RenderEventRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::Markers)) RenderMarkerOverlays();
    
    // NEW categories
    if (IsCategoryEnabled(OverlayCategory::BgParts)) RenderBgPartOverlays();
    if (IsCategoryEnabled(OverlayCategory::ServerPaths)) RenderServerPathOverlays();
    if (IsCategoryEnabled(OverlayCategory::ClientPaths)) RenderClientPathOverlays();
    if (IsCategoryEnabled(OverlayCategory::NavMeshRanges)) RenderNavMeshRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::DoorRanges)) RenderDoorRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::GimmickRanges)) RenderGimmickRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::KeepRanges)) RenderKeepRangeOverlays();
    if (IsCategoryEnabled(OverlayCategory::ChairMarkers)) RenderChairMarkerOverlays();
    if (IsCategoryEnabled(OverlayCategory::VfxLocations)) RenderVfxLocationOverlays();
    if (IsCategoryEnabled(OverlayCategory::SoundLocations)) RenderSoundLocationOverlays();
    
    // NavMesh overlays (don't require zone layout)
    if (IsCategoryEnabled(OverlayCategory::NavMesh)) RenderNavMeshOverlays();
    if (IsCategoryEnabled(OverlayCategory::NavMeshPath)) RenderNavMeshPathOverlays();
    if (IsCategoryEnabled(OverlayCategory::OffMeshLinks)) RenderOffMeshLinkOverlays();
}

// ============================================================================
// Per-Category Rendering (reusing patterns from ZoneLayoutViewerModule)
// ============================================================================

void WorldOverlayManager::RenderBNpcOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetBNpcColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& npc : layout->BattleNpcs) {
        float dx = npc.Position.x - camPos.x;
        float dy = npc.Position.y - camPos.y;
        float dz = npc.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(npc.Position.x, npc.Position.y, npc.Position.z);
        renderer.DrawSphere(pos, 0.5f * m_settings.Scale, color, true, 8);
        renderer.DrawCylinder(pos, 0.3f * m_settings.Scale, 2.0f * m_settings.Scale, color, 8, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 top = pos;
            top.y += 2.0f * m_settings.Scale;
            const char* name = GameData::LookupBNpcName(npc.NameId);
            std::string label = name ? std::format("{} L{}", name, npc.Level) 
                                     : std::format("BNpc {} L{}", npc.NameId, npc.Level);
            renderer.DrawText3D(top, label, color, 0.8f);
        }
    }
}

void WorldOverlayManager::RenderENpcOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetENpcColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& npc : layout->EventNpcs) {
        float dx = npc.Position.x - camPos.x;
        float dy = npc.Position.y - camPos.y;
        float dz = npc.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(npc.Position.x, npc.Position.y, npc.Position.z);
        renderer.DrawSphere(pos, 0.5f * m_settings.Scale, color, true, 8);
        renderer.DrawCylinder(pos, 0.25f * m_settings.Scale, 2.5f * m_settings.Scale, color, 8, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 top = pos;
            top.y += 2.5f * m_settings.Scale;
            const char* name = GameData::LookupENpcName(npc.ENpcId);
            std::string label = name ? name : std::format("ENpc {}", npc.ENpcId);
            renderer.DrawText3D(top, label, color, 0.8f);
        }
    }
}

void WorldOverlayManager::RenderEventObjectOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetEventObjectColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& obj : layout->EventObjects) {
        float dx = obj.Position.x - camPos.x;
        float dy = obj.Position.y - camPos.y;
        float dz = obj.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(obj.Position.x, obj.Position.y, obj.Position.z);
        DebugVisuals::Vec3 halfExtents(0.4f * m_settings.Scale, 0.4f * m_settings.Scale, 0.4f * m_settings.Scale);
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.5f * m_settings.Scale;
            renderer.DrawText3D(labelPos, std::format("EObj {}", obj.BaseId), color, 0.7f);
        }
    }
}

void WorldOverlayManager::RenderFateRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetFateRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& fate : layout->FateRanges) {
        float dx = fate.Position.x - camPos.x;
        float dy = fate.Position.y - camPos.y;
        float dz = fate.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(fate.Position.x, fate.Position.y, fate.Position.z);
        float radius = (std::max)({fate.Scale.x, fate.Scale.z}) * 0.5f * m_settings.Scale;
        if (radius < 5.0f) radius = 10.0f;
        
        DebugVisuals::Color outerColor = color;
        outerColor.a *= 0.3f;
        renderer.DrawCircle(pos, radius, outerColor, 32, true);
        renderer.DrawCircle(pos, radius, color, 32, false);
        renderer.DrawCircle(pos, radius * 0.5f, color, 24, false);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 2.0f;
            renderer.DrawText3D(labelPos, std::format("FATE #{}", idx), color, 1.0f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderExitOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetExitColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& exit : layout->Exits) {
        float dx = exit.Position.x - camPos.x;
        float dy = exit.Position.y - camPos.y;
        float dz = exit.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(exit.Position.x, exit.Position.y, exit.Position.z);
        float radius = (std::max)({exit.Scale.x, exit.Scale.y, exit.Scale.z}) * m_settings.Scale;
        if (radius < 1.0f) radius = 2.0f;
        
        float height = 3.0f * m_settings.Scale;
        renderer.DrawCylinder(pos, radius, height, color, 24, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 3.5f * m_settings.Scale;
            const char* destName = GameData::LookupTerritoryName(exit.DestTerritoryType);
            std::string label = destName ? std::format("-> {}", destName) 
                                         : std::format("-> Zone {}", exit.DestTerritoryType);
            renderer.DrawText3D(labelPos, label, color, 1.0f);
        }
    }
}

void WorldOverlayManager::RenderPopRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetPopRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& pop : layout->PopRanges) {
        float dx = pop.Position.x - camPos.x;
        float dy = pop.Position.y - camPos.y;
        float dz = pop.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pop.Position.x, pop.Position.y, pop.Position.z);
        float radius = (std::max)({pop.Scale.x, pop.Scale.z}) * 0.5f * m_settings.Scale;
        if (radius < 0.5f) radius = 1.0f;
        
        renderer.DrawCircle(pos, radius, color, 16, true);
        
        DebugVisuals::Color crossColor = color;
        crossColor.a = (std::min)(1.0f, color.a * 2.0f);
        DebugVisuals::Vec3 left = pos; left.x -= radius * 0.5f;
        DebugVisuals::Vec3 right = pos; right.x += radius * 0.5f;
        DebugVisuals::Vec3 front = pos; front.z -= radius * 0.5f;
        DebugVisuals::Vec3 back = pos; back.z += radius * 0.5f;
        renderer.DrawLine(left, right, crossColor, 2.0f);
        renderer.DrawLine(front, back, crossColor, 2.0f);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.5f;
            renderer.DrawText3D(labelPos, std::format("Pop #{}", idx), color, 0.7f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderGatheringOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetGatheringColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& pt : layout->GatheringPoints) {
        float dx = pt.Position.x - camPos.x;
        float dy = pt.Position.y - camPos.y;
        float dz = pt.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
        renderer.DrawCircle(pos, 0.8f * m_settings.Scale, color, 12, true);
        renderer.DrawCylinder(pos, 0.15f * m_settings.Scale, 1.5f * m_settings.Scale, color, 6, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 2.0f * m_settings.Scale;
            renderer.DrawText3D(labelPos, std::format("Gather #{}", idx), color, 0.6f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderTreasureOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetTreasureColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& pt : layout->Treasures) {
        float dx = pt.Position.x - camPos.x;
        float dy = pt.Position.y - camPos.y;
        float dz = pt.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
        DebugVisuals::Vec3 halfExtents(0.4f * m_settings.Scale, 0.3f * m_settings.Scale, 0.3f * m_settings.Scale);
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.0f * m_settings.Scale;
            renderer.DrawText3D(labelPos, std::format("Chest #{}", idx), color, 0.6f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderAetheryteOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetAetheryteColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& pt : layout->Aetherytes) {
        float dx = pt.Position.x - camPos.x;
        float dy = pt.Position.y - camPos.y;
        float dz = pt.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
        renderer.DrawSphere(pos, 1.0f * m_settings.Scale, color, true, 12);
        renderer.DrawCylinder(pos, 0.3f * m_settings.Scale, 10.0f * m_settings.Scale, color, 8, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 5.0f * m_settings.Scale;
            renderer.DrawText3D(labelPos, "Aetheryte", color, 1.0f);
        }
    }
}

void WorldOverlayManager::RenderCollisionOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetCollisionColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& box : layout->CollisionBoxes) {
        float dx = box.Position.x - camPos.x;
        float dy = box.Position.y - camPos.y;
        float dz = box.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(box.Position.x, box.Position.y, box.Position.z);
        DebugVisuals::Vec3 halfExtents(
            box.Scale.x * 0.5f * m_settings.Scale,
            box.Scale.y * 0.5f * m_settings.Scale,
            box.Scale.z * 0.5f * m_settings.Scale
        );
        renderer.DrawBox(pos, halfExtents, color, true);
    }
}

void WorldOverlayManager::RenderMapRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetMapRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& map : layout->MapRanges) {
        float dx = map.Position.x - camPos.x;
        float dy = map.Position.y - camPos.y;
        float dz = map.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(map.Position.x, map.Position.y, map.Position.z);
        DebugVisuals::Vec3 halfExtents(
            map.Scale.x * 0.5f * m_settings.Scale,
            map.Scale.y * 0.5f * m_settings.Scale,
            map.Scale.z * 0.5f * m_settings.Scale
        );
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += halfExtents.y + 0.5f;
            renderer.DrawText3D(labelPos, std::format("Map #{}", idx), color, 0.6f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderEventRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetEventRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& r : layout->EventRanges) {
        float dx = r.Position.x - camPos.x;
        float dy = r.Position.y - camPos.y;
        float dz = r.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(r.Position.x, r.Position.y, r.Position.z);
        float radius = (std::max)({r.Scale.x, r.Scale.z}) * 0.5f * m_settings.Scale;
        if (radius < 0.5f) radius = 1.0f;
        
        renderer.DrawCircle(pos, radius, color, 16, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.0f;
            renderer.DrawText3D(labelPos, std::format("EvRange #{}", idx), color, 0.5f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderMarkerOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetMarkerColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& m : layout->Markers) {
        float dx = m.Position.x - camPos.x;
        float dy = m.Position.y - camPos.y;
        float dz = m.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(m.Position.x, m.Position.y, m.Position.z);
        renderer.DrawSphere(pos, 0.4f * m_settings.Scale, color, true, 8);
        renderer.DrawCylinder(pos, 0.1f * m_settings.Scale, 3.0f * m_settings.Scale, color, 6, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 top = pos;
            top.y += 3.5f * m_settings.Scale;
            renderer.DrawText3D(top, std::format("Marker T{}", m.Type), color, 0.6f);
        }
    }
}

// ============================================================================
// NavMesh Rendering
// ============================================================================

void WorldOverlayManager::RenderNavMeshOverlays() {
    auto& navMgr = NavMeshManager::GetInstance();
    if (!navMgr.HasNavMesh()) return;
    
    auto navMesh = navMgr.GetCurrentNavMesh();
    if (!navMesh || navMesh->tiles.empty()) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color baseColor = GetNavMeshColor();
    baseColor.a *= m_settings.Alpha;
    
    // Render visible tiles
    for (const auto& tile : navMesh->tiles) {
        if (!tile.visible) continue;
        
        // Quick AABB distance check for tile
        float tileCenterX = (tile.boundsMin.x + tile.boundsMax.x) * 0.5f;
        float tileCenterY = (tile.boundsMin.y + tile.boundsMax.y) * 0.5f;
        float tileCenterZ = (tile.boundsMin.z + tile.boundsMax.z) * 0.5f;
        float dx = tileCenterX - camPos.x;
        float dz = tileCenterZ - camPos.z;
        if (dx*dx + dz*dz > maxDistSq * 4.0f) continue;  // Tile distance check is more lenient
        
        // Frustum cull the entire tile using bounding sphere
        float tileRadius = std::sqrt(
            (tile.boundsMax.x - tile.boundsMin.x) * (tile.boundsMax.x - tile.boundsMin.x) +
            (tile.boundsMax.y - tile.boundsMin.y) * (tile.boundsMax.y - tile.boundsMin.y) +
            (tile.boundsMax.z - tile.boundsMin.z) * (tile.boundsMax.z - tile.boundsMin.z)
        ) * 0.5f;
        DebugVisuals::Vec3 tileCenter(tileCenterX, tileCenterY, tileCenterZ);
        if (!renderer.IsSphereInFrustum(tileCenter, tileRadius)) continue;
        
        for (const auto& poly : tile.polygons) {
            if (!poly.walkable) continue;
            if (poly.vertices.size() < 3) continue;
            
            // Distance check for polygon center
            float pdx = poly.center.x - camPos.x;
            float pdy = poly.center.y - camPos.y;
            float pdz = poly.center.z - camPos.z;
            if (pdx*pdx + pdy*pdy + pdz*pdz > maxDistSq) continue;
            
            // Frustum cull polygon center
            DebugVisuals::Vec3 polyCenter(poly.center.x, poly.center.y, poly.center.z);
            if (!renderer.IsPointInFrustum(polyCenter)) continue;
            
            // Color based on area type
            DebugVisuals::Color polyColor = baseColor;
            switch (static_cast<Navigation::NavAreaType>(poly.area)) {
                case Navigation::NavAreaType::Water:
                    polyColor = {0.2f, 0.4f, 0.8f, baseColor.a};
                    break;
                case Navigation::NavAreaType::Road:
                    polyColor = {0.6f, 0.5f, 0.3f, baseColor.a};
                    break;
                case Navigation::NavAreaType::Jump:
                    polyColor = {0.8f, 0.4f, 0.0f, baseColor.a};
                    break;
                default:
                    break;
            }
            
            // Draw polygon as wireframe triangles
            const auto& verts = poly.vertices;
            if (verts.size() >= 3) {
                DebugVisuals::Vec3 center(poly.center.x, poly.center.y + 0.05f, poly.center.z);
                
                // Fan triangulation for convex polygons
                for (size_t i = 1; i < verts.size() - 1; ++i) {
                    DebugVisuals::Vec3 v0(verts[0].x, verts[0].y + 0.05f, verts[0].z);
                    DebugVisuals::Vec3 v1(verts[i].x, verts[i].y + 0.05f, verts[i].z);
                    DebugVisuals::Vec3 v2(verts[i+1].x, verts[i+1].y + 0.05f, verts[i+1].z);
                    
                    // Draw edges
                    renderer.DrawLine(v0, v1, polyColor, 1.0f);
                    renderer.DrawLine(v1, v2, polyColor, 1.0f);
                    renderer.DrawLine(v2, v0, polyColor, 1.0f);
                }
            }
        }
    }
}

void WorldOverlayManager::RenderNavMeshPathOverlays() {
    auto& navMgr = NavMeshManager::GetInstance();
    if (!navMgr.HasActivePath()) return;
    
    const auto& path = navMgr.GetActivePath();
    if (!path.valid || path.waypoints.empty()) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    DebugVisuals::Color pathColor = GetNavMeshPathColor();
    pathColor.a *= m_settings.Alpha;
    
    // Draw path lines
    for (size_t i = 0; i < path.waypoints.size() - 1; ++i) {
        const auto& wp1 = path.waypoints[i];
        const auto& wp2 = path.waypoints[i + 1];
        
        DebugVisuals::Vec3 p1(wp1.x, wp1.y + 0.1f, wp1.z);
        DebugVisuals::Vec3 p2(wp2.x, wp2.y + 0.1f, wp2.z);
        
        renderer.DrawLine(p1, p2, pathColor, 3.0f);
    }
    
    // Draw waypoint markers
    DebugVisuals::Color waypointColor = {0.0f, 0.8f, 0.2f, 0.9f};
    for (size_t i = 0; i < path.waypoints.size(); ++i) {
        const auto& wp = path.waypoints[i];
        DebugVisuals::Vec3 pos(wp.x, wp.y + 0.1f, wp.z);
        
        float sphereSize = (i == 0 || i == path.waypoints.size() - 1) ? 0.4f : 0.2f;
        renderer.DrawSphere(pos, sphereSize * m_settings.Scale, waypointColor, true, 8);
    }
    
    // Draw start/end markers with labels
    if (m_settings.ShowLabels) {
        DebugVisuals::Color startColor = {0.0f, 1.0f, 0.0f, 1.0f};
        DebugVisuals::Color endColor = {1.0f, 0.3f, 0.3f, 1.0f};
        
        DebugVisuals::Vec3 startPos(path.startPos.x, path.startPos.y + 2.0f, path.startPos.z);
        DebugVisuals::Vec3 endPos(path.endPos.x, path.endPos.y + 2.0f, path.endPos.z);
        
        renderer.DrawText3D(startPos, "START", startColor, 0.8f);
        renderer.DrawText3D(endPos, "TARGET", endColor, 0.8f);
        
        // Draw target marker
        DebugVisuals::Vec3 targetGround(path.endPos.x, path.endPos.y, path.endPos.z);
        renderer.DrawCylinder(targetGround, 0.5f * m_settings.Scale, 5.0f * m_settings.Scale, endColor, 12, true);
    }
}

void WorldOverlayManager::RenderOffMeshLinkOverlays() {
    auto& navMgr = NavMeshManager::GetInstance();
    if (!navMgr.HasNavMesh()) return;
    
    auto navMesh = navMgr.GetCurrentNavMesh();
    if (!navMesh) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color linkColor = GetOffMeshLinkColor();
    linkColor.a *= m_settings.Alpha;
    
    for (const auto& tile : navMesh->tiles) {
        for (const auto& conn : tile.offMeshConnections) {
            // Distance check
            float dx = conn.startPos.x - camPos.x;
            float dy = conn.startPos.y - camPos.y;
            float dz = conn.startPos.z - camPos.z;
            if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
            
            DebugVisuals::Vec3 start(conn.startPos.x, conn.startPos.y, conn.startPos.z);
            DebugVisuals::Vec3 end(conn.endPos.x, conn.endPos.y, conn.endPos.z);
            
            // Draw connection line
            renderer.DrawLine(start, end, linkColor, 2.0f);
            
            // Draw start/end spheres
            renderer.DrawSphere(start, 0.3f * m_settings.Scale, linkColor, true, 8);
            renderer.DrawSphere(end, 0.3f * m_settings.Scale, linkColor, true, 8);
            
            // Draw arrow for direction (if one-way)
            if (conn.direction == 0) {
                // One-way: draw arrow pointing from start to end
                DebugVisuals::Vec3 midPoint(
                    (start.x + end.x) * 0.5f,
                    (start.y + end.y) * 0.5f,
                    (start.z + end.z) * 0.5f
                );
                renderer.DrawSphere(midPoint, 0.15f * m_settings.Scale, linkColor, true, 6);
            }
            
            if (m_settings.ShowLabels) {
                DebugVisuals::Vec3 labelPos(
                    (start.x + end.x) * 0.5f,
                    (start.y + end.y) * 0.5f + 1.0f,
                    (start.z + end.z) * 0.5f
                );
                std::string label = conn.direction == 0 ? "Jump (1-way)" : "Jump (2-way)";
                renderer.DrawText3D(labelPos, label, linkColor, 0.5f);
            }
        }
    }
}

// ============================================================================
// NEW Category Rendering
// ============================================================================

void WorldOverlayManager::RenderBgPartOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetBgPartColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& part : layout->BgParts) {
        float dx = part.Position.x - camPos.x;
        float dy = part.Position.y - camPos.y;
        float dz = part.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(part.Position.x, part.Position.y, part.Position.z);
        
        // Draw collision indicator if has collision
        DebugVisuals::Color boxColor = part.HasCollision ? DebugVisuals::Color{0.8f, 0.6f, 0.2f, color.a} : color;
        DebugVisuals::Vec3 halfExtents(0.5f * m_settings.Scale, 0.5f * m_settings.Scale, 0.5f * m_settings.Scale);
        renderer.DrawBox(pos, halfExtents, boxColor, false);
        
        if (m_settings.ShowLabels && !part.ModelPath.empty()) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.0f;
            // Extract just the filename from path
            size_t lastSlash = part.ModelPath.find_last_of("/\\");
            std::string label = (lastSlash != std::string::npos) 
                ? part.ModelPath.substr(lastSlash + 1) 
                : part.ModelPath;
            renderer.DrawText3D(labelPos, label, color, 0.4f);
        }
    }
}

void WorldOverlayManager::RenderServerPathOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetServerPathColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& path : layout->ServerPaths) {
        if (path.ControlPoints.size() < 2) continue;
        
        // Check if any point is in range
        bool inRange = false;
        for (const auto& pt : path.ControlPoints) {
            float dx = pt.Position.x - camPos.x;
            float dy = pt.Position.y - camPos.y;
            float dz = pt.Position.z - camPos.z;
            if (dx*dx + dy*dy + dz*dz <= maxDistSq) {
                inRange = true;
                break;
            }
        }
        if (!inRange) continue;
        
        // Draw path lines
        for (size_t i = 0; i < path.ControlPoints.size() - 1; ++i) {
            const auto& p1 = path.ControlPoints[i];
            const auto& p2 = path.ControlPoints[i + 1];
            DebugVisuals::Vec3 v1(p1.Position.x, p1.Position.y + 0.1f, p1.Position.z);
            DebugVisuals::Vec3 v2(p2.Position.x, p2.Position.y + 0.1f, p2.Position.z);
            renderer.DrawLine(v1, v2, color, 2.0f);
        }
        
        // Draw control points
        for (const auto& pt : path.ControlPoints) {
            DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
            renderer.DrawSphere(pos, 0.2f * m_settings.Scale, color, true, 6);
        }
        
        if (m_settings.ShowLabels && !path.ControlPoints.empty()) {
            const auto& firstPt = path.ControlPoints[0];
            DebugVisuals::Vec3 labelPos(firstPt.Position.x, firstPt.Position.y + 1.0f, firstPt.Position.z);
            renderer.DrawText3D(labelPos, std::format("Path {}", path.PathId), color, 0.5f);
        }
    }
}

void WorldOverlayManager::RenderClientPathOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetClientPathColor();
    color.a *= m_settings.Alpha;
    
    for (const auto& path : layout->ClientPaths) {
        if (path.ControlPoints.size() < 2) continue;
        
        bool inRange = false;
        for (const auto& pt : path.ControlPoints) {
            float dx = pt.Position.x - camPos.x;
            float dy = pt.Position.y - camPos.y;
            float dz = pt.Position.z - camPos.z;
            if (dx*dx + dy*dy + dz*dz <= maxDistSq) {
                inRange = true;
                break;
            }
        }
        if (!inRange) continue;
        
        for (size_t i = 0; i < path.ControlPoints.size() - 1; ++i) {
            const auto& p1 = path.ControlPoints[i];
            const auto& p2 = path.ControlPoints[i + 1];
            DebugVisuals::Vec3 v1(p1.Position.x, p1.Position.y + 0.1f, p1.Position.z);
            DebugVisuals::Vec3 v2(p2.Position.x, p2.Position.y + 0.1f, p2.Position.z);
            renderer.DrawLine(v1, v2, color, 2.0f);
        }
        
        for (const auto& pt : path.ControlPoints) {
            DebugVisuals::Vec3 pos(pt.Position.x, pt.Position.y, pt.Position.z);
            renderer.DrawSphere(pos, 0.15f * m_settings.Scale, color, true, 6);
        }
    }
}

void WorldOverlayManager::RenderNavMeshRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetNavMeshRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& navRange : layout->NavMeshRanges) {
        float dx = navRange.Position.x - camPos.x;
        float dy = navRange.Position.y - camPos.y;
        float dz = navRange.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(navRange.Position.x, navRange.Position.y, navRange.Position.z);
        DebugVisuals::Vec3 halfExtents(
            navRange.Scale.x * 0.5f * m_settings.Scale,
            navRange.Scale.y * 0.5f * m_settings.Scale,
            navRange.Scale.z * 0.5f * m_settings.Scale
        );
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += halfExtents.y + 0.5f;
            renderer.DrawText3D(labelPos, std::format("NavMesh #{}", idx), color, 0.5f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderDoorRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetDoorRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& door : layout->DoorRanges) {
        float dx = door.Position.x - camPos.x;
        float dy = door.Position.y - camPos.y;
        float dz = door.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(door.Position.x, door.Position.y, door.Position.z);
        
        // Draw door as a vertical rectangle
        float width = (std::max)(door.Scale.x, 1.0f) * m_settings.Scale;
        float height = (std::max)(door.Scale.y, 2.0f) * m_settings.Scale;
        DebugVisuals::Vec3 halfExtents(width * 0.5f, height * 0.5f, 0.2f * m_settings.Scale);
        renderer.DrawBox(pos, halfExtents, color, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += height * 0.5f + 0.5f;
            renderer.DrawText3D(labelPos, std::format("Door #{}", idx), color, 0.6f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderGimmickRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetGimmickRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& gimmick : layout->GimmickRanges) {
        float dx = gimmick.Position.x - camPos.x;
        float dy = gimmick.Position.y - camPos.y;
        float dz = gimmick.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(gimmick.Position.x, gimmick.Position.y, gimmick.Position.z);
        float radius = (std::max)({gimmick.Scale.x, gimmick.Scale.z}) * 0.5f * m_settings.Scale;
        if (radius < 0.5f) radius = 1.0f;
        
        renderer.DrawCircle(pos, radius, color, 16, true);
        renderer.DrawSphere(pos, 0.3f * m_settings.Scale, color, true, 8);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.5f;
            renderer.DrawText3D(labelPos, std::format("Gimmick #{}", idx), color, 0.5f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderKeepRangeOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetKeepRangeColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& keep : layout->KeepRanges) {
        float dx = keep.Position.x - camPos.x;
        float dy = keep.Position.y - camPos.y;
        float dz = keep.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(keep.Position.x, keep.Position.y, keep.Position.z);
        float radius = (std::max)({keep.Scale.x, keep.Scale.z}) * 0.5f * m_settings.Scale;
        if (radius < 5.0f) radius = 10.0f;
        
        // Large PvP area
        renderer.DrawCircle(pos, radius, color, 32, false);
        renderer.DrawCircle(pos, radius * 0.8f, color, 24, false);
        
        DebugVisuals::Color innerColor = color;
        innerColor.a *= 0.2f;
        renderer.DrawCircle(pos, radius, innerColor, 32, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 2.0f;
            renderer.DrawText3D(labelPos, std::format("Keep #{}", idx), color, 1.0f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderChairMarkerOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetChairMarkerColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& chair : layout->ChairMarkers) {
        float dx = chair.Position.x - camPos.x;
        float dy = chair.Position.y - camPos.y;
        float dz = chair.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(chair.Position.x, chair.Position.y, chair.Position.z);
        
        // Draw a small chair-like shape
        DebugVisuals::Vec3 seatHalf(0.3f * m_settings.Scale, 0.05f * m_settings.Scale, 0.3f * m_settings.Scale);
        renderer.DrawBox(pos, seatHalf, color, true);
        
        // Draw back of chair
        DebugVisuals::Vec3 backPos = pos;
        backPos.z -= 0.25f * m_settings.Scale;
        backPos.y += 0.25f * m_settings.Scale;
        DebugVisuals::Vec3 backHalf(0.3f * m_settings.Scale, 0.25f * m_settings.Scale, 0.05f * m_settings.Scale);
        renderer.DrawBox(backPos, backHalf, color, true);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 0.8f * m_settings.Scale;
            renderer.DrawText3D(labelPos, std::format("Chair #{}", idx), color, 0.5f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderVfxLocationOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetVfxLocationColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& vfx : layout->VfxLocations) {
        float dx = vfx.Position.x - camPos.x;
        float dy = vfx.Position.y - camPos.y;
        float dz = vfx.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(vfx.Position.x, vfx.Position.y, vfx.Position.z);
        
        // Sparkle effect - small sphere with radiating lines
        renderer.DrawSphere(pos, 0.2f * m_settings.Scale, color, true, 8);
        
        // Draw radiating lines
        float radius = 0.5f * m_settings.Scale;
        for (int i = 0; i < 4; ++i) {
            float angle = i * 3.14159f / 2.0f;
            DebugVisuals::Vec3 end = pos;
            end.x += radius * cosf(angle);
            end.z += radius * sinf(angle);
            renderer.DrawLine(pos, end, color, 1.0f);
        }
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.0f * m_settings.Scale;
            renderer.DrawText3D(labelPos, std::format("VFX #{}", idx), color, 0.4f);
        }
        ++idx;
    }
}

void WorldOverlayManager::RenderSoundLocationOverlays() {
    auto layout = GetCurrentZoneLayout();
    if (!layout) return;
    
    auto& renderer = DebugVisuals::DebugRenderer::GetInstance();
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 camPos = cameraExtractor.GetPlayerPositionLive();
    
    const float maxDistSq = m_settings.MaxRenderDistance * m_settings.MaxRenderDistance;
    DebugVisuals::Color color = GetSoundLocationColor();
    color.a *= m_settings.Alpha;
    
    int idx = 0;
    for (const auto& sound : layout->SoundLocations) {
        float dx = sound.Position.x - camPos.x;
        float dy = sound.Position.y - camPos.y;
        float dz = sound.Position.z - camPos.z;
        if (dx*dx + dy*dy + dz*dz > maxDistSq) continue;
        
        DebugVisuals::Vec3 pos(sound.Position.x, sound.Position.y, sound.Position.z);
        
        // Speaker-like icon - concentric circles
        renderer.DrawSphere(pos, 0.15f * m_settings.Scale, color, true, 8);
        renderer.DrawCircle(pos, 0.4f * m_settings.Scale, color, 12, false);
        renderer.DrawCircle(pos, 0.7f * m_settings.Scale, color, 16, false);
        
        if (m_settings.ShowLabels) {
            DebugVisuals::Vec3 labelPos = pos;
            labelPos.y += 1.0f * m_settings.Scale;
            renderer.DrawText3D(labelPos, std::format("Sound #{}", idx), color, 0.4f);
        }
        ++idx;
    }
}

} // namespace SapphireHook
