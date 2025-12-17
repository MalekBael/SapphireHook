#pragma once
#include "../Core/ZoneLayoutManager.h"
#include "../Core/TerritoryScanner.h"
#include "../Core/NavMeshManager.h"
#include "../Tools/DebugVisualTypes.h"
#include <memory>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <string>

namespace SapphireHook {

/**
 * @brief Manages world overlays with automatic zone-aware loading.
 * 
 * This manager coordinates all debug rendering overlays in the game world.
 * It automatically loads zone layout data when the player changes zones
 * and provides a unified interface for overlay configuration.
 * 
 * Features:
 * - Automatic zone detection via TerritoryScanner
 * - Zone layout auto-loading on territory change
 * - Unified overlay toggle management
 * - Per-category visibility controls
 * - Distance-based culling
 */
class WorldOverlayManager {
public:
    /// Overlay category flags
    enum class OverlayCategory : uint32_t {
        None            = 0,
        BNpcs           = 1 << 0,
        ENpcs           = 1 << 1,
        EventObjects    = 1 << 2,
        FateRanges      = 1 << 3,
        Exits           = 1 << 4,
        PopRanges       = 1 << 5,
        Gathering       = 1 << 6,
        Treasures       = 1 << 7,
        Aetherytes      = 1 << 8,
        Collision       = 1 << 9,
        MapRanges       = 1 << 10,
        EventRanges     = 1 << 11,
        Markers         = 1 << 12,
        NavMesh         = 1 << 13,
        NavMeshPath     = 1 << 14,  // Pathfinding visualization
        OffMeshLinks    = 1 << 15,  // Off-mesh connections (jumps, ladders)
        // NEW categories
        BgParts         = 1 << 16,  // BG parts with collision paths
        ServerPaths     = 1 << 17,  // NPC patrol routes
        ClientPaths     = 1 << 18,  // Player movement hints
        NavMeshRanges   = 1 << 19,  // NavMesh range boxes
        DoorRanges      = 1 << 20,  // Door interaction ranges
        GimmickRanges   = 1 << 21,  // Gimmick interaction ranges
        KeepRanges      = 1 << 22,  // PvP keep areas
        ChairMarkers    = 1 << 23,  // Sit locations
        VfxLocations    = 1 << 24,  // VFX spawn points
        SoundLocations  = 1 << 25,  // Sound emitter locations
        // Composite flags
        AllNpcs         = BNpcs | ENpcs,
        AllRanges       = FateRanges | PopRanges | MapRanges | EventRanges | Exits | NavMeshRanges | DoorRanges | GimmickRanges | KeepRanges,
        AllObjects      = EventObjects | Gathering | Treasures | Aetherytes | ChairMarkers,
        AllNavigation   = NavMesh | NavMeshPath | OffMeshLinks | ServerPaths | ClientPaths,
        AllEnvironment  = BgParts | VfxLocations | SoundLocations,
        All             = 0xFFFFFFFF
    };
    
    /// Overlay appearance settings
    struct OverlaySettings {
        float Alpha = 0.6f;               ///< Global alpha multiplier
        float Scale = 1.0f;               ///< Global scale multiplier
        float MaxRenderDistance = 200.0f; ///< Max distance to render overlays
        bool ShowLabels = true;           ///< Show text labels
        bool EnableFrustumCulling = false;///< Future: frustum culling optimization
        uint32_t EnabledCategories = 0;   ///< Bitmask of enabled OverlayCategory
    };
    
    static WorldOverlayManager& GetInstance();
    
    /// Initialize the manager (registers with TerritoryScanner)
    void Initialize();
    
    /// Shutdown the manager
    void Shutdown();
    
    /// Check if initialized
    bool IsInitialized() const { return m_initialized; }
    
    // ========== Zone Data Access ==========
    
    /// Get the currently loaded zone layout (may be nullptr)
    std::shared_ptr<ZoneLayoutData> GetCurrentZoneLayout() const;
    
    /// Get current territory ID
    uint16_t GetCurrentTerritoryId() const;
    
    /// Get current zone name
    std::string GetCurrentZoneName() const;
    
    /// Force load a specific zone (for manual override/browsing)
    bool LoadZone(uint16_t territoryId);
    
    /// Clear the current zone data
    void ClearCurrentZone();
    
    // ========== Overlay Control ==========
    
    /// Get/set overlay settings
    OverlaySettings& GetSettings() { return m_settings; }
    const OverlaySettings& GetSettings() const { return m_settings; }
    
    /// Enable/disable a specific overlay category
    void SetCategoryEnabled(OverlayCategory category, bool enabled);
    bool IsCategoryEnabled(OverlayCategory category) const;
    
    /// Toggle master overlay enable
    void SetOverlaysEnabled(bool enabled);
    bool AreOverlaysEnabled() const { return m_overlaysEnabled; }
    
    // ========== Rendering ==========
    
    /// Render all enabled overlays (called each frame)
    void RenderOverlays();
    
    // ========== Zone Change Subscription ==========
    
    /// Callback for when zone data is loaded
    using ZoneLoadedCallback = std::function<void(uint16_t territoryId, std::shared_ptr<ZoneLayoutData>)>;
    using CallbackHandle = uint32_t;
    
    CallbackHandle RegisterZoneLoadedCallback(ZoneLoadedCallback callback);
    void UnregisterZoneLoadedCallback(CallbackHandle handle);
    
private:
    WorldOverlayManager() = default;
    ~WorldOverlayManager() = default;
    WorldOverlayManager(const WorldOverlayManager&) = delete;
    WorldOverlayManager& operator=(const WorldOverlayManager&) = delete;
    
    void OnTerritoryChanged(uint16_t newTerritory, uint16_t oldTerritory, const std::string& zoneName);
    void NotifyZoneLoaded(uint16_t territoryId, std::shared_ptr<ZoneLayoutData> layout);
    
    // Rendering helpers (per-category)
    void RenderBNpcOverlays();
    void RenderENpcOverlays();
    void RenderEventObjectOverlays();
    void RenderFateRangeOverlays();
    void RenderExitOverlays();
    void RenderPopRangeOverlays();
    void RenderGatheringOverlays();
    void RenderTreasureOverlays();
    void RenderAetheryteOverlays();
    void RenderCollisionOverlays();
    void RenderMapRangeOverlays();
    void RenderEventRangeOverlays();
    void RenderMarkerOverlays();
    void RenderNavMeshOverlays();
    void RenderNavMeshPathOverlays();
    void RenderOffMeshLinkOverlays();
    // NEW render functions
    void RenderBgPartOverlays();
    void RenderServerPathOverlays();
    void RenderClientPathOverlays();
    void RenderNavMeshRangeOverlays();
    void RenderDoorRangeOverlays();
    void RenderGimmickRangeOverlays();
    void RenderKeepRangeOverlays();
    void RenderChairMarkerOverlays();
    void RenderVfxLocationOverlays();
    void RenderSoundLocationOverlays();
    
    // Color helpers
    static DebugVisuals::Color GetBNpcColor() { return {0.4f, 0.8f, 1.0f, 0.8f}; }
    static DebugVisuals::Color GetENpcColor() { return {0.4f, 1.0f, 0.4f, 0.8f}; }
    static DebugVisuals::Color GetCollisionColor() { return {1.0f, 0.8f, 0.4f, 0.5f}; }
    static DebugVisuals::Color GetExitColor() { return {1.0f, 0.3f, 0.3f, 0.8f}; }
    static DebugVisuals::Color GetPopRangeColor() { return {0.8f, 0.4f, 1.0f, 0.6f}; }
    static DebugVisuals::Color GetMapRangeColor() { return {0.6f, 0.6f, 0.6f, 0.5f}; }
    static DebugVisuals::Color GetEventObjectColor() { return {1.0f, 1.0f, 0.4f, 0.7f}; }
    static DebugVisuals::Color GetEventRangeColor() { return {0.4f, 1.0f, 1.0f, 0.5f}; }
    static DebugVisuals::Color GetFateRangeColor() { return {1.0f, 0.6f, 0.2f, 0.7f}; }
    static DebugVisuals::Color GetGatheringColor() { return {0.2f, 0.8f, 0.4f, 0.7f}; }
    static DebugVisuals::Color GetTreasureColor() { return {1.0f, 0.84f, 0.0f, 0.8f}; }
    static DebugVisuals::Color GetAetheryteColor() { return {0.5f, 0.7f, 1.0f, 0.9f}; }
    static DebugVisuals::Color GetMarkerColor() { return {1.0f, 0.5f, 0.8f, 0.7f}; }
    static DebugVisuals::Color GetNavMeshColor() { return {0.3f, 0.6f, 0.3f, 0.3f}; }
    static DebugVisuals::Color GetNavMeshPathColor() { return {0.0f, 1.0f, 0.0f, 0.9f}; }
    static DebugVisuals::Color GetOffMeshLinkColor() { return {1.0f, 0.5f, 0.0f, 0.8f}; }
    // NEW color helpers
    static DebugVisuals::Color GetBgPartColor() { return {0.6f, 0.6f, 0.7f, 0.4f}; }
    static DebugVisuals::Color GetServerPathColor() { return {1.0f, 0.4f, 0.4f, 0.8f}; }
    static DebugVisuals::Color GetClientPathColor() { return {0.4f, 0.4f, 1.0f, 0.8f}; }
    static DebugVisuals::Color GetNavMeshRangeColor() { return {0.3f, 0.8f, 0.3f, 0.5f}; }
    static DebugVisuals::Color GetDoorRangeColor() { return {0.8f, 0.5f, 0.2f, 0.7f}; }
    static DebugVisuals::Color GetGimmickRangeColor() { return {0.9f, 0.3f, 0.9f, 0.6f}; }
    static DebugVisuals::Color GetKeepRangeColor() { return {0.8f, 0.2f, 0.2f, 0.6f}; }
    static DebugVisuals::Color GetChairMarkerColor() { return {0.4f, 0.6f, 0.8f, 0.8f}; }
    static DebugVisuals::Color GetVfxLocationColor() { return {1.0f, 0.6f, 1.0f, 0.6f}; }
    static DebugVisuals::Color GetSoundLocationColor() { return {0.6f, 1.0f, 0.6f, 0.6f}; }
    
    mutable std::mutex m_mutex;
    
    bool m_initialized = false;
    bool m_overlaysEnabled = false;
    
    uint16_t m_currentTerritoryId = 0;
    std::shared_ptr<ZoneLayoutData> m_currentLayout;
    
    OverlaySettings m_settings;
    
    TerritoryScanner::CallbackHandle m_territoryCallbackHandle = 0;
    
    // Zone loaded callbacks
    std::mutex m_callbackMutex;
    std::vector<std::pair<CallbackHandle, ZoneLoadedCallback>> m_zoneLoadedCallbacks;
    CallbackHandle m_nextCallbackHandle = 1;
};

// Bitwise operators for OverlayCategory
inline WorldOverlayManager::OverlayCategory operator|(WorldOverlayManager::OverlayCategory a, WorldOverlayManager::OverlayCategory b) {
    return static_cast<WorldOverlayManager::OverlayCategory>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline WorldOverlayManager::OverlayCategory operator&(WorldOverlayManager::OverlayCategory a, WorldOverlayManager::OverlayCategory b) {
    return static_cast<WorldOverlayManager::OverlayCategory>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline bool operator!(WorldOverlayManager::OverlayCategory a) {
    return static_cast<uint32_t>(a) == 0;
}

} // namespace SapphireHook
