#pragma once
#include "../Tools/NavMeshLoader.h"
#include "../Core/TerritoryScanner.h"
#include <memory>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <string>
#include <atomic>
#include <filesystem>
#include <DirectXMath.h>

namespace SapphireHook {

/**
 * @brief Manages NavMesh loading per zone with automatic territory detection.
 * 
 * This manager coordinates NavMesh loading for each territory:
 * - Automatic navmesh loading on zone change via TerritoryScanner
 * - Pathfinding queries (A* from player to target)
 * - NavMesh caching for frequently visited zones
 * - Off-mesh connection handling for jumps/ladders
 * 
 * NavMesh files are expected in: {NavMeshBasePath}/{bgName}/{bgName}.nav
 */
class NavMeshManager {
public:
    /// Path finding result
    struct PathResult {
        std::vector<DirectX::XMFLOAT3> waypoints;
        float totalDistance = 0.0f;
        bool reachable = false;
        std::string errorMessage;
        
        bool IsValid() const { return reachable && !waypoints.empty(); }
    };
    
    /// Pathfinding settings
    struct PathfindSettings {
        float searchRadius = 5.0f;           ///< Max distance to search for nearest poly
        float stepSize = 0.5f;               ///< Step size for path smoothing
        float slop = 0.15f;                  ///< Tolerance for position matching
        int maxPolys = 2048;                 ///< Max polygons in path
        int maxSmooth = 2048;                ///< Max smoothed waypoints
        bool smoothPath = true;              ///< Enable path smoothing
    };
    
    /// Current path state for visualization
    struct ActivePath {
        std::vector<DirectX::XMFLOAT3> waypoints;
        DirectX::XMFLOAT3 startPos = {0, 0, 0};
        DirectX::XMFLOAT3 endPos = {0, 0, 0};
        bool valid = false;
        uint64_t calculatedAt = 0;
        size_t currentWaypointIndex = 0;
    };
    
    static NavMeshManager& GetInstance();
    
    /// Initialize the manager (registers with TerritoryScanner)
    void Initialize();
    
    /// Shutdown the manager
    void Shutdown();
    
    /// Check if initialized
    bool IsInitialized() const { return m_initialized; }
    
    // ========== NavMesh Base Path ==========
    
    /// Set the base path where navmesh files are stored
    /// Expected structure: {basePath}/{bgName}/{bgName}.nav
    void SetNavMeshBasePath(const std::filesystem::path& basePath);
    std::filesystem::path GetNavMeshBasePath() const;
    
    // ========== Zone NavMesh Access ==========
    
    /// Get the currently loaded navmesh (may be nullptr)
    std::shared_ptr<Navigation::LoadedNavMesh> GetCurrentNavMesh() const;
    
    /// Check if current zone has a navmesh loaded
    bool HasNavMesh() const;
    
    /// Check if pathfinding is available (requires MSET format)
    bool CanPathfind() const;
    
    /// Get current territory ID
    uint16_t GetCurrentTerritoryId() const;
    
    /// Force load navmesh for a specific zone
    bool LoadNavMeshForZone(uint16_t territoryId);
    
    /// Clear the current navmesh
    void ClearNavMesh();
    
    /// Get loading status
    bool IsLoading() const { return m_loading.load(); }
    float GetLoadProgress() const;
    
    // ========== Pathfinding ==========
    
    /// Find a path from start to end position
    PathResult FindPath(const DirectX::XMFLOAT3& start, const DirectX::XMFLOAT3& end);
    
    /// Find path from player's current position to target
    PathResult FindPathFromPlayer(const DirectX::XMFLOAT3& target);
    
    /// Set the current target for pathfinding (for visualization)
    void SetPathTarget(const DirectX::XMFLOAT3& target);
    
    /// Clear the current path target
    void ClearPathTarget();
    
    /// Get the current active path for rendering
    const ActivePath& GetActivePath() const { return m_activePath; }
    
    /// Check if we have an active path
    bool HasActivePath() const { return m_activePath.valid; }
    
    /// Find nearest valid position on navmesh
    std::optional<DirectX::XMFLOAT3> FindNearestPoint(const DirectX::XMFLOAT3& pos, float radius = 5.0f);
    
    /// Get pathfinding settings
    PathfindSettings& GetPathfindSettings() { return m_pathfindSettings; }
    const PathfindSettings& GetPathfindSettings() const { return m_pathfindSettings; }
    
    // ========== Callbacks ==========
    
    using NavMeshLoadedCallback = std::function<void(uint16_t territoryId, std::shared_ptr<Navigation::LoadedNavMesh>)>;
    using CallbackHandle = uint32_t;
    
    CallbackHandle RegisterNavMeshLoadedCallback(NavMeshLoadedCallback callback);
    void UnregisterNavMeshLoadedCallback(CallbackHandle handle);
    
    // ========== Statistics ==========
    
    struct NavMeshStats {
        size_t totalPolygons = 0;
        size_t totalVertices = 0;
        size_t totalTiles = 0;
        size_t totalOffMeshConnections = 0;
        bool canPathfind = false;
        std::string format;  // "MSET" or "TESM"
    };
    
    NavMeshStats GetCurrentNavMeshStats() const;
    
private:
    NavMeshManager() = default;
    ~NavMeshManager() = default;
    NavMeshManager(const NavMeshManager&) = delete;
    NavMeshManager& operator=(const NavMeshManager&) = delete;
    
    void OnTerritoryChanged(uint16_t newTerritory, uint16_t oldTerritory, const std::string& zoneName);
    void NotifyNavMeshLoaded(uint16_t territoryId, std::shared_ptr<Navigation::LoadedNavMesh> navMesh);
    
    /// Get navmesh file path for a territory
    std::optional<std::filesystem::path> GetNavMeshPathForTerritory(uint16_t territoryId);
    
    /// Extract bg name from bg path (e.g., "ffxiv/fst_f1/fld/f1f1" -> "f1f1")
    std::string ExtractBgName(const std::string& bgPath);
    
    mutable std::mutex m_mutex;
    
    bool m_initialized = false;
    std::atomic<bool> m_loading{false};
    float m_loadProgress = 0.0f;
    
    std::filesystem::path m_navMeshBasePath;
    
    uint16_t m_currentTerritoryId = 0;
    std::shared_ptr<Navigation::LoadedNavMesh> m_currentNavMesh;
    
    PathfindSettings m_pathfindSettings;
    ActivePath m_activePath;
    
    TerritoryScanner::CallbackHandle m_territoryCallbackHandle = 0;
    
    // NavMesh loaded callbacks
    std::mutex m_callbackMutex;
    std::vector<std::pair<CallbackHandle, NavMeshLoadedCallback>> m_navMeshLoadedCallbacks;
    CallbackHandle m_nextCallbackHandle = 1;
    
    // Cache recently loaded navmeshes (LRU)
    static constexpr size_t MAX_CACHED_NAVMESHES = 3;
    std::unordered_map<uint16_t, std::shared_ptr<Navigation::LoadedNavMesh>> m_navMeshCache;
};

} // namespace SapphireHook
