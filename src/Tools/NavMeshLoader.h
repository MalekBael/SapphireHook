#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <DirectXMath.h>
#include <optional>
#include <functional>
#include <atomic>
#include <memory>
#include <unordered_map>

// Forward declare Detour types to avoid header pollution
struct dtNavMesh;
struct dtNavMeshQuery;

namespace SapphireHook::Navigation {

    // ============================================
    // NavMesh polygon data for rendering
    // ============================================
    struct NavPolygon {
        std::vector<DirectX::XMFLOAT3> vertices;  // Polygon vertices (3-6 typically)
        DirectX::XMFLOAT3 center;                  // Polygon center
        DirectX::XMFLOAT3 normal;                  // Face normal (usually up for walkable)
        uint16_t flags;                            // Polygon flags (area type, etc.)
        uint8_t area;                              // Area ID
        bool walkable;                             // Is this polygon walkable?
    };

    // ============================================
    // Off-mesh connection (jump links, ladders, etc.)
    // ============================================
    struct OffMeshConnection {
        DirectX::XMFLOAT3 startPos;
        DirectX::XMFLOAT3 endPos;
        float radius;
        uint8_t direction;  // 0 = one-way, 1 = bidirectional
        uint8_t area;
        uint16_t flags;
    };

    // ============================================
    // NavMesh tile data
    // ============================================
    struct NavTile {
        int x;
        int y;
        int layer;
        std::vector<NavPolygon> polygons;
        std::vector<OffMeshConnection> offMeshConnections;
        DirectX::XMFLOAT3 boundsMin;
        DirectX::XMFLOAT3 boundsMax;
        bool visible = true;
    };

    // ============================================
    // Area type definitions (customizable)
    // ============================================
    enum class NavAreaType : uint8_t {
        Ground      = 0,   // Normal walkable ground
        Water       = 1,   // Water (swimming)
        Road        = 2,   // Roads/paths (faster movement)
        Grass       = 3,   // Grass/terrain
        Jump        = 4,   // Jump areas
        Disabled    = 5,   // Non-walkable/disabled
        All         = 0x3F // Max area value
    };

    const char* GetAreaTypeName(NavAreaType area);
    DirectX::XMFLOAT4 GetAreaColor(NavAreaType area);

    // ============================================
    // Loaded NavMesh data
    // ============================================
    struct LoadedNavMesh {
        std::string sourcePath;
        std::vector<NavTile> tiles;
        DirectX::XMFLOAT3 worldBoundsMin;
        DirectX::XMFLOAT3 worldBoundsMax;
        
        // Statistics
        size_t totalPolygons = 0;
        size_t totalVertices = 0;
        size_t totalOffMeshConnections = 0;
        size_t tileCount = 0;
        
        // Original Detour mesh (for pathfinding queries)
        dtNavMesh* detourMesh = nullptr;
        dtNavMeshQuery* detourQuery = nullptr;
        
        // Area statistics
        std::unordered_map<uint8_t, size_t> areaStats;
        
        // Check if mesh has any data (MSET has detourMesh, TESM has tiles only)
        bool IsValid() const { return detourMesh != nullptr || !tiles.empty(); }
        
        // Check if pathfinding is available (only MSET format supports this)
        bool CanPathfind() const { return detourMesh != nullptr && detourQuery != nullptr; }
    };

    // ============================================
    // Progress callback for async loading
    // ============================================
    struct NavLoadProgress {
        size_t tilesLoaded = 0;
        size_t totalTiles = 0;
        size_t polygonsLoaded = 0;
        float percentage = 0.0f;
    };
    using NavProgressCallback = std::function<void(const NavLoadProgress&)>;

    // ============================================
    // NavMesh Loader - loads TESM/Detour navmesh files
    // ============================================
    class NavMeshLoader {
    public:
        // Singleton access
        static NavMeshLoader& GetInstance();

        // Load navmesh file (blocking) - supports TESM format (Sapphire custom wrapper)
        std::optional<LoadedNavMesh> LoadNavMesh(const std::filesystem::path& path);
        
        // Load with progress callback
        std::optional<LoadedNavMesh> LoadNavMesh(const std::filesystem::path& path, 
                                                  NavProgressCallback callback);
        
        // Async loading
        void LoadNavMeshAsync(const std::filesystem::path& path,
                              std::function<void(std::optional<LoadedNavMesh>)> onComplete,
                              NavProgressCallback progressCallback = nullptr);
        
        // Cancel ongoing async load
        void CancelLoad();
        bool IsLoading() const { return m_loading.load(); }
        
        // Pathfinding queries (requires loaded navmesh with valid detourMesh/Query)
        std::vector<DirectX::XMFLOAT3> FindPath(const LoadedNavMesh& mesh,
                                                 const DirectX::XMFLOAT3& start,
                                                 const DirectX::XMFLOAT3& end);
        
        // Point queries
        std::optional<DirectX::XMFLOAT3> FindNearestPoint(const LoadedNavMesh& mesh,
                                                           const DirectX::XMFLOAT3& pos,
                                                           float searchRadius = 5.0f);
        
        // Raycast on navmesh
        bool Raycast(const LoadedNavMesh& mesh,
                     const DirectX::XMFLOAT3& start,
                     const DirectX::XMFLOAT3& end,
                     DirectX::XMFLOAT3& hitPoint);

        // Get last error
        const std::string& GetLastError() const { return m_lastError; }
        
        // Cleanup
        void UnloadNavMesh(LoadedNavMesh& mesh);

    private:
        NavMeshLoader() = default;
        ~NavMeshLoader() = default;
        NavMeshLoader(const NavMeshLoader&) = delete;
        NavMeshLoader& operator=(const NavMeshLoader&) = delete;

        // Format-specific loaders
        std::optional<LoadedNavMesh> LoadMSETNavMesh(const uint8_t* data, size_t size,
                                                      const std::string& sourcePath,
                                                      NavProgressCallback progressCallback);
        
        std::optional<LoadedNavMesh> LoadTESMNavMesh(const uint8_t* data, size_t size,
                                                      const std::string& sourcePath,
                                                      NavProgressCallback progressCallback);

        // Internal parsing for TESM format (game extracted)
        bool ParseTESMHeader(const uint8_t* data, size_t size, 
                             uint32_t& version, uint32_t& tileCount,
                             DirectX::XMFLOAT3& boundsMin, DirectX::XMFLOAT3& boundsMax);
        
        // Parse VAND tile data (game format - not Detour compatible)
        bool ParseVANDTile(const uint8_t* data, size_t size,
                           int tileIndex, NavTile& outTile);
        
        // Load raw Detour tile (MSET format)
        bool LoadTile(dtNavMesh* mesh, const uint8_t* data, size_t size, 
                      int tileIndex, NavTile& outTile);
        
        // Extract renderable polygons from Detour tile
        void ExtractPolygonsFromTile(const dtNavMesh* mesh, int tileIndex, NavTile& outTile);

        std::atomic<bool> m_loading{false};
        std::atomic<bool> m_cancelRequested{false};
        std::string m_lastError;
        
        // Parsed header values (for use during loading)
        float m_tileWidth = 32.0f;
        float m_tileHeight = 32.0f;
        uint32_t m_maxTiles = 2048;
        uint32_t m_maxPolys = 2048;
    };

} // namespace SapphireHook::Navigation
