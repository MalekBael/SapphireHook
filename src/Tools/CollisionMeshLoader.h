#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <DirectXMath.h>
#include <optional>
#include <functional>
#include <atomic>

namespace SapphireHook::Collision {

    // ============================================
    // Collision mesh categories for toggling
    // ============================================
    enum class CollisionCategory : uint32_t {
        Unknown         = 0,
        BNPC            = 1,   // LVD_BNPC_* - Battle NPC spawn areas
        NPC             = 2,   // LVD_NPC_* - Regular NPC areas
        Aetheryte       = 3,   // LVD_aetheryte_* - Aetheryte zones
        EventObject     = 4,   // LVD_EO_* - Event objects
        EventNPC        = 5,   // LVD_ENPC_* - Event NPCs
        EventRange      = 6,   // LVD_ER_* - Event ranges/triggers
        Marker          = 7,   // LVD_Marker_* - Position markers
        Pop             = 8,   // LVD_pop_* - Spawn points
        Notorious       = 9,   // LVD_NM_* - Notorious Monster areas
        BGCommon        = 10,  // bgcommon/* - Background collision meshes
        BGParts         = 11,  // bg/* - Zone-specific collision
        Other           = 12,  // Everything else
        
        COUNT           = 13   // Total number of categories
    };

    // Get human-readable name for category
    const char* GetCategoryName(CollisionCategory category);
    
    // Get default color for category (for rendering)
    DirectX::XMFLOAT4 GetDefaultCategoryColor(CollisionCategory category);

    // ============================================
    // Triangle data structure
    // ============================================
    struct Triangle {
        DirectX::XMFLOAT3 v0;
        DirectX::XMFLOAT3 v1;
        DirectX::XMFLOAT3 v2;
        DirectX::XMFLOAT3 normal;  // Computed face normal
    };

    // ============================================
    // Collision mesh object (group of triangles)
    // ============================================
    struct CollisionObject {
        std::string name;                   // Object/group name from OBJ file
        CollisionCategory category;         // Parsed category
        std::vector<Triangle> triangles;    // Triangle data
        DirectX::XMFLOAT3 boundsMin;        // AABB min
        DirectX::XMFLOAT3 boundsMax;        // AABB max
        DirectX::XMFLOAT3 center;           // Center point for LOD/culling
        bool visible = true;                // Render toggle
        
        size_t GetTriangleCount() const { return triangles.size(); }
        void ComputeBounds();               // Calculate AABB from triangles
    };

    // ============================================
    // Loaded collision mesh data
    // ============================================
    struct CollisionMesh {
        std::string name;                   // Filename/identifier
        std::string sourcePath;             // Path to source .obj file
        std::vector<CollisionObject> objects;
        DirectX::XMFLOAT3 worldBoundsMin;   // Overall AABB
        DirectX::XMFLOAT3 worldBoundsMax;
        
        // Statistics
        size_t totalVertices = 0;
        size_t totalTriangles = 0;
        size_t objectCount = 0;
        
        // Get all objects of a specific category
        std::vector<const CollisionObject*> GetObjectsByCategory(CollisionCategory category) const;
        
        // Get category statistics
        std::unordered_map<CollisionCategory, size_t> GetCategoryStats() const;
    };

    // ============================================
    // Progress callback for async loading
    // ============================================
    struct LoadProgress {
        size_t bytesRead = 0;
        size_t totalBytes = 0;
        size_t linesProcessed = 0;
        size_t totalLines = 0;
        size_t verticesLoaded = 0;
        size_t trianglesLoaded = 0;
        size_t objectsLoaded = 0;
        std::string currentObject;
        float percentage = 0.0f;
    };
    using ProgressCallback = std::function<void(const LoadProgress&)>;

    // ============================================
    // OBJ Mesh Loader
    // ============================================
    class CollisionMeshLoader {
    public:
        // Singleton access
        static CollisionMeshLoader& GetInstance();

        // Load OBJ file (blocking)
        std::optional<CollisionMesh> LoadOBJ(const std::filesystem::path& path);
        
        // Load OBJ file with progress callback (still blocking but reports progress)
        std::optional<CollisionMesh> LoadOBJ(const std::filesystem::path& path, ProgressCallback callback);
        
        // Async loading
        void LoadOBJAsync(const std::filesystem::path& path, 
                          std::function<void(std::optional<CollisionMesh>)> onComplete,
                          ProgressCallback progressCallback = nullptr);
        
        // Cancel ongoing async load
        void CancelLoad();
        bool IsLoading() const { return m_loading.load(); }
        
        // Get last error
        const std::string& GetLastError() const { return m_lastError; }

    private:
        CollisionMeshLoader() = default;
        ~CollisionMeshLoader() = default;
        CollisionMeshLoader(const CollisionMeshLoader&) = delete;
        CollisionMeshLoader& operator=(const CollisionMeshLoader&) = delete;

        // Internal parsing
        CollisionCategory ParseCategory(const std::string& objectName);
        DirectX::XMFLOAT3 ComputeNormal(const DirectX::XMFLOAT3& v0, 
                                         const DirectX::XMFLOAT3& v1, 
                                         const DirectX::XMFLOAT3& v2);

        std::atomic<bool> m_loading{false};
        std::atomic<bool> m_cancelRequested{false};
        std::string m_lastError;
    };

} // namespace SapphireHook::Collision
