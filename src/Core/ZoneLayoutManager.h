#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>

namespace SapphireHook {

// ============================================================================
// Layout Data Structures
// ============================================================================

// 3D position/vector
struct Vec3 {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
};

// BattleNPC spawn point data from LGB
struct BNpcSpawnPoint {
    uint32_t NameId = 0;       // BNpcName ID for lookup
    uint32_t BaseId = 0;       // BNpcBase ID
    uint8_t  Level = 0;        // NPC level
    Vec3     Position;         // World position
    Vec3     Rotation;         // Rotation (radians)
    Vec3     Scale;            // Scale
    uint32_t LayerId = 0;      // Layer this spawn belongs to
};

// EventNPC data from LGB
struct ENpcSpawnPoint {
    uint32_t ENpcId = 0;       // ENpcResident ID
    Vec3     Position;         // World position
    Vec3     Rotation;         // Rotation
    Vec3     Scale;            // Scale
    uint32_t LayerId = 0;      // Layer this spawn belongs to
};

// Collision box data from LGB
struct CollisionBox {
    Vec3     Position;         // World position
    Vec3     Scale;            // Box dimensions/scale
    Vec3     Rotation;         // Rotation
    uint32_t LayerId = 0;      // Layer this box belongs to
};

// Exit range (zone transitions)
struct ExitRange {
    uint16_t DestTerritoryType = 0;  // Destination zone ID
    Vec3     Position;               // World position
    Vec3     Rotation;               // Rotation
    Vec3     Scale;                  // Range dimensions
    uint32_t LayerId = 0;
};

// Pop range (spawn areas)
struct PopRange {
    Vec3     Position;         // World position
    Vec3     Rotation;         // Rotation
    Vec3     Scale;            // Range dimensions
    uint32_t LayerId = 0;
};

// Map range
struct MapRange {
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Event object (EObj) - interactable objects
struct EventObject {
    uint32_t BaseId = 0;       // EObj ID
    uint32_t BoundInstanceId = 0;
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Event range (trigger zones)
struct EventRange {
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// FATE range
struct FateRange {
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Gathering point
struct GatheringPoint {
    uint32_t BaseId = 0;       // Gathering point ID
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Treasure (chest)
struct TreasurePoint {
    uint32_t BaseId = 0;
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Aetheryte
struct AetherytePoint {
    uint32_t BaseId = 0;
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Env location (environment triggers)
struct EnvLocation {
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Marker positions (quest markers, target markers, etc.)
struct MarkerPoint {
    uint32_t Type = 0;         // Marker type (quest, target, etc.)
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
};

// Complete zone layout data
struct ZoneLayoutData {
    uint32_t TerritoryId = 0;
    std::string BgPath;
    std::vector<std::string> LoadedLgbFiles;  // Track which LGB files were loaded
    
    // NPCs
    std::vector<BNpcSpawnPoint> BattleNpcs;
    std::vector<ENpcSpawnPoint> EventNpcs;
    
    // Ranges
    std::vector<ExitRange> Exits;
    std::vector<PopRange> PopRanges;
    std::vector<MapRange> MapRanges;
    std::vector<EventRange> EventRanges;
    std::vector<FateRange> FateRanges;
    
    // Objects
    std::vector<EventObject> EventObjects;
    std::vector<GatheringPoint> GatheringPoints;
    std::vector<TreasurePoint> Treasures;
    std::vector<AetherytePoint> Aetherytes;
    
    // Environment & Misc
    std::vector<CollisionBox> CollisionBoxes;
    std::vector<EnvLocation> EnvLocations;
    std::vector<MarkerPoint> Markers;
    
    bool IsLoaded() const { return !BgPath.empty(); }
    size_t TotalEntryCount() const {
        return BattleNpcs.size() + EventNpcs.size() + CollisionBoxes.size() + 
               Exits.size() + PopRanges.size() + MapRanges.size() +
               EventRanges.size() + FateRanges.size() + EventObjects.size() +
               GatheringPoints.size() + Treasures.size() + Aetherytes.size() +
               EnvLocations.size() + Markers.size();
    }
};

// ============================================================================
// Zone Layout Manager
// ============================================================================

class ZoneLayoutManager {
public:
    // Load layout data for a territory (by ID)
    // Returns nullptr if territory has no layout or loading fails
    std::shared_ptr<ZoneLayoutData> LoadZoneLayout(uint32_t territoryId);
    
    // Load layout data for a territory (by Bg path)
    std::shared_ptr<ZoneLayoutData> LoadZoneLayoutByPath(const std::string& bgPath);
    
    // Get cached layout data for a territory
    std::shared_ptr<ZoneLayoutData> GetCachedLayout(uint32_t territoryId) const;
    
    // Clear cached layout data
    void ClearCache();
    
    // Check if GameData is available for loading
    bool CanLoadLayouts() const;
    
    // Get the last error message
    const std::string& GetLastError() const { return m_lastError; }
    
    // Statistics
    size_t GetCacheSize() const { return m_cache.size(); }
    
private:
    // Parse a single LGB file and append data to layout
    bool ParseLgbFile(const std::string& filePath, ZoneLayoutData& layout);
    
    std::unordered_map<uint32_t, std::shared_ptr<ZoneLayoutData>> m_cache;
    std::string m_lastError;
};

// Global instance accessor
ZoneLayoutManager& GetZoneLayoutManager();

} // namespace SapphireHook
