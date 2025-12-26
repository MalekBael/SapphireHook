#pragma once
#include <cstdint>
#include <cmath>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>

namespace SapphireHook {

// ============================================================================
// Enums from datReader
// ============================================================================

// TriggerBox shape types
enum class TriggerBoxShape : int32_t {
    Box = 1,
    Sphere = 2,
    Cylinder = 3,
    Board = 4,
    Mesh = 5,
    BoardBothSides = 6
};

// Pop range types
enum class PopType : uint32_t {
    PC = 1,
    NPC = 2,
    BNPC = 2,
    Content = 3
};

// Door states
enum class DoorState : int32_t {
    Auto = 1,
    Open = 2,
    Closed = 3
};

// ============================================================================
// Layout Data Structures
// ============================================================================

// 3D position/vector
struct Vec3 {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    
    // Distance to another point (3D)
    [[nodiscard]] float DistanceTo(const Vec3& other) const {
        float dx = x - other.x;
        float dy = y - other.y;
        float dz = z - other.z;
        return std::sqrt(dx * dx + dy * dy + dz * dz);
    }
    
    // Distance to another point (2D, ignoring Y)
    [[nodiscard]] float DistanceTo2D(const Vec3& other) const {
        float dx = x - other.x;
        float dz = z - other.z;
        return std::sqrt(dx * dx + dz * dz);
    }
    
    // Squared distance (faster, avoids sqrt)
    [[nodiscard]] float DistanceSquaredTo(const Vec3& other) const {
        float dx = x - other.x;
        float dy = y - other.y;
        float dz = z - other.z;
        return dx * dx + dy * dy + dz * dz;
    }
};

// Collision mesh vertex
struct CollisionVertex {
    float x, y, z;
};

// Collision mesh triangle (indices into vertex array)
struct CollisionTriangle {
    uint32_t i0, i1, i2;
};

// PCB collision mesh data (from game dat files)
struct ZoneCollisionMesh {
    std::vector<CollisionVertex> Vertices;
    std::vector<CollisionTriangle> Triangles;
    Vec3 BoundsMin;
    Vec3 BoundsMax;
    uint32_t LayerId = 0;
};

// BG Parts - static environment with collision
struct BGPart {
    std::string ModelPath;
    std::string CollisionPath;
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
    bool HasCollision = false;
    bool IsVisible = true;
    bool RenderShadowEnabled = false;
    float RenderModelClipRange = 0.0f;
    // Collision config
    TriggerBoxShape CollisionShape = TriggerBoxShape::Box;
    uint32_t CollisionAttribute = 0;
    uint32_t CollisionAttributeMask = 0;
    Vec3 CollisionAABBMin;
    Vec3 CollisionAABBMax;
};

// Server path control point
struct PathControlPoint {
    Vec3 Position;
    uint16_t PointId = 0;
};

// Server path - NPC patrol routes
struct ServerPath {
    uint32_t PathId = 0;
    std::vector<PathControlPoint> ControlPoints;
    uint32_t LayerId = 0;
};

// Client path - player movement hints
struct ClientPath {
    uint32_t PathId = 0;
    std::vector<PathControlPoint> ControlPoints;
    uint32_t LayerId = 0;
};

// SharedGroup reference (for recursive loading)
struct SharedGroupRef {
    std::string SgbPath;
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
    // Initial states from SGData
    DoorState InitialDoorState = DoorState::Auto;
    bool RandomTimelineAutoPlay = false;
    bool RandomTimelineLoopPlayback = false;
    bool IsCollisionControllableWithoutEObj = false;
    uint32_t BoundClientPathInstanceID = 0;
    bool NotCreateNavimeshDoor = false;
};

// Timeline animation data
struct TimelineData {
    uint32_t TimelineId = 0;
    std::string Name;
    bool AutoPlay = false;
    bool LoopPlayback = false;
    uint32_t LayerId = 0;
};

// NavMesh range (walkable area boundary)
struct NavMeshRange {
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
};

// Door range (door trigger zone)
struct DoorRange {
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
};

// Gimmick range (puzzle/interaction zone)
struct GimmickRange {
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
};

// Keep range (PvP)
struct KeepRange {
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
};

// Chair marker (sittable position)
struct ChairMarker {
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
};

// VFX location
struct VfxLocation {
    std::string VfxPath;
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
};

// Sound location
struct SoundLocation {
    Vec3 Position;
    Vec3 Rotation;
    Vec3 Scale;
    uint32_t LayerId = 0;
};

// Layer info for filtering
struct LayerInfo {
    uint32_t LayerId = 0;
    std::string Name;
    uint16_t FestivalId = 0;
    uint16_t FestivalPhaseId = 0;
    bool IsHousing = false;
    bool IsTemporary = false;
    bool IsBushLayer = false;
};

// BattleNPC spawn point data from LGB
struct BNpcSpawnPoint {
    uint32_t NameId = 0;       // BNpcName ID for lookup
    uint32_t BaseId = 0;       // BNpcBase ID
    uint16_t Level = 0;        // NPC level
    Vec3     Position;         // World position
    Vec3     Rotation;         // Rotation (radians)
    Vec3     Scale;            // Scale
    uint32_t LayerId = 0;      // Layer this spawn belongs to
    // Spawn conditions
    uint32_t PopWeather = 0;   // Weather required for spawn
    uint8_t  PopTimeStart = 0; // Eorzea time start (0-23)
    uint8_t  PopTimeEnd = 0;   // Eorzea time end (0-23)
    uint8_t  PopInterval = 0;  // Respawn interval
    uint8_t  PopRate = 0;      // Spawn probability
    // Movement/AI
    uint8_t  WanderingRange = 0; // How far NPC wanders
    uint8_t  Route = 0;        // Patrol route index
    uint32_t MoveAI = 0;       // Movement AI type
    uint32_t NormalAI = 0;     // Combat AI type
    uint32_t ServerPathId = 0; // Patrol path reference
    // Aggro/Linking
    float    SenseRangeRate = 1.0f; // Aggro range multiplier
    uint8_t  ActiveType = 0;   // Aggro behavior type
    uint8_t  LinkGroup = 0;    // Link pull group
    uint8_t  LinkFamily = 0;   // Link pull family
    uint8_t  LinkRange = 0;    // Link pull range
    uint8_t  LinkCountLimit = 0;
    bool     LinkParent = false;
    bool     LinkReply = false;
    // Appearance
    uint32_t EquipmentID = 0;  // Equipment set
    uint32_t CustomizeID = 0;  // Appearance customization
    // Misc
    uint32_t FateLayoutLabelId = 0;
    uint32_t BoundInstanceID = 0;
    uint16_t TerritoryRange = 0;
    uint8_t  BNPCRankId = 0;   // S/A/B rank etc
    bool     Nonpop = false;   // Does not naturally spawn
};

// EventNPC data from LGB
struct ENpcSpawnPoint {
    uint32_t ENpcId = 0;       // ENpcResident ID
    Vec3     Position;         // World position
    Vec3     Rotation;         // Rotation
    Vec3     Scale;            // Scale
    uint32_t LayerId = 0;      // Layer this spawn belongs to
    // Spawn conditions (from NPCInstanceObject)
    uint32_t PopWeather = 0;
    uint8_t  PopTimeStart = 0;
    uint8_t  PopTimeEnd = 0;
    uint32_t MoveAI = 0;
    uint8_t  WanderingRange = 0;
    uint8_t  Route = 0;
    uint16_t EventGroup = 0;
};

// Collision box data from LGB
struct CollisionBox {
    Vec3     Position;         // World position
    Vec3     Scale;            // Box dimensions/scale
    Vec3     Rotation;         // Rotation
    uint32_t LayerId = 0;      // Layer this box belongs to
    TriggerBoxShape Shape = TriggerBoxShape::Box;
    int16_t  Priority = 0;
    bool     Enabled = true;
    uint32_t Attribute = 0;
    uint32_t AttributeMask = 0;
    uint32_t ResourceId = 0;
    bool     PushPlayerOut = false;
};

// Exit range (zone transitions)
struct ExitRange {
    uint16_t DestTerritoryType = 0;  // Destination zone ID
    Vec3     Position;               // World position
    Vec3     Rotation;               // Rotation
    Vec3     Scale;                  // Range dimensions
    uint32_t LayerId = 0;
    TriggerBoxShape Shape = TriggerBoxShape::Box;
    uint32_t ExitType = 0;           // Exit behavior type
    uint16_t ZoneId = 0;             // Source zone ID
    int32_t  Index = 0;              // Exit index
    uint32_t DestInstanceObjectId = 0; // Where player spawns
    uint32_t ReturnInstanceObjectId = 0;
    float    Direction = 0.0f;       // Facing direction on exit
};

// Pop range (spawn areas)
struct PopRange {
    Vec3     Position;         // World position
    Vec3     Rotation;         // Rotation
    Vec3     Scale;            // Range dimensions
    uint32_t LayerId = 0;
    PopType  Type = PopType::PC;  // What can spawn here
    float    InnerRadiusRatio = 0.0f;
    uint8_t  Index = 0;
};

// Map range
struct MapRange {
    Vec3     Position;
    Vec3     Rotation;
    Vec3     Scale;
    uint32_t LayerId = 0;
    TriggerBoxShape Shape = TriggerBoxShape::Box;
    uint32_t MapId = 0;
    uint32_t PlaceNameBlock = 0;   // Area name ID
    uint32_t PlaceNameSpot = 0;    // Specific location name ID
    uint32_t BGM = 0;              // Background music ID
    uint32_t Weather = 0;          // Weather type
    uint8_t  HousingBlockId = 0;
    uint8_t  DiscoveryIndex = 0;
    bool     RestBonusEffective = false;
    bool     MapEnabled = true;
    bool     PlaceNameEnabled = true;
    bool     DiscoveryEnabled = true;
    bool     BGMEnabled = true;
    bool     WeatherEnabled = true;
    bool     RestBonusEnabled = false;
    bool     LiftEnabled = false;
    bool     HousingEnabled = false;
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
    TriggerBoxShape Shape = TriggerBoxShape::Box;
    int16_t  Priority = 0;
    bool     Enabled = true;
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
    std::vector<std::string> LoadedSgbFiles;  // Track which SGB files were loaded
    
    // Layer info for filtering
    std::vector<LayerInfo> Layers;
    
    // NPCs
    std::vector<BNpcSpawnPoint> BattleNpcs;
    std::vector<ENpcSpawnPoint> EventNpcs;
    
    // Ranges
    std::vector<ExitRange> Exits;
    std::vector<PopRange> PopRanges;
    std::vector<MapRange> MapRanges;
    std::vector<EventRange> EventRanges;
    std::vector<FateRange> FateRanges;
    std::vector<NavMeshRange> NavMeshRanges;
    std::vector<DoorRange> DoorRanges;
    std::vector<GimmickRange> GimmickRanges;
    std::vector<KeepRange> KeepRanges;
    
    // Objects
    std::vector<EventObject> EventObjects;
    std::vector<GatheringPoint> GatheringPoints;
    std::vector<TreasurePoint> Treasures;
    std::vector<AetherytePoint> Aetherytes;
    std::vector<ChairMarker> ChairMarkers;
    
    // Environment & Misc
    std::vector<CollisionBox> CollisionBoxes;
    std::vector<EnvLocation> EnvLocations;
    std::vector<MarkerPoint> Markers;
    std::vector<VfxLocation> VfxLocations;
    std::vector<SoundLocation> SoundLocations;
    
    // NEW: BG geometry and paths
    std::vector<BGPart> BgParts;
    std::vector<ZoneCollisionMesh> CollisionMeshes;
    std::vector<ServerPath> ServerPaths;
    std::vector<ClientPath> ClientPaths;
    std::vector<SharedGroupRef> SharedGroups;
    std::vector<TimelineData> Timelines;
    
    bool IsLoaded() const { return !BgPath.empty(); }
    size_t TotalEntryCount() const {
        return BattleNpcs.size() + EventNpcs.size() + CollisionBoxes.size() + 
               Exits.size() + PopRanges.size() + MapRanges.size() +
               EventRanges.size() + FateRanges.size() + EventObjects.size() +
               GatheringPoints.size() + Treasures.size() + Aetherytes.size() +
               EnvLocations.size() + Markers.size() + NavMeshRanges.size() +
               DoorRanges.size() + GimmickRanges.size() + KeepRanges.size() +
               ChairMarkers.size() + VfxLocations.size() + SoundLocations.size() +
               BgParts.size() + CollisionMeshes.size() + ServerPaths.size() +
               ClientPaths.size() + SharedGroups.size() + Timelines.size();
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
    
    // Parse a SGB (SharedGroup) file recursively
    bool ParseSgbFile(const std::string& filePath, ZoneLayoutData& layout, 
                      const Vec3& parentPos, const Vec3& parentRot, const Vec3& parentScale);
    
    // Parse PCB collision mesh file
    bool ParsePcbFile(const std::string& filePath, ZoneLayoutData& layout, 
                      uint32_t layerId, const Vec3& pos, const Vec3& rot, const Vec3& scale);
    
    std::unordered_map<uint32_t, std::shared_ptr<ZoneLayoutData>> m_cache;
    std::string m_lastError;
};

// Global instance accessor
ZoneLayoutManager& GetZoneLayoutManager();

// ============================================================================
// Zone Context - Spatial awareness for hooks and packet decoding
// ============================================================================

// Result of a nearby element search with distance
template<typename T>
struct NearbyElement {
    const T* element = nullptr;
    float distance = 0.0f;
    
    operator bool() const { return element != nullptr; }
    const T* operator->() const { return element; }
    const T& operator*() const { return *element; }
};

// Zone context containing nearby elements within a search radius
struct ZoneContext {
    uint32_t territoryId = 0;
    Vec3 queryPosition;
    float searchRadius = 50.0f;
    
    // Nearby elements (sorted by distance)
    NearbyElement<ExitRange> nearestExit;
    NearbyElement<PopRange> nearestSpawnPoint;
    NearbyElement<EventObject> nearestInteractable;
    NearbyElement<AetherytePoint> nearestAetheryte;
    NearbyElement<GatheringPoint> nearestGatheringPoint;
    NearbyElement<MapRange> currentMapRange;
    
    // Lists of all nearby elements within radius
    std::vector<NearbyElement<BNpcSpawnPoint>> nearbyEnemies;
    std::vector<NearbyElement<ENpcSpawnPoint>> nearbyNpcs;
    std::vector<NearbyElement<EventObject>> nearbyObjects;
    std::vector<NearbyElement<FateRange>> nearbyFateRanges;
    
    // Flags
    bool isValid = false;
    bool hasLayoutData = false;
};

// Get zone context for a position in a territory
// Returns context with nearby elements within the specified radius
ZoneContext GetZoneContextForPosition(uint32_t territoryId, const Vec3& position, float searchRadius = 50.0f);

// Validate that a BNPC spawn at a position matches known spawn data
// Returns true if the spawn is valid, false if suspicious
struct BNpcValidationResult {
    bool isValid = false;
    bool hasLayoutData = false;
    bool matchesKnownSpawn = false;
    float distanceToNearestSpawn = -1.0f;
    uint32_t matchedNameId = 0;
    std::string reason;
};

BNpcValidationResult ValidateBNpcSpawn(uint32_t territoryId, uint32_t bnpcNameId, const Vec3& position, float tolerance = 50.0f);

// Check if a position is within any known exit range
bool IsPositionNearExit(uint32_t territoryId, const Vec3& position, float tolerance = 10.0f);

// Check if a position is within a FATE range
bool IsPositionInFateRange(uint32_t territoryId, const Vec3& position);

// Get the map range a position is in (for PlaceName lookups)
std::optional<uint32_t> GetPlaceNameForPosition(uint32_t territoryId, const Vec3& position);

} // namespace SapphireHook
