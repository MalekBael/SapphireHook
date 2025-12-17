#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <filesystem>

// Forward declaration for xiv::dat::GameData
namespace xiv { namespace dat { class GameData; } }

namespace GameData {

// ============================================================================
// Initialization & Lifecycle
// ============================================================================

// Initialize from the game's sqpack directory (e.g., "C:/FFXIV/game/sqpack")
// Call once at startup. Returns true if successfully loaded game data.
bool Initialize(const std::filesystem::path& sqpackPath);

// Check if initialized
bool IsInitialized() noexcept;

// Reload all data (re-reads from sqpack)
bool Reload();

// Get the sqpack directory path
const std::filesystem::path& GetDataDirectory();

// ============================================================================
// Item Lookups
// ============================================================================

// Lookup item name by ID. Returns nullptr if not found.
const char* LookupItemName(uint32_t itemId) noexcept;

// Lookup item with full info (name + ID)
std::string FormatItem(uint32_t itemId);

// ============================================================================
// Action/Ability Lookups
// ============================================================================

// Lookup action name by ID. Returns nullptr if not found.
const char* LookupActionName(uint32_t actionId) noexcept;

// Format action with ID
std::string FormatAction(uint32_t actionId);

// ============================================================================
// Status Effect Lookups
// ============================================================================

// Lookup status effect name by ID
const char* LookupStatusName(uint32_t statusId) noexcept;

std::string FormatStatus(uint32_t statusId);

// ============================================================================
// Territory/Zone Lookups
// ============================================================================

// Lookup territory/zone name by ID
const char* LookupTerritoryName(uint32_t territoryId) noexcept;

std::string FormatTerritory(uint32_t territoryId);

// Lookup territory's Bg (level) path by ID (e.g., "ffxiv/fst_f1/twn/f1t1/level/f1t1")
// Returns nullptr if not found or territory has no Bg path
const char* LookupTerritoryBgPath(uint32_t territoryId) noexcept;

// ============================================================================
// Map Lookups
// ============================================================================

// Map info structure with coordinate conversion data
struct MapInfo {
    uint32_t mapId = 0;
    uint16_t territoryType = 0;
    uint16_t sizeFactor = 100;  // Default 100 = 1.0 scale
    int16_t offsetX = 0;
    int16_t offsetY = 0;
    std::string path;
    
    // Convert world X/Z coordinate to map 2D coordinate
    // Based on Saint Coinach: ToMapCoordinate3d
    double WorldToMap(double worldCoord, int offset) const {
        double c = sizeFactor / 100.0;
        double offsetValue = (worldCoord + offset) * c;
        return ((41.0 / c) * ((offsetValue + 1024.0) / 2048.0)) + 1.0;
    }
    
    // Convert map 2D coordinate back to world X/Z coordinate
    // Inverse of WorldToMap
    double MapToWorld(double mapCoord, int offset) const {
        double c = sizeFactor / 100.0;
        // Reverse: mapCoord = ((41.0 / c) * ((offsetValue + 1024.0) / 2048.0)) + 1.0
        // (mapCoord - 1.0) * c / 41.0 = (offsetValue + 1024.0) / 2048.0
        // (mapCoord - 1.0) * c * 2048.0 / 41.0 = offsetValue + 1024.0
        // offsetValue = (mapCoord - 1.0) * c * 2048.0 / 41.0 - 1024.0
        // worldCoord = offsetValue / c - offset
        double offsetValue = (mapCoord - 1.0) * c * 2048.0 / 41.0 - 1024.0;
        return offsetValue / c - offset;
    }
    
    // Convenience: Convert world position to map position using this map's offsets
    double WorldXToMapX(double worldX) const { return WorldToMap(worldX, offsetX); }
    double WorldZToMapY(double worldZ) const { return WorldToMap(worldZ, offsetY); }
    double MapXToWorldX(double mapX) const { return MapToWorld(mapX, offsetX); }
    double MapYToWorldZ(double mapY) const { return MapToWorld(mapY, offsetY); }
};

// Lookup map path by ID
const char* LookupMapPath(uint32_t mapId) noexcept;

// Lookup full map info by ID
const MapInfo* LookupMapInfo(uint32_t mapId) noexcept;

// Lookup map info by territory type (convenience)
const MapInfo* LookupMapInfoByTerritory(uint32_t territoryType) noexcept;

// ============================================================================
// Weather Lookups
// ============================================================================

const char* LookupWeatherName(uint32_t weatherId) noexcept;
std::string FormatWeather(uint32_t weatherId);

// ============================================================================
// World (Server) Lookups
// ============================================================================

const char* LookupWorldName(uint32_t worldId) noexcept;
std::string FormatWorld(uint32_t worldId);

// ============================================================================
// Aetheryte Lookups
// ============================================================================

const char* LookupAetheryteName(uint32_t aetheryteId) noexcept;
std::string FormatAetheryte(uint32_t aetheryteId);

// ============================================================================
// InstanceContent (Duty) Lookups
// ============================================================================

const char* LookupInstanceContentName(uint32_t instanceContentId) noexcept;
std::string FormatInstanceContent(uint32_t instanceContentId);

// ============================================================================
// Raw File Access
// ============================================================================

// Get the underlying GameData instance for direct file access
// Returns nullptr if not initialized
::xiv::dat::GameData* GetGameDataInstance() noexcept;

// ============================================================================
// Class/Job Lookups
// ============================================================================

// Lookup class/job name by ID
const char* LookupClassJobName(uint8_t classJobId) noexcept;

std::string FormatClassJob(uint8_t classJobId);

// ============================================================================
// Mount & Minion Lookups
// ============================================================================

const char* LookupMountName(uint32_t mountId) noexcept;
std::string FormatMount(uint32_t mountId);

const char* LookupMinionName(uint32_t minionId) noexcept;
std::string FormatMinion(uint32_t minionId);

// ============================================================================
// Emote Lookups
// ============================================================================

const char* LookupEmoteName(uint32_t emoteId) noexcept;
std::string FormatEmote(uint32_t emoteId);

// ============================================================================
// Quest Lookups
// ============================================================================

const char* LookupQuestName(uint32_t questId) noexcept;
std::string FormatQuest(uint32_t questId);

// ============================================================================
// BNpc (Battle NPC / Monster) Lookups
// ============================================================================

const char* LookupBNpcName(uint32_t bnpcNameId) noexcept;

// ============================================================================
// ENpc (Event NPC) Lookups
// ============================================================================

const char* LookupENpcName(uint32_t enpcId) noexcept;

// ============================================================================
// PlaceName Lookups
// ============================================================================

const char* LookupPlaceName(uint32_t placeNameId) noexcept;
std::string FormatPlaceName(uint32_t placeNameId);

// ============================================================================
// Statistics
// ============================================================================

struct LoadStats {
    size_t itemCount = 0;
    size_t actionCount = 0;
    size_t statusCount = 0;
    size_t territoryCount = 0;
    size_t classJobCount = 0;
    size_t mountCount = 0;
    size_t minionCount = 0;
    size_t emoteCount = 0;
    size_t questCount = 0;
    size_t bnpcCount = 0;
    size_t enpcCount = 0;
    size_t placeNameCount = 0;
    size_t mapCount = 0;
    size_t weatherCount = 0;
    size_t worldCount = 0;
    size_t aetheryteCount = 0;
    size_t instanceContentCount = 0;
    bool initialized = false;
};

const LoadStats& GetLoadStats();

} // namespace GameData
