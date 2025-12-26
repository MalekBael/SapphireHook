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

// Read a raw file from the game data archives
// Returns empty optional if file not found or read failed
// Example paths:
//   "exd/item.exh"                           - EXD header
//   "bg/ffxiv/fst_f1/twn/f1t1/level/f1t1.lgb" - Zone layout
//   "chara/human/c0101/obj/body/b0001/model/c0101b0001_top.mdl" - Model
std::optional<std::vector<char>> ReadRawFile(const std::string& path);

// Check if a file exists in the game data archives
bool DoesFileExist(const std::string& path);

// Get file size without reading content (returns 0 if not found)
size_t GetFileSize(const std::string& path);

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
// FATE Lookups
// ============================================================================

const char* LookupFateName(uint32_t fateId) noexcept;
std::string FormatFate(uint32_t fateId);

// ============================================================================
// Recipe Lookups (Crafting)
// ============================================================================

// Note: Recipe sheet doesn't have a name field, but we can show the crafted item
const char* LookupRecipeName(uint32_t recipeId) noexcept;
std::string FormatRecipe(uint32_t recipeId);

// ============================================================================
// Content Finder Condition Lookups (Duty Finder)
// ============================================================================

const char* LookupContentFinderConditionName(uint32_t conditionId) noexcept;
std::string FormatContentFinderCondition(uint32_t conditionId);

// ============================================================================
// Leve (Levequest) Lookups
// ============================================================================

const char* LookupLeveName(uint32_t leveId) noexcept;
std::string FormatLeve(uint32_t leveId);

// ============================================================================
// Achievement Lookups
// ============================================================================

const char* LookupAchievementName(uint32_t achievementId) noexcept;
std::string FormatAchievement(uint32_t achievementId);

// ============================================================================
// Title Lookups
// ============================================================================

const char* LookupTitleName(uint32_t titleId) noexcept;
std::string FormatTitle(uint32_t titleId);

// ============================================================================
// Orchestrion Lookups
// ============================================================================

const char* LookupOrchestrionName(uint32_t orchestrionId) noexcept;
std::string FormatOrchestrion(uint32_t orchestrionId);

// ============================================================================
// Triple Triad Card Lookups
// ============================================================================

const char* LookupTripleTriadCardName(uint32_t cardId) noexcept;
std::string FormatTripleTriadCard(uint32_t cardId);

// ============================================================================
// Asset Path Resolution (for models, textures, maps, UI)
// ============================================================================

/// @brief Equipment model slot IDs (for path resolution)
enum class EquipSlot : uint8_t {
    MainHand = 0,
    OffHand = 1,
    Head = 2,
    Body = 3,
    Hands = 4,
    Legs = 6,
    Feet = 7,
    Earring = 8,
    Necklace = 9,
    Bracelet = 10,
    Ring = 11
};

/// @brief Resolve equipment model path
/// @param primaryId Primary model ID (e.g., weapon/armor model)
/// @param secondaryId Secondary model ID (variant)
/// @param slot Equipment slot
/// @return Path like "chara/equipment/e0001/model/c0101e0001_top.mdl"
std::string ResolveEquipmentModelPath(uint16_t primaryId, uint16_t secondaryId, EquipSlot slot);

/// @brief Resolve monster/BNpc model path
/// @param modelId Monster model ID
/// @param bodyId Body variant (usually 0001)
/// @param typeId Type variant (usually 0001)
/// @return Path like "chara/monster/m0001/obj/body/b0001/model/m0001b0001.mdl"
std::string ResolveMonsterModelPath(uint16_t modelId, uint16_t bodyId = 1, uint16_t typeId = 1);

/// @brief Resolve character face/hair/body model path
/// @param race Race ID (0101 = Hyur Midlander Male, etc.)
/// @param partType "face", "hair", "body", "tail", "ear"
/// @param partId Part ID
/// @return Path like "chara/human/c0101/obj/face/f0001/model/c0101f0001_fac.mdl"
std::string ResolveCharacterModelPath(uint16_t raceId, const std::string& partType, uint16_t partId);

/// @brief Resolve map texture path for a territory
/// @param territoryId Territory type ID
/// @param variant Map variant (00, 01, etc. for different map layers)
/// @return Path like "ui/map/f1t1/00/f1t100_m.tex"
std::string ResolveMapTexturePath(uint32_t territoryId, uint8_t variant = 0);

/// @brief Resolve UI icon path
/// @param iconId Icon ID
/// @param highRes Whether to get high resolution version
/// @return Path like "ui/icon/000000/000001.tex" or "ui/icon/000000/000001_hr1.tex"
std::string ResolveIconPath(uint32_t iconId, bool highRes = false);

/// @brief Resolve item icon path by item ID (looks up Item sheet for IconID)
/// @param itemId Item ID
/// @param highRes Whether to get high resolution version
/// @return Icon path or empty string if item not found
std::string ResolveItemIconPath(uint32_t itemId, bool highRes = false);

/// @brief Resolve action icon path by action ID
/// @param actionId Action ID
/// @param highRes Whether to get high resolution version
/// @return Icon path or empty string if action not found
std::string ResolveActionIconPath(uint32_t actionId, bool highRes = false);

/// @brief Resolve territory's LGB (Level Group Binary) path
/// @param territoryId Territory type ID
/// @return Path like "bg/ffxiv/fst_f1/twn/f1t1/level/bg.lgb"
std::string ResolveTerritoryLgbPath(uint32_t territoryId);

/// @brief Resolve territory's SGB (Scene Group Binary) path
/// @param territoryId Territory type ID
/// @return Path like "bg/ffxiv/fst_f1/twn/f1t1/level/planner.sgb"
std::string ResolveTerritoryPlannerPath(uint32_t territoryId);

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
    // New sheets for enhanced packet decoding
    size_t fateCount = 0;
    size_t recipeCount = 0;
    size_t contentFinderConditionCount = 0;
    size_t leveCount = 0;
    size_t achievementCount = 0;
    size_t titleCount = 0;
    size_t orchestrionCount = 0;
    size_t tripleTriadCardCount = 0;
    bool initialized = false;
};

const LoadStats& GetLoadStats();

} // namespace GameData
