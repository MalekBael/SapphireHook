#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <filesystem>

namespace GameData {

// ============================================================================
// Initialization & Lifecycle
// ============================================================================

// Initialize all lookup tables from JSON files in the data directory
// Call once at startup. Returns true if at least one file loaded successfully.
bool Initialize(const std::filesystem::path& dataDir);

// Reload all data files (for runtime updates)
bool Reload();

// Get the data directory path
const std::filesystem::path& GetDataDirectory();

// ============================================================================
// Item Lookups
// ============================================================================

// Lookup item name by ID. Returns nullptr if not found.
const char* LookupItemName(uint32_t itemId) noexcept;

// Lookup item with full info (name + optional extra data)
std::string FormatItem(uint32_t itemId);

// ============================================================================
// Action/Ability Lookups
// ============================================================================

// Lookup action name by ID. Returns nullptr if not found.
const char* LookupActionName(uint32_t actionId) noexcept;

// Format action with category info
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
    bool initialized = false;
};

const LoadStats& GetLoadStats();

} // namespace GameData
