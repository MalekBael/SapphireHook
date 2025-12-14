#include "GameDataLookup.h"
#include <GameData.h>
#include <ExdData.h>
#include <ExdCat.h>
#include <Exd.h>
#include <Exd/Structs.h>
#include <unordered_map>
#include <mutex>
#include <format>
#include <memory>
#include "../Logger/Logger.h"

using SapphireHook::LogInfo;
using SapphireHook::LogWarning;
using SapphireHook::LogError;

// Type aliases for datReader types to avoid namespace collision with GameData
using XivGameData = xiv::dat::GameData;
using XivExdData = xiv::exd::ExdData;
using XivLanguage = xiv::exd::Language;

namespace GameData {

// ============================================================================
// Internal Storage
// ============================================================================

namespace {
    std::filesystem::path s_sqpackPath;
    LoadStats s_stats;
    std::mutex s_mutex;
    
    // Game data instances
    std::unique_ptr<XivGameData> s_gameData;
    std::unique_ptr<XivExdData> s_exdData;
    
    // Cache maps - populated on-demand for frequently accessed data
    // Key is ID, value is name string
    std::unordered_map<uint32_t, std::string> s_items;
    std::unordered_map<uint32_t, std::string> s_actions;
    std::unordered_map<uint32_t, std::string> s_statuses;
    std::unordered_map<uint32_t, std::string> s_territories;
    std::unordered_map<uint32_t, std::string> s_classJobs;
    std::unordered_map<uint32_t, std::string> s_mounts;
    std::unordered_map<uint32_t, std::string> s_minions;
    std::unordered_map<uint32_t, std::string> s_emotes;
    std::unordered_map<uint32_t, std::string> s_quests;
    std::unordered_map<uint32_t, std::string> s_bnpcs;
    std::unordered_map<uint32_t, std::string> s_enpcs;
    std::unordered_map<uint32_t, std::string> s_placeNames;
    std::unordered_map<uint32_t, std::string> s_territoryBgPaths;

    // Helper to load a sheet into a cache map
    template<typename StructT, typename ExtractName>
    bool LoadSheet(const std::string& sheetName, std::unordered_map<uint32_t, std::string>& cache, 
                   size_t& count, ExtractName extractName) {
        try {
            if (!s_exdData) return false;
            
            auto& cat = s_exdData->get_category(sheetName);
            // Use get_data() which falls back to Language::none if English isn't available
            auto& exd = cat.get_data(XivLanguage::en);
            auto rows = exd.get_sheet_rows<StructT>();
            
            cache.clear();
            for (const auto& [id, row] : rows) {
                std::string name = extractName(row);
                if (!name.empty()) {
                    cache[id] = std::move(name);
                }
            }
            
            count = cache.size();
            LogInfo("[GameData] Loaded " + std::to_string(count) + " entries from " + sheetName);
            return true;
        }
        catch (const std::exception& e) {
            LogWarning("[GameData] Error loading " + sheetName + ": " + e.what());
            return false;
        }
    }

    void ClearCaches() {
        s_items.clear();
        s_actions.clear();
        s_statuses.clear();
        s_territories.clear();
        s_classJobs.clear();
        s_mounts.clear();
        s_minions.clear();
        s_emotes.clear();
        s_quests.clear();
        s_bnpcs.clear();
        s_enpcs.clear();
        s_placeNames.clear();
        s_territoryBgPaths.clear();
        s_stats = LoadStats{};
    }
    
} // anonymous namespace

// ============================================================================
// Initialization
// ============================================================================

bool Initialize(const std::filesystem::path& sqpackPath) {
    std::lock_guard lock(s_mutex);
    
    ClearCaches();
    s_sqpackPath = sqpackPath;
    
    if (!std::filesystem::exists(sqpackPath)) {
        LogWarning("[GameData] sqpack path does not exist: " + sqpackPath.string());
        return false;
    }
    
    try {
        LogInfo("[GameData] Initializing from sqpack: " + sqpackPath.string());
        
        s_gameData = std::make_unique<XivGameData>(sqpackPath);
        s_exdData = std::make_unique<XivExdData>(*s_gameData);
        
        // Load commonly used sheets
        // Item: Text.SGL is the singular name
        LoadSheet<Excel::Item>("Item", s_items, s_stats.itemCount, 
            [](const auto& row) { return row->getString(row->_data.Text.SGL); });
            
        // Action: Text.Name
        LoadSheet<Excel::Action>("Action", s_actions, s_stats.actionCount,
            [](const auto& row) { return row->getString(row->_data.Text.Name); });
            
        // Status: Text.Name
        LoadSheet<Excel::Status>("Status", s_statuses, s_stats.statusCount,
            [](const auto& row) { return row->getString(row->_data.Text.Name); });
        
        // ClassJob: Text.Name
        LoadSheet<Excel::ClassJob>("ClassJob", s_classJobs, s_stats.classJobCount,
            [](const auto& row) { return row->getString(row->_data.Text.Name); });
            
        // Mount: Text.SGL
        LoadSheet<Excel::Mount>("Mount", s_mounts, s_stats.mountCount,
            [](const auto& row) { return row->getString(row->_data.Text.SGL); });
            
        // Companion (minion): Text.SGL
        LoadSheet<Excel::Companion>("Companion", s_minions, s_stats.minionCount,
            [](const auto& row) { return row->getString(row->_data.Text.SGL); });
            
        // Emote: Text.Name
        LoadSheet<Excel::Emote>("Emote", s_emotes, s_stats.emoteCount,
            [](const auto& row) { return row->getString(row->_data.Text.Name); });
            
        // Quest: Text.Name
        LoadSheet<Excel::Quest>("Quest", s_quests, s_stats.questCount,
            [](const auto& row) { return row->getString(row->_data.Text.Name); });
            
        // BNpcName: Text.SGL
        LoadSheet<Excel::BNpcName>("BNpcName", s_bnpcs, s_stats.bnpcCount,
            [](const auto& row) { return row->getString(row->_data.Text.SGL); });
            
        // ENpcResident: Text.SGL
        LoadSheet<Excel::ENpcResident>("ENpcResident", s_enpcs, s_stats.enpcCount,
            [](const auto& row) { return row->getString(row->_data.Text.SGL); });
            
        // PlaceName: Text.SGL
        LoadSheet<Excel::PlaceName>("PlaceName", s_placeNames, s_stats.placeNameCount,
            [](const auto& row) { return row->getString(row->_data.Text.SGL); });
            
        // TerritoryType: Name (not in a Text struct)
        LoadSheet<Excel::TerritoryType>("TerritoryType", s_territories, s_stats.territoryCount,
            [](const auto& row) { return row->getString(row->_data.Name); });
        
        // Also load TerritoryType LVB paths (level paths for zone layout)
        {
            size_t lvbCount = 0;
            LoadSheet<Excel::TerritoryType>("TerritoryType", s_territoryBgPaths, lvbCount,
                [](const auto& row) { return row->getString(row->_data.LVB); });
        }
        
        s_stats.initialized = true;
        LogInfo("[GameData] Initialization complete");
        return true;
    }
    catch (const std::exception& e) {
        LogError("[GameData] Failed to initialize: " + std::string(e.what()));
        s_gameData.reset();
        s_exdData.reset();
        return false;
    }
}

bool IsInitialized() noexcept {
    return s_stats.initialized && s_gameData != nullptr && s_exdData != nullptr;
}

bool Reload() {
    if (s_sqpackPath.empty()) return false;
    return Initialize(s_sqpackPath);
}

const std::filesystem::path& GetDataDirectory() {
    return s_sqpackPath;
}

// ============================================================================
// Lookup Functions
// ============================================================================

const char* LookupItemName(uint32_t itemId) noexcept {
    auto it = s_items.find(itemId);
    return (it != s_items.end()) ? it->second.c_str() : nullptr;
}

std::string FormatItem(uint32_t itemId) {
    if (auto* name = LookupItemName(itemId)) {
        return std::format("{} ({})", name, itemId);
    }
    return std::to_string(itemId);
}

const char* LookupActionName(uint32_t actionId) noexcept {
    auto it = s_actions.find(actionId);
    return (it != s_actions.end()) ? it->second.c_str() : nullptr;
}

std::string FormatAction(uint32_t actionId) {
    if (auto* name = LookupActionName(actionId)) {
        return std::format("{} ({})", name, actionId);
    }
    return std::to_string(actionId);
}

const char* LookupStatusName(uint32_t statusId) noexcept {
    auto it = s_statuses.find(statusId);
    return (it != s_statuses.end()) ? it->second.c_str() : nullptr;
}

std::string FormatStatus(uint32_t statusId) {
    if (auto* name = LookupStatusName(statusId)) {
        return std::format("{} ({})", name, statusId);
    }
    return std::to_string(statusId);
}

const char* LookupTerritoryName(uint32_t territoryId) noexcept {
    auto it = s_territories.find(territoryId);
    return (it != s_territories.end()) ? it->second.c_str() : nullptr;
}

std::string FormatTerritory(uint32_t territoryId) {
    if (auto* name = LookupTerritoryName(territoryId)) {
        return std::format("{} ({})", name, territoryId);
    }
    return std::to_string(territoryId);
}

const char* LookupTerritoryBgPath(uint32_t territoryId) noexcept {
    auto it = s_territoryBgPaths.find(territoryId);
    return (it != s_territoryBgPaths.end()) ? it->second.c_str() : nullptr;
}

const char* LookupClassJobName(uint8_t classJobId) noexcept {
    auto it = s_classJobs.find(static_cast<uint32_t>(classJobId));
    return (it != s_classJobs.end()) ? it->second.c_str() : nullptr;
}

std::string FormatClassJob(uint8_t classJobId) {
    if (auto* name = LookupClassJobName(classJobId)) {
        return std::format("{} ({})", name, static_cast<unsigned>(classJobId));
    }
    return std::to_string(static_cast<unsigned>(classJobId));
}

const char* LookupMountName(uint32_t mountId) noexcept {
    auto it = s_mounts.find(mountId);
    return (it != s_mounts.end()) ? it->second.c_str() : nullptr;
}

std::string FormatMount(uint32_t mountId) {
    if (auto* name = LookupMountName(mountId)) {
        return std::format("{} ({})", name, mountId);
    }
    return std::to_string(mountId);
}

const char* LookupMinionName(uint32_t minionId) noexcept {
    auto it = s_minions.find(minionId);
    return (it != s_minions.end()) ? it->second.c_str() : nullptr;
}

std::string FormatMinion(uint32_t minionId) {
    if (auto* name = LookupMinionName(minionId)) {
        return std::format("{} ({})", name, minionId);
    }
    return std::to_string(minionId);
}

const char* LookupEmoteName(uint32_t emoteId) noexcept {
    auto it = s_emotes.find(emoteId);
    return (it != s_emotes.end()) ? it->second.c_str() : nullptr;
}

std::string FormatEmote(uint32_t emoteId) {
    if (auto* name = LookupEmoteName(emoteId)) {
        return std::format("{} ({})", name, emoteId);
    }
    return std::to_string(emoteId);
}

const char* LookupQuestName(uint32_t questId) noexcept {
    auto it = s_quests.find(questId);
    return (it != s_quests.end()) ? it->second.c_str() : nullptr;
}

std::string FormatQuest(uint32_t questId) {
    if (auto* name = LookupQuestName(questId)) {
        return std::format("{} ({})", name, questId);
    }
    return std::to_string(questId);
}

const char* LookupBNpcName(uint32_t bnpcNameId) noexcept {
    auto it = s_bnpcs.find(bnpcNameId);
    return (it != s_bnpcs.end()) ? it->second.c_str() : nullptr;
}

const char* LookupENpcName(uint32_t enpcId) noexcept {
    auto it = s_enpcs.find(enpcId);
    return (it != s_enpcs.end()) ? it->second.c_str() : nullptr;
}

const char* LookupPlaceName(uint32_t placeNameId) noexcept {
    auto it = s_placeNames.find(placeNameId);
    return (it != s_placeNames.end()) ? it->second.c_str() : nullptr;
}

std::string FormatPlaceName(uint32_t placeNameId) {
    if (auto* name = LookupPlaceName(placeNameId)) {
        return std::format("{} ({})", name, placeNameId);
    }
    return std::to_string(placeNameId);
}

const LoadStats& GetLoadStats() {
    return s_stats;
}

XivGameData* GetGameDataInstance() noexcept {
    return s_gameData.get();
}

} // namespace GameData
