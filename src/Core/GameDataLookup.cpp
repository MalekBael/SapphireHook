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
    std::unordered_map<uint32_t, std::string> s_maps;  // Just paths for backwards compat
    std::unordered_map<uint32_t, MapInfo> s_mapInfos;  // Full map info
    std::unordered_map<uint32_t, uint32_t> s_territoryToMap;  // TerritoryType -> MapId
    std::unordered_map<uint32_t, std::string> s_weathers;
    std::unordered_map<uint32_t, std::string> s_worlds;
    std::unordered_map<uint32_t, std::string> s_aetherytes;
    std::unordered_map<uint32_t, std::string> s_instanceContents;
    
    // New EXD sheets for enhanced packet decoding
    std::unordered_map<uint32_t, std::string> s_fates;
    std::unordered_map<uint32_t, std::string> s_recipes;
    std::unordered_map<uint32_t, std::string> s_contentFinderConditions;
    std::unordered_map<uint32_t, std::string> s_leves;
    std::unordered_map<uint32_t, std::string> s_achievements;
    std::unordered_map<uint32_t, std::string> s_titles;
    std::unordered_map<uint32_t, std::string> s_orchestrions;
    std::unordered_map<uint32_t, std::string> s_tripleTriadCards;

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
        s_maps.clear();
        s_mapInfos.clear();
        s_territoryToMap.clear();
        s_weathers.clear();
        s_worlds.clear();
        s_aetherytes.clear();
        s_instanceContents.clear();
        s_fates.clear();
        s_recipes.clear();
        s_contentFinderConditions.clear();
        s_leves.clear();
        s_achievements.clear();
        s_titles.clear();
        s_orchestrions.clear();
        s_tripleTriadCards.clear();
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
        
        // Map: Try to load using the simple LoadSheet first
        // The Map struct might have issues with get_sheet_rows, so we'll just load paths for now
        // and add full MapInfo support later if needed
        LoadSheet<Excel::Map>("Map", s_maps, s_stats.mapCount,
            [](const auto& row) { return row->getString(row->_data.Path); });
        
        // Build MapInfo by reading TerritoryType first, then fetching Map data per-row
        // We avoid get_sheet_rows<Excel::Map> since it can crash with large sheets
        try {
            auto& terrCat = s_exdData->get_category("TerritoryType");
            auto& terrExd = terrCat.get_data(XivLanguage::en);
            auto terrRows = terrExd.get_sheet_rows<Excel::TerritoryType>();
            
            // Get the Map exd for individual row lookups
            auto& mapCat = s_exdData->get_category("Map");
            auto& mapExd = mapCat.get_data(XivLanguage::en);
            
            size_t mapDataReadCount = 0;
            for (const auto& [terrId, row] : terrRows) {
                uint16_t mapId = row->_data.Map;
                if (mapId == 0) continue;
                
                MapInfo info;
                info.mapId = mapId;
                info.territoryType = static_cast<uint16_t>(terrId);
                info.sizeFactor = 100;  // Default
                info.offsetX = 0;
                info.offsetY = 0;
                
                // Try to read actual Map data using get_row (non-templated, returns Fields)
                // Map columns based on EXD schema:
                // Index 3: SizeFactor (UInt16)
                // Index 7: OffsetX (Int16)
                // Index 8: OffsetY (Int16)
                try {
                    auto fields = mapExd.get_row(mapId);
                    if (fields.size() > 8) {
                        // SizeFactor at index 3 (UInt16)
                        if (auto* sf = std::get_if<uint16_t>(&fields[3])) {
                            info.sizeFactor = *sf;
                        }
                        // OffsetX at index 7 (Int16)
                        if (auto* ox = std::get_if<int16_t>(&fields[7])) {
                            info.offsetX = *ox;
                        }
                        // OffsetY at index 8 (Int16)
                        if (auto* oy = std::get_if<int16_t>(&fields[8])) {
                            info.offsetY = *oy;
                        }
                        mapDataReadCount++;
                    }
                }
                catch (...) {
                    // Could not read this Map row, keep defaults
                }
                
                s_mapInfos[mapId] = info;
                s_territoryToMap[terrId] = mapId;
            }
            LogInfo("[GameData] Built " + std::to_string(s_mapInfos.size()) + " MapInfo entries (" 
                + std::to_string(mapDataReadCount) + " with Map data)");
        }
        catch (const std::exception& e) {
            LogWarning("[GameData] Could not build MapInfo from TerritoryType: " + std::string(e.what()));
        }
        
        // Weather: Text.Name
        LogInfo("[GameData] Loading Weather...");
        try {
            LoadSheet<Excel::Weather>("Weather", s_weathers, s_stats.weatherCount,
                [](const auto& row) { return row->getString(row->_data.Text.Name); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] Weather loading failed: " + std::string(e.what()));
        }
        
        // World: InternalName (the actual world name string)
        LogInfo("[GameData] Loading World...");
        try {
            LoadSheet<Excel::World>("World", s_worlds, s_stats.worldCount,
                [](const auto& row) { return row->getString(row->_data.InternalName); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] World loading failed: " + std::string(e.what()));
        }
        
        // Aetheryte: Text.SGL
        LogInfo("[GameData] Loading Aetheryte...");
        try {
            LoadSheet<Excel::Aetheryte>("Aetheryte", s_aetherytes, s_stats.aetheryteCount,
                [](const auto& row) { return row->getString(row->_data.Text.SGL); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] Aetheryte loading failed: " + std::string(e.what()));
        }
        
        // InstanceContent: Text.Name
        LogInfo("[GameData] Loading InstanceContent...");
        try {
            LoadSheet<Excel::InstanceContent>("InstanceContent", s_instanceContents, s_stats.instanceContentCount,
                [](const auto& row) { return row->getString(row->_data.Text.Name); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] InstanceContent loading failed: " + std::string(e.what()));
        }
        
        // ====================================================================
        // NEW: Enhanced Packet Decoding Sheets
        // ====================================================================
        
        // Fate: Text.TitleText (FATE name)
        LogInfo("[GameData] Loading Fate...");
        try {
            LoadSheet<Excel::Fate>("Fate", s_fates, s_stats.fateCount,
                [](const auto& row) { return row->getString(row->_data.Text.TitleText); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] Fate loading failed: " + std::string(e.what()));
        }
        
        // Leve: Text.Name (Levequest name)
        LogInfo("[GameData] Loading Leve...");
        try {
            LoadSheet<Excel::Leve>("Leve", s_leves, s_stats.leveCount,
                [](const auto& row) { return row->getString(row->_data.Text.Name); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] Leve loading failed: " + std::string(e.what()));
        }
        
        // Achievement: Text.Name
        LogInfo("[GameData] Loading Achievement...");
        try {
            LoadSheet<Excel::Achievement>("Achievement", s_achievements, s_stats.achievementCount,
                [](const auto& row) { return row->getString(row->_data.Text.Name); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] Achievement loading failed: " + std::string(e.what()));
        }
        
        // Title: Text.Male (use male variant as primary)
        LogInfo("[GameData] Loading Title...");
        try {
            LoadSheet<Excel::Title>("Title", s_titles, s_stats.titleCount,
                [](const auto& row) { return row->getString(row->_data.Text.Male); });
        } catch (const std::exception& e) {
            LogWarning("[GameData] Title loading failed: " + std::string(e.what()));
        }
        
        // ContentFinderCondition: We need to get the name via the linked InstanceContent
        // For now, store the InstanceContentId as the "name" and lookup at runtime
        // Or we could build a more complex lookup. For simplicity, use InstanceContent names.
        LogInfo("[GameData] Loading ContentFinderCondition...");
        try {
            // ContentFinderCondition links to InstanceContent via InstanceContentId field
            // We'll read ContentFinderCondition and look up names from s_instanceContents
            auto& cat = s_exdData->get_category("ContentFinderCondition");
            auto& exd = cat.get_data(XivLanguage::en);
            auto rows = exd.get_sheet_rows<Excel::ContentFinderCondition>();
            
            s_contentFinderConditions.clear();
            for (const auto& [id, row] : rows) {
                uint16_t instanceId = row->_data.InstanceContentId;
                // Look up the instance content name
                auto it = s_instanceContents.find(instanceId);
                if (it != s_instanceContents.end() && !it->second.empty()) {
                    s_contentFinderConditions[id] = it->second;
                }
            }
            s_stats.contentFinderConditionCount = s_contentFinderConditions.size();
            LogInfo("[GameData] Loaded " + std::to_string(s_stats.contentFinderConditionCount) + " entries from ContentFinderCondition");
        } catch (const std::exception& e) {
            LogWarning("[GameData] ContentFinderCondition loading failed: " + std::string(e.what()));
        }
        
        // Recipe: Doesn't have a name field, but we store the CraftItemId for runtime lookup
        // We'll format recipes as "Recipe #X (creates ItemName)" at format time
        // For the cache, store the item name of the crafted item
        LogInfo("[GameData] Loading Recipe...");
        try {
            auto& cat = s_exdData->get_category("Recipe");
            auto& exd = cat.get_data(XivLanguage::en);
            auto rows = exd.get_sheet_rows<Excel::Recipe>();
            
            s_recipes.clear();
            for (const auto& [id, row] : rows) {
                int32_t craftItemId = row->_data.CraftItemId;
                if (craftItemId > 0) {
                    // Look up the crafted item name
                    auto it = s_items.find(static_cast<uint32_t>(craftItemId));
                    if (it != s_items.end() && !it->second.empty()) {
                        s_recipes[id] = it->second;
                    }
                }
            }
            s_stats.recipeCount = s_recipes.size();
            LogInfo("[GameData] Loaded " + std::to_string(s_stats.recipeCount) + " entries from Recipe");
        } catch (const std::exception& e) {
            LogWarning("[GameData] Recipe loading failed: " + std::string(e.what()));
        }
        
        // Note: Orchestrion and TripleTriadCard sheets are not in Structs.h
        // We'll add placeholders and implement when struct definitions are available
        s_stats.orchestrionCount = 0;
        s_stats.tripleTriadCardCount = 0;
        
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

const char* LookupMapPath(uint32_t mapId) noexcept {
    auto it = s_maps.find(mapId);
    return (it != s_maps.end()) ? it->second.c_str() : nullptr;
}

const MapInfo* LookupMapInfo(uint32_t mapId) noexcept {
    auto it = s_mapInfos.find(mapId);
    return (it != s_mapInfos.end()) ? &it->second : nullptr;
}

const MapInfo* LookupMapInfoByTerritory(uint32_t territoryType) noexcept {
    auto mapIt = s_territoryToMap.find(territoryType);
    if (mapIt == s_territoryToMap.end()) return nullptr;
    
    auto infoIt = s_mapInfos.find(mapIt->second);
    return (infoIt != s_mapInfos.end()) ? &infoIt->second : nullptr;
}

const char* LookupWeatherName(uint32_t weatherId) noexcept {
    auto it = s_weathers.find(weatherId);
    return (it != s_weathers.end()) ? it->second.c_str() : nullptr;
}

std::string FormatWeather(uint32_t weatherId) {
    if (auto* name = LookupWeatherName(weatherId)) {
        return std::format("{} ({})", name, weatherId);
    }
    return std::to_string(weatherId);
}

const char* LookupWorldName(uint32_t worldId) noexcept {
    auto it = s_worlds.find(worldId);
    return (it != s_worlds.end()) ? it->second.c_str() : nullptr;
}

std::string FormatWorld(uint32_t worldId) {
    if (auto* name = LookupWorldName(worldId)) {
        return std::format("{} ({})", name, worldId);
    }
    return std::to_string(worldId);
}

const char* LookupAetheryteName(uint32_t aetheryteId) noexcept {
    auto it = s_aetherytes.find(aetheryteId);
    return (it != s_aetherytes.end()) ? it->second.c_str() : nullptr;
}

std::string FormatAetheryte(uint32_t aetheryteId) {
    if (auto* name = LookupAetheryteName(aetheryteId)) {
        return std::format("{} ({})", name, aetheryteId);
    }
    return std::to_string(aetheryteId);
}

const char* LookupInstanceContentName(uint32_t instanceContentId) noexcept {
    auto it = s_instanceContents.find(instanceContentId);
    return (it != s_instanceContents.end()) ? it->second.c_str() : nullptr;
}

std::string FormatInstanceContent(uint32_t instanceContentId) {
    if (auto* name = LookupInstanceContentName(instanceContentId)) {
        return std::format("{} ({})", name, instanceContentId);
    }
    return std::to_string(instanceContentId);
}

// ============================================================================
// NEW: Enhanced Packet Decoding Lookups
// ============================================================================

const char* LookupFateName(uint32_t fateId) noexcept {
    auto it = s_fates.find(fateId);
    return (it != s_fates.end()) ? it->second.c_str() : nullptr;
}

std::string FormatFate(uint32_t fateId) {
    if (auto* name = LookupFateName(fateId)) {
        return std::format("{} ({})", name, fateId);
    }
    return std::to_string(fateId);
}

const char* LookupRecipeName(uint32_t recipeId) noexcept {
    auto it = s_recipes.find(recipeId);
    return (it != s_recipes.end()) ? it->second.c_str() : nullptr;
}

std::string FormatRecipe(uint32_t recipeId) {
    if (auto* itemName = LookupRecipeName(recipeId)) {
        return std::format("Recipe: {} ({})", itemName, recipeId);
    }
    return std::format("Recipe #{}", recipeId);
}

const char* LookupContentFinderConditionName(uint32_t conditionId) noexcept {
    auto it = s_contentFinderConditions.find(conditionId);
    return (it != s_contentFinderConditions.end()) ? it->second.c_str() : nullptr;
}

std::string FormatContentFinderCondition(uint32_t conditionId) {
    if (auto* name = LookupContentFinderConditionName(conditionId)) {
        return std::format("{} ({})", name, conditionId);
    }
    return std::format("ContentFinder #{}", conditionId);
}

const char* LookupLeveName(uint32_t leveId) noexcept {
    auto it = s_leves.find(leveId);
    return (it != s_leves.end()) ? it->second.c_str() : nullptr;
}

std::string FormatLeve(uint32_t leveId) {
    if (auto* name = LookupLeveName(leveId)) {
        return std::format("{} ({})", name, leveId);
    }
    return std::to_string(leveId);
}

const char* LookupAchievementName(uint32_t achievementId) noexcept {
    auto it = s_achievements.find(achievementId);
    return (it != s_achievements.end()) ? it->second.c_str() : nullptr;
}

std::string FormatAchievement(uint32_t achievementId) {
    if (auto* name = LookupAchievementName(achievementId)) {
        return std::format("{} ({})", name, achievementId);
    }
    return std::to_string(achievementId);
}

const char* LookupTitleName(uint32_t titleId) noexcept {
    auto it = s_titles.find(titleId);
    return (it != s_titles.end()) ? it->second.c_str() : nullptr;
}

std::string FormatTitle(uint32_t titleId) {
    if (auto* name = LookupTitleName(titleId)) {
        return std::format("{} ({})", name, titleId);
    }
    return std::to_string(titleId);
}

const char* LookupOrchestrionName(uint32_t orchestrionId) noexcept {
    auto it = s_orchestrions.find(orchestrionId);
    return (it != s_orchestrions.end()) ? it->second.c_str() : nullptr;
}

std::string FormatOrchestrion(uint32_t orchestrionId) {
    if (auto* name = LookupOrchestrionName(orchestrionId)) {
        return std::format("{} ({})", name, orchestrionId);
    }
    return std::to_string(orchestrionId);
}

const char* LookupTripleTriadCardName(uint32_t cardId) noexcept {
    auto it = s_tripleTriadCards.find(cardId);
    return (it != s_tripleTriadCards.end()) ? it->second.c_str() : nullptr;
}

std::string FormatTripleTriadCard(uint32_t cardId) {
    if (auto* name = LookupTripleTriadCardName(cardId)) {
        return std::format("{} ({})", name, cardId);
    }
    return std::to_string(cardId);
}

// ============================================================================
// Asset Path Resolution
// ============================================================================

namespace {
    // Helper to zero-pad IDs for path construction
    std::string PadId(uint16_t id, size_t width = 4) {
        std::string s = std::to_string(id);
        if (s.length() < width) {
            s.insert(0, width - s.length(), '0');
        }
        return s;
    }
    
    // Equipment slot suffix for model files
    const char* GetEquipSlotSuffix(EquipSlot slot) {
        switch (slot) {
            case EquipSlot::MainHand:
            case EquipSlot::OffHand:
                return ""; // Weapons have different structure
            case EquipSlot::Head:   return "_met";  // helmet/met
            case EquipSlot::Body:   return "_top";  // top
            case EquipSlot::Hands:  return "_glv";  // gloves
            case EquipSlot::Legs:   return "_dwn";  // down/legs
            case EquipSlot::Feet:   return "_sho";  // shoes
            case EquipSlot::Earring:
            case EquipSlot::Necklace:
            case EquipSlot::Bracelet:
            case EquipSlot::Ring:
                return "_acc";  // accessory
            default: return "";
        }
    }
    
    // Equipment category folder for model files
    const char* GetEquipCategoryFolder(EquipSlot slot) {
        switch (slot) {
            case EquipSlot::MainHand:
            case EquipSlot::OffHand:
                return "weapon";
            case EquipSlot::Earring:
            case EquipSlot::Necklace:
            case EquipSlot::Bracelet:
            case EquipSlot::Ring:
                return "accessory";
            default:
                return "equipment";
        }
    }
}

std::string ResolveEquipmentModelPath(uint16_t primaryId, uint16_t secondaryId, EquipSlot slot) {
    std::string category = GetEquipCategoryFolder(slot);
    std::string suffix = GetEquipSlotSuffix(slot);
    std::string ePad = PadId(primaryId);
    std::string vPad = PadId(secondaryId);
    
    if (slot == EquipSlot::MainHand || slot == EquipSlot::OffHand) {
        // Weapons: chara/weapon/w0001/obj/body/b0001/model/w0001b0001.mdl
        return std::format("chara/{}/w{}/obj/body/b{}/model/w{}b{}.mdl", 
            category, ePad, vPad, ePad, vPad);
    } else if (category == "accessory") {
        // Accessories: chara/accessory/a0001/model/c0101a0001_acc.mdl
        return std::format("chara/{}/a{}/model/c0101a{}{}.mdl", 
            category, ePad, ePad, suffix);
    } else {
        // Regular equipment: chara/equipment/e0001/model/c0101e0001_top.mdl
        return std::format("chara/{}/e{}/model/c0101e{}{}.mdl", 
            category, ePad, ePad, suffix);
    }
}

std::string ResolveMonsterModelPath(uint16_t modelId, uint16_t bodyId, uint16_t typeId) {
    std::string mPad = PadId(modelId);
    std::string bPad = PadId(bodyId);
    std::string tPad = PadId(typeId);
    
    // Monster models: chara/monster/m0001/obj/body/b0001/model/m0001b0001.mdl
    return std::format("chara/monster/m{}/obj/body/b{}/model/m{}b{}.mdl", 
        mPad, bPad, mPad, bPad);
}

std::string ResolveCharacterModelPath(uint16_t raceId, const std::string& partType, uint16_t partId) {
    std::string cPad = PadId(raceId);
    std::string pPad = PadId(partId);
    
    // Map part type to file prefix and suffix
    char typeChar = 'f'; // default to face
    std::string suffix = "_fac";
    
    if (partType == "face") {
        typeChar = 'f'; suffix = "_fac";
    } else if (partType == "hair") {
        typeChar = 'h'; suffix = "_hir";
    } else if (partType == "body") {
        typeChar = 'b'; suffix = "_top";
    } else if (partType == "tail") {
        typeChar = 't'; suffix = "_til";
    } else if (partType == "ear") {
        typeChar = 'z'; suffix = "_zer"; // zear
    }
    
    // chara/human/c0101/obj/face/f0001/model/c0101f0001_fac.mdl
    return std::format("chara/human/c{}/obj/{}/{}{}/model/c{}{}{}{}.mdl",
        cPad, partType, typeChar, pPad, cPad, typeChar, pPad, suffix);
}

std::string ResolveMapTexturePath(uint32_t territoryId, uint8_t variant) {
    // Get territory's Bg path to extract map folder
    const char* bgPath = LookupTerritoryBgPath(territoryId);
    if (!bgPath) return "";
    
    std::string_view bg(bgPath);
    
    // Extract the last folder from bg path (e.g., "f1t1" from "ffxiv/fst_f1/twn/f1t1")
    auto lastSlash = bg.rfind('/');
    if (lastSlash == std::string_view::npos) return "";
    
    // Get just the level folder name and its parent
    std::string_view levelFolder = bg.substr(lastSlash + 1);
    auto secondLastSlash = bg.rfind('/', lastSlash - 1);
    std::string_view fullPath = (secondLastSlash != std::string_view::npos) 
        ? bg.substr(secondLastSlash + 1) 
        : levelFolder;
    
    // ui/map/f1t1/00/f1t100_m.tex (variant as 2-digit: 00, 01, etc.)
    std::string varStr = PadId(variant, 2);
    return std::format("ui/map/{}/{}/{}{}_{}.tex", 
        levelFolder, varStr, levelFolder, varStr, 'm');
}

std::string ResolveIconPath(uint32_t iconId, bool highRes) {
    // Icons are organized in folders of 1000: 000000, 001000, 002000, etc.
    uint32_t folder = (iconId / 1000) * 1000;
    
    std::string folderStr = PadId(static_cast<uint16_t>(folder), 6);
    std::string iconStr = PadId(static_cast<uint16_t>(iconId), 6);
    
    // To handle larger IDs (6 digits total)
    if (folder >= 100000) {
        folderStr = std::to_string(folder);
        iconStr = std::to_string(iconId);
        // Pad to 6 digits
        while (folderStr.length() < 6) folderStr.insert(0, 1, '0');
        while (iconStr.length() < 6) iconStr.insert(0, 1, '0');
    }
    
    if (highRes) {
        return std::format("ui/icon/{}/{}_hr1.tex", folderStr, iconStr);
    }
    return std::format("ui/icon/{}/{}.tex", folderStr, iconStr);
}

std::string ResolveItemIconPath(uint32_t itemId, bool highRes) {
    // Need to look up item's icon ID from the Item sheet
    auto it = s_items.find(itemId);
    if (it == s_items.end()) return "";
    
    // We stored just the name, but we need the icon ID
    // This would require storing more data in the cache
    // For now, return empty - this needs Item sheet access
    // TODO: Extend s_items to store ItemInfo { name, iconId, etc. }
    return "";
}

std::string ResolveActionIconPath(uint32_t actionId, bool highRes) {
    // Similar to items - needs icon ID from Action sheet
    // TODO: Extend s_actions to store ActionInfo { name, iconId, etc. }
    return "";
}

std::string ResolveTerritoryLgbPath(uint32_t territoryId) {
    const char* bgPath = LookupTerritoryBgPath(territoryId);
    if (!bgPath) return "";
    
    // bg/[BgPath]/level/bg.lgb
    return std::format("bg/{}/level/bg.lgb", bgPath);
}

std::string ResolveTerritoryPlannerPath(uint32_t territoryId) {
    const char* bgPath = LookupTerritoryBgPath(territoryId);
    if (!bgPath) return "";
    
    // bg/[BgPath]/level/planner.sgb
    return std::format("bg/{}/level/planner.sgb", bgPath);
}

const LoadStats& GetLoadStats() {
    return s_stats;
}

XivGameData* GetGameDataInstance() noexcept {
    return s_gameData.get();
}

std::optional<std::vector<char>> ReadRawFile(const std::string& path) {
    if (!s_gameData) return std::nullopt;
    
    try {
        auto file = s_gameData->getFile(path);
        if (!file) return std::nullopt;
        
        auto& sections = file->get_data_sections();
        if (sections.empty()) return std::nullopt;
        
        // Return the first (usually only) data section
        return sections.front();
    }
    catch (const std::exception& e) {
        LogWarning("[GameData] ReadRawFile failed for '" + path + "': " + e.what());
        return std::nullopt;
    }
    catch (...) {
        return std::nullopt;
    }
}

bool DoesFileExist(const std::string& path) {
    if (!s_gameData) return false;
    
    try {
        return s_gameData->doesFileExist(path);
    }
    catch (...) {
        return false;
    }
}

size_t GetFileSize(const std::string& path) {
    if (!s_gameData) return 0;
    
    try {
        auto file = s_gameData->getFile(path);
        if (!file) return 0;
        
        auto& sections = file->get_data_sections();
        if (sections.empty()) return 0;
        
        return sections.front().size();
    }
    catch (...) {
        return 0;
    }
}

} // namespace GameData
