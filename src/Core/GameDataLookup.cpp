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

const LoadStats& GetLoadStats() {
    return s_stats;
}

XivGameData* GetGameDataInstance() noexcept {
    return s_gameData.get();
}

} // namespace GameData
