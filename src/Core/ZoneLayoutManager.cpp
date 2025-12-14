#include "ZoneLayoutManager.h"
#include "GameDataLookup.h"
#include "../Logger/Logger.h"

#include <GameData.h>
#include <File.h>
#include <DatCategories/bg/lgb.h>
#include <DatCategories/InstanceObjectParser.h>
#include <DatCategories/InstanceObject.h>
#include <DatCategories/DatCommon.h>

#include <unordered_map>
#include <format>

namespace SapphireHook {

// ============================================================================
// Global Instance
// ============================================================================

static ZoneLayoutManager s_layoutManager;

ZoneLayoutManager& GetZoneLayoutManager() {
    return s_layoutManager;
}

// ============================================================================
// Helper Functions
// ============================================================================

namespace {

// Convert vec3 from datReader to our Vec3
Vec3 ConvertVec3(const vec3& v) {
    return Vec3{ v.x, v.y, v.z };
}

// Convert InstanceObject transform to position/rotation/scale
void ExtractTransform(const InstanceObjectBase& obj, Vec3& pos, Vec3& rot, Vec3& scale) {
    pos = { obj.Transformation.Translation.x, obj.Transformation.Translation.y, obj.Transformation.Translation.z };
    rot = { obj.Transformation.Rotation.x, obj.Transformation.Rotation.y, obj.Transformation.Rotation.z };
    scale = { obj.Transformation.Scale.x, obj.Transformation.Scale.y, obj.Transformation.Scale.z };
}

} // anonymous namespace

// ============================================================================
// ZoneLayoutManager Implementation
// ============================================================================

bool ZoneLayoutManager::CanLoadLayouts() const {
    return GameData::GetGameDataInstance() != nullptr;
}

std::shared_ptr<ZoneLayoutData> ZoneLayoutManager::GetCachedLayout(uint32_t territoryId) const {
    auto it = m_cache.find(territoryId);
    return (it != m_cache.end()) ? it->second : nullptr;
}

void ZoneLayoutManager::ClearCache() {
    m_cache.clear();
}

std::shared_ptr<ZoneLayoutData> ZoneLayoutManager::LoadZoneLayout(uint32_t territoryId) {
    // Check cache first
    if (auto cached = GetCachedLayout(territoryId)) {
        return cached;
    }
    
    // Get the Bg path for this territory
    const char* bgPath = GameData::LookupTerritoryBgPath(territoryId);
    if (!bgPath || bgPath[0] == '\0') {
        m_lastError = std::format("Territory {} has no Bg path", territoryId);
        return nullptr;
    }
    
    auto layout = LoadZoneLayoutByPath(bgPath);
    if (layout) {
        layout->TerritoryId = territoryId;
        m_cache[territoryId] = layout;
    }
    return layout;
}

std::shared_ptr<ZoneLayoutData> ZoneLayoutManager::LoadZoneLayoutByPath(const std::string& bgPath) {
    auto* gameData = GameData::GetGameDataInstance();
    if (!gameData) {
        m_lastError = "GameData not initialized";
        return nullptr;
    }
    
    auto layout = std::make_shared<ZoneLayoutData>();
    layout->BgPath = bgPath;
    
    // The LVB field contains paths like: ffxiv/fst_f1/fld/f1f1/level/f1f1
    // LGB files are in the parent directory: bg/ffxiv/fst_f1/fld/f1f1/level/*.lgb
    // So we need to strip the last component (zone name) from the path
    std::string levelPath = bgPath;
    auto lastSlash = levelPath.rfind('/');
    if (lastSlash != std::string::npos) {
        levelPath = levelPath.substr(0, lastSlash);
    }
    
    // LGB files to try loading
    std::vector<std::string> lgbFiles = {
        "bg/" + levelPath + "/bg.lgb",        // Background objects
        "bg/" + levelPath + "/planmap.lgb",   // Plan/map data
        "bg/" + levelPath + "/planevent.lgb", // Event NPCs
        "bg/" + levelPath + "/planlive.lgb",  // Live objects (BNpcs, etc)
        "bg/" + levelPath + "/vfx.lgb",       // VFX
        "bg/" + levelPath + "/sound.lgb",     // Sound
        "bg/" + levelPath + "/planner.lgb"    // Planner data (if exists)
    };
    
    int filesLoaded = 0;
    for (const auto& lgbPath : lgbFiles) {
        if (ParseLgbFile(lgbPath, *layout)) {
            layout->LoadedLgbFiles.push_back(lgbPath);
            filesLoaded++;
        }
    }
    
    if (filesLoaded == 0) {
        m_lastError = std::format("No LGB files found for path: {}", bgPath);
        return nullptr;
    }
    
    LogInfo(std::format("[ZoneLayout] Loaded {} for territory ({} files, {} total entries)",
        bgPath, filesLoaded, layout->TotalEntryCount()));
    LogInfo(std::format("[ZoneLayout]   BNpcs={}, ENpcs={}, EObjs={}, Exits={}, PopRanges={}, FateRanges={}",
        layout->BattleNpcs.size(), layout->EventNpcs.size(), layout->EventObjects.size(),
        layout->Exits.size(), layout->PopRanges.size(), layout->FateRanges.size()));
    
    return layout;
}

bool ZoneLayoutManager::ParseLgbFile(const std::string& filePath, ZoneLayoutData& layout) {
    auto* gameData = GameData::GetGameDataInstance();
    if (!gameData) return false;
    
    try {
        // Check if file exists first
        if (!gameData->doesFileExist(filePath)) {
            return false;
        }
        
        // Fetch the file
        auto file = gameData->getFile(filePath);
        if (!file) {
            return false;
        }
        
        auto& sections = file->get_data_sections();
        if (sections.empty()) {
            return false;
        }
        
        // Make a copy since LGB_FILE takes non-const char*
        std::vector<char> data = sections[0];
        if (data.size() < sizeof(LGB_FILE_HEADER)) {
            LogWarning(std::format("[ZoneLayout] LGB file too small: {}", filePath));
            return false;
        }
        
        // Parse the LGB file
        LGB_FILE lgbFile(data.data());
        
        // Process all groups
        for (const auto& group : lgbFile.groups) {
            uint32_t layerId = group.header.LayerID;
            
            for (const auto& entry : group.entries) {
                if (!entry) continue;
                
                switch (entry->getType()) {
                    case eAssetType::BattleNPC: {
                        auto* bnpcEntry = dynamic_cast<BattleNPCEntry*>(entry.get());
                        if (bnpcEntry) {
                            BNpcSpawnPoint spawn;
                            spawn.NameId = bnpcEntry->header.NameId;
                            spawn.BaseId = bnpcEntry->header.BaseId;
                            spawn.Level = bnpcEntry->header.Level;
                            ExtractTransform(bnpcEntry->header, spawn.Position, spawn.Rotation, spawn.Scale);
                            spawn.LayerId = layerId;
                            layout.BattleNpcs.push_back(spawn);
                        }
                        break;
                    }
                    
                    case eAssetType::EventNPC: {
                        auto* enpcEntry = dynamic_cast<EventNPCEntry*>(entry.get());
                        if (enpcEntry) {
                            ENpcSpawnPoint spawn;
                            spawn.ENpcId = enpcEntry->header.BaseId;
                            ExtractTransform(enpcEntry->header, spawn.Position, spawn.Rotation, spawn.Scale);
                            spawn.LayerId = layerId;
                            layout.EventNpcs.push_back(spawn);
                        }
                        break;
                    }
                    
                    case eAssetType::EventObject: {
                        auto* eobjEntry = dynamic_cast<EventObjectEntry*>(entry.get());
                        if (eobjEntry) {
                            EventObject obj;
                            obj.BaseId = eobjEntry->header.BaseId;
                            obj.BoundInstanceId = eobjEntry->header.BoundInstanceID;
                            ExtractTransform(eobjEntry->header, obj.Position, obj.Rotation, obj.Scale);
                            obj.LayerId = layerId;
                            layout.EventObjects.push_back(obj);
                        }
                        break;
                    }
                    
                    case eAssetType::CollisionBox: {
                        auto* collEntry = dynamic_cast<CollisionBoxEntry*>(entry.get());
                        if (collEntry) {
                            CollisionBox box;
                            ExtractTransform(collEntry->header, box.Position, box.Rotation, box.Scale);
                            box.LayerId = layerId;
                            layout.CollisionBoxes.push_back(box);
                        }
                        break;
                    }
                    
                    case eAssetType::ExitRange: {
                        auto* exitEntry = dynamic_cast<ExitRangeEntry*>(entry.get());
                        if (exitEntry) {
                            ExitRange exit;
                            exit.DestTerritoryType = exitEntry->header.destTerritoryType;
                            ExtractTransform(exitEntry->header, exit.Position, exit.Rotation, exit.Scale);
                            exit.LayerId = layerId;
                            layout.Exits.push_back(exit);
                        }
                        break;
                    }
                    
                    case eAssetType::PopRange: {
                        auto* popEntry = dynamic_cast<PopRangeEntry*>(entry.get());
                        if (popEntry) {
                            PopRange pop;
                            ExtractTransform(popEntry->header, pop.Position, pop.Rotation, pop.Scale);
                            pop.LayerId = layerId;
                            layout.PopRanges.push_back(pop);
                        }
                        break;
                    }
                    
                    case eAssetType::MapRange: {
                        auto* mapEntry = dynamic_cast<MapRangeEntry*>(entry.get());
                        if (mapEntry) {
                            MapRange map;
                            ExtractTransform(mapEntry->header, map.Position, map.Rotation, map.Scale);
                            map.LayerId = layerId;
                            layout.MapRanges.push_back(map);
                        }
                        break;
                    }
                    
                    case eAssetType::EventRange: {
                        auto* eventRangeEntry = dynamic_cast<EventRangeEntry*>(entry.get());
                        if (eventRangeEntry) {
                            EventRange evRange;
                            ExtractTransform(eventRangeEntry->header, evRange.Position, evRange.Rotation, evRange.Scale);
                            evRange.LayerId = layerId;
                            layout.EventRanges.push_back(evRange);
                        }
                        break;
                    }
                    
                    case eAssetType::FateRange: {
                        // FateRange uses base InstanceObjectEntry (no special entry class yet)
                        FateRange fate;
                        ExtractTransform(entry->header, fate.Position, fate.Rotation, fate.Scale);
                        fate.LayerId = layerId;
                        layout.FateRanges.push_back(fate);
                        break;
                    }
                    
                    case eAssetType::Gathering: {
                        // Gathering uses base InstanceObjectEntry
                        GatheringPoint gather;
                        ExtractTransform(entry->header, gather.Position, gather.Rotation, gather.Scale);
                        gather.LayerId = layerId;
                        layout.GatheringPoints.push_back(gather);
                        break;
                    }
                    
                    case eAssetType::Treasure: {
                        TreasurePoint treasure;
                        ExtractTransform(entry->header, treasure.Position, treasure.Rotation, treasure.Scale);
                        treasure.LayerId = layerId;
                        layout.Treasures.push_back(treasure);
                        break;
                    }
                    
                    case eAssetType::Aetheryte: {
                        AetherytePoint aetheryte;
                        ExtractTransform(entry->header, aetheryte.Position, aetheryte.Rotation, aetheryte.Scale);
                        aetheryte.LayerId = layerId;
                        layout.Aetherytes.push_back(aetheryte);
                        break;
                    }
                    
                    case eAssetType::EnvLocation: {
                        EnvLocation env;
                        ExtractTransform(entry->header, env.Position, env.Rotation, env.Scale);
                        env.LayerId = layerId;
                        layout.EnvLocations.push_back(env);
                        break;
                    }
                    
                    case eAssetType::QuestMarker:
                    case eAssetType::TargetMarker: {
                        MarkerPoint marker;
                        marker.Type = static_cast<uint32_t>(entry->getType());
                        ExtractTransform(entry->header, marker.Position, marker.Rotation, marker.Scale);
                        marker.LayerId = layerId;
                        layout.Markers.push_back(marker);
                        break;
                    }
                    
                    default:
                        // Ignore other entry types (BG, SharedGroup, VFX, Sound, etc.)
                        break;
                }
            }
        }
        
        return true;
    }
    catch (const std::exception& e) {
        // Silently fail for individual files - they might not exist
        return false;
    }
}

} // namespace SapphireHook
