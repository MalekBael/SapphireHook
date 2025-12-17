#include "ZoneLayoutManager.h"
#include "GameDataLookup.h"
#include "../Logger/Logger.h"

#include <GameData.h>
#include <File.h>
#include <DatCategories/bg/lgb.h>
#include <DatCategories/bg/sgb.h>
#include <DatCategories/bg/pcb.h>
#include <DatCategories/InstanceObjectParser.h>
#include <DatCategories/InstanceObject.h>
#include <DatCategories/DatCommon.h>

#include <unordered_map>
#include <unordered_set>
#include <format>
#include <cmath>

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

// Transform a position by parent transform (simplified - rotation ignored for now)
Vec3 TransformPosition(const Vec3& local, const Vec3& parentPos, const Vec3& parentRot, const Vec3& parentScale) {
    // Simple transform: scale then translate (rotation would need quaternions/matrices)
    Vec3 result;
    result.x = local.x * parentScale.x + parentPos.x;
    result.y = local.y * parentScale.y + parentPos.y;
    result.z = local.z * parentScale.z + parentPos.z;
    return result;
}

// Track loaded SGB files to prevent infinite recursion
static thread_local std::unordered_set<std::string> s_loadedSgbFiles;

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
            
            // Store layer info
            LayerInfo layerInfo;
            layerInfo.LayerId = layerId;
            layerInfo.Name = group.name;
            layerInfo.FestivalId = group.header.FestivalID;
            layerInfo.FestivalPhaseId = group.header.FestivalPhaseID;
            layerInfo.IsHousing = group.header.IsHousing != 0;
            layerInfo.IsTemporary = group.header.IsTemporary != 0;
            layerInfo.IsBushLayer = group.header.IsBushLayer != 0;
            layout.Layers.push_back(layerInfo);
            
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
                            // Spawn conditions
                            spawn.PopWeather = bnpcEntry->header.PopWeather;
                            spawn.PopTimeStart = bnpcEntry->header.PopTimeStart;
                            spawn.PopTimeEnd = bnpcEntry->header.PopTimeEnd;
                            spawn.PopInterval = bnpcEntry->header.PopInterval;
                            spawn.PopRate = bnpcEntry->header.PopRate;
                            // Movement/AI
                            spawn.WanderingRange = bnpcEntry->header.WanderingRange;
                            spawn.Route = bnpcEntry->header.Route;
                            spawn.MoveAI = bnpcEntry->header.MoveAI;
                            spawn.NormalAI = bnpcEntry->header.NormalAI;
                            spawn.ServerPathId = bnpcEntry->header.ServerPathId;
                            // Aggro/Linking
                            spawn.SenseRangeRate = bnpcEntry->header.SenseRangeRate;
                            spawn.ActiveType = bnpcEntry->header.ActiveType;
                            spawn.LinkGroup = bnpcEntry->header.LinkGroup;
                            spawn.LinkFamily = bnpcEntry->header.LinkFamily;
                            spawn.LinkRange = bnpcEntry->header.LinkRange;
                            spawn.LinkCountLimit = bnpcEntry->header.LinkCountLimit;
                            spawn.LinkParent = bnpcEntry->header.LinkParent != 0;
                            spawn.LinkReply = bnpcEntry->header.LinkReply != 0;
                            // Appearance
                            spawn.EquipmentID = bnpcEntry->header.EquipmentID;
                            spawn.CustomizeID = bnpcEntry->header.CustomizeID;
                            // Misc
                            spawn.FateLayoutLabelId = bnpcEntry->header.FateLayoutLabelId;
                            spawn.BoundInstanceID = bnpcEntry->header.BoundInstanceID;
                            spawn.TerritoryRange = bnpcEntry->header.TerritoryRange;
                            spawn.BNPCRankId = bnpcEntry->header.BNPCRankId;
                            spawn.Nonpop = bnpcEntry->header.Nonpop != 0;
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
                            // Note: ENPCData doesn't have all NPCInstanceObject fields exposed,
                            // but we can access them if needed via reinterpret_cast in the future
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
                            box.Shape = static_cast<TriggerBoxShape>(collEntry->header.triggerBoxShape);
                            box.Priority = collEntry->header.priority;
                            box.Enabled = collEntry->header.enabled != 0;
                            box.Attribute = collEntry->header.m_attribute;
                            box.AttributeMask = collEntry->header.m_attributeMask;
                            box.ResourceId = collEntry->header.m_resourceId;
                            box.PushPlayerOut = collEntry->header.m_pushPlayerOut;
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
                            exit.Shape = static_cast<TriggerBoxShape>(exitEntry->header.triggerBoxType.triggerBoxShape);
                            exit.ExitType = exitEntry->header.exitType;
                            exit.ZoneId = exitEntry->header.zoneId;
                            exit.Index = exitEntry->header.index;
                            exit.DestInstanceObjectId = exitEntry->header.destInstanceObjectId;
                            exit.ReturnInstanceObjectId = exitEntry->header.returnInstanceObjectId;
                            exit.Direction = exitEntry->header.direction;
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
                            pop.Type = static_cast<PopType>(popEntry->header.popType);
                            pop.InnerRadiusRatio = popEntry->header.innerRadiusRatio;
                            pop.Index = popEntry->header.index;
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
                            map.Shape = static_cast<TriggerBoxShape>(mapEntry->header.triggerBoxType.triggerBoxShape);
                            map.MapId = mapEntry->header.mapId;
                            map.PlaceNameBlock = mapEntry->header.placeNameBlock;
                            map.PlaceNameSpot = mapEntry->header.placeNameSpot;
                            map.BGM = mapEntry->header.bGM;
                            map.Weather = mapEntry->header.weather;
                            map.HousingBlockId = mapEntry->header.housingBlockId;
                            map.DiscoveryIndex = mapEntry->header.discoveryIndex;
                            map.RestBonusEffective = mapEntry->header.restBonusEffective != 0;
                            map.MapEnabled = mapEntry->header.mapEnabled != 0;
                            map.PlaceNameEnabled = mapEntry->header.placeNameEnabled != 0;
                            map.DiscoveryEnabled = mapEntry->header.discoveryEnabled != 0;
                            map.BGMEnabled = mapEntry->header.bGMEnabled != 0;
                            map.WeatherEnabled = mapEntry->header.weatherEnabled != 0;
                            map.RestBonusEnabled = mapEntry->header.restBonusEnabled != 0;
                            map.LiftEnabled = mapEntry->header.liftEnabled != 0;
                            map.HousingEnabled = mapEntry->header.housingEnabled != 0;
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
                            evRange.Shape = static_cast<TriggerBoxShape>(eventRangeEntry->header.triggerBox.triggerBoxShape);
                            evRange.Priority = eventRangeEntry->header.triggerBox.priority;
                            evRange.Enabled = eventRangeEntry->header.triggerBox.enabled != 0;
                            layout.EventRanges.push_back(evRange);
                        }
                        break;
                    }
                    
                    case eAssetType::FateRange: {
                        FateRange fate;
                        ExtractTransform(entry->header, fate.Position, fate.Rotation, fate.Scale);
                        fate.LayerId = layerId;
                        layout.FateRanges.push_back(fate);
                        break;
                    }
                    
                    case eAssetType::Gathering: {
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
                    
                    // NEW: BG Parts with collision paths
                    case eAssetType::BG: {
                        auto* bgEntry = dynamic_cast<BGEntry*>(entry.get());
                        if (bgEntry) {
                            BGPart part;
                            part.ModelPath = bgEntry->modelFileName;
                            part.CollisionPath = bgEntry->collisionFileName;
                            ExtractTransform(bgEntry->header, part.Position, part.Rotation, part.Scale);
                            part.LayerId = layerId;
                            part.HasCollision = !part.CollisionPath.empty();
                            part.IsVisible = bgEntry->header.IsVisible != 0;
                            part.RenderShadowEnabled = bgEntry->header.RenderShadowEnabled != 0;
                            part.RenderModelClipRange = bgEntry->header.RenderModelClipRange;
                            // Collision config
                            part.CollisionShape = static_cast<TriggerBoxShape>(bgEntry->collisionConfig.CollisionBoxShape);
                            part.CollisionAttribute = bgEntry->collisionConfig.CollisionAttribute;
                            part.CollisionAttributeMask = bgEntry->collisionConfig.CollisionAttributeMask;
                            part.CollisionAABBMin = { bgEntry->collisionConfig.AABBMinX, bgEntry->collisionConfig.AABBMinY, bgEntry->collisionConfig.AABBMinZ };
                            part.CollisionAABBMax = { bgEntry->collisionConfig.AABBMaxX, bgEntry->collisionConfig.AABBMaxY, bgEntry->collisionConfig.AABBMaxZ };
                            layout.BgParts.push_back(part);
                            
                            // Optionally load PCB collision mesh
                            if (part.HasCollision && layout.CollisionMeshes.size() < 100) {
                                // Limit collision meshes to prevent memory bloat
                                ParsePcbFile("bg/" + part.CollisionPath, layout, layerId, 
                                    part.Position, part.Rotation, part.Scale);
                            }
                        }
                        break;
                    }
                    
                    // NEW: SharedGroup (SGB) - recursive loading
                    case eAssetType::SharedGroup: {
                        auto* sgEntry = dynamic_cast<SharedGroupEntry*>(entry.get());
                        if (sgEntry) {
                            SharedGroupRef ref;
                            ref.SgbPath = sgEntry->AssetPath;
                            ExtractTransform(sgEntry->header, ref.Position, ref.Rotation, ref.Scale);
                            ref.LayerId = layerId;
                            // SGData fields from header
                            ref.InitialDoorState = static_cast<DoorState>(sgEntry->header.InitialDoorState);
                            ref.RandomTimelineAutoPlay = sgEntry->header.RandomTimelineAutoPlay != 0;
                            ref.BoundClientPathInstanceID = sgEntry->header.BoundClientPathInstanceID;
                            ref.NotCreateNavimeshDoor = sgEntry->header.NotCreateNavimeshDoor != 0;
                            layout.SharedGroups.push_back(ref);
                            
                            // Recursively parse SGB if not already loaded
                            if (!ref.SgbPath.empty() && s_loadedSgbFiles.find(ref.SgbPath) == s_loadedSgbFiles.end()) {
                                s_loadedSgbFiles.insert(ref.SgbPath);
                                ParseSgbFile("bg/" + ref.SgbPath, layout, ref.Position, ref.Rotation, ref.Scale);
                            }
                        }
                        break;
                    }
                    
                    // NEW: Server paths (NPC patrol routes)
                    case eAssetType::ServerPath: {
                        // ServerPathData not yet in InstanceObjectParser, use base data
                        ServerPath path;
                        path.PathId = entry->header.InstanceID;
                        path.LayerId = layerId;
                        // Control points would need to be parsed from raw data
                        layout.ServerPaths.push_back(path);
                        break;
                    }
                    
                    // NEW: Client paths
                    case eAssetType::ClientPath: {
                        ClientPath path;
                        path.PathId = entry->header.InstanceID;
                        path.LayerId = layerId;
                        layout.ClientPaths.push_back(path);
                        break;
                    }
                    
                    // NEW: NavMesh range
                    case eAssetType::NaviMeshRange: {
                        NavMeshRange navMesh;
                        ExtractTransform(entry->header, navMesh.Position, navMesh.Rotation, navMesh.Scale);
                        navMesh.LayerId = layerId;
                        layout.NavMeshRanges.push_back(navMesh);
                        break;
                    }
                    
                    // NEW: Door range
                    case eAssetType::DoorRange: {
                        DoorRange door;
                        ExtractTransform(entry->header, door.Position, door.Rotation, door.Scale);
                        door.LayerId = layerId;
                        layout.DoorRanges.push_back(door);
                        break;
                    }
                    
                    // NEW: Gimmick range
                    case eAssetType::GimmickRange: {
                        GimmickRange gimmick;
                        ExtractTransform(entry->header, gimmick.Position, gimmick.Rotation, gimmick.Scale);
                        gimmick.LayerId = layerId;
                        layout.GimmickRanges.push_back(gimmick);
                        break;
                    }
                    
                    // NEW: Keep range (PvP)
                    case eAssetType::KeepRange: {
                        KeepRange keep;
                        ExtractTransform(entry->header, keep.Position, keep.Rotation, keep.Scale);
                        keep.LayerId = layerId;
                        layout.KeepRanges.push_back(keep);
                        break;
                    }
                    
                    // NEW: Chair marker
                    case eAssetType::ChairMarker: {
                        ChairMarker chair;
                        ExtractTransform(entry->header, chair.Position, chair.Rotation, chair.Scale);
                        chair.LayerId = layerId;
                        layout.ChairMarkers.push_back(chair);
                        break;
                    }
                    
                    // NEW: VFX locations
                    case eAssetType::VFX: {
                        VfxLocation vfx;
                        ExtractTransform(entry->header, vfx.Position, vfx.Rotation, vfx.Scale);
                        vfx.LayerId = layerId;
                        layout.VfxLocations.push_back(vfx);
                        break;
                    }
                    
                    // NEW: Sound locations
                    case eAssetType::Sound: {
                        SoundLocation sound;
                        ExtractTransform(entry->header, sound.Position, sound.Rotation, sound.Scale);
                        sound.LayerId = layerId;
                        layout.SoundLocations.push_back(sound);
                        break;
                    }
                    
                    default:
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

bool ZoneLayoutManager::ParseSgbFile(const std::string& filePath, ZoneLayoutData& layout, 
                                      const Vec3& parentPos, const Vec3& parentRot, const Vec3& parentScale) {
    auto* gameData = GameData::GetGameDataInstance();
    if (!gameData) return false;
    
    try {
        if (!gameData->doesFileExist(filePath)) {
            return false;
        }
        
        auto file = gameData->getFile(filePath);
        if (!file) return false;
        
        auto& sections = file->get_data_sections();
        if (sections.empty()) return false;
        
        std::vector<char> data = sections[0];
        if (data.size() < sizeof(SGB_HEADER)) return false;
        
        SGB_FILE sgbFile(data.data());
        layout.LoadedSgbFiles.push_back(filePath);
        
        // Extract timelines
        for (size_t i = 0; i < sgbFile.timelines.size(); ++i) {
            const auto& tl = sgbFile.timelines[i];
            TimelineData timeline;
            timeline.TimelineId = tl.TimelineID;
            timeline.Name = (i < sgbFile.timelineNames.size()) ? sgbFile.timelineNames[i] : "";
            timeline.AutoPlay = tl.AutoPlay != 0;
            timeline.LoopPlayback = tl.LoopPlayback != 0;
            layout.Timelines.push_back(timeline);
        }
        
        // Extract instance objects from each layer
        for (const auto& [layerId, entries] : sgbFile.layerInstanceObjects) {
            for (const auto& entry : entries) {
                if (!entry) continue;
                
                Vec3 pos, rot, scale;
                ExtractTransform(entry->header, pos, rot, scale);
                
                // Transform by parent
                pos = TransformPosition(pos, parentPos, parentRot, parentScale);
                
                switch (entry->getType()) {
                    case eAssetType::EventNPC: {
                        auto* enpcEntry = dynamic_cast<EventNPCEntry*>(entry.get());
                        if (enpcEntry) {
                            ENpcSpawnPoint spawn;
                            spawn.ENpcId = enpcEntry->header.BaseId;
                            spawn.Position = pos;
                            spawn.Rotation = rot;
                            spawn.Scale = scale;
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
                            obj.Position = pos;
                            obj.Rotation = rot;
                            obj.Scale = scale;
                            obj.LayerId = layerId;
                            layout.EventObjects.push_back(obj);
                        }
                        break;
                    }
                    
                    case eAssetType::BG: {
                        auto* bgEntry = dynamic_cast<BGEntry*>(entry.get());
                        if (bgEntry) {
                            BGPart part;
                            part.ModelPath = bgEntry->modelFileName;
                            part.CollisionPath = bgEntry->collisionFileName;
                            part.Position = pos;
                            part.Rotation = rot;
                            part.Scale = scale;
                            part.LayerId = layerId;
                            part.HasCollision = !part.CollisionPath.empty();
                            part.IsVisible = bgEntry->header.IsVisible != 0;
                            part.RenderShadowEnabled = bgEntry->header.RenderShadowEnabled != 0;
                            part.RenderModelClipRange = bgEntry->header.RenderModelClipRange;
                            // Collision config
                            part.CollisionShape = static_cast<TriggerBoxShape>(bgEntry->collisionConfig.CollisionBoxShape);
                            part.CollisionAttribute = bgEntry->collisionConfig.CollisionAttribute;
                            part.CollisionAttributeMask = bgEntry->collisionConfig.CollisionAttributeMask;
                            part.CollisionAABBMin = { bgEntry->collisionConfig.AABBMinX, bgEntry->collisionConfig.AABBMinY, bgEntry->collisionConfig.AABBMinZ };
                            part.CollisionAABBMax = { bgEntry->collisionConfig.AABBMaxX, bgEntry->collisionConfig.AABBMaxY, bgEntry->collisionConfig.AABBMaxZ };
                            layout.BgParts.push_back(part);
                        }
                        break;
                    }
                    
                    case eAssetType::CollisionBox: {
                        auto* collEntry = dynamic_cast<CollisionBoxEntry*>(entry.get());
                        if (collEntry) {
                            CollisionBox box;
                            box.Position = pos;
                            box.Rotation = rot;
                            box.Scale = scale;
                            box.LayerId = layerId;
                            // TriggerBox details from collEntry->header (CollisionBoxData)
                            box.Shape = static_cast<TriggerBoxShape>(collEntry->header.triggerBoxShape);
                            box.Priority = collEntry->header.priority;
                            box.Enabled = collEntry->header.enabled != 0;
                            box.Attribute = collEntry->header.m_attribute;
                            box.AttributeMask = collEntry->header.m_attributeMask;
                            box.ResourceId = collEntry->header.m_resourceId;
                            box.PushPlayerOut = collEntry->header.m_pushPlayerOut;
                            layout.CollisionBoxes.push_back(box);
                        }
                        break;
                    }
                    
                    // Recursively handle SharedGroups in SGB
                    case eAssetType::SharedGroup: {
                        auto* sgEntry = dynamic_cast<SharedGroupEntry*>(entry.get());
                        if (sgEntry && !sgEntry->AssetPath.empty()) {
                            // Store reference with SGData details
                            SharedGroupRef ref;
                            ref.SgbPath = sgEntry->AssetPath;
                            ref.Position = pos;
                            ref.Rotation = rot;
                            ref.Scale = scale;
                            ref.LayerId = layerId;
                            // SGData fields from header
                            ref.InitialDoorState = static_cast<DoorState>(sgEntry->header.InitialDoorState);
                            ref.RandomTimelineAutoPlay = sgEntry->header.RandomTimelineAutoPlay != 0;
                            ref.BoundClientPathInstanceID = sgEntry->header.BoundClientPathInstanceID;
                            ref.NotCreateNavimeshDoor = sgEntry->header.NotCreateNavimeshDoor != 0;
                            layout.SharedGroups.push_back(ref);
                            
                            if (s_loadedSgbFiles.find(sgEntry->AssetPath) == s_loadedSgbFiles.end()) {
                                s_loadedSgbFiles.insert(sgEntry->AssetPath);
                                ParseSgbFile("bg/" + sgEntry->AssetPath, layout, pos, rot, scale);
                            }
                        }
                        break;
                    }
                    
                    default:
                        break;
                }
            }
        }
        
        return true;
    }
    catch (...) {
        return false;
    }
}

bool ZoneLayoutManager::ParsePcbFile(const std::string& filePath, ZoneLayoutData& layout,
                                      uint32_t layerId, const Vec3& pos, const Vec3& rot, const Vec3& scale) {
    auto* gameData = GameData::GetGameDataInstance();
    if (!gameData) return false;
    
    try {
        if (!gameData->doesFileExist(filePath)) {
            return false;
        }
        
        auto file = gameData->getFile(filePath);
        if (!file) return false;
        
        auto& sections = file->get_data_sections();
        if (sections.empty()) return false;
        
        std::vector<char> data = sections[0];
        if (data.size() < sizeof(PCB_HEADER)) return false;
        
        PCB_FILE pcbFile(data.data());
        
        ZoneCollisionMesh mesh;
        mesh.LayerId = layerId;
        mesh.BoundsMin = { 1e9f, 1e9f, 1e9f };
        mesh.BoundsMax = { -1e9f, -1e9f, -1e9f };
        
        uint32_t vertexOffset = 0;
        
        for (const auto& entry : pcbFile.entries) {
            // Add float vertices
            for (const auto& v : entry.data.vertices) {
                CollisionVertex cv;
                cv.x = v.x * scale.x + pos.x;
                cv.y = v.y * scale.y + pos.y;
                cv.z = v.z * scale.z + pos.z;
                mesh.Vertices.push_back(cv);
                
                // Update bounds
                mesh.BoundsMin.x = (std::min)(mesh.BoundsMin.x, cv.x);
                mesh.BoundsMin.y = (std::min)(mesh.BoundsMin.y, cv.y);
                mesh.BoundsMin.z = (std::min)(mesh.BoundsMin.z, cv.z);
                mesh.BoundsMax.x = (std::max)(mesh.BoundsMax.x, cv.x);
                mesh.BoundsMax.y = (std::max)(mesh.BoundsMax.y, cv.y);
                mesh.BoundsMax.z = (std::max)(mesh.BoundsMax.z, cv.z);
            }
            
            // Add int16 vertices (need to decompress based on bounding box)
            float rangeX = entry.header.x1 - entry.header.x;
            float rangeY = entry.header.y1 - entry.header.y;
            float rangeZ = entry.header.z1 - entry.header.z;
            
            for (const auto& v : entry.data.vertices_i16) {
                CollisionVertex cv;
                cv.x = (entry.header.x + (v.x / 65535.0f) * rangeX) * scale.x + pos.x;
                cv.y = (entry.header.y + (v.y / 65535.0f) * rangeY) * scale.y + pos.y;
                cv.z = (entry.header.z + (v.z / 65535.0f) * rangeZ) * scale.z + pos.z;
                mesh.Vertices.push_back(cv);
                
                mesh.BoundsMin.x = (std::min)(mesh.BoundsMin.x, cv.x);
                mesh.BoundsMin.y = (std::min)(mesh.BoundsMin.y, cv.y);
                mesh.BoundsMin.z = (std::min)(mesh.BoundsMin.z, cv.z);
                mesh.BoundsMax.x = (std::max)(mesh.BoundsMax.x, cv.x);
                mesh.BoundsMax.y = (std::max)(mesh.BoundsMax.y, cv.y);
                mesh.BoundsMax.z = (std::max)(mesh.BoundsMax.z, cv.z);
            }
            
            // Add triangles
            for (const auto& idx : entry.data.indices) {
                CollisionTriangle tri;
                tri.i0 = vertexOffset + idx.index[0];
                tri.i1 = vertexOffset + idx.index[1];
                tri.i2 = vertexOffset + idx.index[2];
                mesh.Triangles.push_back(tri);
            }
            
            vertexOffset += static_cast<uint32_t>(entry.data.vertices.size() + entry.data.vertices_i16.size());
        }
        
        if (!mesh.Vertices.empty()) {
            layout.CollisionMeshes.push_back(std::move(mesh));
        }
        
        return true;
    }
    catch (...) {
        return false;
    }
}

} // namespace SapphireHook
