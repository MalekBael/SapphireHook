#include "NavMeshManager.h"
#include "GameDataLookup.h"
#include "TerritoryScanner.h"
#include "SettingsManager.h"
#include "../Logger/Logger.h"
#include "../Tools/GameCameraExtractor.h"
#include <algorithm>
#include <format>
#include <chrono>

namespace SapphireHook {

NavMeshManager& NavMeshManager::GetInstance() {
    static NavMeshManager instance;
    return instance;
}

void NavMeshManager::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return;
    }
    
    // First, check if we have a saved NavMesh path in settings
    auto& settings = SettingsManager::Instance();
    if (settings.HasNavMeshPath()) {
        m_navMeshBasePath = settings.GetNavMeshPath();
        LogInfo(std::format("[NavMeshManager] Using saved NavMesh path: {}", m_navMeshBasePath.string()));
    } else {
        // Fallback: Look for navmesh/navi folder in common locations
        std::vector<std::filesystem::path> searchPaths = {
            "navi",           // Sapphire server structure
            "navmesh",
            "data/navmesh", 
            "../navi",
            "../navmesh"
        };
        
        for (const auto& path : searchPaths) {
            if (std::filesystem::exists(path)) {
                m_navMeshBasePath = std::filesystem::absolute(path);
                LogInfo(std::format("[NavMeshManager] Found navmesh folder: {}", m_navMeshBasePath.string()));
                break;
            }
        }
    }
    
    // Register for territory changes
    m_territoryCallbackHandle = TerritoryScanner::GetInstance().RegisterCallback(
        [this](uint16_t newTerr, uint16_t oldTerr, const std::string& name) {
            OnTerritoryChanged(newTerr, oldTerr, name);
        }
    );
    
    m_initialized = true;
    
    LogInfo("[NavMeshManager] Initialized");
    
    // If we already have a territory, try to load its navmesh
    auto state = TerritoryScanner::GetInstance().GetCurrentState();
    if (state.IsValid()) {
        LoadNavMeshForZone(state.TerritoryType);
    }
}

void NavMeshManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_territoryCallbackHandle != 0) {
        TerritoryScanner::GetInstance().UnregisterCallback(m_territoryCallbackHandle);
        m_territoryCallbackHandle = 0;
    }
    
    {
        std::lock_guard<std::mutex> cbLock(m_callbackMutex);
        m_navMeshLoadedCallbacks.clear();
    }
    
    // Clean up loaded navmeshes
    if (m_currentNavMesh) {
        Navigation::NavMeshLoader::GetInstance().UnloadNavMesh(*m_currentNavMesh);
        m_currentNavMesh.reset();
    }
    
    for (auto& [id, mesh] : m_navMeshCache) {
        if (mesh) {
            Navigation::NavMeshLoader::GetInstance().UnloadNavMesh(*mesh);
        }
    }
    m_navMeshCache.clear();
    
    m_currentTerritoryId = 0;
    m_initialized = false;
    m_activePath = ActivePath{};
    
    LogInfo("[NavMeshManager] Shutdown");
}

void NavMeshManager::SetNavMeshBasePath(const std::filesystem::path& basePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_navMeshBasePath = basePath;
    
    // Persist the setting
    SettingsManager::Instance().SetNavMeshPath(basePath);
    
    LogInfo(std::format("[NavMeshManager] NavMesh base path set to: {}", basePath.string()));
}

std::filesystem::path NavMeshManager::GetNavMeshBasePath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_navMeshBasePath;
}

std::shared_ptr<Navigation::LoadedNavMesh> NavMeshManager::GetCurrentNavMesh() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentNavMesh;
}

bool NavMeshManager::HasNavMesh() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentNavMesh && m_currentNavMesh->IsValid();
}

bool NavMeshManager::CanPathfind() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentNavMesh && m_currentNavMesh->CanPathfind();
}

uint16_t NavMeshManager::GetCurrentTerritoryId() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentTerritoryId;
}

float NavMeshManager::GetLoadProgress() const {
    return m_loadProgress;
}

std::string NavMeshManager::ExtractBgName(const std::string& bgPath) {
    // Extract last path component: "ffxiv/fst_f1/fld/f1f1" -> "f1f1"
    auto findPos = bgPath.find_last_of('/');
    if (findPos != std::string::npos) {
        return bgPath.substr(findPos + 1);
    }
    return bgPath;
}

std::optional<std::filesystem::path> NavMeshManager::GetNavMeshPathForTerritory(uint16_t territoryId) {
    if (m_navMeshBasePath.empty() || !std::filesystem::exists(m_navMeshBasePath)) {
        return std::nullopt;
    }
    
    // Get the BG name for this territory (e.g., "a2d1" from "ffxiv/sea_s1/fld/a2d1")
    const char* bgPath = GameData::LookupTerritoryBgPath(territoryId);
    if (!bgPath || bgPath[0] == '\0') {
        return std::nullopt;
    }
    
    std::string bgName = ExtractBgName(bgPath);
    if (bgName.empty()) {
        return std::nullopt;
    }
    
    // Sapphire server structure: {basePath}/{bgName}/*.nav
    // e.g., navi/a2d1/mesh.nav or navi/a2d1/a2d1.nav
    auto bgFolder = m_navMeshBasePath / bgName;
    
    if (std::filesystem::exists(bgFolder) && std::filesystem::is_directory(bgFolder)) {
        // Scan the folder for any .nav file
        for (const auto& entry : std::filesystem::directory_iterator(bgFolder)) {
            if (entry.is_regular_file()) {
                auto ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".nav") {
                    return entry.path();
                }
            }
        }
    }
    
    return std::nullopt;
}

bool NavMeshManager::LoadNavMeshForZone(uint16_t territoryId) {
    if (territoryId == 0) {
        ClearNavMesh();
        return true;
    }
    
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_navMeshCache.find(territoryId);
        if (it != m_navMeshCache.end() && it->second) {
            m_currentNavMesh = it->second;
            m_currentTerritoryId = territoryId;
            LogInfo(std::format("[NavMeshManager] Using cached navmesh for zone {}", territoryId));
            NotifyNavMeshLoaded(territoryId, m_currentNavMesh);
            return true;
        }
    }
    
    // Find navmesh file
    auto navPath = GetNavMeshPathForTerritory(territoryId);
    if (!navPath) {
        LogDebug(std::format("[NavMeshManager] No navmesh found for zone {}", territoryId));
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentTerritoryId = territoryId;
        m_currentNavMesh.reset();
        return false;
    }
    
    LogInfo(std::format("[NavMeshManager] Loading navmesh for zone {}: {}", territoryId, navPath->string()));
    
    m_loading = true;
    m_loadProgress = 0.0f;
    
    // Load synchronously for now (async could be added later)
    auto result = Navigation::NavMeshLoader::GetInstance().LoadNavMesh(
        *navPath,
        [this](const Navigation::NavLoadProgress& progress) {
            m_loadProgress = progress.percentage;
        }
    );
    
    m_loading = false;
    
    if (result) {
        auto navMesh = std::make_shared<Navigation::LoadedNavMesh>(std::move(*result));
        
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_currentNavMesh = navMesh;
            m_currentTerritoryId = territoryId;
            
            // Add to cache (with LRU eviction if needed)
            if (m_navMeshCache.size() >= MAX_CACHED_NAVMESHES) {
                // Simple eviction: remove first entry (not true LRU but simple)
                auto oldest = m_navMeshCache.begin();
                if (oldest->second) {
                    Navigation::NavMeshLoader::GetInstance().UnloadNavMesh(*oldest->second);
                }
                m_navMeshCache.erase(oldest);
            }
            m_navMeshCache[territoryId] = navMesh;
        }
        
        LogInfo(std::format("[NavMeshManager] Loaded navmesh: {} tiles, {} polygons, pathfinding={}",
            navMesh->tileCount, navMesh->totalPolygons, navMesh->CanPathfind() ? "yes" : "no"));
        
        NotifyNavMeshLoaded(territoryId, navMesh);
        return true;
    } else {
        LogWarning(std::format("[NavMeshManager] Failed to load navmesh: {}", 
            Navigation::NavMeshLoader::GetInstance().GetLastError()));
        
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentTerritoryId = territoryId;
        m_currentNavMesh.reset();
        return false;
    }
}

void NavMeshManager::ClearNavMesh() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentNavMesh.reset();
    m_currentTerritoryId = 0;
    m_activePath = ActivePath{};
}

void NavMeshManager::OnTerritoryChanged(uint16_t newTerritory, uint16_t oldTerritory, const std::string& zoneName) {
    LogDebug(std::format("[NavMeshManager] Territory changed: {} -> {} ({})", 
        oldTerritory, newTerritory, zoneName));
    
    // Clear active path on zone change
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_activePath = ActivePath{};
    }
    
    // Load navmesh for new zone
    LoadNavMeshForZone(newTerritory);
}

NavMeshManager::PathResult NavMeshManager::FindPath(const DirectX::XMFLOAT3& start, const DirectX::XMFLOAT3& end) {
    PathResult result;
    
    std::shared_ptr<Navigation::LoadedNavMesh> navMesh;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        navMesh = m_currentNavMesh;
    }
    
    if (!navMesh || !navMesh->CanPathfind()) {
        result.errorMessage = "No pathfinding-capable navmesh loaded";
        return result;
    }
    
    // Use NavMeshLoader's FindPath
    auto waypoints = Navigation::NavMeshLoader::GetInstance().FindPath(*navMesh, start, end);
    
    if (waypoints.empty()) {
        result.errorMessage = "No path found";
        return result;
    }
    
    result.waypoints = std::move(waypoints);
    result.reachable = true;
    
    // Calculate total distance
    result.totalDistance = 0.0f;
    for (size_t i = 1; i < result.waypoints.size(); ++i) {
        float dx = result.waypoints[i].x - result.waypoints[i-1].x;
        float dy = result.waypoints[i].y - result.waypoints[i-1].y;
        float dz = result.waypoints[i].z - result.waypoints[i-1].z;
        result.totalDistance += std::sqrt(dx*dx + dy*dy + dz*dz);
    }
    
    return result;
}

NavMeshManager::PathResult NavMeshManager::FindPathFromPlayer(const DirectX::XMFLOAT3& target) {
    auto& camera = DebugVisuals::GameCameraExtractor::GetInstance();
    if (!camera.IsInitialized()) {
        PathResult result;
        result.errorMessage = "Camera extractor not initialized";
        return result;
    }
    
    DirectX::XMFLOAT3 playerPos = camera.GetPlayerPositionLive();
    return FindPath(playerPos, target);
}

void NavMeshManager::SetPathTarget(const DirectX::XMFLOAT3& target) {
    auto pathResult = FindPathFromPlayer(target);
    
    auto& camera = DebugVisuals::GameCameraExtractor::GetInstance();
    DirectX::XMFLOAT3 playerPos = camera.IsInitialized() ? 
        camera.GetPlayerPositionLive() : DirectX::XMFLOAT3{0, 0, 0};
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_activePath.waypoints = std::move(pathResult.waypoints);
    m_activePath.startPos = playerPos;
    m_activePath.endPos = target;
    m_activePath.valid = pathResult.reachable;
    m_activePath.calculatedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    m_activePath.currentWaypointIndex = 0;
    
    if (pathResult.reachable) {
        LogInfo(std::format("[NavMeshManager] Path set: {} waypoints, {:.1f}m distance",
            m_activePath.waypoints.size(), pathResult.totalDistance));
    } else {
        LogWarning(std::format("[NavMeshManager] Path failed: {}", pathResult.errorMessage));
    }
}

void NavMeshManager::ClearPathTarget() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_activePath = ActivePath{};
}

std::optional<DirectX::XMFLOAT3> NavMeshManager::FindNearestPoint(const DirectX::XMFLOAT3& pos, float radius) {
    std::shared_ptr<Navigation::LoadedNavMesh> navMesh;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        navMesh = m_currentNavMesh;
    }
    
    if (!navMesh || !navMesh->CanPathfind()) {
        return std::nullopt;
    }
    
    return Navigation::NavMeshLoader::GetInstance().FindNearestPoint(*navMesh, pos, radius);
}

NavMeshManager::NavMeshStats NavMeshManager::GetCurrentNavMeshStats() const {
    NavMeshStats stats;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_currentNavMesh) {
        return stats;
    }
    
    stats.totalPolygons = m_currentNavMesh->totalPolygons;
    stats.totalVertices = m_currentNavMesh->totalVertices;
    stats.totalTiles = m_currentNavMesh->tileCount;
    stats.totalOffMeshConnections = m_currentNavMesh->totalOffMeshConnections;
    stats.canPathfind = m_currentNavMesh->CanPathfind();
    stats.format = m_currentNavMesh->detourMesh ? "MSET" : "TESM";
    
    return stats;
}

NavMeshManager::CallbackHandle NavMeshManager::RegisterNavMeshLoadedCallback(NavMeshLoadedCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    CallbackHandle handle = m_nextCallbackHandle++;
    m_navMeshLoadedCallbacks.emplace_back(handle, std::move(callback));
    return handle;
}

void NavMeshManager::UnregisterNavMeshLoadedCallback(CallbackHandle handle) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    auto it = std::remove_if(m_navMeshLoadedCallbacks.begin(), m_navMeshLoadedCallbacks.end(),
        [handle](const auto& pair) { return pair.first == handle; });
    m_navMeshLoadedCallbacks.erase(it, m_navMeshLoadedCallbacks.end());
}

void NavMeshManager::NotifyNavMeshLoaded(uint16_t territoryId, std::shared_ptr<Navigation::LoadedNavMesh> navMesh) {
    std::vector<NavMeshLoadedCallback> callbacksCopy;
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        callbacksCopy.reserve(m_navMeshLoadedCallbacks.size());
        for (const auto& pair : m_navMeshLoadedCallbacks) {
            callbacksCopy.push_back(pair.second);
        }
    }
    
    for (const auto& callback : callbacksCopy) {
        try {
            callback(territoryId, navMesh);
        } catch (const std::exception& e) {
            LogError(std::format("[NavMeshManager] Callback exception: {}", e.what()));
        }
    }
}

} // namespace SapphireHook
