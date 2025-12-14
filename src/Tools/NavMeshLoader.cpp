#include "NavMeshLoader.h"
#include "../Logger/Logger.h"
#include <fstream>
#include <thread>
#include <cstring>
#include <format>

// Detour includes
#include <recastnavigation/DetourNavMesh.h>
#include <recastnavigation/DetourNavMeshQuery.h>
#include <recastnavigation/DetourCommon.h>

namespace SapphireHook::Navigation {

    // Bring in logging functions
    using SapphireHook::LogInfo;
    using SapphireHook::LogDebug;
    using SapphireHook::LogWarning;
    using SapphireHook::LogError;

    // ============================================
    // Sapphire Server MSET Format (Detour-compatible)
    // ============================================
    // This is the format Sapphire server generates - uses raw Detour tile data
    // Magic: 'M'<<24 | 'S'<<16 | 'E'<<8 | 'T' = 0x4D534554 = "MSET"
    constexpr uint32_t MSET_MAGIC = 'M' << 24 | 'S' << 16 | 'E' << 8 | 'T';  // 0x4D534554
    constexpr uint32_t MSET_VERSION = 1;
    
    // MSET header structure (from Sapphire NaviProvider.h)
    struct MSETHeader {
        int32_t magic;        // MSET_MAGIC
        int32_t version;      // 1
        int32_t numTiles;     // Number of tiles
        dtNavMeshParams params;  // Detour native params (includes orig, tileWidth, tileHeight, maxTiles, maxPolys)
    };
    
    // MSET tile header (from Sapphire NaviProvider.h)
    struct MSETTileHeader {
        dtTileRef tileRef;    // 8 bytes
        int32_t dataSize;     // 4 bytes
    };  // Followed by dataSize bytes of raw Detour tile data

    // ============================================
    // Game's TESM/VAND Format (NOT Detour-compatible)
    // ============================================
    // This is the format extracted from game files - custom format, NOT raw Detour data
    // We cannot use Detour's addTile() with this format - must parse manually for visualization only
    constexpr uint32_t TESM_MAGIC = 0x4D534554;  // "TESM" little-endian (same bytes as MSET but different meaning)
    constexpr uint32_t VAND_MAGIC = 0x444E4156;  // "VAND" little-endian
    // TESM header: magic(4) + version(4) + tileCount(4) + boundsMin(12) + tileWidth(4) + tileHeight(4) + maxTiles(4) + polyBits(4)
    constexpr size_t TESM_HEADER_SIZE = 4 + 4 + 4 + 12 + 4 + 4 + 4 + 4; // 40 bytes
    
    // ============================================
    // Area type helpers
    // ============================================
    const char* GetAreaTypeName(NavAreaType area) {
        switch (area) {
            case NavAreaType::Ground:   return "Ground";
            case NavAreaType::Water:    return "Water";
            case NavAreaType::Road:     return "Road";
            case NavAreaType::Grass:    return "Grass";
            case NavAreaType::Jump:     return "Jump";
            case NavAreaType::Disabled: return "Disabled";
            case NavAreaType::All:      return "All";
            default:                    return "Unknown";
        }
    }
    
    DirectX::XMFLOAT4 GetAreaColor(NavAreaType area) {
        switch (area) {
            case NavAreaType::Ground:   return { 0.2f, 0.8f, 0.2f, 0.5f };  // Green
            case NavAreaType::Water:    return { 0.2f, 0.4f, 0.9f, 0.5f };  // Blue
            case NavAreaType::Road:     return { 0.7f, 0.5f, 0.2f, 0.5f };  // Brown
            case NavAreaType::Grass:    return { 0.4f, 0.9f, 0.3f, 0.5f };  // Light green
            case NavAreaType::Jump:     return { 0.9f, 0.9f, 0.2f, 0.5f };  // Yellow
            case NavAreaType::Disabled: return { 0.5f, 0.5f, 0.5f, 0.3f };  // Gray
            default:                    return { 0.8f, 0.8f, 0.8f, 0.5f };  // White
        }
    }

    // ============================================
    // Singleton
    // ============================================
    NavMeshLoader& NavMeshLoader::GetInstance() {
        static NavMeshLoader instance;
        return instance;
    }

    // ============================================
    // Load NavMesh (blocking)
    // ============================================
    std::optional<LoadedNavMesh> NavMeshLoader::LoadNavMesh(const std::filesystem::path& path) {
        return LoadNavMesh(path, nullptr);
    }
    
    std::optional<LoadedNavMesh> NavMeshLoader::LoadNavMesh(
        const std::filesystem::path& path,
        NavProgressCallback progressCallback)
    {
        m_lastError.clear();
        m_loading.store(true);
        m_cancelRequested.store(false);
        
        // Read entire file
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            m_lastError = "Failed to open file: " + path.string();
            LogError(m_lastError);
            m_loading.store(false);
            return std::nullopt;
        }
        
        size_t fileSize = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);
        
        if (fileSize < 16) {  // Minimum header size
            m_lastError = "File too small for navmesh header";
            LogError(m_lastError);
            m_loading.store(false);
            return std::nullopt;
        }
        
        std::vector<uint8_t> fileData(fileSize);
        file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
        file.close();
        
        // Detect format by checking first 4 bytes and header structure
        uint32_t magic = *reinterpret_cast<const uint32_t*>(fileData.data());
        
        // Check for MSET format (Sapphire server format with raw Detour tiles)
        // MSET magic is big-endian: 'M'<<24 | 'S'<<16 | 'E'<<8 | 'T'
        if (magic == MSET_MAGIC) {
            LogInfo("Detected MSET format (Sapphire server navmesh)");
            return LoadMSETNavMesh(fileData.data(), fileSize, path.string(), progressCallback);
        }
        
        // For TESM format (game extracted), the bytes are the same but interpreted differently
        // TESM is 0x4D534554 little-endian which reads as "TESM" string
        // Since the magic values are the same, we need to check the version field
        // MSET version 1 has dtNavMeshParams after numTiles
        // TESM version 1 has boundsMin after numTiles
        
        // Check if this looks like MSET by checking if dtNavMeshParams.orig values are reasonable
        if (fileSize >= sizeof(MSETHeader)) {
            const MSETHeader* msetHeader = reinterpret_cast<const MSETHeader*>(fileData.data());
            if (msetHeader->version == MSET_VERSION) {
                // Check if the params look valid (tile dimensions should be positive, reasonable values)
                if (msetHeader->params.tileWidth > 0 && msetHeader->params.tileWidth < 10000 &&
                    msetHeader->params.tileHeight > 0 && msetHeader->params.tileHeight < 10000 &&
                    msetHeader->params.maxTiles > 0 && msetHeader->params.maxTiles < 100000) {
                    LogInfo("Detected MSET format based on header structure");
                    return LoadMSETNavMesh(fileData.data(), fileSize, path.string(), progressCallback);
                }
            }
        }
        
        // Otherwise treat as TESM (game format - cannot use with Detour)
        LogInfo("Detected TESM format (game navmesh - visualization only)");
        return LoadTESMNavMesh(fileData.data(), fileSize, path.string(), progressCallback);
    }
    
    // ============================================
    // Load MSET format (Sapphire server navmesh with raw Detour tiles)
    // ============================================
    std::optional<LoadedNavMesh> NavMeshLoader::LoadMSETNavMesh(
        const uint8_t* data, size_t size,
        const std::string& sourcePath,
        NavProgressCallback progressCallback)
    {
        if (size < sizeof(MSETHeader)) {
            m_lastError = "File too small for MSET header";
            LogError(m_lastError);
            m_loading.store(false);
            return std::nullopt;
        }
        
        const MSETHeader* header = reinterpret_cast<const MSETHeader*>(data);
        
        if (header->magic != MSET_MAGIC) {
            m_lastError = "Invalid MSET magic";
            LogError(m_lastError);
            m_loading.store(false);
            return std::nullopt;
        }
        
        if (header->version != MSET_VERSION) {
            m_lastError = std::format("Unsupported MSET version: {}", header->version);
            LogError(m_lastError);
            m_loading.store(false);
            return std::nullopt;
        }
        
        LogInfo(std::format("Loading MSET NavMesh: {} tiles", header->numTiles));
        LogDebug(std::format("  Origin: ({:.1f}, {:.1f}, {:.1f})", 
                 header->params.orig[0], header->params.orig[1], header->params.orig[2]));
        LogDebug(std::format("  TileSize: {:.1f}x{:.1f}, maxTiles: {}, maxPolys: {}",
                 header->params.tileWidth, header->params.tileHeight,
                 header->params.maxTiles, header->params.maxPolys));
        
        // Create Detour navmesh
        dtNavMesh* navMesh = dtAllocNavMesh();
        if (!navMesh) {
            m_lastError = "Failed to allocate dtNavMesh";
            LogError(m_lastError);
            m_loading.store(false);
            return std::nullopt;
        }
        
        dtStatus status = navMesh->init(&header->params);
        if (dtStatusFailed(status)) {
            m_lastError = std::format("Failed to init dtNavMesh: status=0x{:X}", status);
            LogError(m_lastError);
            dtFreeNavMesh(navMesh);
            m_loading.store(false);
            return std::nullopt;
        }
        
        // Prepare result
        LoadedNavMesh result;
        result.sourcePath = sourcePath;
        result.worldBoundsMin = { header->params.orig[0], header->params.orig[1], header->params.orig[2] };
        result.worldBoundsMax = { 
            header->params.orig[0] + header->params.tileWidth * 64,
            header->params.orig[1] + 500.0f,
            header->params.orig[2] + header->params.tileHeight * 64 
        };
        result.detourMesh = navMesh;
        result.tiles.reserve(header->numTiles);
        
        size_t offset = sizeof(MSETHeader);
        NavLoadProgress progress{};
        progress.totalTiles = header->numTiles;
        
        int loadedTiles = 0;
        for (int32_t i = 0; i < header->numTiles && !m_cancelRequested.load(); ++i) {
            if (offset + sizeof(MSETTileHeader) > size) {
                LogWarning(std::format("Unexpected end of file at tile {}", i));
                break;
            }
            
            const MSETTileHeader* tileHeader = reinterpret_cast<const MSETTileHeader*>(data + offset);
            offset += sizeof(MSETTileHeader);
            
            if (!tileHeader->tileRef || !tileHeader->dataSize) {
                LogDebug(std::format("Skipping empty tile {}", i));
                continue;
            }
            
            if (offset + tileHeader->dataSize > size) {
                LogWarning(std::format("Tile {} data extends past file end", i));
                break;
            }
            
            // Load the tile (this is raw Detour tile data)
            NavTile tile;
            if (LoadTile(navMesh, data + offset, tileHeader->dataSize, loadedTiles, tile)) {
                result.tiles.push_back(std::move(tile));
                result.totalPolygons += result.tiles.back().polygons.size();
                result.totalOffMeshConnections += result.tiles.back().offMeshConnections.size();
                loadedTiles++;
            }
            
            offset += tileHeader->dataSize;
            
            // Progress callback
            if (progressCallback) {
                progress.tilesLoaded = i + 1;
                progress.polygonsLoaded = result.totalPolygons;
                progress.percentage = static_cast<float>(i + 1) / header->numTiles * 100.0f;
                progressCallback(progress);
            }
        }
        
        // Calculate stats
        for (const auto& tile : result.tiles) {
            for (const auto& poly : tile.polygons) {
                result.totalVertices += poly.vertices.size();
                result.areaStats[poly.area]++;
            }
        }
        result.tileCount = result.tiles.size();
        
        // Create query object for pathfinding
        result.detourQuery = dtAllocNavMeshQuery();
        if (result.detourQuery) {
            result.detourQuery->init(navMesh, 2048);
        }
        
        LogInfo(std::format("NavMesh loaded: {} tiles, {} polygons, {} vertices",
                result.tileCount, result.totalPolygons, result.totalVertices));
        
        m_loading.store(false);
        return result;
    }
    
    // ============================================
    // Load TESM format (game navmesh - visualization only, no Detour)
    // ============================================
    std::optional<LoadedNavMesh> NavMeshLoader::LoadTESMNavMesh(
        const uint8_t* data, size_t size,
        const std::string& sourcePath,
        NavProgressCallback progressCallback)
    {
        // Parse TESM header
        uint32_t version = 0;
        uint32_t tileCount = 0;
        DirectX::XMFLOAT3 boundsMin{}, boundsMax{};
        
        if (!ParseTESMHeader(data, size, version, tileCount, boundsMin, boundsMax)) {
            m_loading.store(false);
            return std::nullopt;
        }
        
        LogInfo(std::format("Loading TESM NavMesh: {} tiles, version {} (visualization only)", tileCount, version));
        LogWarning("TESM format does not contain Detour-compatible data. Pathfinding will not work.");
        LogDebug(std::format("  Bounds: ({:.1f}, {:.1f}, {:.1f})", boundsMin.x, boundsMin.y, boundsMin.z));
        
        // Prepare result - NO Detour mesh for TESM format
        LoadedNavMesh result;
        result.sourcePath = sourcePath;
        result.worldBoundsMin = boundsMin;
        result.worldBoundsMax = boundsMax;
        result.detourMesh = nullptr;  // Cannot use Detour with TESM
        result.detourQuery = nullptr;
        result.tiles.reserve(tileCount);
        
        size_t offset = TESM_HEADER_SIZE;
        NavLoadProgress progress{};
        progress.totalTiles = tileCount;
        
        for (uint32_t i = 0; i < tileCount && !m_cancelRequested.load(); ++i) {
            // Each tile: tileRef(4) + size(4) + data[size]
            if (offset + 8 > size) {
                LogWarning(std::format("Unexpected end of file at tile {}", i));
                break;
            }
            
            uint32_t tileRef = *reinterpret_cast<const uint32_t*>(data + offset);
            uint32_t tileSize = *reinterpret_cast<const uint32_t*>(data + offset + 4);
            
            if (i == 0) {
                LogDebug(std::format("First tile: offset={}, tileRef=0x{:08X}, size={}", offset, tileRef, tileSize));
            }
            
            if (offset + 8 + tileSize > size) {
                LogWarning(std::format("Tile {} extends past file end", i));
                break;
            }
            
            // Check VAND magic at start of tile data
            uint32_t magic = *reinterpret_cast<const uint32_t*>(data + offset + 8);
            if (magic != VAND_MAGIC) {
                LogWarning(std::format("Invalid tile magic at tile {}: 0x{:08X} (expected VAND)", i, magic));
                break;
            }
            
            // Parse VAND tile data manually for visualization
            NavTile tile;
            const uint8_t* tileData = data + offset + 8 + 4;  // Skip tileRef+size+VAND
            size_t tileDataSize = tileSize - 4;  // Size minus VAND magic
            
            if (ParseVANDTile(tileData, tileDataSize, i, tile)) {
                result.tiles.push_back(std::move(tile));
                result.totalPolygons += result.tiles.back().polygons.size();
            }
            
            offset += 8 + tileSize;
            
            // Progress callback
            if (progressCallback) {
                progress.tilesLoaded = i + 1;
                progress.polygonsLoaded = result.totalPolygons;
                progress.percentage = static_cast<float>(i + 1) / tileCount * 100.0f;
                progressCallback(progress);
            }
        }
        
        // Calculate stats
        for (const auto& tile : result.tiles) {
            for (const auto& poly : tile.polygons) {
                result.totalVertices += poly.vertices.size();
                result.areaStats[poly.area]++;
            }
        }
        result.tileCount = result.tiles.size();
        
        LogInfo(std::format("TESM NavMesh loaded: {} tiles, {} polygons, {} vertices (no pathfinding)",
                result.tileCount, result.totalPolygons, result.totalVertices));
        
        m_loading.store(false);
        return result;
    }
    
    // ============================================
    // Parse VAND tile data (game format) for visualization
    // ============================================
    bool NavMeshLoader::ParseVANDTile(
        const uint8_t* data, size_t size,
        int tileIndex, NavTile& outTile)
    {
        // VAND format is NOT documented - this is best-effort parsing
        // The data structure appears to be a custom format, not raw Detour
        
        if (size < 16) {
            return false;
        }
        
        // Try to extract what we can from the VAND tile data
        // This is speculative - we need to reverse engineer the actual format
        
        // For now, log what we see and create a placeholder tile
        if (tileIndex == 0) {
            LogDebug(std::format("VAND tile 0: {} bytes of custom format data", size));
            
            // Dump first 64 bytes for analysis
            size_t dumpSize = std::min<size_t>(size, 64);
            std::string hexDump;
            for (size_t i = 0; i < dumpSize; ++i) {
                if (i > 0 && i % 16 == 0) hexDump += "\n  ";
                else if (i > 0 && i % 8 == 0) hexDump += " ";
                hexDump += std::format("{:02X} ", data[i]);
            }
            LogDebug(std::format("VAND tile data:\n  {}", hexDump));
        }
        
        // Mark tile as parsed but empty for now
        outTile.x = tileIndex % 16;
        outTile.y = tileIndex / 16;
        outTile.layer = 0;
        
        // We cannot extract polygons without understanding the VAND format
        // Return true to indicate we processed the tile, but it has no renderable data
        return true;
    }
    
    // ============================================
    // Async load
    // ============================================
    void NavMeshLoader::LoadNavMeshAsync(
        const std::filesystem::path& path,
        std::function<void(std::optional<LoadedNavMesh>)> onComplete,
        NavProgressCallback progressCallback)
    {
        if (m_loading.load()) {
            LogWarning("NavMesh load already in progress");
            if (onComplete) {
                onComplete(std::nullopt);
            }
            return;
        }
        
        std::thread([this, path, onComplete, progressCallback]() {
            auto result = LoadNavMesh(path, progressCallback);
            if (onComplete) {
                onComplete(std::move(result));
            }
        }).detach();
    }
    
    void NavMeshLoader::CancelLoad() {
        m_cancelRequested.store(true);
    }

    // ============================================
    // TESM header parsing
    // ============================================
    bool NavMeshLoader::ParseTESMHeader(
        const uint8_t* data, size_t size,
        uint32_t& version, uint32_t& tileCount,
        DirectX::XMFLOAT3& boundsMin, DirectX::XMFLOAT3& boundsMax)
    {
        if (size < TESM_HEADER_SIZE) {
            m_lastError = "File too small for TESM header";
            return false;
        }
        
        const uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
        if (magic != TESM_MAGIC) {
            m_lastError = "Invalid TESM magic: 0x" + std::to_string(magic);
            LogError(std::format("Expected TESM (0x{:08X}), got 0x{:08X}", TESM_MAGIC, magic));
            return false;
        }
        
        size_t offset = 4;
        version = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += 4;
        
        tileCount = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += 4;
        
        // Bounds min only
        boundsMin.x = *reinterpret_cast<const float*>(data + offset); offset += 4;
        boundsMin.y = *reinterpret_cast<const float*>(data + offset); offset += 4;
        boundsMin.z = *reinterpret_cast<const float*>(data + offset); offset += 4;
        
        // tileWidth, tileHeight (we'll read these into local vars)
        m_tileWidth = *reinterpret_cast<const float*>(data + offset); offset += 4;
        m_tileHeight = *reinterpret_cast<const float*>(data + offset); offset += 4;
        
        // maxTiles, polyBits (maxPolys is derived from polyBits)
        m_maxTiles = *reinterpret_cast<const uint32_t*>(data + offset); offset += 4;
        uint32_t polyBits = *reinterpret_cast<const uint32_t*>(data + offset); offset += 4;
        m_maxPolys = 1 << polyBits;  // polyBits encodes the max polys as a power of 2
        
        // Calculate boundsMax from boundsMin + tile dimensions
        // Use the values from the file for init params
        boundsMax.x = boundsMin.x + m_tileWidth * 64;  // Approximate based on tile count
        boundsMax.y = boundsMin.y + 100.0f;  // Height estimate
        boundsMax.z = boundsMin.z + m_tileHeight * 64;
        
        LogDebug(std::format("TESM header: tileWidth={:.1f}, tileHeight={:.1f}, maxTiles={}, maxPolys={}",
                 m_tileWidth, m_tileHeight, m_maxTiles, m_maxPolys));
        
        return true;
    }
    
    // ============================================
    // Load individual tile
    // ============================================
    bool NavMeshLoader::LoadTile(
        dtNavMesh* mesh, const uint8_t* data, size_t size,
        int tileIndex, NavTile& outTile)
    {
        // Allocate a copy of the data for Detour (it takes ownership)
        uint8_t* tileData = static_cast<uint8_t*>(dtAlloc(size, DT_ALLOC_PERM));
        if (!tileData) {
            LogWarning(std::format("Failed to allocate tile data for tile {}", tileIndex));
            return false;
        }
        std::memcpy(tileData, data, size);
        
        // Add tile to navmesh
        dtTileRef tileRef = 0;
        dtStatus status = mesh->addTile(tileData, static_cast<int>(size), DT_TILE_FREE_DATA, 0, &tileRef);
        
        if (dtStatusFailed(status)) {
            dtFree(tileData);
            LogWarning(std::format("Failed to add tile {} to navmesh: status=0x{:X}", tileIndex, status));
            return false;
        }
        
        // Extract polygon data for rendering
        ExtractPolygonsFromTile(mesh, tileIndex, outTile);
        
        return true;
    }
    
    // ============================================
    // Extract polygons from loaded tile
    // ============================================
    void NavMeshLoader::ExtractPolygonsFromTile(
        const dtNavMesh* mesh, int tileIndex, NavTile& outTile)
    {
        // Find the tile by index (may need iteration for sparse tiles)
        const dtMeshTile* tile = nullptr;
        int tileCount = mesh->getMaxTiles();
        int found = 0;
        
        for (int i = 0; i < tileCount; ++i) {
            const dtMeshTile* t = mesh->getTile(i);
            if (t && t->header) {
                if (found == tileIndex) {
                    tile = t;
                    break;
                }
                ++found;
            }
        }
        
        if (!tile || !tile->header) {
            return;
        }
        
        const dtMeshHeader* header = tile->header;
        
        // Set tile info
        outTile.x = header->x;
        outTile.y = header->y;
        outTile.layer = header->layer;
        outTile.boundsMin = { header->bmin[0], header->bmin[1], header->bmin[2] };
        outTile.boundsMax = { header->bmax[0], header->bmax[1], header->bmax[2] };
        
        outTile.polygons.reserve(header->polyCount);
        
        // Extract each polygon
        for (int i = 0; i < header->polyCount; ++i) {
            const dtPoly* poly = &tile->polys[i];
            
            NavPolygon navPoly;
            navPoly.flags = poly->flags;
            navPoly.area = poly->getArea();
            navPoly.walkable = (poly->getType() != DT_POLYTYPE_OFFMESH_CONNECTION);
            
            // Get polygon vertices
            if (poly->getType() == DT_POLYTYPE_OFFMESH_CONNECTION) {
                // Off-mesh connection - handled separately
                continue;
            }
            
            navPoly.vertices.reserve(poly->vertCount);
            DirectX::XMFLOAT3 center{ 0, 0, 0 };
            
            for (int j = 0; j < poly->vertCount; ++j) {
                const float* v = &tile->verts[poly->verts[j] * 3];
                navPoly.vertices.push_back({ v[0], v[1], v[2] });
                center.x += v[0];
                center.y += v[1];
                center.z += v[2];
            }
            
            if (!navPoly.vertices.empty()) {
                float invCount = 1.0f / navPoly.vertices.size();
                navPoly.center = { center.x * invCount, center.y * invCount, center.z * invCount };
            }
            
            // Compute normal (assume mostly horizontal polygons)
            if (navPoly.vertices.size() >= 3) {
                const auto& v0 = navPoly.vertices[0];
                const auto& v1 = navPoly.vertices[1];
                const auto& v2 = navPoly.vertices[2];
                
                DirectX::XMFLOAT3 e1 = { v1.x - v0.x, v1.y - v0.y, v1.z - v0.z };
                DirectX::XMFLOAT3 e2 = { v2.x - v0.x, v2.y - v0.y, v2.z - v0.z };
                
                navPoly.normal = {
                    e1.y * e2.z - e1.z * e2.y,
                    e1.z * e2.x - e1.x * e2.z,
                    e1.x * e2.y - e1.y * e2.x
                };
                
                // Normalize
                float len = std::sqrt(navPoly.normal.x * navPoly.normal.x +
                                      navPoly.normal.y * navPoly.normal.y +
                                      navPoly.normal.z * navPoly.normal.z);
                if (len > 0.0001f) {
                    navPoly.normal.x /= len;
                    navPoly.normal.y /= len;
                    navPoly.normal.z /= len;
                }
            }
            
            outTile.polygons.push_back(std::move(navPoly));
        }
        
        // Extract off-mesh connections
        outTile.offMeshConnections.reserve(header->offMeshConCount);
        for (int i = 0; i < header->offMeshConCount; ++i) {
            const dtOffMeshConnection* con = &tile->offMeshCons[i];
            
            OffMeshConnection navCon;
            navCon.startPos = { con->pos[0], con->pos[1], con->pos[2] };
            navCon.endPos = { con->pos[3], con->pos[4], con->pos[5] };
            navCon.radius = con->rad;
            navCon.direction = con->flags & DT_OFFMESH_CON_BIDIR ? 1 : 0;
            navCon.area = con->poly ? tile->polys[con->poly - tile->header->offMeshBase].getArea() : 0;
            navCon.flags = con->flags;
            
            outTile.offMeshConnections.push_back(navCon);
        }
    }
    
    // ============================================
    // Pathfinding
    // ============================================
    std::vector<DirectX::XMFLOAT3> NavMeshLoader::FindPath(
        const LoadedNavMesh& mesh,
        const DirectX::XMFLOAT3& start,
        const DirectX::XMFLOAT3& end)
    {
        std::vector<DirectX::XMFLOAT3> path;
        
        if (!mesh.detourQuery || !mesh.detourMesh) {
            m_lastError = "NavMesh not initialized for queries";
            return path;
        }
        
        dtQueryFilter filter;
        filter.setIncludeFlags(0xFFFF);
        filter.setExcludeFlags(0);
        
        // Find start poly
        float startPos[3] = { start.x, start.y, start.z };
        float endPos[3] = { end.x, end.y, end.z };
        float extents[3] = { 5.0f, 5.0f, 5.0f };
        
        dtPolyRef startRef = 0, endRef = 0;
        float nearestStart[3], nearestEnd[3];
        
        mesh.detourQuery->findNearestPoly(startPos, extents, &filter, &startRef, nearestStart);
        mesh.detourQuery->findNearestPoly(endPos, extents, &filter, &endRef, nearestEnd);
        
        if (!startRef || !endRef) {
            m_lastError = "Could not find start/end polygons";
            return path;
        }
        
        // Find path
        dtPolyRef polyPath[256];
        int polyCount = 0;
        mesh.detourQuery->findPath(startRef, endRef, nearestStart, nearestEnd, 
                                   &filter, polyPath, &polyCount, 256);
        
        if (polyCount == 0) {
            m_lastError = "No path found";
            return path;
        }
        
        // Get straight path
        float straightPath[256 * 3];
        unsigned char pathFlags[256];
        dtPolyRef pathPolys[256];
        int straightPathCount = 0;
        
        mesh.detourQuery->findStraightPath(nearestStart, nearestEnd,
                                            polyPath, polyCount,
                                            straightPath, pathFlags, pathPolys,
                                            &straightPathCount, 256);
        
        path.reserve(straightPathCount);
        for (int i = 0; i < straightPathCount; ++i) {
            path.push_back({
                straightPath[i * 3],
                straightPath[i * 3 + 1],
                straightPath[i * 3 + 2]
            });
        }
        
        return path;
    }
    
    std::optional<DirectX::XMFLOAT3> NavMeshLoader::FindNearestPoint(
        const LoadedNavMesh& mesh,
        const DirectX::XMFLOAT3& pos,
        float searchRadius)
    {
        if (!mesh.detourQuery) {
            return std::nullopt;
        }
        
        dtQueryFilter filter;
        filter.setIncludeFlags(0xFFFF);
        
        float queryPos[3] = { pos.x, pos.y, pos.z };
        float extents[3] = { searchRadius, searchRadius, searchRadius };
        
        dtPolyRef nearestRef = 0;
        float nearestPt[3];
        
        mesh.detourQuery->findNearestPoly(queryPos, extents, &filter, &nearestRef, nearestPt);
        
        if (!nearestRef) {
            return std::nullopt;
        }
        
        return DirectX::XMFLOAT3{ nearestPt[0], nearestPt[1], nearestPt[2] };
    }
    
    bool NavMeshLoader::Raycast(
        const LoadedNavMesh& mesh,
        const DirectX::XMFLOAT3& start,
        const DirectX::XMFLOAT3& end,
        DirectX::XMFLOAT3& hitPoint)
    {
        if (!mesh.detourQuery) {
            return false;
        }
        
        dtQueryFilter filter;
        filter.setIncludeFlags(0xFFFF);
        
        float startPos[3] = { start.x, start.y, start.z };
        float endPos[3] = { end.x, end.y, end.z };
        float extents[3] = { 2.0f, 4.0f, 2.0f };
        
        dtPolyRef startRef = 0;
        float nearestPt[3];
        mesh.detourQuery->findNearestPoly(startPos, extents, &filter, &startRef, nearestPt);
        
        if (!startRef) {
            return false;
        }
        
        float t = 0;
        float hitNormal[3];
        dtPolyRef path[256];
        int pathCount = 0;
        
        mesh.detourQuery->raycast(startRef, nearestPt, endPos, &filter, 
                                  &t, hitNormal, path, &pathCount, 256);
        
        if (t >= 1.0f) {
            // No hit, full path traversable
            hitPoint = end;
            return false;
        }
        
        // Hit point
        hitPoint = {
            nearestPt[0] + (endPos[0] - nearestPt[0]) * t,
            nearestPt[1] + (endPos[1] - nearestPt[1]) * t,
            nearestPt[2] + (endPos[2] - nearestPt[2]) * t
        };
        return true;
    }
    
    // ============================================
    // Cleanup
    // ============================================
    void NavMeshLoader::UnloadNavMesh(LoadedNavMesh& mesh) {
        if (mesh.detourQuery) {
            dtFreeNavMeshQuery(mesh.detourQuery);
            mesh.detourQuery = nullptr;
        }
        if (mesh.detourMesh) {
            dtFreeNavMesh(mesh.detourMesh);
            mesh.detourMesh = nullptr;
        }
        mesh.tiles.clear();
        mesh.areaStats.clear();
        mesh.totalPolygons = 0;
        mesh.totalVertices = 0;
        mesh.tileCount = 0;
    }

} // namespace SapphireHook::Navigation
