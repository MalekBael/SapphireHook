#include "TerritoryScanner.h"
#include "GameDataLookup.h"
#include "SafeMemory.h"
#include "../Logger/Logger.h"
#include "../Analysis/PatternScanner.h"
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"
#include <algorithm>
#include <format>

namespace SapphireHook {

// Namespace alias for packet structures
namespace ServerZone = PacketStructures::Server::Zone;

TerritoryScanner& TerritoryScanner::GetInstance() {
    static TerritoryScanner instance;
    return instance;
}

void TerritoryScanner::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return;
    }
    
    m_currentState = TerritoryState{};
    m_initialized = true;
    
    LogInfo("[TerritoryScanner] Initialized - waiting for InitZone packet");
}

void TerritoryScanner::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    {
        std::lock_guard<std::mutex> cbLock(m_callbackMutex);
        m_callbacks.clear();
    }
    
    m_currentState = TerritoryState{};
    m_initialized = false;
    
    LogInfo("[TerritoryScanner] Shutdown");
}

void TerritoryScanner::OnInitZonePacket(const void* packetData, size_t packetSize) {
    if (!packetData || packetSize < sizeof(ServerZone::FFXIVIpcInitZone)) {
        LogWarning("[TerritoryScanner] Invalid InitZone packet size");
        return;
    }
    
    const auto* initZone = reinterpret_cast<const ServerZone::FFXIVIpcInitZone*>(packetData);
    
    uint16_t oldTerritory = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        oldTerritory = m_currentState.TerritoryType;
        
        m_currentState.TerritoryType = initZone->TerritoryType;
        m_currentState.ZoneId = initZone->ZoneId;
        m_currentState.TerritoryIndex = initZone->TerritoryIndex;
        m_currentState.LayoutId = initZone->LayoutId;
        m_currentState.LayerSetId = initZone->LayerSetId;
        m_currentState.WeatherId = initZone->WeatherId;
        m_currentState.SpawnPos[0] = initZone->Pos[0];
        m_currentState.SpawnPos[1] = initZone->Pos[1];
        m_currentState.SpawnPos[2] = initZone->Pos[2];
    }
    
    // Get zone name for logging
    const char* zoneName = GameData::LookupTerritoryName(initZone->TerritoryType);
    std::string zoneStr = zoneName ? zoneName : std::format("Zone_{}", initZone->TerritoryType);
    
    if (oldTerritory != initZone->TerritoryType) {
        LogInfo(std::format("[TerritoryScanner] Zone changed: {} -> {} ({})", 
            oldTerritory, initZone->TerritoryType, zoneStr));
        NotifyCallbacks(initZone->TerritoryType, oldTerritory);
    } else {
        LogDebug(std::format("[TerritoryScanner] Zone reload: {} ({})", 
            initZone->TerritoryType, zoneStr));
    }
}

void TerritoryScanner::OnMoveTerritoryPacket(const void* packetData, size_t packetSize) {
    // MoveTerritory is sent when walking between zones
    // It has less data than InitZone but still contains territoryType and zoneId
    
    // Minimal struct just to read the fields we need
    // Full struct in ServerZoneDef.h has territoryType as uint8_t which seems wrong
    // for territory IDs > 255, but we'll work with what we have
    struct MoveTerritoryHeader {
        int16_t index;
        uint8_t territoryType;  // Note: uint8_t limits to 0-255
        uint8_t zoneId;
    };
    
    if (!packetData || packetSize < sizeof(MoveTerritoryHeader)) {
        LogWarning("[TerritoryScanner] Invalid MoveTerritory packet size");
        return;
    }
    
    const auto* moveTerritory = reinterpret_cast<const MoveTerritoryHeader*>(packetData);
    
    // MoveTerritory has uint8_t for territory which is problematic for IDs > 255
    // Try to handle this gracefully
    uint16_t newTerritoryType = moveTerritory->territoryType;
    uint16_t newZoneId = moveTerritory->zoneId;
    
    uint16_t oldTerritory = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        oldTerritory = m_currentState.TerritoryType;
        
        // Only update territory type and zone ID from MoveTerritory
        // Other fields will be set by the subsequent InitZone
        m_currentState.TerritoryType = newTerritoryType;
        m_currentState.ZoneId = newZoneId;
    }
    
    // Get zone name for logging
    const char* zoneName = GameData::LookupTerritoryName(newTerritoryType);
    std::string zoneStr = zoneName ? zoneName : std::format("Zone_{}", newTerritoryType);
    
    if (oldTerritory != newTerritoryType) {
        LogInfo(std::format("[TerritoryScanner] MoveTerritory: {} -> {} ({})", 
            oldTerritory, newTerritoryType, zoneStr));
        NotifyCallbacks(newTerritoryType, oldTerritory);
    }
}

TerritoryScanner::TerritoryState TerritoryScanner::GetCurrentState() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentState;
}

uint16_t TerritoryScanner::GetCurrentTerritoryType() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentState.TerritoryType;
}

std::string TerritoryScanner::GetCurrentZoneName() const {
    uint16_t terrType;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        terrType = m_currentState.TerritoryType;
    }
    
    if (terrType == 0) {
        return "Unknown";
    }
    
    const char* name = GameData::LookupTerritoryName(terrType);
    return name ? name : std::format("Zone_{}", terrType);
}

bool TerritoryScanner::HasValidTerritory() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentState.IsValid();
}

TerritoryScanner::CallbackHandle TerritoryScanner::RegisterCallback(TerritoryChangeCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    
    CallbackHandle handle = m_nextHandle++;
    m_callbacks.emplace_back(handle, std::move(callback));
    
    LogDebug(std::format("[TerritoryScanner] Registered callback handle {}", handle));
    return handle;
}

void TerritoryScanner::UnregisterCallback(CallbackHandle handle) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    
    auto it = std::remove_if(m_callbacks.begin(), m_callbacks.end(),
        [handle](const auto& pair) { return pair.first == handle; });
    
    if (it != m_callbacks.end()) {
        m_callbacks.erase(it, m_callbacks.end());
        LogDebug(std::format("[TerritoryScanner] Unregistered callback handle {}", handle));
    }
}

void TerritoryScanner::NotifyCallbacks(uint16_t newTerritory, uint16_t oldTerritory) {
    // Get zone name
    const char* zoneName = GameData::LookupTerritoryName(newTerritory);
    std::string zoneStr = zoneName ? zoneName : "";
    
    // Copy callbacks to avoid holding lock during invocation
    std::vector<TerritoryChangeCallback> callbacksCopy;
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        callbacksCopy.reserve(m_callbacks.size());
        for (const auto& pair : m_callbacks) {
            callbacksCopy.push_back(pair.second);
        }
    }
    
    // Invoke callbacks outside of lock
    for (const auto& callback : callbacksCopy) {
        try {
            callback(newTerritory, oldTerritory, zoneStr);
        } catch (const std::exception& e) {
            LogError(std::format("[TerritoryScanner] Callback exception: {}", e.what()));
        }
    }
}

bool TerritoryScanner::TryScanMemory() {
    // Try to read territory from game memory using known patterns
    // This is a fallback when packet capture isn't working
    
    // If we already attempted and failed, don't retry (pattern scan is expensive)
    if (m_memoryScanAttempted && m_cachedTerritoryPtr == 0) {
        return false;
    }
    
    // First check if we have a cached pointer
    if (m_cachedTerritoryPtr != 0) {
        if (IsValidMemoryAddress(m_cachedTerritoryPtr, sizeof(uint16_t))) {
            uint16_t territoryType = *reinterpret_cast<uint16_t*>(m_cachedTerritoryPtr);
            
            // Sanity check - territory IDs are typically < 2000
            if (territoryType > 0 && territoryType < 2000) {
                uint16_t oldTerritory;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    oldTerritory = m_currentState.TerritoryType;
                    
                    if (oldTerritory != territoryType) {
                        m_currentState.TerritoryType = territoryType;
                    }
                }
                
                if (oldTerritory != territoryType) {
                    const char* zoneName = GameData::LookupTerritoryName(territoryType);
                    std::string zoneStr = zoneName ? zoneName : std::format("Zone_{}", territoryType);
                    LogInfo(std::format("[TerritoryScanner] Memory scan detected zone change: {} -> {} ({})", 
                        oldTerritory, territoryType, zoneStr));
                    NotifyCallbacks(territoryType, oldTerritory);
                }
                return true;
            }
        }
        // Cache invalid, clear it
        m_cachedTerritoryPtr = 0;
    }
    
    // Mark that we're attempting memory scan (only do expensive scan once)
    m_memoryScanAttempted = true;
    
    // Try to find g_Framework using known 3.35 signature
    // Pattern: 48 8B 0D ?? ?? ?? ?? 0F 94 C2 8B F8
    // This gives us Framework* - we need to find TerritoryType offset
    static constexpr const char* g_FrameworkPattern = "48 8B 0D ?? ?? ?? ?? 0F 94 C2 8B F8";
    
    auto result = PatternScanner::ScanMainModule(g_FrameworkPattern);
    if (!result) {
        LogDebug("[TerritoryScanner] g_Framework pattern not found (won't retry)");
        return false;
    }
    
    // The pattern starts with "48 8B 0D" (mov rcx, [rip+offset])
    // The offset is at bytes 3-6 (RIP-relative)
    uintptr_t patternAddr = result->address;
    if (!IsValidMemoryAddress(patternAddr + 3, 4)) {
        LogDebug("[TerritoryScanner] Invalid memory at pattern offset");
        return false;
    }
    
    // Read RIP-relative offset and calculate absolute address
    int32_t ripOffset = *reinterpret_cast<int32_t*>(patternAddr + 3);
    uintptr_t frameworkPtrAddr = patternAddr + 7 + ripOffset; // 7 = instruction length
    
    if (!IsValidMemoryAddress(frameworkPtrAddr, sizeof(uintptr_t))) {
        LogDebug("[TerritoryScanner] Invalid g_Framework pointer address");
        return false;
    }
    
    uintptr_t frameworkPtr = *reinterpret_cast<uintptr_t*>(frameworkPtrAddr);
    if (frameworkPtr == 0 || !IsValidMemoryAddress(frameworkPtr, 0x100)) {
        LogDebug("[TerritoryScanner] Framework instance is null or invalid");
        return false;
    }
    
    LogInfo(std::format("[TerritoryScanner] Found Framework at 0x{:X}", frameworkPtr));
    
    // Common territory offsets in FFXIV Framework:
    // These may vary by version, we'll try several common offsets
    static constexpr size_t territoryOffsets[] = {
        0x1624,  // Retail 6.x TerritoryType offset  
        0x1648,  // Alternative offset
        0x160C,  // 3.35 possible offset
        0x1600,  // Another possibility
        0x1610,  // Another possibility
    };
    
    for (size_t offset : territoryOffsets) {
        uintptr_t territoryAddr = frameworkPtr + offset;
        if (!IsValidMemoryAddress(territoryAddr, sizeof(uint16_t))) {
            continue;
        }
        
        uint16_t territoryType = *reinterpret_cast<uint16_t*>(territoryAddr);
        
        // Validate - territory IDs are typically between 1 and ~2000
        if (territoryType > 0 && territoryType < 2000) {
            // Check if this looks like a known zone
            const char* zoneName = GameData::LookupTerritoryName(territoryType);
            if (zoneName != nullptr) {
                // Found a valid territory!
                m_cachedTerritoryPtr = territoryAddr;
                
                uint16_t oldTerritory;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    oldTerritory = m_currentState.TerritoryType;
                    m_currentState.TerritoryType = territoryType;
                }
                
                LogInfo(std::format("[TerritoryScanner] Found TerritoryType at offset 0x{:X}: {} ({})", 
                    offset, territoryType, zoneName));
                
                if (oldTerritory != territoryType) {
                    NotifyCallbacks(territoryType, oldTerritory);
                }
                return true;
            }
        }
    }
    
    LogDebug("[TerritoryScanner] Could not find valid TerritoryType in Framework");
    return false;
}

void TerritoryScanner::ForceSetTerritory(uint16_t territoryType) {
    uint16_t oldTerritory;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        oldTerritory = m_currentState.TerritoryType;
        m_currentState.TerritoryType = territoryType;
    }
    
    if (oldTerritory != territoryType) {
        LogInfo(std::format("[TerritoryScanner] Force set territory: {} -> {}", 
            oldTerritory, territoryType));
        NotifyCallbacks(territoryType, oldTerritory);
    }
}

} // namespace SapphireHook
