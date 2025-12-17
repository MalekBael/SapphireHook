#pragma once
#include <cstdint>
#include <string>
#include <functional>
#include <vector>
#include <mutex>
#include <optional>

namespace SapphireHook {

/**
 * @brief Tracks the current territory (zone) the player is in.
 * 
 * This service provides real-time territory information through multiple sources:
 * 1. InitZone packet interception (primary, most reliable)
 * 2. Memory scanning (fallback, for when packets are missed)
 * 
 * Other modules can register callbacks to be notified when the player changes zones.
 */
class TerritoryScanner {
public:
    /// Callback signature for territory change notifications
    /// Parameters: (newTerritoryType, oldTerritoryType, zoneName)
    using TerritoryChangeCallback = std::function<void(uint16_t, uint16_t, const std::string&)>;
    
    /// Handle for unregistering callbacks
    using CallbackHandle = uint32_t;
    
    /// Territory state data
    struct TerritoryState {
        uint16_t TerritoryType = 0;       ///< Current territory type (zone ID)
        uint16_t ZoneId = 0;              ///< Internal zone ID
        uint16_t TerritoryIndex = 0;      ///< Instance index
        uint32_t LayoutId = 0;            ///< Current layout ID
        uint32_t LayerSetId = 0;          ///< Current layer set
        uint8_t  WeatherId = 0;           ///< Current weather
        float    SpawnPos[3] = {0,0,0};   ///< Spawn position
        
        bool IsValid() const { return TerritoryType != 0; }
    };
    
    static TerritoryScanner& GetInstance();
    
    /// Initialize the scanner (called during DLL initialization)
    void Initialize();
    
    /// Shutdown the scanner (called during DLL unload)
    void Shutdown();
    
    /// Process an InitZone packet (called from packet decoder)
    void OnInitZonePacket(const void* packetData, size_t packetSize);
    
    /// Process a MoveTerritory packet (called from packet decoder)
    /// Used when walking between zones (not teleporting)
    void OnMoveTerritoryPacket(const void* packetData, size_t packetSize);
    
    /// Get the current territory state
    TerritoryState GetCurrentState() const;
    
    /// Get just the current territory type (zone ID)
    uint16_t GetCurrentTerritoryType() const;
    
    /// Get the current zone name (looked up from GameData)
    std::string GetCurrentZoneName() const;
    
    /// Check if we have valid territory data
    bool HasValidTerritory() const;
    
    /// Register a callback for territory changes
    /// Returns a handle that can be used to unregister
    CallbackHandle RegisterCallback(TerritoryChangeCallback callback);
    
    /// Unregister a callback by handle
    void UnregisterCallback(CallbackHandle handle);
    
    /// Attempt to scan memory for current territory (fallback if packets missed)
    /// Returns true if a valid territory was found
    bool TryScanMemory();
    
    /// Force update territory (for testing/manual override)
    void ForceSetTerritory(uint16_t territoryType);
    
private:
    TerritoryScanner() = default;
    ~TerritoryScanner() = default;
    TerritoryScanner(const TerritoryScanner&) = delete;
    TerritoryScanner& operator=(const TerritoryScanner&) = delete;
    
    void NotifyCallbacks(uint16_t newTerritory, uint16_t oldTerritory);
    
    mutable std::mutex m_mutex;
    TerritoryState m_currentState;
    
    std::mutex m_callbackMutex;
    std::vector<std::pair<CallbackHandle, TerritoryChangeCallback>> m_callbacks;
    CallbackHandle m_nextHandle = 1;
    
    bool m_initialized = false;
    
    // Memory scan cache
    uintptr_t m_cachedTerritoryPtr = 0;
    bool m_memoryScanAttempted = false;  // Only scan once, not every frame
};

} // namespace SapphireHook
