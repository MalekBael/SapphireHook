#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <chrono>
#include "DebugVisualTypes.h"

namespace SapphireHook::DebugVisuals {

    /// <summary>
    /// Simple 3D position structure
    /// </summary>
    struct ActorPosition {
        float x = 0.0f;
        float y = 0.0f;
        float z = 0.0f;
        float rotation = 0.0f;  // Direction/heading
    };

    /// <summary>
    /// Actor type classification
    /// </summary>
    enum class ActorType : uint8_t {
        Unknown = 0,
        Player = 1,
        BattleNpc = 2,
        EventNpc = 3,
        Treasure = 4,
        Aetheryte = 5,
        GatheringPoint = 6,
        EventObj = 7,
        Mount = 8,
        Companion = 9,
        Retainer = 10,
        Area = 11,
        Housing = 12,
        Cutscene = 13,
        CardStand = 14,
    };

    /// <summary>
    /// Tracked actor information
    /// </summary>
    struct TrackedActor {
        uint32_t actorId = 0;
        ActorType type = ActorType::Unknown;
        ActorPosition position;
        std::string name;
        uint32_t ownerId = 0;       // For pets/companions
        uint32_t targetId = 0;      // Current target
        uint8_t level = 0;
        uint8_t classJob = 0;
        uint32_t currentHp = 0;
        uint32_t maxHp = 0;
        bool isHostile = false;
        std::chrono::steady_clock::time_point lastUpdate;
    };

    /// <summary>
    /// Tracks actor positions based on network packets.
    /// This allows debug visuals to be drawn around actors without
    /// needing to read game memory directly.
    /// </summary>
    class ActorTracker {
    public:
        static ActorTracker& GetInstance();

        // Called from packet handlers
        void OnPlayerSpawn(uint32_t actorId, const std::string& name, float x, float y, float z, float rotation,
                          uint8_t level, uint8_t classJob, uint32_t currentHp, uint32_t maxHp);
        void OnNpcSpawn(uint32_t actorId, uint32_t npcId, const std::string& name, float x, float y, float z, float rotation,
                       ActorType type, uint32_t ownerId, bool isHostile, uint32_t currentHp, uint32_t maxHp);
        void OnActorMove(uint32_t actorId, float x, float y, float z, float rotation);
        void OnActorSetPos(uint32_t actorId, float x, float y, float z, float rotation);
        void OnActorDespawn(uint32_t actorId);
        void OnActorTarget(uint32_t actorId, uint32_t targetId);
        void OnActorHpUpdate(uint32_t actorId, uint32_t currentHp, uint32_t maxHp);
        void OnZoneChange();  // Clear all actors on zone change

        // Query interface
        std::optional<TrackedActor> GetActor(uint32_t actorId) const;
        std::optional<ActorPosition> GetActorPosition(uint32_t actorId) const;
        std::vector<TrackedActor> GetAllActors() const;
        std::vector<TrackedActor> GetActorsByType(ActorType type) const;
        std::vector<TrackedActor> GetNearbyActors(float x, float y, float z, float radius) const;

        // Local player tracking
        void SetLocalPlayerId(uint32_t actorId) { m_localPlayerId = actorId; }
        uint32_t GetLocalPlayerId() const { return m_localPlayerId; }
        std::optional<TrackedActor> GetLocalPlayer() const;

        // Cleanup
        void CleanupStaleActors(std::chrono::seconds maxAge = std::chrono::seconds(60));
        void Clear();

        // Stats
        size_t GetActorCount() const;

    private:
        ActorTracker() = default;
        ~ActorTracker() = default;
        ActorTracker(const ActorTracker&) = delete;
        ActorTracker& operator=(const ActorTracker&) = delete;

        mutable std::mutex m_mutex;
        std::unordered_map<uint32_t, TrackedActor> m_actors;
        uint32_t m_localPlayerId = 0;
    };

} // namespace SapphireHook::DebugVisuals
