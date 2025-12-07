#include "ActorTracker.h"
#include "../Logger/Logger.h"
#include <cmath>
#include <format>

namespace SapphireHook::DebugVisuals {

    ActorTracker& ActorTracker::GetInstance() {
        static ActorTracker instance;
        return instance;
    }

    void ActorTracker::OnPlayerSpawn(uint32_t actorId, const std::string& name, 
                                      float x, float y, float z, float rotation,
                                      uint8_t level, uint8_t classJob, 
                                      uint32_t currentHp, uint32_t maxHp) {
        std::lock_guard<std::mutex> lock(m_mutex);

        TrackedActor actor;
        actor.actorId = actorId;
        actor.type = ActorType::Player;
        actor.name = name;
        actor.position = { x, y, z, rotation };
        actor.level = level;
        actor.classJob = classJob;
        actor.currentHp = currentHp;
        actor.maxHp = maxHp;
        actor.isHostile = false;
        actor.lastUpdate = std::chrono::steady_clock::now();

        m_actors[actorId] = actor;
        
        LogDebug(std::format("ActorTracker: Player '{}' (0x{:X}) spawned at ({:.1f}, {:.1f}, {:.1f})",
                 name, actorId, x, y, z));
    }

    void ActorTracker::OnNpcSpawn(uint32_t actorId, uint32_t npcId, const std::string& name,
                                   float x, float y, float z, float rotation,
                                   ActorType type, uint32_t ownerId, bool isHostile,
                                   uint32_t currentHp, uint32_t maxHp) {
        std::lock_guard<std::mutex> lock(m_mutex);

        TrackedActor actor;
        actor.actorId = actorId;
        actor.type = type;
        actor.name = name;
        actor.position = { x, y, z, rotation };
        actor.ownerId = ownerId;
        actor.isHostile = isHostile;
        actor.currentHp = currentHp;
        actor.maxHp = maxHp;
        actor.lastUpdate = std::chrono::steady_clock::now();

        m_actors[actorId] = actor;

        LogDebug(std::format("ActorTracker: NPC '{}' (0x{:X}) type {} spawned at ({:.1f}, {:.1f}, {:.1f})",
                 name, actorId, static_cast<int>(type), x, y, z));
    }

    void ActorTracker::OnActorMove(uint32_t actorId, float x, float y, float z, float rotation) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_actors.find(actorId);
        if (it != m_actors.end()) {
            it->second.position = { x, y, z, rotation };
            it->second.lastUpdate = std::chrono::steady_clock::now();
        } else {
            // Create a placeholder for unknown actor
            TrackedActor actor;
            actor.actorId = actorId;
            actor.type = ActorType::Unknown;
            actor.position = { x, y, z, rotation };
            actor.lastUpdate = std::chrono::steady_clock::now();
            m_actors[actorId] = actor;
        }
    }

    void ActorTracker::OnActorSetPos(uint32_t actorId, float x, float y, float z, float rotation) {
        // Same as move for our purposes
        OnActorMove(actorId, x, y, z, rotation);
    }

    void ActorTracker::OnActorDespawn(uint32_t actorId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_actors.find(actorId);
        if (it != m_actors.end()) {
            LogDebug(std::format("ActorTracker: Actor '{}' (0x{:X}) despawned", 
                     it->second.name, actorId));
            m_actors.erase(it);
        }
    }

    void ActorTracker::OnActorTarget(uint32_t actorId, uint32_t targetId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_actors.find(actorId);
        if (it != m_actors.end()) {
            it->second.targetId = targetId;
            it->second.lastUpdate = std::chrono::steady_clock::now();
        }
    }

    void ActorTracker::OnActorHpUpdate(uint32_t actorId, uint32_t currentHp, uint32_t maxHp) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_actors.find(actorId);
        if (it != m_actors.end()) {
            it->second.currentHp = currentHp;
            it->second.maxHp = maxHp;
            it->second.lastUpdate = std::chrono::steady_clock::now();
        }
    }

    void ActorTracker::OnZoneChange() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_actors.clear();
        LogInfo("ActorTracker: Zone change - cleared all actors");
    }

    std::optional<TrackedActor> ActorTracker::GetActor(uint32_t actorId) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_actors.find(actorId);
        if (it != m_actors.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::optional<ActorPosition> ActorTracker::GetActorPosition(uint32_t actorId) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_actors.find(actorId);
        if (it != m_actors.end()) {
            return it->second.position;
        }
        return std::nullopt;
    }

    std::vector<TrackedActor> ActorTracker::GetAllActors() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        std::vector<TrackedActor> result;
        result.reserve(m_actors.size());
        for (const auto& [id, actor] : m_actors) {
            result.push_back(actor);
        }
        return result;
    }

    std::vector<TrackedActor> ActorTracker::GetActorsByType(ActorType type) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        std::vector<TrackedActor> result;
        for (const auto& [id, actor] : m_actors) {
            if (actor.type == type) {
                result.push_back(actor);
            }
        }
        return result;
    }

    std::vector<TrackedActor> ActorTracker::GetNearbyActors(float x, float y, float z, float radius) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        float radiusSq = radius * radius;
        std::vector<TrackedActor> result;
        
        for (const auto& [id, actor] : m_actors) {
            float dx = actor.position.x - x;
            float dy = actor.position.y - y;
            float dz = actor.position.z - z;
            float distSq = dx * dx + dy * dy + dz * dz;
            
            if (distSq <= radiusSq) {
                result.push_back(actor);
            }
        }
        return result;
    }

    std::optional<TrackedActor> ActorTracker::GetLocalPlayer() const {
        if (m_localPlayerId == 0) {
            return std::nullopt;
        }
        return GetActor(m_localPlayerId);
    }

    void ActorTracker::CleanupStaleActors(std::chrono::seconds maxAge) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto now = std::chrono::steady_clock::now();
        auto it = m_actors.begin();
        while (it != m_actors.end()) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.lastUpdate);
            if (age > maxAge) {
                LogDebug(std::format("ActorTracker: Removing stale actor 0x{:X} (age: {}s)", 
                         it->first, age.count()));
                it = m_actors.erase(it);
            } else {
                ++it;
            }
        }
    }

    void ActorTracker::Clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_actors.clear();
        m_localPlayerId = 0;
    }

    size_t ActorTracker::GetActorCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_actors.size();
    }

} // namespace SapphireHook::DebugVisuals
