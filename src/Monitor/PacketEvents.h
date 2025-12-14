#pragma once
#include <cstdint>
#include <functional>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <DirectXMath.h>

namespace SapphireHook {

    // ============================================
    // ActorMove event data (from packet 0x0192)
    // Position encoding: (raw - 32768) / 32.0f gives world coordinates
    // ============================================
    struct ActorMoveEvent {
        uint32_t sourceActorId;     // The actor that's moving (BNPC/NPC)
        uint32_t targetActorId;     // Usually the player observing
        DirectX::XMFLOAT3 position; // World position (properly decoded)
        float direction;            // Direction in radians
        uint8_t speed;              // Movement speed
        uint8_t flags;              // Movement flags
        uint64_t timestamp;         // When the packet was received
    };

    // ============================================
    // PlayerSpawn event data (from packet 0x0190)
    // Contains REAL float world coordinates!
    // ============================================
    struct PlayerSpawnEvent {
        uint32_t actorId;           // The spawned actor's ID (from segment header)
        DirectX::XMFLOAT3 position; // Real float world position
        float direction;            // Direction in radians
        uint8_t objKind;            // Object kind (1=PC, 2=BattleNpc, etc)
        uint32_t npcId;             // BNpc name ID
        uint64_t timestamp;         // When the packet was received
    };

    // Callback types
    using ActorMoveCallback = std::function<void(const ActorMoveEvent&)>;
    using PlayerSpawnCallback = std::function<void(const PlayerSpawnEvent&)>;

    // ============================================
    // Packet Event Dispatcher - singleton
    // Allows modules to subscribe to decoded packet events
    // ============================================
    class PacketEventDispatcher {
    public:
        static PacketEventDispatcher& Instance() {
            static PacketEventDispatcher inst;
            return inst;
        }

        // ---- ActorMove subscriptions ----
        uint32_t SubscribeActorMove(ActorMoveCallback callback) {
            std::lock_guard<std::mutex> lock(m_mutex);
            uint32_t id = m_nextSubId++;
            m_actorMoveCallbacks[id] = std::move(callback);
            return id;
        }

        void UnsubscribeActorMove(uint32_t subId) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_actorMoveCallbacks.erase(subId);
        }

        void DispatchActorMove(const ActorMoveEvent& event) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& [id, callback] : m_actorMoveCallbacks) {
                try {
                    callback(event);
                } catch (...) {}
            }
        }

        // ---- PlayerSpawn subscriptions ----
        uint32_t SubscribePlayerSpawn(PlayerSpawnCallback callback) {
            std::lock_guard<std::mutex> lock(m_mutex);
            uint32_t id = m_nextSubId++;
            m_playerSpawnCallbacks[id] = std::move(callback);
            return id;
        }

        void UnsubscribePlayerSpawn(uint32_t subId) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_playerSpawnCallbacks.erase(subId);
        }

        void DispatchPlayerSpawn(const PlayerSpawnEvent& event) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& [id, callback] : m_playerSpawnCallbacks) {
                try {
                    callback(event);
                } catch (...) {}
            }
        }

        // Helper to decode ActorMove position from packed uint16[3] to world coordinates
        // Formula: (raw - 32768) / 32.0f
        // The uint16 is centered at 32768, with scale factor of 32
        static DirectX::XMFLOAT3 DecodeActorMovePosition(const uint16_t pos[3]) {
            constexpr float kScale = 32.0f;
            return {
                (static_cast<float>(pos[0]) - 32768.0f) / kScale,
                (static_cast<float>(pos[1]) - 32768.0f) / kScale,
                (static_cast<float>(pos[2]) - 32768.0f) / kScale
            };
        }

        // Helper to convert direction from uint16 to radians (PlayerSpawn uses uint16 dir)
        static float DecodeDirection16(uint16_t dir) {
            // uint16 direction: 0-65535 maps to 0-2π
            return static_cast<float>(dir) * (3.14159265f / 32768.0f);
        }

        // Decode direction from uint8 to radians (ActorMove uses uint8 dir)
        static float DecodeDirection8(uint8_t dir) {
            return static_cast<float>(dir) * (3.14159265f / 128.0f);
        }

    private:
        PacketEventDispatcher() = default;
        
        std::mutex m_mutex;
        uint32_t m_nextSubId = 1;
        std::unordered_map<uint32_t, ActorMoveCallback> m_actorMoveCallbacks;
        std::unordered_map<uint32_t, PlayerSpawnCallback> m_playerSpawnCallbacks;
    };

} // namespace SapphireHook
