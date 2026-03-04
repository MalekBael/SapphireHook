#pragma once
#include <cstdint>
#include <functional>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <DirectXMath.h>

namespace SapphireHook {
	struct ActorMoveEvent {
		uint32_t sourceActorId;
		uint32_t targetActorId;
		DirectX::XMFLOAT3 position;
		float direction;
		uint8_t speed;
		uint8_t flags;
		uint64_t timestamp;
	};

	struct PlayerSpawnEvent {
		uint32_t actorId;
		DirectX::XMFLOAT3 position;
		float direction;
		uint8_t objKind;
		uint32_t npcId;
		uint64_t timestamp;
	};

	using ActorMoveCallback = std::function<void(const ActorMoveEvent&)>;
	using PlayerSpawnCallback = std::function<void(const PlayerSpawnEvent&)>;

	class PacketEventDispatcher {
	public:
		static PacketEventDispatcher& Instance() {
			static PacketEventDispatcher inst;
			return inst;
		}

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
				}
				catch (...) {}
			}
		}

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
				}
				catch (...) {}
			}
		}

		static DirectX::XMFLOAT3 DecodeActorMovePosition(const uint16_t pos[3]) {
			constexpr float kScale = 32.0f;
			return {
				(static_cast<float>(pos[0]) - 32768.0f) / kScale,
				(static_cast<float>(pos[1]) - 32768.0f) / kScale,
				(static_cast<float>(pos[2]) - 32768.0f) / kScale
			};
		}

		static float DecodeDirection16(uint16_t dir) {
			return static_cast<float>(dir) * (3.14159265f / 32768.0f);
		}

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
}
