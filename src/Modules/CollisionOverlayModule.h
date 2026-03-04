#pragma once
#include "../UI/UIModule.h"
#include "../Tools/CollisionMeshLoader.h"
#include "../Tools/NavMeshLoader.h"
#include "../Monitor/PacketEvents.h"
#include <memory>
#include <array>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

namespace SapphireHook {
	// Bring in collision types
	using Collision::CollisionCategory;
	using Collision::CollisionMesh;
	using Collision::CollisionObject;
	using Collision::LoadProgress;
	using CollisionLoadProgress = Collision::LoadProgress;
	using Collision::GetCategoryName;
	using Collision::GetDefaultCategoryColor;
	using Collision::CollisionMeshLoader;

	class CollisionOverlayModule : public UIModule {
	public:
		CollisionOverlayModule();
		~CollisionOverlayModule() override;

		const char* GetName() const override { return "collision_overlay"; }
		const char* GetDisplayName() const override { return "Collision Overlay"; }

		void RenderMenu() override;
		void RenderWindow() override;
		bool IsWindowOpen() const override { return m_windowOpen; }
		void SetWindowOpen(bool open) override { m_windowOpen = open; }

		// Called by main render loop to draw 3D overlays
		void Render3DOverlay();

	private:
		bool m_windowOpen = false;

		// ======== Collision Mesh (OBJ) ========
		bool m_showCollisionMesh = false;
		std::optional<CollisionMesh> m_loadedCollision;
		std::string m_collisionFilePath;
		bool m_loadingCollision = false;
		CollisionLoadProgress m_collisionProgress{};

		// Category toggles and colors
		std::array<bool, static_cast<size_t>(CollisionCategory::COUNT)> m_categoryVisible;
		std::array<float, 4> m_categoryColorOverride = { -1, -1, -1, -1 }; // RGBA, -1 = use default
		float m_collisionAlpha = 0.4f;
		bool m_showCollisionWireframe = true;
		bool m_showCollisionFilled = false;

		// ======== NavMesh ========
		bool m_showNavMesh = false;
		std::optional<Navigation::LoadedNavMesh> m_loadedNavMesh;
		std::string m_navMeshFilePath;
		bool m_loadingNavMesh = false;
		Navigation::NavLoadProgress m_navMeshProgress{};

		// NavMesh display options
		float m_navMeshAlpha = 0.3f;
		bool m_showNavMeshWireframe = true;
		bool m_showNavMeshFilled = true;
		bool m_showOffMeshConnections = true;
		bool m_colorByArea = true;
		std::array<bool, 64> m_areaVisible;  // Area type toggles
		float m_navMeshYOffset = 0.0f;  // Y offset to align navmesh with ground

		// ======== BNPC Path Visualization ========
		bool m_showBNPCPaths = false;
		float m_bnpcPathUpdateInterval = 0.5f;  // Seconds between path updates
		float m_bnpcMaxTrackDistance = 100.0f;  // Max distance to track BNPCs
		bool m_showBNPCPositionHistory = true;
		int m_bnpcHistoryLength = 20;  // Number of past positions to show
		bool m_showCalibrationStatus = false;  // Show calibration debug info

		// Player position history tracking (as proof of concept before BNPC scanning)
		struct TrackedEntity {
			uint32_t id = 0;
			std::string name;
			std::vector<DirectX::XMFLOAT3> positionHistory;
			DirectX::XMFLOAT3 lastPosition = { 0, 0, 0 };
			float lastDirection = 0.0f;
			uint64_t lastUpdateTime = 0;
			uint8_t type = 0;  // 0=player, 1=hostile, 2=friendly, 3=neutral

			// Auto-calibration: spawn position from PlayerSpawn (accurate)
			// is used to calculate offset when first ActorMove arrives
			DirectX::XMFLOAT3 spawnPosition = { 0, 0, 0 };  // From PlayerSpawn (ground truth)
			DirectX::XMFLOAT3 calibrationOffset = { 0, 0, 0 };  // spawnPos - firstActorMovePos
			bool hasSpawnPosition = false;  // Did we see this entity spawn?
			bool isCalibrated = false;  // Have we calculated the offset?
		};
		std::vector<TrackedEntity> m_trackedEntities;
		std::mutex m_trackedEntitiesMutex;  // Protects m_trackedEntities from packet callback
		std::chrono::steady_clock::time_point m_lastPathUpdate;
		bool m_trackPlayerPath = true;  // Track player's own path for testing
		uint32_t m_actorMoveSubId = 0;  // Subscription ID for ActorMove events
		uint32_t m_playerSpawnSubId = 0;  // Subscription ID for PlayerSpawn events

		// Callback handlers for packet events
		void OnActorMove(const ActorMoveEvent& event);
		void OnPlayerSpawn(const PlayerSpawnEvent& event);

		// ======== Rendering settings ========
		float m_maxRenderDistance = 61.0f;  // Only render objects within this distance
		bool m_depthTest = true;
		bool m_cullBackfaces = false;

		// ======== UI State ========
		int m_selectedTab = 0;  // 0 = Collision, 1 = NavMesh
		char m_filePathBuffer[512] = {};

		// Internal helpers
		void RenderCollisionTab();
		void RenderNavMeshTab();
		void RenderBNPCPathsTab();
		void RenderSettingsTab();
		void RenderStatistics();

		void LoadCollisionFile(const std::string& path);
		void LoadNavMeshFile(const std::string& path);

		void RenderCollisionMesh();
		void RenderNavMesh();
		void RenderBNPCPaths();

		void DrawTriangle(const DirectX::XMFLOAT3& v0,
			const DirectX::XMFLOAT3& v1,
			const DirectX::XMFLOAT3& v2,
			const DirectX::XMFLOAT4& color,
			bool filled, bool wireframe);

		DirectX::XMFLOAT4 GetCollisionCategoryColor(CollisionCategory cat) const;
		DirectX::XMFLOAT4 GetNavAreaColor(uint8_t area) const;
	};
} // namespace SapphireHook
