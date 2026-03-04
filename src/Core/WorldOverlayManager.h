#pragma once
#include "../Core/ZoneLayoutManager.h"
#include "../Core/TerritoryScanner.h"
#include "../Core/NavMeshManager.h"
#include "../Tools/DebugVisualTypes.h"
#include <memory>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <string>

namespace SapphireHook {
	class WorldOverlayManager {
	public:
		enum class OverlayCategory : uint32_t {
			None = 0,
			BNpcs = 1 << 0,
			ENpcs = 1 << 1,
			EventObjects = 1 << 2,
			FateRanges = 1 << 3,
			Exits = 1 << 4,
			PopRanges = 1 << 5,
			Gathering = 1 << 6,
			Treasures = 1 << 7,
			Aetherytes = 1 << 8,
			Collision = 1 << 9,
			MapRanges = 1 << 10,
			EventRanges = 1 << 11,
			Markers = 1 << 12,
			NavMesh = 1 << 13,
			NavMeshPath = 1 << 14,
			OffMeshLinks = 1 << 15,
			BgParts = 1 << 16,
			ServerPaths = 1 << 17,
			ClientPaths = 1 << 18,
			NavMeshRanges = 1 << 19,
			DoorRanges = 1 << 20,
			GimmickRanges = 1 << 21,
			KeepRanges = 1 << 22,
			ChairMarkers = 1 << 23,
			VfxLocations = 1 << 24,
			SoundLocations = 1 << 25,
			AllNpcs = BNpcs | ENpcs,
			AllRanges = FateRanges | PopRanges | MapRanges | EventRanges | Exits | NavMeshRanges | DoorRanges | GimmickRanges | KeepRanges,
			AllObjects = EventObjects | Gathering | Treasures | Aetherytes | ChairMarkers,
			AllNavigation = NavMesh | NavMeshPath | OffMeshLinks | ServerPaths | ClientPaths,
			AllEnvironment = BgParts | VfxLocations | SoundLocations,
			All = 0xFFFFFFFF
		};

		struct ZoneInfo {
			uint16_t territoryId = 0;
			std::string zoneName;
			std::string placeName;
			std::string regionName;
			std::string bgPath;
			uint8_t weatherRate = 0;
			bool isContentFinderContent = false;
			std::string contentName;
			uint16_t contentLevel = 0;
			bool isPvP = false;
			bool hasMount = true;
			bool hasAetheryte = false;
			size_t layoutElementCount = 0;
		};

		struct OverlaySettings {
			float Alpha = 0.6f;
			float Scale = 1.0f;
			float MaxRenderDistance = 200.0f;
			bool ShowLabels = true;
			float LabelScale = 2.0f;
			bool EnableFrustumCulling = false;
			uint32_t EnabledCategories = 0;
		};

		static WorldOverlayManager& GetInstance();

		void Initialize();

		void Shutdown();

		bool IsInitialized() const { return m_initialized; }

		std::shared_ptr<ZoneLayoutData> GetCurrentZoneLayout() const;

		uint16_t GetCurrentTerritoryId() const;

		std::string GetCurrentZoneName() const;

		ZoneInfo GetCurrentZoneInfo() const;

		bool LoadZone(uint16_t territoryId);

		void ClearCurrentZone();

		OverlaySettings& GetSettings() { return m_settings; }
		const OverlaySettings& GetSettings() const { return m_settings; }

		void SetCategoryEnabled(OverlayCategory category, bool enabled);
		bool IsCategoryEnabled(OverlayCategory category) const;

		void SetOverlaysEnabled(bool enabled);
		bool AreOverlaysEnabled() const { return m_overlaysEnabled; }

		void RenderOverlays();

		using ZoneLoadedCallback = std::function<void(uint16_t territoryId, std::shared_ptr<ZoneLayoutData>)>;
		using CallbackHandle = uint32_t;

		CallbackHandle RegisterZoneLoadedCallback(ZoneLoadedCallback callback);
		void UnregisterZoneLoadedCallback(CallbackHandle handle);

	private:
		WorldOverlayManager() = default;
		~WorldOverlayManager() = default;
		WorldOverlayManager(const WorldOverlayManager&) = delete;
		WorldOverlayManager& operator=(const WorldOverlayManager&) = delete;

		void OnTerritoryChanged(uint16_t newTerritory, uint16_t oldTerritory, const std::string& zoneName);
		void NotifyZoneLoaded(uint16_t territoryId, std::shared_ptr<ZoneLayoutData> layout);

		void RenderBNpcOverlays();
		void RenderENpcOverlays();
		void RenderEventObjectOverlays();
		void RenderFateRangeOverlays();
		void RenderExitOverlays();
		void RenderPopRangeOverlays();
		void RenderGatheringOverlays();
		void RenderTreasureOverlays();
		void RenderAetheryteOverlays();
		void RenderCollisionOverlays();
		void RenderMapRangeOverlays();
		void RenderEventRangeOverlays();
		void RenderMarkerOverlays();
		void RenderNavMeshOverlays();
		void RenderNavMeshPathOverlays();
		void RenderOffMeshLinkOverlays();
		void RenderBgPartOverlays();
		void RenderServerPathOverlays();
		void RenderClientPathOverlays();
		void RenderNavMeshRangeOverlays();
		void RenderDoorRangeOverlays();
		void RenderGimmickRangeOverlays();
		void RenderKeepRangeOverlays();
		void RenderChairMarkerOverlays();
		void RenderVfxLocationOverlays();
		void RenderSoundLocationOverlays();

		static DebugVisuals::Color GetBNpcColor() { return { 0.4f, 0.8f, 1.0f, 0.8f }; }
		static DebugVisuals::Color GetENpcColor() { return { 0.4f, 1.0f, 0.4f, 0.8f }; }
		static DebugVisuals::Color GetCollisionColor() { return { 1.0f, 0.8f, 0.4f, 0.5f }; }
		static DebugVisuals::Color GetExitColor() { return { 1.0f, 0.3f, 0.3f, 0.8f }; }
		static DebugVisuals::Color GetPopRangeColor() { return { 0.8f, 0.4f, 1.0f, 0.6f }; }
		static DebugVisuals::Color GetMapRangeColor() { return { 0.6f, 0.6f, 0.6f, 0.5f }; }
		static DebugVisuals::Color GetEventObjectColor() { return { 1.0f, 1.0f, 0.4f, 0.7f }; }
		static DebugVisuals::Color GetEventRangeColor() { return { 0.4f, 1.0f, 1.0f, 0.5f }; }
		static DebugVisuals::Color GetFateRangeColor() { return { 1.0f, 0.6f, 0.2f, 0.7f }; }
		static DebugVisuals::Color GetGatheringColor() { return { 0.2f, 0.8f, 0.4f, 0.7f }; }
		static DebugVisuals::Color GetTreasureColor() { return { 1.0f, 0.84f, 0.0f, 0.8f }; }
		static DebugVisuals::Color GetAetheryteColor() { return { 0.5f, 0.7f, 1.0f, 0.9f }; }
		static DebugVisuals::Color GetMarkerColor() { return { 1.0f, 0.5f, 0.8f, 0.7f }; }
		static DebugVisuals::Color GetNavMeshColor() { return { 0.3f, 0.6f, 0.3f, 0.3f }; }
		static DebugVisuals::Color GetNavMeshPathColor() { return { 0.0f, 1.0f, 0.0f, 0.9f }; }
		static DebugVisuals::Color GetOffMeshLinkColor() { return { 1.0f, 0.5f, 0.0f, 0.8f }; }
		static DebugVisuals::Color GetBgPartColor() { return { 0.6f, 0.6f, 0.7f, 0.4f }; }
		static DebugVisuals::Color GetServerPathColor() { return { 1.0f, 0.4f, 0.4f, 0.8f }; }
		static DebugVisuals::Color GetClientPathColor() { return { 0.4f, 0.4f, 1.0f, 0.8f }; }
		static DebugVisuals::Color GetNavMeshRangeColor() { return { 0.3f, 0.8f, 0.3f, 0.5f }; }
		static DebugVisuals::Color GetDoorRangeColor() { return { 0.8f, 0.5f, 0.2f, 0.7f }; }
		static DebugVisuals::Color GetGimmickRangeColor() { return { 0.9f, 0.3f, 0.9f, 0.6f }; }
		static DebugVisuals::Color GetKeepRangeColor() { return { 0.8f, 0.2f, 0.2f, 0.6f }; }
		static DebugVisuals::Color GetChairMarkerColor() { return { 0.4f, 0.6f, 0.8f, 0.8f }; }
		static DebugVisuals::Color GetVfxLocationColor() { return { 1.0f, 0.6f, 1.0f, 0.6f }; }
		static DebugVisuals::Color GetSoundLocationColor() { return { 0.6f, 1.0f, 0.6f, 0.6f }; }

		mutable std::mutex m_mutex;

		bool m_initialized = false;
		bool m_overlaysEnabled = false;

		uint16_t m_currentTerritoryId = 0;
		std::shared_ptr<ZoneLayoutData> m_currentLayout;

		OverlaySettings m_settings;

		TerritoryScanner::CallbackHandle m_territoryCallbackHandle = 0;

		std::mutex m_callbackMutex;
		std::vector<std::pair<CallbackHandle, ZoneLoadedCallback>> m_zoneLoadedCallbacks;
		CallbackHandle m_nextCallbackHandle = 1;
	};

	inline WorldOverlayManager::OverlayCategory operator|(WorldOverlayManager::OverlayCategory a, WorldOverlayManager::OverlayCategory b) {
		return static_cast<WorldOverlayManager::OverlayCategory>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
	}
	inline WorldOverlayManager::OverlayCategory operator&(WorldOverlayManager::OverlayCategory a, WorldOverlayManager::OverlayCategory b) {
		return static_cast<WorldOverlayManager::OverlayCategory>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
	}
	inline bool operator!(WorldOverlayManager::OverlayCategory a) {
		return static_cast<uint32_t>(a) == 0;
	}
}
