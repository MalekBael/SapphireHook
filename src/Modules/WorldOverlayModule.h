#pragma once
#include "../UI/UIModule.h"
#include "../Core/WorldOverlayManager.h"
#include <string>
#include <DirectXMath.h>

namespace SapphireHook {

/// Represents a selected world marker for inspection
struct SelectedMarker {
    enum class Type {
        None,
        BNpc,
        ENpc,
        EventObject,
        Exit,
        PopRange,
        Gathering,
        Treasure,
        Aetheryte,
        Marker,
        FateRange
    };
    
    Type type = Type::None;
    uint32_t index = 0;          // Index in the layout array
    uint32_t id = 0;             // Entity ID (NpcId, BaseId, etc.)
    std::string name;            // Display name
    DirectX::XMFLOAT3 position = {0, 0, 0};
    DirectX::XMFLOAT3 scale = {1, 1, 1};
    
    bool IsValid() const { return type != Type::None; }
    void Clear() { type = Type::None; index = 0; id = 0; name.clear(); }
};

/**
 * @brief UI Module for World Overlay controls.
 * 
 * This module provides a unified interface for controlling all world overlays.
 * It integrates with WorldOverlayManager and NavMeshManager to:
 * - Show current zone information
 * - Toggle overlay categories on/off
 * - Adjust overlay appearance settings
 * - Show zone statistics
 * - Pathfinding target selection and visualization
 * - Interactive marker selection, search, teleport
 */
class WorldOverlayModule : public UIModule {
public:
    WorldOverlayModule() = default;
    ~WorldOverlayModule() override = default;

    // UIModule interface
    const char* GetName() const override { return "world_overlay"; }
    const char* GetDisplayName() const override { return "World Overlay"; }
    void Initialize() override;
    void Shutdown() override;
    void RenderMenu() override;
    void RenderWindow() override;
    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    bool m_windowOpen = false;
    
    // Pathfinding target input
    float m_pathTargetX = 0.0f;
    float m_pathTargetY = 0.0f;
    float m_pathTargetZ = 0.0f;
    bool m_usePlayerPosAsTarget = false;
    
    // Interactive marker selection
    SelectedMarker m_selectedMarker;
    char m_searchFilter[128] = "";
    bool m_showMarkerBrowser = false;
    
    // Rendering helpers
    void RenderZoneInfo();
    void RenderOverlayToggles();
    void RenderAppearanceSettings();
    void RenderZoneStats();
    void RenderQuickToggles();
    void RenderNavMeshSection();
    void RenderPathfindingSection();
    
    // New interactive features
    void RenderMarkerBrowser();
    void RenderSelectedMarkerDetails();
    void TeleportToSelectedMarker();
    void CopyPositionToClipboard();
    bool MatchesSearchFilter(const std::string& name, uint32_t id) const;
};

} // namespace SapphireHook
