#pragma once
#include "../UI/UIModule.h"
#include "../Core/ZoneLayoutManager.h"
#include "../Tools/DebugVisualTypes.h"
#include <string>
#include <vector>
#include <memory>

namespace SapphireHook {

// Simple territory info for UI display
struct TerritoryInfo {
    uint32_t id = 0;
    std::string name;
    std::string bgPath;
};

class ZoneLayoutViewerModule : public UIModule {
public:
    ZoneLayoutViewerModule();
    ~ZoneLayoutViewerModule() override = default;

    // UIModule interface
    const char* GetName() const override { return "zone_layout_viewer"; }
    const char* GetDisplayName() const override { return "Zone Layout Viewer"; }
    void Initialize() override;
    void Shutdown() override;
    void RenderMenu() override;
    void RenderWindow() override;
    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    // UI state
    bool m_windowOpen = false;
    
    // Territory selection
    std::vector<TerritoryInfo> m_territories;
    int m_selectedTerritoryIndex = -1;
    char m_filterText[256] = "";
    std::vector<int> m_filteredIndices;
    
    // Loaded layout data
    std::shared_ptr<ZoneLayoutData> m_currentLayout;
    std::string m_lastError;
    
    // View options (checkboxes in UI)
    bool m_showBNpcs = true;
    bool m_showENpcs = true;
    bool m_showCollision = true;
    bool m_showExits = true;
    bool m_showPopRanges = false;
    bool m_showMapRanges = false;
    
    // Overlay rendering toggles
    bool m_overlayEnabled = false;
    bool m_overlayBNpcs = false;
    bool m_overlayENpcs = false;
    bool m_overlayCollision = false;
    bool m_overlayExits = true;
    bool m_overlayPopRanges = true;
    bool m_overlayMapRanges = false;
    bool m_overlayEventObjects = false;
    bool m_overlayEventRanges = false;
    bool m_overlayFateRanges = true;
    bool m_overlayGathering = false;
    bool m_overlayTreasures = false;
    bool m_overlayAetherytes = true;
    bool m_overlayMarkers = false;
    
    // Overlay appearance settings
    float m_overlayAlpha = 0.6f;
    float m_overlayScale = 1.0f;
    bool m_showLabels = true;
    float m_maxRenderDistance = 200.0f;
    
    // Tab selection
    int m_currentTab = 0;
    
    // Methods
    void LoadTerritoryList();
    void UpdateFilter();
    void LoadSelectedTerritory();
    
    // Render helpers
    void RenderTerritorySelector();
    void RenderLayoutSummary();
    void RenderOverlaySettings();
    void RenderBNpcTab();
    void RenderENpcTab();
    void RenderCollisionTab();
    void RenderExitsTab();
    void RenderPopRangesTab();
    void RenderMapRangesTab();
    void RenderEventObjectsTab();
    void RenderEventRangesTab();
    void RenderFateRangesTab();
    void RenderGatheringTab();
    void RenderTreasuresTab();
    void RenderAetherytesTab();
    void RenderMarkersTab();
    
    // 3D Overlay rendering
    void RenderOverlays();
    void RenderBNpcOverlays();
    void RenderENpcOverlays();
    void RenderCollisionOverlays();
    void RenderExitOverlays();
    void RenderPopRangeOverlays();
    void RenderMapRangeOverlays();
    void RenderEventObjectOverlays();
    void RenderEventRangeOverlays();
    void RenderFateRangeOverlays();
    void RenderGatheringOverlays();
    void RenderTreasureOverlays();
    void RenderAetheryteOverlays();
    void RenderMarkerOverlays();
    
    // Helper to get overlay colors
    static DebugVisuals::Color GetBNpcColor() { return {0.4f, 0.8f, 1.0f, 0.8f}; }      // Cyan
    static DebugVisuals::Color GetENpcColor() { return {0.4f, 1.0f, 0.4f, 0.8f}; }      // Green
    static DebugVisuals::Color GetCollisionColor() { return {1.0f, 0.8f, 0.4f, 0.5f}; } // Orange
    static DebugVisuals::Color GetExitColor() { return {1.0f, 0.3f, 0.3f, 0.8f}; }      // Red
    static DebugVisuals::Color GetPopRangeColor() { return {0.8f, 0.4f, 1.0f, 0.6f}; }  // Purple
    static DebugVisuals::Color GetMapRangeColor() { return {0.6f, 0.6f, 0.6f, 0.5f}; }  // Gray
    static DebugVisuals::Color GetEventObjectColor() { return {1.0f, 1.0f, 0.4f, 0.7f}; } // Yellow
    static DebugVisuals::Color GetEventRangeColor() { return {0.4f, 1.0f, 1.0f, 0.5f}; }  // Cyan-ish
    static DebugVisuals::Color GetFateRangeColor() { return {1.0f, 0.6f, 0.2f, 0.7f}; }   // Orange-red (FATE)
    static DebugVisuals::Color GetGatheringColor() { return {0.2f, 0.8f, 0.4f, 0.7f}; }   // Green variant
    static DebugVisuals::Color GetTreasureColor() { return {1.0f, 0.84f, 0.0f, 0.8f}; }   // Gold
    static DebugVisuals::Color GetAetheryteColor() { return {0.5f, 0.7f, 1.0f, 0.9f}; }   // Light blue
    static DebugVisuals::Color GetMarkerColor() { return {1.0f, 0.5f, 0.8f, 0.7f}; }      // Pink
};

} // namespace SapphireHook
