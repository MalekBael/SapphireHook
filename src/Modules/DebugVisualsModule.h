#pragma once
#include "../UI/UIModule.h"
#include "../Tools/DebugVisualTypes.h"
#include <DirectXMath.h>
#include <vector>

namespace SapphireHook {

    // Marker stored at a FIXED WORLD LOCATION
    // Once placed, the marker stays at that exact world position forever
    // Regardless of where the player moves, the marker remains anchored to that spot
    // Rendered via DirectX DebugRenderer as 3D circles in world space
    struct WorldMarker {
        DirectX::XMFLOAT3 position;  // Fixed world coordinates (X, Y, Z)
        float radius;                 // Radius in world units
        uint32_t color;               // ABGR format
        bool active;
    };

    /// <summary>
    /// UI Module for configuring and controlling the debug visualization system.
    /// Allows toggling the renderer, adjusting settings, and viewing debug visuals
    /// sent from the Sapphire server.
    /// </summary>
    class DebugVisualsModule final : public UIModule {
    public:
        // UIModule interface
        const char* GetName() const override { return "debug_visuals"; }
        const char* GetDisplayName() const override { return "Debug Visuals"; }
        
        void Initialize() override;
        void Shutdown() override;
        
        void RenderMenu() override;
        void RenderWindow() override;
        
        bool IsWindowOpen() const override { return m_windowOpen; }
        void SetWindowOpen(bool open) override { m_windowOpen = open; }

        // Debug visual controls
        bool IsVisualsEnabled() const { return m_visualsEnabled; }
        void SetVisualsEnabled(bool enabled);

        bool IsServerRunning() const;
        bool StartServer(uint16_t port = DebugVisuals::DEBUG_VISUAL_PORT);
        void StopServer();

        // Test/demo functions
        void DrawTestPrimitives();
        void ClearAllVisuals();
        void SendTestPacket();  // Send a test UDP packet to verify server is receiving
        
        // Fixed position marker system
        void MarkCurrentPosition();
        void ClearMarkers();
        void RenderMarkers();   // Called each frame to draw markers on screen

    private:
        void RenderStatisticsSection();
        void RenderSettingsSection();
        void RenderTestSection();
        void RenderPrimitiveList();
        void RenderMarkerSection();

        bool m_windowOpen = false;
        bool m_visualsEnabled = true;
        bool m_depthTestEnabled = false;
        bool m_showTestPrimitives = false;

        // Server settings
        uint16_t m_serverPort = DebugVisuals::DEBUG_VISUAL_PORT;
        bool m_autoStartServer = false;

        // Camera matrix source selection
        int m_cameraSource = 0;  // 0 = Manual, 1 = Auto-detect from game
        float m_manualFov = 45.0f;
        float m_manualNear = 0.1f;
        float m_manualFar = 1000.0f;
        
        // World-space markers anchored to fixed ground locations
        std::vector<WorldMarker> m_markers;
        float m_markerBaseRadius = 1.0f;    // Base radius in world units
        float m_markerHeightOffset = 0.0f; // Offset from lookAt Y to place on floor
        bool m_showMarkers = true;
    };

} // namespace SapphireHook
