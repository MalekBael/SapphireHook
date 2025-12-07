#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "DebugVisualsModule.h"
#include "../Tools/DebugRenderer.h"
#include "../Tools/DebugVisualServer.h"
#include "../Tools/GameCameraExtractor.h"
#include "../Tools/ActorTracker.h"
#include "../Logger/Logger.h"
#include <imgui.h>
#include <format>
#include <cmath>

#pragma comment(lib, "ws2_32.lib")

namespace SapphireHook {

    using namespace DebugVisuals;

    void DebugVisualsModule::Initialize() {
        LogInfo("DebugVisualsModule: Initializing");

        // Note: ViewProjectionHook is disabled - we now build our own matrices
        // from the known-good camera position (0x100) and lookAt (0xE0) offsets.
        // This is more reliable than trying to read garbage matrix data or hook
        // functions that aren't actually WorldToScreen.

        // Auto-start server if configured
        if (m_autoStartServer) {
            StartServer(m_serverPort);
        }
    }

    void DebugVisualsModule::Shutdown() {
        LogInfo("DebugVisualsModule: Shutting down");
        
        StopServer();
        
        if (DebugRenderer::GetInstance().IsInitialized()) {
            DebugRenderer::GetInstance().Shutdown();
        }
    }

    void DebugVisualsModule::SetVisualsEnabled(bool enabled) {
        m_visualsEnabled = enabled;
        
        if (DebugRenderer::GetInstance().IsInitialized()) {
            DebugRenderer::GetInstance().SetEnabled(enabled);
        }
    }

    bool DebugVisualsModule::IsServerRunning() const {
        return DebugVisualServer::GetInstance().IsRunning();
    }

    bool DebugVisualsModule::StartServer(uint16_t port) {
        return DebugVisualServer::GetInstance().Start(port);
    }

    void DebugVisualsModule::StopServer() {
        DebugVisualServer::GetInstance().Stop();
    }

    void DebugVisualsModule::RenderMenu() {
        if (ImGui::MenuItem("Debug Visuals", nullptr, m_windowOpen)) {
            m_windowOpen = !m_windowOpen;
        }
    }

    void DebugVisualsModule::RenderWindow() {
        // Render markers even when window is closed (they use DirectX, not ImGui)
        if (m_showMarkers && !m_markers.empty()) {
            RenderMarkers();
        }
        
        if (!m_windowOpen) {
            return;
        }

        ImGui::SetNextWindowSize(ImVec2(450, 500), ImGuiCond_FirstUseEver);
        
        if (ImGui::Begin("Debug Visuals", &m_windowOpen)) {
            // Main enable toggle
            if (ImGui::Checkbox("Enable Debug Visuals", &m_visualsEnabled)) {
                SetVisualsEnabled(m_visualsEnabled);
            }

            ImGui::Separator();

            if (ImGui::BeginTabBar("DebugVisualsTabBar")) {
                if (ImGui::BeginTabItem("Statistics")) {
                    RenderStatisticsSection();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Settings")) {
                    RenderSettingsSection();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Test")) {
                    RenderTestSection();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Primitives")) {
                    RenderPrimitiveList();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Markers")) {
                    RenderMarkerSection();
                    ImGui::EndTabItem();
                }

                ImGui::EndTabBar();
            }
        }
        ImGui::End();
    }

    void DebugVisualsModule::RenderStatisticsSection() {
        auto& renderer = DebugRenderer::GetInstance();
        auto& server = DebugVisualServer::GetInstance();

        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Renderer");
        ImGui::Separator();
        
        ImGui::Text("Initialized: %s", renderer.IsInitialized() ? "Yes" : "No");
        ImGui::Text("Enabled: %s", renderer.IsEnabled() ? "Yes" : "No");
        ImGui::Text("Depth Test: %s", renderer.IsDepthTestEnabled() ? "On" : "Off");
        ImGui::Text("Persistent Primitives: %zu", renderer.GetPrimitiveCount());

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Network Server");
        ImGui::Separator();
        
        bool serverRunning = server.IsRunning();
        ImGui::Text("Status: %s", serverRunning ? "Running" : "Stopped");
        
        if (serverRunning) {
            ImGui::Text("Port: %u", server.GetPort());
            ImGui::Text("Packets Received: %llu", server.GetPacketsReceived());
            ImGui::Text("Bytes Received: %llu", server.GetBytesReceived());
            ImGui::Text("Errors: %llu", server.GetErrorCount());
        }

        ImGui::Spacing();
        
        if (serverRunning) {
            if (ImGui::Button("Stop Server")) {
                StopServer();
            }
            ImGui::SameLine();
            if (ImGui::Button("Send Test Packet")) {
                SendTestPacket();
            }
            ImGui::SetItemTooltip("Send a test UDP packet to verify the server is receiving");
        } else {
            ImGui::SetNextItemWidth(100);
            ImGui::InputScalar("Port", ImGuiDataType_U16, &m_serverPort);
            ImGui::SameLine();
            if (ImGui::Button("Start Server")) {
                StartServer(m_serverPort);
            }
        }
    }

    void DebugVisualsModule::RenderSettingsSection() {
        auto& renderer = DebugRenderer::GetInstance();
        auto& cameraExtractor = GameCameraExtractor::GetInstance();

        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Rendering Options");
        ImGui::Separator();

        if (ImGui::Checkbox("Depth Testing", &m_depthTestEnabled)) {
            renderer.SetDepthTestEnabled(m_depthTestEnabled);
        }
        ImGui::SetItemTooltip("When enabled, debug visuals will be occluded by game geometry");

        ImGui::Checkbox("Auto-start Server", &m_autoStartServer);
        ImGui::SetItemTooltip("Automatically start the debug visual server when the module initializes");

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Camera Settings");
        ImGui::Separator();

        // Camera extraction status
        CameraExtractionStatus cameraStatus = cameraExtractor.GetStatus();
        ImVec4 statusColor;
        switch (cameraStatus) {
            case CameraExtractionStatus::Ready:
                statusColor = ImVec4(0.4f, 1.0f, 0.4f, 1.0f);
                break;
            case CameraExtractionStatus::SignaturesNotFound:
            case CameraExtractionStatus::ExtractionFailed:
                statusColor = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);
                break;
            default:
                statusColor = ImVec4(1.0f, 0.8f, 0.3f, 1.0f);
                break;
        }
        ImGui::TextColored(statusColor, "Camera Status: %s", ToString(cameraStatus));

        // Show camera addresses for debugging
        if (cameraExtractor.IsInitialized()) {
            uintptr_t camMgr = cameraExtractor.GetCameraManagerAddress();
            uintptr_t activeCam = cameraExtractor.GetActiveCameraAddress();
            if (camMgr != 0) {
                ImGui::Text("Camera Manager: 0x%llX", camMgr);
            }
            if (activeCam != 0) {
                ImGui::Text("Active Camera: 0x%llX", activeCam);
            }
        }

        // Show projection method
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Projection Method");
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Using LookAt Matrix");
        ImGui::TextWrapped("View/Projection matrices built from camera position (0x100) and lookAt (0xE0). "
                          "Game matrices at 0x40/0x80 are garbage - we construct our own.");

        ImGui::Spacing();

        const char* cameraSources[] = { "Manual", "Auto-detect (Game)" };
        ImGui::Combo("Camera Source", &m_cameraSource, cameraSources, 2);

        if (m_cameraSource == 0) {
            // Manual camera mode
            ImGui::SliderFloat("FOV", &m_manualFov, 30.0f, 120.0f, "%.1f deg");
            ImGui::SliderFloat("Near Plane", &m_manualNear, 0.01f, 10.0f, "%.2f");
            ImGui::SliderFloat("Far Plane", &m_manualFar, 100.0f, 10000.0f, "%.0f");

            if (ImGui::Button("Apply Manual Camera")) {
                // Create a simple perspective projection
                float aspectRatio = 16.0f / 9.0f;  // TODO: Get actual screen ratio
                DirectX::XMMATRIX proj = DirectX::XMMatrixPerspectiveFovLH(
                    DirectX::XMConvertToRadians(m_manualFov),
                    aspectRatio,
                    m_manualNear,
                    m_manualFar
                );
                
                // Identity view matrix for now
                DirectX::XMMATRIX view = DirectX::XMMatrixIdentity();
                
                renderer.SetViewProjection(view, proj);
            }
            
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), 
                              "Manual mode uses a fixed camera. Primitives won't track the game camera.");
        } else {
            // Auto-detect mode
            const auto& camera = cameraExtractor.GetCachedCamera();
            
            if (cameraStatus == CameraExtractionStatus::Ready) {
                if (camera.valid) {
                    // cam.lookAt = player position (from 0x100)
                    // cam.position = computed camera eye (player + dist + angles)
                    ImGui::Text("Player Position: (%.1f, %.1f, %.1f)", 
                               camera.lookAt.x, camera.lookAt.y, camera.lookAt.z);
                    ImGui::Text("Camera Eye (computed): (%.1f, %.1f, %.1f)", 
                               camera.position.x, camera.position.y, camera.position.z);
                    ImGui::Text("FOV: %.1f deg", DirectX::XMConvertToDegrees(camera.fovY));
                }
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), 
                                  "Camera ready - WorldToScreen active!");
            } else if (cameraStatus == CameraExtractionStatus::SignaturesNotFound) {
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), 
                                  "Could not find camera signatures for this game version.");
            } else if (cameraStatus == CameraExtractionStatus::ExtractionFailed) {
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), 
                                  "Camera found but extraction failed.");
            } else {
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), 
                                  "Camera extraction in progress...");
            }
            
            // Always show debug buttons
            if (ImGui::Button("Dump Camera Memory")) {
                cameraExtractor.DumpCameraMemory();
            }
            ImGui::SameLine();
            if (ImGui::Button("Dump Matrices")) {
                cameraExtractor.DumpVerifiedMatrices();
            }
            ImGui::SetItemTooltip("Dump all matrices from camera at offset 0x20 (with world coords)");
            
            if (ImGui::Button("Compare Memory")) {
                cameraExtractor.CompareCameraMemory();
            }
            ImGui::SetItemTooltip("Click once to snapshot, move camera, click again to see changes");
            ImGui::SameLine();
            if (ImGui::Button("Compare Cameras")) {
                cameraExtractor.CompareActiveCameraVsRenderCamera();
            }
            ImGui::SetItemTooltip("Compare matrices from ActiveCamera (0x20) vs RenderCamera (0x40)");
            ImGui::SameLine();
            if (ImGui::Button("Retry Scan")) {
                cameraExtractor.RescanSignatures();
            }
        }

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Network Protocol");
        ImGui::Separator();
        
        ImGui::Text("Protocol Version: %d", PROTOCOL_VERSION);
        ImGui::Text("Default Port: %u", DEBUG_VISUAL_PORT);
        ImGui::Text("Visual Magic: 0x%08X ('DBGV')", DEBUG_VISUAL_MAGIC);
        ImGui::Text("Command Magic: 0x%08X ('DBGC')", DEBUG_COMMAND_MAGIC);
    }

    void DebugVisualsModule::RenderTestSection() {
        auto& renderer = DebugRenderer::GetInstance();

        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Test Primitives");
        ImGui::Separator();

        if (!renderer.IsInitialized()) {
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), 
                              "Renderer not initialized. Debug visuals will not be visible.");
            return;
        }

        ImGui::Checkbox("Show Test Primitives", &m_showTestPrimitives);
        
        if (m_showTestPrimitives) {
            DrawTestPrimitives();
        }

        ImGui::Spacing();

        if (ImGui::Button("Add Test Line")) {
            DebugLine line;
            line.start = { 0, 0, 0 };
            line.end = { 10, 5, 0 };
            line.color = Color::Red();
            line.thickness = 2.0f;
            
            static uint32_t lineId = 1000;
            renderer.AddLine(lineId++, line, 5.0f);
        }

        ImGui::SameLine();

        if (ImGui::Button("Add Test Sphere")) {
            DebugSphere sphere;
            sphere.center = { 5, 2, 5 };
            sphere.radius = 2.0f;
            sphere.color = Color::Green();
            sphere.filled = false;
            sphere.segments = 16;
            
            static uint32_t sphereId = 2000;
            renderer.AddSphere(sphereId++, sphere, 5.0f);
        }

        ImGui::SameLine();

        if (ImGui::Button("Add Test Circle")) {
            DebugCircle circle;
            circle.center = { -5, 0.1f, 0 };
            circle.radius = 3.0f;
            circle.color = Color::Yellow();
            circle.segments = 32;
            circle.filled = true;
            circle.yRotation = 0;
            
            static uint32_t circleId = 3000;
            renderer.AddCircle(circleId++, circle, 5.0f);
        }

        ImGui::Spacing();

        if (ImGui::Button("Clear All Primitives")) {
            ClearAllVisuals();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Camera Diagnostics");
        ImGui::Separator();

        auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
        ImGui::Text("RenderManager ptr: 0x%llX", static_cast<unsigned long long>(cameraExtractor.GetRenderManagerAddress()));
        if (ImGui::Button("Dump RenderManager Memory")) {
            cameraExtractor.DumpRenderManagerMemory();
        }
        ImGui::SameLine();
        if (ImGui::Button("Dump Verified Matrices")) {
            cameraExtractor.DumpVerifiedMatrices();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Position Tracking");
        ImGui::Separator();

        // Show current tracked position from ActorTracker
        auto& tracker = ActorTracker::GetInstance();
        auto localPlayer = tracker.GetLocalPlayer();
        
        if (localPlayer) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Player Position (from packets):");
            ImGui::Text("  Engine Coords: (%.2f, %.2f, %.2f)", 
                       localPlayer->position.x, localPlayer->position.y, localPlayer->position.z);
            ImGui::Text("  Rotation: %.2f rad (%.1f deg)", 
                       localPlayer->position.rotation, 
                       localPlayer->position.rotation * 180.0f / 3.14159f);
            ImGui::Text("  Actor ID: 0x%X", localPlayer->actorId);
            if (!localPlayer->name.empty()) {
                ImGui::Text("  Name: %s", localPlayer->name.c_str());
            }
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "No player position tracked yet.");
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), 
                              "Position will update when movement packets are received.");
        }

        ImGui::Text("Tracked Actors: %zu", tracker.GetActorCount());
        
        // Clear tracking button
        if (ImGui::Button("Clear Tracking")) {
            tracker.Clear();
            LogInfo("ActorTracker: Cleared all tracked actors");
        }
        ImGui::SameLine();
        
        // Manual player ID input
        static char playerIdInput[16] = "0x00200001";
        ImGui::SetNextItemWidth(100);
        ImGui::InputText("##playerid", playerIdInput, sizeof(playerIdInput));
        ImGui::SameLine();
        if (ImGui::Button("Set Player ID")) {
            uint32_t newPlayerId = 0;
            if (playerIdInput[0] == '0' && (playerIdInput[1] == 'x' || playerIdInput[1] == 'X')) {
                newPlayerId = static_cast<uint32_t>(std::strtoul(playerIdInput, nullptr, 16));
            } else {
                newPlayerId = static_cast<uint32_t>(std::strtoul(playerIdInput, nullptr, 10));
            }
            if (newPlayerId != 0) {
                tracker.SetLocalPlayerId(newPlayerId);
                LogInfo(std::format("ActorTracker: Set local player ID to 0x{:X}", newPlayerId));
            }
        }
        
        ImGui::Text("Current Player ID: 0x%X", tracker.GetLocalPlayerId());

        // Manual position input for testing - default to typical player position
        static float testPos[3] = { -180.0f, 5.0f, 45.0f };
        static bool initializedPos = false;
        
        // If we have a player with real position, use that as default
        if (!initializedPos) {
            auto player = tracker.GetLocalPlayer();
            if (player && (std::abs(player->position.x) > 0.1f || 
                          std::abs(player->position.y) > 0.1f || 
                          std::abs(player->position.z) > 0.1f)) {
                testPos[0] = player->position.x;
                testPos[1] = player->position.y;
                testPos[2] = player->position.z;
            }
            initializedPos = true;
        }
        
        ImGui::Spacing();
        ImGui::Text("Manual Test Position:");
        ImGui::InputFloat3("##testpos", testPos);
        if (ImGui::Button("Set Test Position")) {
            // Update existing player position or create test player
            auto existingPlayer = tracker.GetLocalPlayer();
            if (existingPlayer && existingPlayer->actorId != 0xDEADBEEF) {
                // Update the real player's position
                tracker.OnActorMove(existingPlayer->actorId, 
                                   testPos[0], testPos[1], testPos[2], 0.0f);
                LogInfo(std::format("Updated player 0x{:X} to ({:.2f}, {:.2f}, {:.2f})", 
                        existingPlayer->actorId, testPos[0], testPos[1], testPos[2]));
            } else {
                // Create test player only if no real player exists
                uint32_t testActorId = 0xDEADBEEF;
                tracker.SetLocalPlayerId(testActorId);
                tracker.OnPlayerSpawn(testActorId, "TestPlayer", 
                                      testPos[0], testPos[1], testPos[2], 0.0f,
                                      1, 1, 1000, 1000);
                LogInfo(std::format("Created test player at ({:.2f}, {:.2f}, {:.2f})", 
                        testPos[0], testPos[1], testPos[2]));
            }
        }

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), 
                          "Note: Engine coords differ from minimap UI coords.\n"
                          "Test primitives are drawn around the tracked position.");
    }

    void DebugVisualsModule::RenderPrimitiveList() {
        auto& renderer = DebugRenderer::GetInstance();

        size_t count = renderer.GetPrimitiveCount();
        ImGui::Text("Total Primitives: %zu", count);

        if (count == 0) {
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "No primitives currently active.");
            return;
        }

        ImGui::Separator();

        // TODO: Add detailed primitive list with IDs, types, and remaining lifetime
        ImGui::TextWrapped("Detailed primitive list coming soon...");
    }

    void DebugVisualsModule::DrawTestPrimitives() {
        auto& renderer = DebugRenderer::GetInstance();
        if (!renderer.IsInitialized()) {
            return;
        }

        // Get player position from GameCameraExtractor (confirmed: lookAt at 0xE0 is player position)
        // We've abandoned ActorTracker (packet-based) in favor of direct memory reading
        float px = 0.0f, py = 0.0f, pz = 0.0f;
        
        auto& cameraExtractor = GameCameraExtractor::GetInstance();
        if (cameraExtractor.IsInitialized()) {
            cameraExtractor.Update();  // Force update to get current position
            if (cameraExtractor.IsReady()) {
                const auto& cam = cameraExtractor.GetCachedCamera();
                if (cam.valid) {
                    // Use lookAt (0xE0) which is the player/target position
                    // Confirmed via memory dumps: 0xE0 stays constant when camera rotates
                    // while 0x100 (camera position) changes
                    px = cam.lookAt.x;
                    py = cam.lookAt.y;
                    pz = cam.lookAt.z;
                }
            }
        }

        // If we still don't have a position, don't draw - would be at origin which is wrong
        if (std::abs(px) < 0.1f && std::abs(py) < 0.1f && std::abs(pz) < 0.1f) {
            return;  // Skip drawing until we have a valid position
        }

        // Draw a grid on the ground around the player
        Color gridColor = { 0.3f, 0.3f, 0.3f, 0.5f };
        for (int i = -5; i <= 5; ++i) {
            renderer.DrawLine({ px + static_cast<float>(i), py, pz - 5 }, 
                             { px + static_cast<float>(i), py, pz + 5 }, gridColor);
            renderer.DrawLine({ px - 5, py, pz + static_cast<float>(i) }, 
                             { px + 5, py, pz + static_cast<float>(i) }, gridColor);
        }

        // Draw coordinate axes at player position
        renderer.DrawArrow({ px, py, pz }, { px + 2, py, pz }, Color::Red(), 2.0f, 0.2f);    // X axis
        renderer.DrawArrow({ px, py, pz }, { px, py + 2, pz }, Color::Green(), 2.0f, 0.2f);  // Y axis
        renderer.DrawArrow({ px, py, pz }, { px, py, pz + 2 }, Color::Blue(), 2.0f, 0.2f);   // Z axis

        // Draw some test shapes around the player
        renderer.DrawSphere({ px + 3, py + 1, pz }, 0.5f, Color::Cyan(), false, 16);
        renderer.DrawBox({ px - 3, py + 0.5f, pz }, { 0.5f, 0.5f, 0.5f }, Color::Magenta());
        renderer.DrawCircle({ px, py + 0.05f, pz + 3 }, 1.0f, Color::Yellow(), 32, true);
        renderer.DrawCylinder({ px, py, pz - 3 }, 0.5f, 1.5f, Color::Orange(), 16);

        // Draw text labels
        renderer.DrawText3D({ px + 2.5f, py, pz }, "X", Color::Red());
        renderer.DrawText3D({ px, py + 2.5f, pz }, "Y", Color::Green());
        renderer.DrawText3D({ px, py, pz + 2.5f }, "Z", Color::Blue());
        renderer.DrawText3D({ px, py + 3, pz }, "Player", Color::White());

        // Draw a ring around player (like a targeting indicator)
        renderer.DrawCircle({ px, py + 0.1f, pz }, 1.5f, Color::Green(), 32, false);
    }

    void DebugVisualsModule::ClearAllVisuals() {
        auto& renderer = DebugRenderer::GetInstance();
        renderer.ClearAllPrimitives();
        LogInfo("DebugVisualsModule: Cleared all primitives");
    }

    void DebugVisualsModule::SendTestPacket() {
        // Send a test UDP packet to ourselves to verify the server is receiving
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            LogError("SendTestPacket: Failed to create socket");
            return;
        }

        sockaddr_in destAddr{};
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(m_serverPort);
        inet_pton(AF_INET, "127.0.0.1", &destAddr.sin_addr);

        // Create a test line packet
        struct TestPacket {
            DebugVisualPacketHeader header;
            DebugLine line;
        } packet{};

        packet.header.magic = DEBUG_VISUAL_MAGIC;
        packet.header.version = PROTOCOL_VERSION;
        packet.header.primitiveType = static_cast<uint8_t>(PrimitiveType::Line);
        packet.header.id = 9999;  // Test ID
        packet.header.lifetime = 5.0f;  // 5 seconds
        packet.header.dataSize = sizeof(DebugLine);

        // Bright magenta line from origin upward - should be very visible
        packet.line.start = { 0.0f, 0.0f, 0.0f };
        packet.line.end = { 0.0f, 10.0f, 0.0f };
        packet.line.color = { 1.0f, 0.0f, 1.0f, 1.0f };  // Magenta
        packet.line.thickness = 5.0f;

        int bytesSent = sendto(sock, reinterpret_cast<const char*>(&packet), sizeof(packet), 0,
                               reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr));

        closesocket(sock);

        if (bytesSent == SOCKET_ERROR) {
            LogError(std::format("SendTestPacket: sendto failed with error {}", WSAGetLastError()));
        } else {
            LogInfo(std::format("SendTestPacket: Sent {} bytes to port {}", bytesSent, m_serverPort));
        }
    }

    // ============================================
    // Fixed Position Marker System
    // ============================================
    
    void DebugVisualsModule::RenderMarkerSection() {
        auto& cameraExtractor = GameCameraExtractor::GetInstance();
        
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Position Markers");
        ImGui::Separator();
        
        // Show current player position
        DirectX::XMFLOAT3 playerPos = {0, 0, 0};
        bool hasPosition = false;
        
        if (cameraExtractor.IsInitialized() && cameraExtractor.Update()) {
            const auto& cam = cameraExtractor.GetCachedCamera();
            if (cam.valid) {
                // cam.lookAt = player world position (from 0x100)
                // cam.position = computed camera eye (from player + distance + angles)
                playerPos = cam.lookAt;
                hasPosition = true;
            }
        }
        
        if (hasPosition) {
            ImGui::Text("Player Position: (%.1f, %.1f, %.1f)", playerPos.x, playerPos.y, playerPos.z);
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Player position not available");
        }
        
        ImGui::Spacing();
        
        // Mark position button
        if (hasPosition) {
            if (ImGui::Button("Mark Current Position", ImVec2(200, 30))) {
                MarkCurrentPosition();
            }
            ImGui::SetItemTooltip("Place a circle marker at your current position");
        } else {
            ImGui::BeginDisabled();
            ImGui::Button("Mark Current Position", ImVec2(200, 30));
            ImGui::EndDisabled();
        }
        
        ImGui::SameLine();
        if (ImGui::Button("Clear All Markers")) {
            ClearMarkers();
        }
        
        ImGui::Spacing();
        ImGui::Checkbox("Show Markers", &m_showMarkers);
        ImGui::SliderFloat("Base Radius", &m_markerBaseRadius, 0.5f, 5.0f, "%.1f units");
        ImGui::SliderFloat("Height Offset", &m_markerHeightOffset, -3.0f, 3.0f, "%.1f");
        ImGui::SetItemTooltip("Vertical offset for marker placement (negative = down, positive = up)");
        
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Active Markers: %zu", m_markers.size());
        ImGui::Separator();
        
        // List markers with distance from player
        for (size_t i = 0; i < m_markers.size(); ++i) {
            const auto& marker = m_markers[i];
            ImGui::PushID(static_cast<int>(i));
            
            // Calculate distance from player to marker
            float distance = 0.0f;
            if (hasPosition) {
                float dx = marker.position.x - playerPos.x;
                float dy = marker.position.y - playerPos.y;
                float dz = marker.position.z - playerPos.z;
                distance = std::sqrt(dx*dx + dy*dy + dz*dz);
            }
            
            ImGui::Text("[%zu] (%.1f, %.1f, %.1f) - %.1fm away", i, 
                marker.position.x, marker.position.y, marker.position.z, distance);
            ImGui::SameLine();
            if (ImGui::SmallButton("X")) {
                m_markers.erase(m_markers.begin() + i);
                ImGui::PopID();
                break;
            }
            
            ImGui::PopID();
        }
    }
    
    void DebugVisualsModule::MarkCurrentPosition() {
        auto& cameraExtractor = GameCameraExtractor::GetInstance();
        
        if (!cameraExtractor.IsInitialized()) {
            return;
        }
        
        cameraExtractor.Update();
        const auto& cam = cameraExtractor.GetCachedCamera();
        
        if (!cam.valid) {
            return;
        }
        
        // cam.lookAt = player world position (from 0x100: X=185.1, Y=14.1, Z=665.7)
        // Place marker at current player location
        // This marker will STAY at this world position forever
        WorldMarker marker;
        marker.position = cam.lookAt;  // Fixed world coordinates
        marker.position.y += m_markerHeightOffset;  // Apply height offset to place on ground
        marker.radius = m_markerBaseRadius;
        marker.color = IM_COL32(0, 255, 0, 200);  // Green with transparency
        marker.active = true;
        
        m_markers.push_back(marker);
        
        LogInfo(std::format("[Markers] Placed WORLD-SPACE marker at ({:.1f}, {:.1f}, {:.1f}) - stays anchored to this location",
            marker.position.x, marker.position.y, marker.position.z));
    }
    
    void DebugVisualsModule::ClearMarkers() {
        m_markers.clear();
        LogInfo("[Markers] Cleared all markers");
    }
    
    // WorldToScreen removed - DirectX DebugRenderer handles world-to-screen projection automatically
    
    void DebugVisualsModule::RenderMarkers() {
        if (!m_showMarkers || m_markers.empty()) {
            return;
        }
        
        // Use DirectX DebugRenderer for true world-space rendering
        // This renders the markers as 3D circles in the game world,
        // similar to how the blue arena lines and cardinal directions are rendered
        auto& renderer = DebugRenderer::GetInstance();
        if (!renderer.IsInitialized() || !renderer.IsEnabled()) {
            return;
        }
        
        // Render each marker as a 3D circle flat on the ground
        for (size_t i = 0; i < m_markers.size(); ++i) {
            const auto& marker = m_markers[i];
            if (!marker.active) {
                continue;
            }
            
            // Convert XMFLOAT3 to Vec3 for DebugRenderer
            DebugVisuals::Vec3 worldPos(marker.position.x, marker.position.y, marker.position.z);
            
            // Convert ABGR color to RGBA (0, 255, 0, 200) = green with alpha
            uint32_t abgr = marker.color;
            uint8_t a = (abgr >> 24) & 0xFF;
            uint8_t b = (abgr >> 16) & 0xFF;
            uint8_t g = (abgr >> 8) & 0xFF;
            uint8_t r = (abgr >> 0) & 0xFF;
            
            // Create color (DebugRenderer uses RGBA floats 0.0-1.0)
            DebugVisuals::Color markerColor(
                r / 255.0f,
                g / 255.0f,
                b / 255.0f,
                a / 255.0f
            );
            
            // Draw a single filled circle with outline
            DebugVisuals::Color outlineColor(r / 255.0f, g / 255.0f, b / 255.0f, 1.0f);
            
            // Filled circle
            renderer.DrawCircle(
                worldPos,
                marker.radius,
                markerColor,
                32,
                true
            );
            
            // Outline for visibility
            renderer.DrawCircle(
                worldPos,
                marker.radius,
                outlineColor,
                32,
                false
            );
        }
    }

} // namespace SapphireHook
