#include "../UI/imgui_overlay.h"
#include "../Logger/Logger.h"     
#include <d3d11.h>
#include <dxgi.h>
#include <Windows.h>
#include <cstdio>
#include <iostream>
#include <sstream>      
#include <iomanip>
#include <format>
#include <cmath>
#include <algorithm>  // for std::clamp
#include "../vendor/imgui/imgui.h"
#include "../../vendor/imgui/backends/imgui_impl_dx11.h"
#include "../../vendor/imgui/backends/imgui_impl_win32.h"
#include <MinHook.h>
#include "../UI/UIManager.h"
// NEW: ImPlot for charts
#include "../../vendor/implot/implot.h"
// NEW: Debug renderer for 3D visuals
#include "../Tools/DebugRenderer.h"
// NEW: Camera extractor for auto-detecting game camera matrices
#include "../Tools/GameCameraExtractor.h"
// NEW: D3D11 Matrix Capture for hooking constant buffer updates
#include "../Tools/D3D11MatrixCapture.h"
// NEW: ViewProjectionHook for capturing matrix from game's W2S function
#include "../Tools/ViewProjectionHook.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

typedef HRESULT(__stdcall* Present_t)(IDXGISwapChain*, UINT, UINT);
typedef HRESULT(__stdcall* ResizeBuffers_t)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);

// UpdateSubresource hook for capturing constant buffer updates
typedef void(__stdcall* UpdateSubresource_t)(ID3D11DeviceContext*, ID3D11Resource*, UINT, const D3D11_BOX*, const void*, UINT, UINT);
UpdateSubresource_t oUpdateSubresource = nullptr;

// VSSetConstantBuffers hook for capturing constant buffers when bound to pipeline
typedef void(__stdcall* VSSetConstantBuffers_t)(ID3D11DeviceContext*, UINT, UINT, ID3D11Buffer* const*);
VSSetConstantBuffers_t oVSSetConstantBuffers = nullptr;

Present_t oPresent = nullptr;
ResizeBuffers_t oResizeBuffers = nullptr;

HWND g_hWnd = nullptr;
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static bool g_isMinimized = false;
static bool g_deviceLost = false;
static bool g_renderTargetValid = false;
static bool g_overlayInitialized = false;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void CreateRenderTarget(IDXGISwapChain* pSwapChain)
{
    using namespace SapphireHook;
    
    if (g_mainRenderTargetView)
    {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }

    ID3D11Texture2D* pBackBuffer = nullptr;
    HRESULT hr = pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
    if (SUCCEEDED(hr) && pBackBuffer)
    {
        hr = g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
        
        if (SUCCEEDED(hr))
        {
            g_renderTargetValid = true;
            LogDebug("Render target created successfully");
        }
        else
        {
            LogError("Failed to create render target view: 0x" + std::to_string(hr));
            g_renderTargetValid = false;
        }
    }
    else
    {
        LogError("Failed to get back buffer: 0x" + std::to_string(hr));
        g_renderTargetValid = false;
    }
}

void CleanupRenderTarget()
{
    using namespace SapphireHook;
    
    if (g_mainRenderTargetView)
    {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
        LogDebug("Render target cleaned up");
    }
    g_renderTargetValid = false;
}

// Hook for ID3D11DeviceContext::UpdateSubresource to capture constant buffer updates
void __stdcall hkUpdateSubresource(ID3D11DeviceContext* context, ID3D11Resource* dstResource, 
                                    UINT dstSubresource, const D3D11_BOX* dstBox, 
                                    const void* srcData, UINT srcRowPitch, UINT srcDepthPitch)
{
    // Wrap matrix capture in SEH to prevent crashes
    __try {
        SapphireHook::DebugVisuals::D3D11MatrixCapture::GetInstance().OnUpdateSubresource(
            dstResource, dstSubresource, dstBox, srcData, srcRowPitch, srcDepthPitch);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Silently ignore exceptions in matrix capture
    }
    
    // Call original
    oUpdateSubresource(context, dstResource, dstSubresource, dstBox, srcData, srcRowPitch, srcDepthPitch);
}

// Hook for ID3D11DeviceContext::VSSetConstantBuffers to capture when camera CB is bound
void __stdcall hkVSSetConstantBuffers(ID3D11DeviceContext* context, UINT startSlot, 
                                       UINT numBuffers, ID3D11Buffer* const* buffers)
{
    // Forward to matrix capture for analysis (reads buffer contents when bound)
    SapphireHook::DebugVisuals::D3D11MatrixCapture::GetInstance().OnVSSetConstantBuffers(
        startSlot, numBuffers, buffers, context);
    
    // Call original
    oVSSetConstantBuffers(context, startSlot, numBuffers, buffers);
}

HRESULT __stdcall hkResizeBuffers(IDXGISwapChain* pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags)
{
    using namespace SapphireHook;
    
    LogDebug("ResizeBuffers called: " + std::to_string(Width) + "x" + std::to_string(Height));
    
    CleanupRenderTarget();
    
    HRESULT hr = oResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
    
    if (SUCCEEDED(hr) && !g_isMinimized && g_overlayInitialized)
    {
        CreateRenderTarget(pSwapChain);
    }
    
    return hr;
}

WNDPROC oWndProc = nullptr;
LRESULT __stdcall WndProc(const HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    using namespace SapphireHook;
    
    if (uMsg == WM_KEYDOWN && wParam == VK_INSERT)
    {
        if (UIManager::HasInstance())
        {
            UIManager::GetInstance().ToggleMenu();
        }
        return TRUE;
    }

    switch (uMsg)
    {
    case WM_SIZE:
        {
            UINT newWidth = LOWORD(lParam);
            UINT newHeight = HIWORD(lParam);
            
            switch (wParam)
            {
            case SIZE_MINIMIZED:
                LogInfo("Window minimized - pausing overlay rendering");
                g_isMinimized = true;
                CleanupRenderTarget();
                return 0;
                
            case SIZE_RESTORED:
                if (g_isMinimized)
                {
                    LogInfo("Window restored from minimized state");
                    g_isMinimized = false;
                }
                break;
                
            case SIZE_MAXIMIZED:
                LogInfo("Window maximized");
                g_isMinimized = false;
                break;
            }
            
            if (!g_isMinimized && newWidth > 0 && newHeight > 0)
            {
                LogDebug("Window resized to: " + std::to_string(newWidth) + "x" + std::to_string(newHeight));
            }
        }
        break;

    case WM_ACTIVATE:
        switch (LOWORD(wParam))
        {
        case WA_INACTIVE:
            LogDebug("Window deactivated");
            break;
        case WA_ACTIVE:
        case WA_CLICKACTIVE:
            LogDebug("Window activated");
            g_isMinimized = false;        
            break;
        }
        break;

    case WM_DISPLAYCHANGE:
        LogInfo("Display change detected - may need to recreate resources");
        g_deviceLost = true;
        break;

    case WM_DESTROY:
    case WM_CLOSE:
        LogInfo("Window closing - cleaning up overlay resources");
        CleanupRenderTarget();
        break;

    case WM_POWERBROADCAST:
        if (wParam == PBT_APMRESUMESUSPEND)
        {
            LogInfo("System resumed from sleep - marking device as potentially lost");
            g_deviceLost = true;
        }
        break;
    }

    if (UIManager::HasInstance() && UIManager::GetInstance().IsMenuVisible() && !g_isMinimized)
    {
        LRESULT imgui_result = ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam);

        ImGuiIO& io = ImGui::GetIO();

        if (imgui_result ||
            ((uMsg >= WM_MOUSEFIRST && uMsg <= WM_MOUSELAST) && io.WantCaptureMouse) ||
            ((uMsg >= WM_KEYFIRST && uMsg <= WM_KEYLAST) && io.WantCaptureKeyboard))
        {
            return imgui_result ? imgui_result : TRUE;
        }
    }

    return CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam);
}

HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
    using namespace SapphireHook;
    
    if (g_isMinimized)
    {
        return oPresent(pSwapChain, SyncInterval, Flags);
    }

    if (!g_overlayInitialized)
    {
        if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&g_pd3dDevice)))
        {
            g_pd3dDevice->GetImmediateContext(&g_pd3dDeviceContext);
            DXGI_SWAP_CHAIN_DESC sd;
            pSwapChain->GetDesc(&sd);
            g_hWnd = sd.OutputWindow;

            CreateRenderTarget(pSwapChain);

            ImGui::CreateContext();
            // Create ImPlot context to support plotting modules
            ImPlot::CreateContext();
            ImGuiIO& io = ImGui::GetIO();
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
            io.MouseDrawCursor = false;

            ImGui::StyleColorsDark();

            ImGui_ImplWin32_Init(g_hWnd);
            ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

            oWndProc = (WNDPROC)SetWindowLongPtr(g_hWnd, GWLP_WNDPROC, (LONG_PTR)WndProc);

            // Check if UIManager singleton exists and verify it has modules
            if (UIManager::HasInstance())
            {
                UIManager& uiManager = UIManager::GetInstance();
                LogInfo("Overlay found existing UIManager singleton at: " + 
                       std::to_string(reinterpret_cast<uintptr_t>(&uiManager)));
                LogInfo("This instance has " + std::to_string(uiManager.GetModuleCount()) + " modules");
                
                if (uiManager.GetModuleCount() == 0)
                {
                    LogError("WARNING: UIManager singleton has 0 modules! This indicates a problem.");
                }
            }
            else
            {
                LogError("ERROR: No UIManager singleton exists when overlay initializes!");
                LogError("This should not happen! Modules should be registered before overlay init.");
            }

            // Initialize Debug Renderer for 3D visuals
            auto& debugRenderer = SapphireHook::DebugVisuals::DebugRenderer::GetInstance();
            if (debugRenderer.Initialize(g_pd3dDevice, g_pd3dDeviceContext))
            {
                LogInfo("Debug Renderer initialized successfully");
                
                // Set initial screen size from swap chain desc
                debugRenderer.SetScreenSize(static_cast<float>(sd.BufferDesc.Width), 
                                            static_cast<float>(sd.BufferDesc.Height));
            }
            else
            {
                LogWarning("Debug Renderer failed to initialize - 3D debug visuals will not be available");
            }

            // Initialize Game Camera Extractor for auto-detecting camera matrices
            auto& cameraExtractor = SapphireHook::DebugVisuals::GameCameraExtractor::GetInstance();
            if (cameraExtractor.Initialize())
            {
                LogInfo(std::string("Game Camera Extractor initialized - status: ") + 
                        ToString(cameraExtractor.GetStatus()));
            }
            else
            {
                LogWarning("Game Camera Extractor failed to initialize - using manual camera mode");
            }

            g_overlayInitialized = true;
            LogInfo("Overlay initialized successfully");
        }
        else
        {
            LogError("Failed to get D3D11 device from swap chain");
            return oPresent(pSwapChain, SyncInterval, Flags);
        }
    }

    if (g_deviceLost)
    {
        LogInfo("Attempting to recover from device lost state");
        
        HRESULT deviceState = g_pd3dDevice->GetDeviceRemovedReason();
        if (deviceState == S_OK)
        {
            CreateRenderTarget(pSwapChain);
            g_deviceLost = false;
            LogInfo("Device recovered successfully");
        }
        else
        {
            LogError("Device is actually lost: 0x" + std::to_string(deviceState));
            return oPresent(pSwapChain, SyncInterval, Flags);
        }
    }

    if (!g_renderTargetValid || !g_mainRenderTargetView)
    {
        CreateRenderTarget(pSwapChain);
        if (!g_renderTargetValid)
        {
            return oPresent(pSwapChain, SyncInterval, Flags);
        }
    }

    // Always update camera extractor for player position (used in menu bar)
    auto& cameraExtractor = SapphireHook::DebugVisuals::GameCameraExtractor::GetInstance();
    if (cameraExtractor.IsInitialized())
    {
        cameraExtractor.Update();  // Updates m_cachedPlayerPosition
    }

    // Render 3D debug visuals BEFORE ImGui (so they appear in world space)
    auto& debugRenderer = SapphireHook::DebugVisuals::DebugRenderer::GetInstance();
    if (debugRenderer.IsInitialized() && debugRenderer.IsEnabled())
    {
        // Update screen size in case of resize
        DXGI_SWAP_CHAIN_DESC scDesc;
        if (SUCCEEDED(pSwapChain->GetDesc(&scDesc)))
        {
            debugRenderer.SetScreenSize(static_cast<float>(scDesc.BufferDesc.Width),
                                         static_cast<float>(scDesc.BufferDesc.Height));
        }

        // Update camera matrices - try multiple sources in priority order
        // 1. D3D11MatrixCapture (directly captured from GPU)
        // 2. GameCameraExtractor (reading game memory)
        // 3. Fallback (origin)
        
        auto& matrixCapture = SapphireHook::DebugVisuals::D3D11MatrixCapture::GetInstance();
        // cameraExtractor already updated above
        bool cameraValid = false;
        DirectX::XMFLOAT3 cameraPosition = {0.0f, 0.0f, 0.0f};
        
        // Method 1: Try pre-computed ViewProjection from game camera
        // UPDATED: Now probes FFXIVClientStructs offsets (0xA0, 0xE0->0x10/0x1A0) in addition to 3.35 offsets
        // Set to FALSE to enable probing; will fallback to constructed matrices if probing fails
        bool skipGameMatrices = false;  // Try game matrices first (with new FFXIVClientStructs offsets)
        
        // Get camera position from already-updated extractor
        if (cameraExtractor.IsInitialized())
        {
            const auto& camera = cameraExtractor.GetCachedCamera();
            if (camera.valid)
            {
                cameraPosition = camera.position;
            }
        }
        
        if (!skipGameMatrices && cameraExtractor.IsInitialized())
        {
            const auto& camera = cameraExtractor.GetCachedCamera();
            if (camera.valid)
            {
                // Give D3D11MatrixCapture our known camera position for validation
                matrixCapture.SetKnownCameraPosition(cameraPosition);
                
                // Try the pre-computed ViewProjection matrix first
                // This uses probed offsets from FFXIVClientStructs (0xA0, 0xE0->0x10/0x1A0)
                DirectX::XMMATRIX viewProj;
                if (cameraExtractor.GetViewProjectionMatrix(viewProj)) 
                {
                    debugRenderer.SetViewProjectionDirect(viewProj);
                    cameraValid = true;
                    
                    static bool loggedViewProj = false;
                    if (!loggedViewProj) {
                        SapphireHook::LogInfo(std::format("Debug Renderer: Using game ViewProjection (cached/built), camera at ({:.1f}, {:.1f}, {:.1f})",
                            cameraPosition.x, cameraPosition.y, cameraPosition.z));
                        loggedViewProj = true;
                    }
                }
                else
                {
                    // Fallback: try probed best matrices (View + Projection separately)
                    DirectX::XMMATRIX bestView, bestProj;
                    if (cameraExtractor.GetBestMatrices(bestView, bestProj)) 
                    {
                        debugRenderer.SetViewProjection(bestView, bestProj);
                        cameraValid = true;
                        
                        static bool loggedBestMatrices = false;
                        if (!loggedBestMatrices) {
                            SapphireHook::LogInfo(std::format("Debug Renderer: Using probed best matrices (fallback), camera at ({:.1f}, {:.1f}, {:.1f})",
                                cameraPosition.x, cameraPosition.y, cameraPosition.z));
                            loggedBestMatrices = true;
                        }
                    }
                    else
                    {
                        // Last resort: raw matrices from standard offsets (0x40, 0x80)
                        DirectX::XMFLOAT4X4 projFloat;
                        DirectX::XMStoreFloat4x4(&projFloat, camera.projection);
                        bool hasValidMatrices = (projFloat._11 != 0.0f && projFloat._11 != 1.0f);
                        
                        if (hasValidMatrices) {
                            debugRenderer.SetViewProjection(camera.view, camera.projection);
                            cameraValid = true;
                            
                            static bool loggedRaw = false;
                            if (!loggedRaw) {
                                SapphireHook::LogInfo(std::format("Debug Renderer: Using raw View+Proj matrices (last resort), camera at ({:.1f}, {:.1f}, {:.1f})",
                                    cameraPosition.x, cameraPosition.y, cameraPosition.z));
                                loggedRaw = true;
                            }
                        }
                    }
                }
            }
        }
        
        // Method 2: Try D3D11 matrix capture (fallback, or upgrade if we have matching camera)
        if (!cameraValid && matrixCapture.HasValidMatrices())
        {
            DirectX::XMMATRIX viewProj = matrixCapture.GetViewProjectionMatrix();
            DirectX::XMMATRIX view = matrixCapture.GetViewMatrix();
            DirectX::XMMATRIX proj = matrixCapture.GetProjectionMatrix();
            
            // Validate the captured matrices
            DirectX::XMFLOAT4X4 vpFloat;
            DirectX::XMStoreFloat4x4(&vpFloat, viewProj);
            bool hasValidVP = (vpFloat._11 != 0.0f && vpFloat._11 != 1.0f &&
                              !std::isnan(vpFloat._11) && !std::isinf(vpFloat._11));
            
            // Check if we have a valid camera position from D3D11
            DirectX::XMFLOAT3 d3dCamPos = matrixCapture.GetCameraPosition();
            bool hasValidCamPos = (std::abs(d3dCamPos.x) > 0.1f || std::abs(d3dCamPos.y) > 0.1f || std::abs(d3dCamPos.z) > 0.1f);
            
            // Also check if D3D11 camera matches our known camera position (if we have one)
            bool matchesKnownCamera = false;
            if (hasValidCamPos && (std::abs(cameraPosition.x) > 0.1f || std::abs(cameraPosition.y) > 0.1f || std::abs(cameraPosition.z) > 0.1f))
            {
                float dx = d3dCamPos.x - cameraPosition.x;
                float dy = d3dCamPos.y - cameraPosition.y;
                float dz = d3dCamPos.z - cameraPosition.z;
                float dist = std::sqrt(dx*dx + dy*dy + dz*dz);
                matchesKnownCamera = (dist < 15.0f);  // Within 15 units
            }
            
            if (hasValidVP && (hasValidCamPos || matchesKnownCamera)) {
                debugRenderer.SetViewProjection(view, proj);
                if (hasValidCamPos) {
                    cameraPosition = d3dCamPos;
                }
                cameraValid = true;
                
                static bool loggedCapture = false;
                if (!loggedCapture) {
                    SapphireHook::LogInfo(std::format("Debug Renderer: Using D3D11 captured matrices, camera at ({:.1f}, {:.1f}, {:.1f}), matches={}",
                        d3dCamPos.x, d3dCamPos.y, d3dCamPos.z, matchesKnownCamera ? "yes" : "no"));
                    loggedCapture = true;
                }
            }
        }

        // Method 3 & 4: Construct from position or use fallback
        if (!cameraValid)
        {
            static bool loggedOnce = false;
            
            // Get camera position and look-at target from extraction
            float camX = cameraPosition.x;
            float camY = cameraPosition.y;
            float camZ = cameraPosition.z;
            
            // Get look-at target (player position) from camera extractor
            // This is the point the camera is looking at (0xE0)
            float playerX = 0.0f, playerY = 0.0f, playerZ = 0.0f;
            const auto& cachedCam = cameraExtractor.GetCachedCamera();
            if (cachedCam.valid) {
                playerX = cachedCam.lookAt.x;
                playerY = cachedCam.lookAt.y;
                playerZ = cachedCam.lookAt.z;
            }
            
            bool hasCameraPosition = (std::abs(camX) > 0.1f || std::abs(camY) > 0.1f || std::abs(camZ) > 0.1f);
            bool hasPlayerPosition = (std::abs(playerX) > 0.1f || std::abs(playerY) > 0.1f || std::abs(playerZ) > 0.1f);
            
            if (!loggedOnce) {
                if (hasCameraPosition) {
                    SapphireHook::LogInfo(std::format("Debug Renderer: Camera at ({:.1f}, {:.1f}, {:.1f}), Player at ({:.1f}, {:.1f}, {:.1f})", 
                        camX, camY, camZ, playerX, playerY, playerZ));
                } else {
                    SapphireHook::LogInfo("Debug Renderer: Using fallback camera at origin");
                }
                loggedOnce = true;
            }

            // Construct view matrix
            // IMPORTANT: We use the camera-to-player direction for orientation,
            // but cache the normalized direction to reduce wobble from camera lag
            DirectX::XMMATRIX view;
            
            // Static cache for direction smoothing
            static DirectX::XMFLOAT3 cachedForward = {0.0f, 0.0f, 1.0f};
            static DirectX::XMFLOAT3 lastCameraPos = {0.0f, 0.0f, 0.0f};
            static DirectX::XMFLOAT3 lastPlayerPos = {0.0f, 0.0f, 0.0f};
            static bool dirInitialized = false;
            
            if (hasCameraPosition && hasPlayerPosition) {
                // Compute current direction from camera to player
                float dirX = playerX - camX;
                float dirY = (playerY + 1.0f) - camY;  // Aim at player center
                float dirZ = playerZ - camZ;
                float length = std::sqrt(dirX*dirX + dirY*dirY + dirZ*dirZ);
                
                if (length > 0.1f) {
                    dirX /= length;
                    dirY /= length;
                    dirZ /= length;
                    
                    if (!dirInitialized) {
                        // First time - use current direction
                        cachedForward = {dirX, dirY, dirZ};
                        dirInitialized = true;
                    } else {
                        // Check if camera has rotated significantly (vs just player moved)
                        // We consider it a rotation if the angle between old and new forward > 2 degrees
                        float dot = cachedForward.x * dirX + cachedForward.y * dirY + cachedForward.z * dirZ;
                        dot = std::clamp(dot, -1.0f, 1.0f);
                        float angleDeg = std::acos(dot) * 180.0f / 3.14159265f;
                        
                        // Only update cached direction if angle changed significantly (likely rotation)
                        // Small angle changes are likely camera lag/smoothing, ignore those
                        if (angleDeg > 2.0f) {
                            // Smoothly interpolate toward new direction
                            float t = (std::min)(angleDeg / 30.0f, 1.0f);  // More aggressive for larger angles
                            cachedForward.x = cachedForward.x * (1.0f - t) + dirX * t;
                            cachedForward.y = cachedForward.y * (1.0f - t) + dirY * t;
                            cachedForward.z = cachedForward.z * (1.0f - t) + dirZ * t;
                            
                            // Re-normalize
                            float len = std::sqrt(cachedForward.x*cachedForward.x + 
                                                  cachedForward.y*cachedForward.y + 
                                                  cachedForward.z*cachedForward.z);
                            if (len > 0.001f) {
                                cachedForward.x /= len;
                                cachedForward.y /= len;
                                cachedForward.z /= len;
                            }
                        }
                    }
                }
                
                // Build view matrix using cached direction
                DirectX::XMVECTOR eye = DirectX::XMVectorSet(camX, camY, camZ, 1.0f);
                DirectX::XMVECTOR target = DirectX::XMVectorSet(
                    camX + cachedForward.x * 10.0f,
                    camY + cachedForward.y * 10.0f,
                    camZ + cachedForward.z * 10.0f,
                    1.0f
                );
                view = DirectX::XMMatrixLookAtLH(eye, target, DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f));
                
                lastCameraPos = {camX, camY, camZ};
                lastPlayerPos = {playerX, playerY, playerZ};
            } else if (hasPlayerPosition) {
                // Only player position - put camera behind and above player
                DirectX::XMVECTOR eye = DirectX::XMVectorSet(playerX, playerY + 8.0f, playerZ - 10.0f, 1.0f);
                DirectX::XMVECTOR target = DirectX::XMVectorSet(playerX, playerY + 1.0f, playerZ, 1.0f);
                view = DirectX::XMMatrixLookAtLH(eye, target, DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f));
            } else if (hasCameraPosition) {
                // Only camera position - look forward (this won't match game camera rotation)
                // Use a fixed forward direction - primitives will be in world space but camera angle won't match
                DirectX::XMVECTOR eye = DirectX::XMVectorSet(camX, camY, camZ, 1.0f);
                // Look toward origin-ish direction from camera
                DirectX::XMVECTOR target = DirectX::XMVectorSet(0.0f, 0.0f, 0.0f, 1.0f);
                view = DirectX::XMMatrixLookAtLH(eye, target, DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f));
            } else {
                // Fallback: look at origin from behind
                view = DirectX::XMMatrixLookAtLH(
                    DirectX::XMVectorSet(0.0f, 10.0f, -20.0f, 1.0f),
                    DirectX::XMVectorSet(0.0f, 0.0f, 0.0f, 1.0f),
                    DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f)
                );
            }

            float screenWidth = debugRenderer.GetScreenWidth();
            float screenHeight = debugRenderer.GetScreenHeight();
            float aspectRatio = (screenHeight > 0) ? (screenWidth / screenHeight) : (16.0f / 9.0f);

            // Use perspective projection to match game's rendering
            // Try to use actual FOV from game camera, fallback to 45 degrees
            float fovRadians = DirectX::XMConvertToRadians(45.0f);  // Default
            if (cachedCam.valid && cachedCam.fovY > 0.0f && cachedCam.fovY < DirectX::XM_PI) {
                fovRadians = cachedCam.fovY;  // Already in radians from GameCameraExtractor
            }
            
            DirectX::XMMATRIX projection = DirectX::XMMatrixPerspectiveFovLH(
                fovRadians,
                aspectRatio,
                0.1f,
                10000.0f
            );

            debugRenderer.SetViewProjection(view, projection);
        }

        // Begin debug frame - clears buffers and draws persistent primitives
        debugRenderer.BeginFrame();
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // Always use the singleton instance - this is where DrawTestPrimitives() gets called
    if (UIManager::HasInstance())
    {
        UIManager& uiManager = UIManager::GetInstance();
        uiManager.RenderMainMenu();
        uiManager.RenderAllWindows();
    }

    // End debug frame AFTER UI rendering but BEFORE ImGui render
    // This ensures DrawTestPrimitives() calls during UI rendering get flushed
    auto& debugRendererRef = SapphireHook::DebugVisuals::DebugRenderer::GetInstance();
    if (debugRendererRef.IsInitialized() && debugRendererRef.IsEnabled())
    {
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        debugRendererRef.EndFrame();
    }

    ImGui::Render();
    
    if (g_mainRenderTargetView)
    {
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }

    return oPresent(pSwapChain, SyncInterval, Flags);
}

void InitOverlay()
{
    using namespace SapphireHook;
    
    LogInfo("Initializing overlay...");

    HMODULE hDXGI = GetModuleHandleA("dxgi.dll");
    if (!hDXGI)
    {
        LogError("Failed to get dxgi.dll handle");
        return;
    }

    IDXGISwapChain* pSwapChain;
    ID3D11Device* pDevice;
    ID3D11DeviceContext* pContext;
    D3D_FEATURE_LEVEL featureLevel;
    DXGI_SWAP_CHAIN_DESC swapChainDesc = {};

    swapChainDesc.BufferCount = 1;
    swapChainDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swapChainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapChainDesc.OutputWindow = GetForegroundWindow();
    swapChainDesc.SampleDesc.Count = 1;
    swapChainDesc.Windowed = TRUE;
    swapChainDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    if (FAILED(D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0,
        D3D11_SDK_VERSION, &swapChainDesc, &pSwapChain, &pDevice, &featureLevel, &pContext)))
    {
        LogError("Failed to create dummy device");
        return;
    }

    void** pVTable = *(void***)pSwapChain;
    void* pPresent = pVTable[8];             
    void* pResizeBuffers = pVTable[13];      

    // Get device context vtable for UpdateSubresource and VSSetConstantBuffers hooks
    void** pContextVTable = *(void***)pContext;
    void* pUpdateSubresource = pContextVTable[48];  // ID3D11DeviceContext::UpdateSubresource is at index 48
    void* pVSSetConstantBuffers = pContextVTable[7]; // ID3D11DeviceContext::VSSetConstantBuffers is at index 7

    std::ostringstream oss;
    oss << "Found Present function at: 0x" << std::hex << reinterpret_cast<uintptr_t>(pPresent);
    LogInfo(oss.str());
    
    oss.str("");
    oss << "Found ResizeBuffers function at: 0x" << std::hex << reinterpret_cast<uintptr_t>(pResizeBuffers);
    LogInfo(oss.str());

    oss.str("");
    oss << "Found UpdateSubresource function at: 0x" << std::hex << reinterpret_cast<uintptr_t>(pUpdateSubresource);
    LogInfo(oss.str());

    oss.str("");
    oss << "Found VSSetConstantBuffers function at: 0x" << std::hex << reinterpret_cast<uintptr_t>(pVSSetConstantBuffers);
    LogInfo(oss.str());

    pSwapChain->Release();
    pDevice->Release();
    pContext->Release();

    MH_STATUS hookResult = MH_CreateHook(pPresent, &hkPresent, (void**)&oPresent);
    if (hookResult != MH_OK)
    {
        LogError("Failed to create Present hook. Error: " + std::to_string(hookResult));
        return;
    }

    hookResult = MH_CreateHook(pResizeBuffers, &hkResizeBuffers, (void**)&oResizeBuffers);
    if (hookResult != MH_OK)
    {
        LogError("Failed to create ResizeBuffers hook. Error: " + std::to_string(hookResult));
        return;
    }

    // RE-ENABLED: Only UpdateSubresource hook - this is safe as it just reads data already being passed
    // VSSetConstantBuffers hook is still DISABLED as it does CopyResource/Map which can crash
    hookResult = MH_CreateHook(pUpdateSubresource, &hkUpdateSubresource, (void**)&oUpdateSubresource);
    if (hookResult != MH_OK)
    {
        LogWarning("Failed to create UpdateSubresource hook. Error: " + std::to_string(hookResult));
        // Don't return - this is optional
    }
    else
    {
        LogInfo("UpdateSubresource hook created - will capture constant buffer updates");
    }

    // VSSetConstantBuffers hook DISABLED - it calls CopyResource/Map which can cause crashes
    // hookResult = MH_CreateHook(pVSSetConstantBuffers, &hkVSSetConstantBuffers, (void**)&oVSSetConstantBuffers);
    LogInfo("VSSetConstantBuffers hook DISABLED (causes crashes due to CopyResource/Map calls)");

    hookResult = MH_EnableHook(pPresent);
    if (hookResult != MH_OK)
    {
        LogError("Failed to enable Present hook. Error: " + std::to_string(hookResult));
        return;
    }

    hookResult = MH_EnableHook(pResizeBuffers);
    if (hookResult != MH_OK)
    {
        LogError("Failed to enable ResizeBuffers hook. Error: " + std::to_string(hookResult));
        return;
    }

    // Enable UpdateSubresource hook if it was created
    if (oUpdateSubresource)
    {
        hookResult = MH_EnableHook(pUpdateSubresource);
        if (hookResult != MH_OK)
        {
            LogWarning("Failed to enable UpdateSubresource hook. Error: " + std::to_string(hookResult));
        }
        else
        {
            LogInfo("UpdateSubresource hook ENABLED - capturing constant buffer updates for ViewProjection");
        }
    }

    // VSSetConstantBuffers hook remains disabled

    LogInfo("Overlay hooks installed successfully!");
}

void CleanupOverlay()
{
    using namespace SapphireHook;
    
    LogInfo("Cleaning up overlay...");

    g_overlayInitialized = false;

    // Shutdown Game Camera Extractor first
    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    if (cameraExtractor.IsInitialized())
    {
        cameraExtractor.Shutdown();
        LogInfo("Game Camera Extractor shutdown completed");
    }

    // Shutdown Debug Renderer
    auto& debugRenderer = DebugVisuals::DebugRenderer::GetInstance();
    if (debugRenderer.IsInitialized())
    {
        debugRenderer.Shutdown();
        LogInfo("Debug Renderer shutdown completed");
    }

    if (oWndProc && g_hWnd)
    {
        SetWindowLongPtr(g_hWnd, GWLP_WNDPROC, (LONG_PTR)oWndProc);
        oWndProc = nullptr;
        LogInfo("Window procedure restored");
    }

    // Shutdown backends first
    if (ImGui::GetCurrentContext())
    {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
    }

    // Destroy plotting and GUI contexts
    if (ImPlot::GetCurrentContext())
    {
        ImPlot::DestroyContext();
    }
    if (ImGui::GetCurrentContext())
    {
        ImGui::DestroyContext();
        LogInfo("ImGui cleaned up");
    }

    CleanupRenderTarget();
    
    if (g_pd3dDeviceContext)
    {
        g_pd3dDeviceContext->Release();
        g_pd3dDeviceContext = nullptr;
    }
    
    if (g_pd3dDevice)
    {
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    }

    g_hWnd = nullptr;
    g_isMinimized = false;
    g_deviceLost = false;
    g_renderTargetValid = false;

    LogInfo("Overlay cleanup completed");
}