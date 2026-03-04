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
#include <algorithm>    
#include <atomic>        
#include "../vendor/imgui/imgui.h"
#include "../../vendor/imgui/backends/imgui_impl_dx11.h"
#include "../../vendor/imgui/backends/imgui_impl_win32.h"
#include "../../vendor/imgui/IconsFontAwesome6.h"
#include "../../vendor/imgui/fa-solid-900.h"
#include "../../vendor/imgui/ImGuiNotify.hpp"
#include <MinHook.h>
#include "../UI/UIManager.h"
#include "../../vendor/implot/implot.h"
#include "../Tools/DebugRenderer.h"
#include "../Tools/GameCameraExtractor.h"
#include "../Tools/D3D11MatrixCapture.h"
#include "../Tools/ViewProjectionHook.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

typedef HRESULT(__stdcall* Present_t)(IDXGISwapChain*, UINT, UINT);
typedef HRESULT(__stdcall* ResizeBuffers_t)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);

typedef void(__stdcall* UpdateSubresource_t)(ID3D11DeviceContext*, ID3D11Resource*, UINT, const D3D11_BOX*, const void*, UINT, UINT);
UpdateSubresource_t oUpdateSubresource = nullptr;

typedef void(__stdcall* VSSetConstantBuffers_t)(ID3D11DeviceContext*, UINT, UINT, ID3D11Buffer* const*);
VSSetConstantBuffers_t oVSSetConstantBuffers = nullptr;

Present_t oPresent = nullptr;
ResizeBuffers_t oResizeBuffers = nullptr;

static void* g_pPresentTarget = nullptr;
static void* g_pResizeBuffersTarget = nullptr;
static void* g_pUpdateSubresourceTarget = nullptr;

HWND g_hWnd = nullptr;
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static bool g_isMinimized = false;
static bool g_deviceLost = false;
static bool g_renderTargetValid = false;
static bool g_overlayInitialized = false;
static std::atomic<bool> g_overlayShutdown{ false };       

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
            LogError("Failed to create render target view: " + Logger::HexFormat(static_cast<uint32_t>(hr)));
            g_renderTargetValid = false;
        }
    }
    else
    {
        LogError("Failed to get back buffer: " + Logger::HexFormat(static_cast<uint32_t>(hr)));
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

void __stdcall hkUpdateSubresource(ID3D11DeviceContext* context, ID3D11Resource* dstResource, 
                                    UINT dstSubresource, const D3D11_BOX* dstBox, 
                                    const void* srcData, UINT srcRowPitch, UINT srcDepthPitch)
{
    if (!g_overlayShutdown.load(std::memory_order_acquire)) {
        __try {
            SapphireHook::DebugVisuals::D3D11MatrixCapture::GetInstance().OnUpdateSubresource(
                dstResource, dstSubresource, dstBox, srcData, srcRowPitch, srcDepthPitch);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    oUpdateSubresource(context, dstResource, dstSubresource, dstBox, srcData, srcRowPitch, srcDepthPitch);
}

void __stdcall hkVSSetConstantBuffers(ID3D11DeviceContext* context, UINT startSlot, 
                                       UINT numBuffers, ID3D11Buffer* const* buffers)
{
    if (!g_overlayShutdown.load(std::memory_order_acquire)) {
        SapphireHook::DebugVisuals::D3D11MatrixCapture::GetInstance().OnVSSetConstantBuffers(
            startSlot, numBuffers, buffers, context);
    }
    
    oVSSetConstantBuffers(context, startSlot, numBuffers, buffers);
}

HRESULT __stdcall hkResizeBuffers(IDXGISwapChain* pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags)
{
    using namespace SapphireHook;
    
    if (g_overlayShutdown.load(std::memory_order_acquire))
    {
        return oResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
    }
    
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
    
    if (g_overlayShutdown.load(std::memory_order_acquire))
    {
        return oWndProc ? CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam) : DefWindowProc(hWnd, uMsg, wParam, lParam);
    }
    
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
    
    if (g_overlayShutdown.load(std::memory_order_acquire))
    {
        return oPresent(pSwapChain, SyncInterval, Flags);
    }
    
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
            ImPlot::CreateContext();
            ImGuiIO& io = ImGui::GetIO();
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
            io.MouseDrawCursor = false;

            ImGui::StyleColorsDark();

            {
                io.Fonts->AddFontDefault();
                
                static const ImWchar icons_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
                ImFontConfig icons_config;
                icons_config.MergeMode = true;
                icons_config.PixelSnapH = true;
                icons_config.GlyphMinAdvanceX = 13.0f;
                icons_config.GlyphOffset = ImVec2(0.0f, 1.0f);
                
                io.Fonts->AddFontFromMemoryCompressedTTF(
                    fa_solid_900_compressed_data,
                    fa_solid_900_compressed_size,
                    13.0f,
                    &icons_config,
                    icons_ranges
                );
                
                LogInfo("Font Awesome 6 icons loaded for notifications");
            }

            ImGui_ImplWin32_Init(g_hWnd);
            ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

            oWndProc = (WNDPROC)SetWindowLongPtr(g_hWnd, GWLP_WNDPROC, (LONG_PTR)WndProc);

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

            auto& debugRenderer = SapphireHook::DebugVisuals::DebugRenderer::GetInstance();
            if (debugRenderer.Initialize(g_pd3dDevice, g_pd3dDeviceContext))
            {
                LogInfo("Debug Renderer initialized successfully");
                
                debugRenderer.SetScreenSize(static_cast<float>(sd.BufferDesc.Width), 
                                            static_cast<float>(sd.BufferDesc.Height));
            }
            else
            {
                LogWarning("Debug Renderer failed to initialize - 3D debug visuals will not be available");
            }

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
            LogError("Device is actually lost: " + Logger::HexFormat(static_cast<uint32_t>(deviceState)));
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

    auto& cameraExtractor = SapphireHook::DebugVisuals::GameCameraExtractor::GetInstance();
    if (cameraExtractor.IsInitialized())
    {
        cameraExtractor.Update();    
    }

    auto& debugRenderer = SapphireHook::DebugVisuals::DebugRenderer::GetInstance();
    if (debugRenderer.IsInitialized() && debugRenderer.IsEnabled())
    {
        DXGI_SWAP_CHAIN_DESC scDesc;
        if (SUCCEEDED(pSwapChain->GetDesc(&scDesc)))
        {
            debugRenderer.SetScreenSize(static_cast<float>(scDesc.BufferDesc.Width),
                                         static_cast<float>(scDesc.BufferDesc.Height));
        }

        auto& matrixCapture = SapphireHook::DebugVisuals::D3D11MatrixCapture::GetInstance();
        bool cameraValid = false;
        DirectX::XMFLOAT3 cameraPosition = {0.0f, 0.0f, 0.0f};
        
        bool skipGameMatrices = false;          
        
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
                matrixCapture.SetKnownCameraPosition(cameraPosition);
                
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
        
        if (!cameraValid && matrixCapture.HasValidMatrices())
        {
            DirectX::XMMATRIX viewProj = matrixCapture.GetViewProjectionMatrix();
            DirectX::XMMATRIX view = matrixCapture.GetViewMatrix();
            DirectX::XMMATRIX proj = matrixCapture.GetProjectionMatrix();
            
            DirectX::XMFLOAT4X4 vpFloat;
            DirectX::XMStoreFloat4x4(&vpFloat, viewProj);
            bool hasValidVP = (vpFloat._11 != 0.0f && vpFloat._11 != 1.0f &&
                              !std::isnan(vpFloat._11) && !std::isinf(vpFloat._11));
            
            DirectX::XMFLOAT3 d3dCamPos = matrixCapture.GetCameraPosition();
            bool hasValidCamPos = (std::abs(d3dCamPos.x) > 0.1f || std::abs(d3dCamPos.y) > 0.1f || std::abs(d3dCamPos.z) > 0.1f);
            
            bool matchesKnownCamera = false;
            if (hasValidCamPos && (std::abs(cameraPosition.x) > 0.1f || std::abs(cameraPosition.y) > 0.1f || std::abs(cameraPosition.z) > 0.1f))
            {
                float dx = d3dCamPos.x - cameraPosition.x;
                float dy = d3dCamPos.y - cameraPosition.y;
                float dz = d3dCamPos.z - cameraPosition.z;
                float dist = std::sqrt(dx*dx + dy*dy + dz*dz);
                matchesKnownCamera = (dist < 15.0f);     
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

        if (!cameraValid)
        {
            static bool loggedOnce = false;
            
            float camX = cameraPosition.x;
            float camY = cameraPosition.y;
            float camZ = cameraPosition.z;
            
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

            DirectX::XMMATRIX view;
            
            static DirectX::XMFLOAT3 cachedForward = {0.0f, 0.0f, 1.0f};
            static DirectX::XMFLOAT3 lastCameraPos = {0.0f, 0.0f, 0.0f};
            static DirectX::XMFLOAT3 lastPlayerPos = {0.0f, 0.0f, 0.0f};
            static bool dirInitialized = false;
            
            if (hasCameraPosition && hasPlayerPosition) {
                float dirX = playerX - camX;
                float dirY = (playerY + 1.0f) - camY;      
                float dirZ = playerZ - camZ;
                float length = std::sqrt(dirX*dirX + dirY*dirY + dirZ*dirZ);
                
                if (length > 0.1f) {
                    dirX /= length;
                    dirY /= length;
                    dirZ /= length;
                    
                    if (!dirInitialized) {
                        cachedForward = {dirX, dirY, dirZ};
                        dirInitialized = true;
                    } else {
                        float dot = cachedForward.x * dirX + cachedForward.y * dirY + cachedForward.z * dirZ;
                        dot = std::clamp(dot, -1.0f, 1.0f);
                        float angleDeg = std::acos(dot) * 180.0f / 3.14159265f;
                        
                        if (angleDeg > 2.0f) {
                            float t = (std::min)(angleDeg / 30.0f, 1.0f);       
                            cachedForward.x = cachedForward.x * (1.0f - t) + dirX * t;
                            cachedForward.y = cachedForward.y * (1.0f - t) + dirY * t;
                            cachedForward.z = cachedForward.z * (1.0f - t) + dirZ * t;
                            
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
                DirectX::XMVECTOR eye = DirectX::XMVectorSet(playerX, playerY + 8.0f, playerZ - 10.0f, 1.0f);
                DirectX::XMVECTOR target = DirectX::XMVectorSet(playerX, playerY + 1.0f, playerZ, 1.0f);
                view = DirectX::XMMatrixLookAtLH(eye, target, DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f));
            } else if (hasCameraPosition) {
                DirectX::XMVECTOR eye = DirectX::XMVectorSet(camX, camY, camZ, 1.0f);
                DirectX::XMVECTOR target = DirectX::XMVectorSet(0.0f, 0.0f, 0.0f, 1.0f);
                view = DirectX::XMMatrixLookAtLH(eye, target, DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f));
            } else {
                view = DirectX::XMMatrixLookAtLH(
                    DirectX::XMVectorSet(0.0f, 10.0f, -20.0f, 1.0f),
                    DirectX::XMVectorSet(0.0f, 0.0f, 0.0f, 1.0f),
                    DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f)
                );
            }

            float screenWidth = debugRenderer.GetScreenWidth();
            float screenHeight = debugRenderer.GetScreenHeight();
            float aspectRatio = (screenHeight > 0) ? (screenWidth / screenHeight) : (16.0f / 9.0f);

            float fovRadians = DirectX::XMConvertToRadians(45.0f);   
            if (cachedCam.valid && cachedCam.fovY > 0.0f && cachedCam.fovY < DirectX::XM_PI) {
                fovRadians = cachedCam.fovY;       
            }
            
            DirectX::XMMATRIX projection = DirectX::XMMatrixPerspectiveFovLH(
                fovRadians,
                aspectRatio,
                0.1f,
                10000.0f
            );

            debugRenderer.SetViewProjection(view, projection);
        }

        debugRenderer.BeginFrame();
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    if (UIManager::HasInstance())
    {
        UIManager& uiManager = UIManager::GetInstance();
        uiManager.RenderMainMenu();
        uiManager.RenderAllWindows();
    }

    auto& debugRendererRef = SapphireHook::DebugVisuals::DebugRenderer::GetInstance();
    if (debugRendererRef.IsInitialized() && debugRendererRef.IsEnabled())
    {
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        debugRendererRef.EndFrame();
    }

    ImGui::RenderNotifications();

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

    void** pContextVTable = *(void***)pContext;
    void* pUpdateSubresource = pContextVTable[48];       
    void* pVSSetConstantBuffers = pContextVTable[7];      

    g_pPresentTarget = pPresent;
    g_pResizeBuffersTarget = pResizeBuffers;
    g_pUpdateSubresourceTarget = pUpdateSubresource;

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

    hookResult = MH_CreateHook(pUpdateSubresource, &hkUpdateSubresource, (void**)&oUpdateSubresource);
    if (hookResult != MH_OK)
    {
        LogWarning("Failed to create UpdateSubresource hook. Error: " + std::to_string(hookResult));
    }
    else
    {
        LogInfo("UpdateSubresource hook created - will capture constant buffer updates");
    }

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

    LogInfo("Overlay hooks installed successfully!");
}

void CleanupOverlay()
{
    using namespace SapphireHook;
    
    LogInfo("Cleaning up overlay...");

    g_overlayShutdown.store(true, std::memory_order_release);
    LogInfo("Overlay shutdown flag set - hooks will now passthrough");
    
    Sleep(50);
    
    g_overlayInitialized = false;

    if (g_pPresentTarget) {
        MH_DisableHook(g_pPresentTarget);
    }
    if (g_pResizeBuffersTarget) {
        MH_DisableHook(g_pResizeBuffersTarget);
    }
    if (g_pUpdateSubresourceTarget) {
        MH_DisableHook(g_pUpdateSubresourceTarget);
    }

    auto& cameraExtractor = DebugVisuals::GameCameraExtractor::GetInstance();
    if (cameraExtractor.IsInitialized())
    {
        cameraExtractor.Shutdown();
        LogInfo("Game Camera Extractor shutdown completed");
    }

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

    if (ImGui::GetCurrentContext())
    {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
    }

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

    LogInfo("Removing overlay hooks...");
    if (g_pPresentTarget) {
        MH_RemoveHook(g_pPresentTarget);
        g_pPresentTarget = nullptr;
    }
    if (g_pResizeBuffersTarget) {
        MH_RemoveHook(g_pResizeBuffersTarget);
        g_pResizeBuffersTarget = nullptr;
    }
    if (g_pUpdateSubresourceTarget) {
        MH_RemoveHook(g_pUpdateSubresourceTarget);
        g_pUpdateSubresourceTarget = nullptr;
    }
    
    oPresent = nullptr;
    oResizeBuffers = nullptr;
    oUpdateSubresource = nullptr;

    g_hWnd = nullptr;
    g_isMinimized = false;
    g_deviceLost = false;
    g_renderTargetValid = false;

    LogInfo("Overlay cleanup completed");
}