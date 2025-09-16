#include "../UI/imgui_overlay.h"
#include "../Logger/Logger.h"     
#include <d3d11.h>
#include <dxgi.h>
#include <Windows.h>
#include <cstdio>
#include <iostream>
#include <sstream>      
#include <iomanip>     
#include "../vendor/imgui/imgui.h"
#include "../../vendor/imgui/backends/imgui_impl_dx11.h"
#include "../../vendor/imgui/backends/imgui_impl_win32.h"
#include "../../vendor/minhook/include/MinHook.h"
#include "../UI/UIManager.h"
// NEW: ImPlot for charts
#include "../../vendor/implot/implot.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

typedef HRESULT(__stdcall* Present_t)(IDXGISwapChain*, UINT, UINT);
typedef HRESULT(__stdcall* ResizeBuffers_t)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);

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

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // Always use the singleton instance
    if (UIManager::HasInstance())
    {
        UIManager& uiManager = UIManager::GetInstance();
        uiManager.RenderMainMenu();
        uiManager.RenderAllWindows();
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

    std::ostringstream oss;
    oss << "Found Present function at: 0x" << std::hex << reinterpret_cast<uintptr_t>(pPresent);
    LogInfo(oss.str());
    
    oss.str("");
    oss << "Found ResizeBuffers function at: 0x" << std::hex << reinterpret_cast<uintptr_t>(pResizeBuffers);
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

    LogInfo("Overlay hooks installed successfully!");
}

void CleanupOverlay()
{
    using namespace SapphireHook;
    
    LogInfo("Cleaning up overlay...");

    g_overlayInitialized = false;

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