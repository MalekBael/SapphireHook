#include "imgui_overlay.h"
#include <d3d11.h>
#include <dxgi.h>
#include <Windows.h>
#include <cstdio>
#include "imgui.h"
#include "vendor/imgui/backends/imgui_impl_dx11.h"
#include "vendor/imgui/backends/imgui_impl_win32.h"
#include "MinHook.h"
#include "UIManager.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

typedef HRESULT(__stdcall* Present_t)(IDXGISwapChain*, UINT, UINT);
Present_t oPresent = nullptr;
HWND g_hWnd = nullptr;
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

// UI Manager instance
static std::unique_ptr<UIManager> g_uiManager;

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Window procedure hook
WNDPROC oWndProc = nullptr;
LRESULT __stdcall WndProc(const HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Handle toggle key first
	if (uMsg == WM_KEYDOWN && wParam == VK_INSERT)
	{
		if (g_uiManager)
		{
			g_uiManager->ToggleMenu();
		}
		return TRUE;
	}

	// Always let ImGui handle input first when menu is visible
	if (g_uiManager && g_uiManager->IsMenuVisible())
	{
		// Let ImGui process the message
		LRESULT imgui_result = ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam);

		// Check if ImGui wants to capture this input
		ImGuiIO& io = ImGui::GetIO();

		// If ImGui handled the message or wants the input, don't pass to game
		if (imgui_result ||
			((uMsg >= WM_MOUSEFIRST && uMsg <= WM_MOUSELAST) && io.WantCaptureMouse) ||
			((uMsg >= WM_KEYFIRST && uMsg <= WM_KEYLAST) && io.WantCaptureKeyboard))
		{
			return imgui_result ? imgui_result : TRUE;
		}
	}

	// Pass to original window procedure
	return CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam);
}

HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
	static bool initialized = false;
	if (!initialized)
	{
		if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&g_pd3dDevice)))
		{
			g_pd3dDevice->GetImmediateContext(&g_pd3dDeviceContext);
			DXGI_SWAP_CHAIN_DESC sd;
			pSwapChain->GetDesc(&sd);
			g_hWnd = sd.OutputWindow;

			ID3D11Texture2D* pBackBuffer;
			pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
			g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
			pBackBuffer->Release();

			// Setup Dear ImGui context
			ImGui::CreateContext();
			ImGuiIO& io = ImGui::GetIO();
			io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
			io.MouseDrawCursor = false;

			ImGui::StyleColorsDark();

			// Setup Platform/Renderer backends
			ImGui_ImplWin32_Init(g_hWnd);
			ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

			// Hook window procedure for input
			oWndProc = (WNDPROC)SetWindowLongPtr(g_hWnd, GWLP_WNDPROC, (LONG_PTR)WndProc);

			// Initialize UI Manager
			g_uiManager = std::make_unique<UIManager>();

			initialized = true;
		}
	}

	// Start the Dear ImGui frame
	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	// Render UI through manager
	if (g_uiManager)
	{
		g_uiManager->RenderMainMenu();
		g_uiManager->RenderAllWindows();
	}

	// Rendering
	ImGui::Render();
	g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

	return oPresent(pSwapChain, SyncInterval, Flags);
}

void InitOverlay()
{
	printf("[SapphireHook] Initializing overlay...\n");

	// NOTE: MinHook is already initialized by hook_manager, so we don't call MH_Initialize() here

	// Get module base of dxgi.dll
	HMODULE hDXGI = GetModuleHandleA("dxgi.dll");
	if (!hDXGI)
	{
		printf("[SapphireHook] Failed to get dxgi.dll handle\n");
		return;
	}

	// Create dummy device to get vtable
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
		printf("[SapphireHook] Failed to create dummy device\n");
		return;
	}

	// Get Present function address from vtable
	void** pVTable = *(void***)pSwapChain;
	void* pPresent = pVTable[8]; // Present is at index 8

	printf("[SapphireHook] Found Present function at: 0x%p\n", pPresent);

	// Clean up dummy device
	pSwapChain->Release();
	pDevice->Release();
	pContext->Release();

	// Create hook (MinHook is already initialized)
	MH_STATUS hookResult = MH_CreateHook(pPresent, &hkPresent, (void**)&oPresent);
	if (hookResult != MH_OK)
	{
		printf("[SapphireHook] Failed to create Present hook. Error: %d\n", hookResult);
		return;
	}

	// Enable hook
	hookResult = MH_EnableHook(pPresent);
	if (hookResult != MH_OK)
	{
		printf("[SapphireHook] Failed to enable Present hook. Error: %d\n", hookResult);
		return;
	}

	printf("[SapphireHook] Overlay hook installed successfully!\n");
}

void CleanupOverlay()
{
	// Cleanup UI Manager
	g_uiManager.reset();

	// Restore original window procedure
	if (oWndProc && g_hWnd)
	{
		SetWindowLongPtr(g_hWnd, GWLP_WNDPROC, (LONG_PTR)oWndProc);
	}

	// Cleanup ImGui
	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	// Cleanup D3D11
	if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
	if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
	if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }

	// NOTE: We don't call MH_DisableHook(MH_ALL_HOOKS) or MH_Uninitialize() here
	// because hook_manager is responsible for MinHook cleanup
}