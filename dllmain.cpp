#include <Windows.h>
#include <Psapi.h>
#include <thread>
#include <cstdio>
#include "hook_manager.h"
#include "imgui_overlay.h"
#include "lua_hook.h"
#include "patternscanner.h"

// Global flag to control initialization
bool g_SafeToInitialize = false;

DWORD WINAPI MainThread(LPVOID lpReserved)
{
	// Wait for 10 seconds before doing ANYTHING
	Sleep(10000);

	// Create a simple log file instead of console
	FILE* logFile = nullptr;
	fopen_s(&logFile, "sapphire_hook_log.txt", "w");
	if (logFile)
	{
		fprintf(logFile, "[SapphireHook] DLL Loaded successfully!\n");
		fprintf(logFile, "[SapphireHook] Waiting for safe initialization...\n");
		fclose(logFile);
	}

	// Wait for the game to be fully loaded (wait for a specific window or module)
	while (true)
	{
		// Check if game is ready (you can add more checks here)
		HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
		if (gameWindow)
		{
			g_SafeToInitialize = true;
			break;
		}
		Sleep(1000);
	}

	// Now try initialization with safety checks
	__try
	{
		// Only allocate console after game is stable
		if (AllocConsole())
		{
			FILE* pCout;
			freopen_s(&pCout, "CONOUT$", "w", stdout);
			printf("[SapphireHook] Console allocated after game stabilization\n");
		}

		// Add delays between each initialization
		Sleep(2000);

		// Try each component separately with error handling
		__try
		{
			InitHooks();
			printf("[SapphireHook] Hooks initialized\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("[SapphireHook] InitHooks failed: 0x%lx\n", GetExceptionCode());
		}

		Sleep(1000);

		__try
		{
			InitLuaHooks();
			printf("[SapphireHook] Lua hooks initialized\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("[SapphireHook] InitLuaHooks failed: 0x%lx\n", GetExceptionCode());
		}

		Sleep(1000);

		__try
		{
			InitOverlay();
			printf("[SapphireHook] Overlay initialized\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("[SapphireHook] InitOverlay failed: 0x%lx\n", GetExceptionCode());
		}

		printf("[SapphireHook] All systems initialized!\n");
		printf("[SapphireHook] Press INSERT to toggle menu, END to unload\n");

		// Main loop
		while (true)
		{
			if (GetAsyncKeyState(VK_END) & 1)
			{
				printf("[SapphireHook] Unloading...\n");
				break;
			}
			Sleep(100);
		}

		// Cleanup
		__try
		{
			CleanupOverlay();
			printf("[SapphireHook] Cleanup completed\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("[SapphireHook] Cleanup error: 0x%lx\n", GetExceptionCode());
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// Log to file if console fails
		FILE* errorLog = nullptr;
		fopen_s(&errorLog, "sapphire_hook_error.txt", "w");
		if (errorLog)
		{
			fprintf(errorLog, "Critical error: 0x%lx\n", GetExceptionCode());
			fclose(errorLog);
		}
	}

	// Free console if allocated
	FreeConsole();

	// Exit thread
	FreeLibraryAndExitThread((HMODULE)lpReserved, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// Disable DLL_THREAD_ATTACH/DETACH calls
		DisableThreadLibraryCalls(hModule);

		// Create thread with a smaller stack size to reduce memory impact
		CreateThread(nullptr, 0x10000, MainThread, hModule, 0, nullptr);
		break;

	case DLL_PROCESS_DETACH:
		// Nothing to do here
		break;
	}
	return TRUE;
}