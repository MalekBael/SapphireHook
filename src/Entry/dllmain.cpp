#include <Windows.h>
#include <Psapi.h>
#include <thread>
#include <cstdio>
#include "../Hooking/hook_manager.h"
#include "../UI/imgui_overlay.h"
#include "../Hooking/lua_hook.h"
#include "../Core/patternscanner.h"
#include "../Logger/Logger.h"
#include "../UI/UIManager.h"    
#include "../Core/FunctionCallMonitor.h"    

bool g_SafeToInitialize = false;

DWORD WINAPI MainThread(LPVOID lpReserved)
{
    FILE* debugFile = nullptr;
    fopen_s(&debugFile, "debug_test.txt", "w");
    if (debugFile) {
        fprintf(debugFile, "MainThread started!\n");
        fclose(debugFile);
    }

    bool consoleAllocated = false;
    if (AllocConsole())
    {
        FILE* pCout;
        freopen_s(&pCout, "CONOUT$", "w", stdout);
        printf("[DEBUG] Console allocated - you should see this immediately!\n");
        consoleAllocated = true;
    }

    try {
        SapphireHook::Logger::Initialize("sapphire_hook.log", true, SapphireHook::LogLevel::Debug);
        
        using namespace SapphireHook;
        LogInfo("=== SapphireHook DLL Loaded ===");
        LogInfo("Logger initialization successful!");
        
        FILE* successFile = nullptr;
        fopen_s(&successFile, "logger_success.txt", "w");
        if (successFile) {
            fprintf(successFile, "Logger initialization succeeded!\n");
            fclose(successFile);
        }
    } catch (...) {
        printf("[ERROR] Logger initialization failed!\n");
        FILE* errorFile = nullptr;
        fopen_s(&errorFile, "logger_error.txt", "w");
        if (errorFile) {
            fprintf(errorFile, "Logger initialization failed!\n");
            fclose(errorFile);
        }
    }

    using namespace SapphireHook;
    LogInfo("Waiting 10 seconds for game stability...");
    
    for (int i = 10; i > 0; i--) {
        LogInfo("Countdown: " + std::to_string(i) + " seconds remaining");
        Sleep(1000);
    }
    
    LogInfo("Waiting for game window...");

    while (true)
    {
        HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
        if (gameWindow)
        {
            g_SafeToInitialize = true;
            LogInfo("Game window found - proceeding with initialization");
            break;
        }
        LogInfo("Still waiting for game window...");
        Sleep(1000);
    }

    bool hooksInitialized = false;
    try
    {
        LogInfo("Initializing hooks...");
        InitHooks();
        LogInfo("Hooks initialized successfully");
        hooksInitialized = true;
    }
    catch (...)
    {
        LogError("InitHooks failed with C++ exception");
    }

    Sleep(1000);

    bool luaInitialized = false;
    try
    {
        LogInfo("Initializing Lua hooks...");
        InitLuaHooks();
        LogInfo("Lua hooks initialized successfully");
        luaInitialized = true;
    }
    catch (...)
    {
        LogError("InitLuaHooks failed with C++ exception");
    }

    Sleep(1000);

    bool overlayInitialized = false;
    try
    {
        LogInfo("Initializing overlay...");
        InitOverlay();
        LogInfo("Overlay initialized successfully");
        overlayInitialized = true;
    }
    catch (...)
    {
        LogError("InitOverlay failed with C++ exception");
    }

    try
    {
        LogInfo("=== STARTING UI MODULE REGISTRATION ===");
        
        UIManager& uiManager = UIManager::GetInstance();
        LogInfo("Got UIManager instance at: " + 
                std::to_string(reinterpret_cast<uintptr_t>(&uiManager)));
        
        uiManager.RegisterDefaultModules();
        
        UIManager& verifyManager = UIManager::GetInstance();
        LogInfo("Verification: UIManager instance at: " + 
                std::to_string(reinterpret_cast<uintptr_t>(&verifyManager)));
        
        if (&uiManager != &verifyManager)
        {
            LogError("CRITICAL: UIManager singleton inconsistency detected!");
            LogError("Registration instance: " + std::to_string(reinterpret_cast<uintptr_t>(&uiManager)));
            LogError("Verification instance: " + std::to_string(reinterpret_cast<uintptr_t>(&verifyManager)));
        }
        else
        {
            LogInfo("✓ UIManager singleton consistency verified");
        }
        
        bool ipcFound = (uiManager.GetModule("ipc_commands") != nullptr);
        bool debugFound = (uiManager.GetModule("debug_commands") != nullptr);
        bool functionFound = (uiManager.GetModule("function_monitor") != nullptr);
        
        LogInfo("=== MODULE REGISTRATION VERIFICATION ===");
        LogInfo("IPC Commands: " + std::string(ipcFound ? "✓ FOUND" : "✗ MISSING"));
        LogInfo("Debug Commands: " + std::string(debugFound ? "✓ FOUND" : "✗ MISSING"));
        LogInfo("Function Monitor: " + std::string(functionFound ? "✓ FOUND" : "✗ MISSING"));
        
        if (ipcFound && debugFound && functionFound)
        {
            LogInfo("🎉 ALL UI MODULES REGISTERED SUCCESSFULLY!");
        }
        else
        {
            LogError("❌ SOME MODULES FAILED TO REGISTER!");
        }
        
        LogInfo("UI modules registration completed");
    }
    catch (const std::exception& e)
    {
        LogError("UI module registration failed with exception: " + std::string(e.what()));
    }
    catch (...)
    {
        LogError("UI module registration failed with unknown exception");
    }

    LogInfo("=== All systems initialized! ===");
    LogInfo("Press INSERT to toggle menu, END to unload");

    while (true)
    {
        if (GetAsyncKeyState(VK_END) & 1)
        {
            LogInfo("Unloading requested...");
            break;
        }
        Sleep(100);
    }

    try
    {
        LogInfo("Starting cleanup...");
        CleanupOverlay();
        LogInfo("Cleanup completed successfully");
    }
    catch (...)
    {
        LogError("Cleanup error occurred");
    }

    LogInfo("SapphireHook unloading...");

    if (consoleAllocated)
    {
        LogInfo("Freeing console...");
        FreeConsole();
    }

    FreeLibraryAndExitThread((HMODULE)lpReserved, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        CreateThread(nullptr, 0x10000, MainThread, hModule, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}