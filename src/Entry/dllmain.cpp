#include <Windows.h>
#include <Psapi.h>
#include <thread>
#include <cstdio>
#include <filesystem>
#include <atomic>
#include <MinHook.h>
#include <spdlog/spdlog.h>

#include "../Hooking/hook_manager.h"
#include "../Hooking/NetworkHooks.h"
#include "../UI/imgui_overlay.h"
#include "../Hooking/lua_hook.h"
#include "../Analysis/PatternScanner.h"
#include "../Logger/Logger.h"
#include "../UI/UIManager.h"
#include "../Modules/FunctionCallMonitor.h"
#include "../Core/GameDataLookup.h"
#include "../Core/SettingsManager.h"

using SapphireHook::LogInfo;
using SapphireHook::LogWarning;
using SapphireHook::LogError;

static HMODULE g_hModule = nullptr;
static std::atomic<bool> g_unloadStarted{ false };

bool g_SafeToInitialize = false;

static bool ShouldAcceptHotkeys()
{
    HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
    if (!gameWindow) return false;
    if (IsIconic(gameWindow)) return false;                     
    return GetForegroundWindow() == gameWindow;                   
}

static void RebindConsoleStreams()
{
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);
    std::ios::sync_with_stdio(true);
    std::cout.clear();
    std::cerr.clear();
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

static bool IsGameWindowMinimized();

static void PerformSafeUnload()
{
    bool expected = false;
    if (!g_unloadStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    try {
        LogInfo("=== Starting Safe DLL Unload ===");

        LogInfo("Phase 1: Stopping monitors and closing windows...");
        if (SapphireHook::UIManager::HasInstance()) {
            auto& ui = SapphireHook::UIManager::GetInstance();

            auto* functionMonitor =
                dynamic_cast<FunctionCallMonitor*>(ui.GetModule("function_monitor"));
            if (functionMonitor) {
                functionMonitor->StopScan();
                functionMonitor->UnhookAllFunctions();
                LogInfo("Function monitor safely stopped");
            }

            auto& modules = ui.GetModules();
            for (auto& module : modules)
                if (module) module->SetWindowOpen(false);
            LogInfo("All module windows closed");
        }

        LogInfo("Phase 2: Signaling overlay shutdown...");
        CleanupOverlay();         
        LogInfo("Overlay cleanup completed");

        LogInfo("Phase 3: Disabling all hooks...");
        MH_DisableHook(MH_ALL_HOOKS);
        LogInfo("All hooks disabled via MH_DisableHook(MH_ALL_HOOKS)");
        
        LogInfo("Waiting for in-flight hook calls to complete...");
        Sleep(300);       

        LogInfo("Phase 4: Shutting down UIManager...");
        SapphireHook::UIManager::Shutdown();
        LogInfo("UIManager shutdown completed");

        LogInfo("Phase 5: Shutting down NetworkHooks...");
        try {
            SapphireHook::NetworkHooks::GetInstance().Shutdown();
            LogInfo("NetworkHooks shutdown completed");
        } catch (...) {
            LogWarning("NetworkHooks shutdown exception (continuing)");
        }

        LogInfo("Phase 6: Shutting down HookManager...");
        SapphireHook::HookManager::Shutdown();
        LogInfo("HookManager shutdown completed");

        LogInfo("=== Safe DLL Unload Complete ===");
        
        Sleep(100);
        
        SapphireHook::Logger::PrepareForShutdown();
        Sleep(50);
        
        spdlog::apply_all([](std::shared_ptr<spdlog::logger> l) {
            l->flush();
        });
        Sleep(50);
        
        spdlog::shutdown();
        
        Sleep(200);
    } catch (...) {
    }
}

static DWORD WINAPI ShutdownThread(LPVOID)
{
    __try {
        PerformSafeUnload();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    if (g_hModule) {
        FreeLibraryAndExitThread(g_hModule, 0);
    }
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall SapphireHook_Shutdown()
{
    HANDLE th = CreateThread(nullptr, 0, ShutdownThread, nullptr, 0, nullptr);
    if (th) CloseHandle(th);
}

DWORD WINAPI MainThread(LPVOID lpReserved)
{
    FILE* debugFile = nullptr;
    fopen_s(&debugFile, "debug_test.txt", "w");
    if (debugFile) { fprintf(debugFile, "MainThread started!\n"); fclose(debugFile); }

    bool consoleAllocated = false;
    if (AllocConsole()) {
        consoleAllocated = true;
        RebindConsoleStreams();
        printf("[DEBUG] Console allocated - rebound streams.\n");
    }

    try {
        const char* envDir = std::getenv("SAPPHIREHOOK_LOG_DIR");
        bool noCreate = (std::getenv("SAPPHIREHOOK_LOG_NOCREATE") != nullptr);
        if (envDir && *envDir) {
            SapphireHook::Logger::Initialize(envDir,
                                             true,
                                             SapphireHook::LogLevel::Debug,
                                             true,
                                             !noCreate);
        } else {
            SapphireHook::Logger::Initialize("sapphire_hook.log",
                                             true,
                                             SapphireHook::LogLevel::Debug,
                                             false,
                                             true);
        }

        SapphireHook::Logger::Instance().ReattachConsole();
        SapphireHook::Logger::Instance().AnnounceLogFileLocation(true);

        using namespace SapphireHook;
        const auto logDir = Logger::Instance().GetLogDirectory();
        LogInfo("Log directory: " + logDir.string());
        LogInfo("=== SapphireHook DLL Loaded ===");
        LogInfo("Logger initialization successful!");
    } catch (...) {
        printf("[ERROR] Logger initialization failed!\n");
        FILE* errorFile = nullptr;
        fopen_s(&errorFile, "logger_error.txt", "w");
        if (errorFile) { fprintf(errorFile, "Logger initialization failed!\n"); fclose(errorFile); }
    }

    using namespace SapphireHook;
    LogInfo("Waiting for game window...");

    while (true) {
        HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
        if (gameWindow) {
            g_SafeToInitialize = true;
            LogInfo("Game window found - proceeding with initialization");
            break;
        }
        LogInfo("Still waiting for game window...");
        Sleep(1000);
    }

    try {
        auto& settings = SettingsManager::Instance();
        std::filesystem::path sqpackPath;
        
        if (settings.HasCustomSqpackPath()) {
            sqpackPath = settings.GetSqpackPath();
            LogInfo("GameData: Using custom sqpack path from settings: " + sqpackPath.string());
        } else {
            wchar_t gamePath[MAX_PATH];
            GetModuleFileNameW(nullptr, gamePath, MAX_PATH);       
            sqpackPath = std::filesystem::path(gamePath).parent_path() / "sqpack";
            LogInfo("GameData: Auto-detected sqpack path: " + sqpackPath.string());
        }
        
        if (GameData::Initialize(sqpackPath)) {
            const auto& stats = GameData::GetLoadStats();
            LogInfo("GameData initialized from sqpack: " + std::to_string(stats.itemCount) + " items, " +
                    std::to_string(stats.actionCount) + " actions, " +
                    std::to_string(stats.classJobCount) + " classjobs, " +
                    std::to_string(stats.statusCount) + " statuses");
        } else {
            LogWarning("GameData: Could not load from: " + sqpackPath.string());
            LogInfo("GameData: Open Settings to configure the sqpack path manually");
        }
    } catch (const std::exception& e) {
        LogWarning("GameData initialization failed: " + std::string(e.what()));
        LogInfo("GameData: Open Settings to configure the sqpack path manually");
    }

    bool hooksInitialized = false;
    try {
        LogInfo("Initializing hooks...");
        InitHooks();
        LogInfo("Hooks initialized successfully");
        hooksInitialized = true;
    } catch (...) {
        LogError("InitHooks failed with C++ exception");
    }

    try {
        LogInfo("Initializing high-level network hooks...");
        if (SapphireHook::NetworkHooks::GetInstance().Initialize()) {
            LogInfo("NetworkHooks initialized successfully");
        } else {
            LogWarning("NetworkHooks: Some hooks could not be installed (signatures may not match this client version)");
        }
    } catch (const std::exception& e) {
        LogWarning("NetworkHooks initialization failed: " + std::string(e.what()));
    } catch (...) {
        LogWarning("NetworkHooks initialization failed with unknown exception");
    }

    Sleep(1000);

    bool luaInitialized = false;
    try {
        LogInfo("Initializing Lua hooks...");
        InitLuaHooks();
        LogInfo("Lua hooks initialized successfully");
        luaInitialized = true;
    } catch (...) {
        LogError("InitLuaHooks failed with C++ exception");
    }

    Sleep(1000);

    bool overlayInitialized = false;
    try {
        LogInfo("Initializing overlay...");
        InitOverlay();
        LogInfo("Overlay initialized successfully");
        overlayInitialized = true;
    } catch (...) {
        LogError("InitOverlay failed with C++ exception");
    }

    try {
        LogInfo("=== INITIALIZING UI MODULES ===");
        UIManager& uiManager = UIManager::GetInstance();
        LogInfo("UIManager instance: " + std::to_string(reinterpret_cast<uintptr_t>(&uiManager)));

        uiManager.RegisterDefaultModules();
        uiManager.VerifyDefaultModules();        
        uiManager.LogModuleSummary();              

        LogInfo("UI module initialization sequence complete");
    } catch (const std::exception& e) {
        LogError("UI module initialization failed: " + std::string(e.what()));
    } catch (...) {
        LogError("UI module initialization failed with unknown exception");
    }

    LogInfo("=== All systems initialized! ===");
    LogInfo("Press INSERT to toggle menu, END to unload");

    const bool disableEndHotkey = (std::getenv("SAPPHIREHOOK_DISABLE_END_HOTKEY") != nullptr);
    static bool s_endWasDown = false;

    while (true) {
        bool endPressed = false;
        if (!disableEndHotkey && ShouldAcceptHotkeys()) {
            SHORT state = GetAsyncKeyState(VK_END);
            bool endDown = (state & 0x8000) != 0;          
            endPressed = endDown && !s_endWasDown;       
            s_endWasDown = endDown;
        } else {
            s_endWasDown = false;      
        }

        const bool uiUnload = (UIManager::HasInstance() && UIManager::IsUnloadRequested());
        const bool minimized = IsGameWindowMinimized();

        if (endPressed) {
            LogInfo("Unloading requested by hotkey (END)");
            break;
        }

        if (uiUnload && !minimized) {
            LogInfo("Unloading requested by UI");
            break;
        }

        static DWORD s_lastWarn = 0;
        if (uiUnload && minimized) {
            ULONGLONG now = GetTickCount64();
            if (now - s_lastWarn > 2000) {
                SapphireHook::Logger::Instance().Warning("UI unload requested while minimized; deferring until window is restored");
                s_lastWarn = (DWORD)now;
            }
        }

        Sleep(100);
    }

    PerformSafeUnload();

    LogInfo("SapphireHook unloading...");

    if (consoleAllocated) FreeConsole();

    FreeLibraryAndExitThread((HMODULE)lpReserved, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        {
            g_hModule = hModule;
            DisableThreadLibraryCalls(hModule);
            
            wchar_t dllPath[MAX_PATH];
            if (GetModuleFileNameW(hModule, dllPath, MAX_PATH) > 0) {
                std::filesystem::path dllDir = std::filesystem::path(dllPath).parent_path();
                SetDllDirectoryW(dllDir.c_str());
                AddDllDirectory(dllDir.c_str());
            }
            
            CreateThread(nullptr, 0x10000, MainThread, hModule, 0, nullptr);
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

static bool IsGameWindowMinimized() {
    HWND hGame = FindWindowW(L"FFXIVGAME", nullptr);
    return hGame ? (IsIconic(hGame) != 0) : false;
}