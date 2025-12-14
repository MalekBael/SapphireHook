#include <Windows.h>
#include <Psapi.h>
#include <thread>
#include <cstdio>
#include <filesystem>
#include <atomic>
#include <MinHook.h>
#include <spdlog/spdlog.h>

#include "../Hooking/hook_manager.h"
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

// New: prevent accidental unloads via false-positive hotkey while minimized/not focused
static bool ShouldAcceptHotkeys()
{
    HWND gameWindow = FindWindowW(L"FFXIVGAME", nullptr);
    if (!gameWindow) return false;
    if (IsIconic(gameWindow)) return false;                  // minimized => ignore
    return GetForegroundWindow() == gameWindow;              // only when game has focus
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

// Centralized, idempotent cleanup (safe to call multiple times)
static void PerformSafeUnload()
{
    // Ensure we only run once even if called by hotkey and export
    bool expected = false;
    if (!g_unloadStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    try {
        LogInfo("=== Starting Safe DLL Unload ===");

        if (SapphireHook::UIManager::HasInstance()) {
            auto& ui = SapphireHook::UIManager::GetInstance();

            // Stop and unhook the function monitor first (removes MinHook/VEH)
            auto* functionMonitor =
                dynamic_cast<FunctionCallMonitor*>(ui.GetModule("function_monitor"));
            if (functionMonitor) {
                functionMonitor->StopScan();
                functionMonitor->UnhookAllFunctions();
                LogInfo("Function monitor safely stopped");
            }

            // Close all module windows
            auto& modules = ui.GetModules();
            for (auto& module : modules)
                if (module) module->SetWindowOpen(false);
            LogInfo("All module windows closed");
        }

        // Tear down overlay next
        CleanupOverlay();
        LogInfo("Overlay cleanup completed");

        // Shutdown UI manager
        SapphireHook::UIManager::Shutdown();
        LogInfo("UIManager shutdown completed");

        // Shutdown HookManager (disables and removes all hooks)
        SapphireHook::HookManager::Shutdown();
        LogInfo("HookManager shutdown completed");

        // Defensive: ensure MinHook is uninitialized even if monitor was not present
        const MH_STATUS st = MH_Uninitialize();
        if (st == MH_OK) {
            LogInfo("MinHook uninitialized");
        } else if (st != MH_ERROR_NOT_INITIALIZED) {
            LogWarning("MinHook uninitialize returned: " + std::to_string(st));
        }

        LogInfo("=== Safe DLL Unload Complete ===");
        
        // Shutdown spdlog to release file handles
        spdlog::shutdown();
        
        Sleep(250);
    } catch (...) {
        LogError("Exception during cleanup - proceeding with unload");
    }
}

static DWORD WINAPI ShutdownThread(LPVOID)
{
    __try {
        PerformSafeUnload();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // best-effort shutdown
    }

    if (g_hModule) {
        FreeLibraryAndExitThread(g_hModule, 0);
    }
    return 0;
}

// Exported entry to request a clean unload from an injector or UI button
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
        // Support custom directory via env:
        //   SAPPHIREHOOK_LOG_DIR=<absolute dir>
        //   SAPPHIREHOOK_LOG_NOCREATE=1  (do not create if missing; fallback to default)
        const char* envDir = std::getenv("SAPPHIREHOOK_LOG_DIR");
        bool noCreate = (std::getenv("SAPPHIREHOOK_LOG_NOCREATE") != nullptr);
        if (envDir && *envDir) {
            // treatAsDirectory=true, createDirectoryIfMissing = !noCreate
            SapphireHook::Logger::Initialize(envDir,
                                             true,
                                             SapphireHook::LogLevel::Debug,
                                             true,
                                             !noCreate);
        } else {
            // default: supply nominal name; we want default temp\SapphireHook
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

    // Initialize game data lookups (items, actions, etc.) from sqpack
    try {
        // First check if user has set a custom sqpack path in settings
        auto& settings = SettingsManager::Instance();
        std::filesystem::path sqpackPath;
        
        if (settings.HasCustomSqpackPath()) {
            sqpackPath = settings.GetSqpackPath();
            LogInfo("GameData: Using custom sqpack path from settings: " + sqpackPath.string());
        } else {
            // Auto-detect: Get FFXIV sqpack path from the game's executable directory
            // The injected process is ffxiv_dx11.exe at <game_install>/game/ffxiv_dx11.exe
            // sqpack is at <game_install>/game/sqpack
            wchar_t gamePath[MAX_PATH];
            GetModuleFileNameW(nullptr, gamePath, MAX_PATH);  // nullptr = main exe (ffxiv_dx11.exe)
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
        uiManager.VerifyDefaultModules();      // dynamic verification
        uiManager.LogModuleSummary();          // enumerate what actually loaded

        LogInfo("UI module initialization sequence complete");
    } catch (const std::exception& e) {
        LogError("UI module initialization failed: " + std::string(e.what()));
    } catch (...) {
        LogError("UI module initialization failed with unknown exception");
    }

    LogInfo("=== All systems initialized! ===");
    LogInfo("Press INSERT to toggle menu, END to unload");

    // New: allow disabling the END hotkey via environment
    const bool disableEndHotkey = (std::getenv("SAPPHIREHOOK_DISABLE_END_HOTKEY") != nullptr);
    // New: robust edge-based hotkey detection
    static bool s_endWasDown = false;

    while (true) {
        // Robust END detection: only when game is foreground, not minimized, and on down edge
        bool endPressed = false;
        if (!disableEndHotkey && ShouldAcceptHotkeys()) {
            SHORT state = GetAsyncKeyState(VK_END);
            bool endDown = (state & 0x8000) != 0;      // high bit: currently down
            endPressed = endDown && !s_endWasDown;     // edge detect
            s_endWasDown = endDown;
        } else {
            s_endWasDown = false; // reset when not accepting hotkeys
        }

        const bool uiUnload = (UIManager::HasInstance() && UIManager::IsUnloadRequested());
        const bool minimized = IsGameWindowMinimized();

        if (endPressed) {
            LogInfo("Unloading requested by hotkey (END)");
            break;
        }

        // Respect UI unload when not minimized; defer if minimized
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

    // Centralized cleanup
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
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0x10000, MainThread, hModule, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        // No heavy work here; PerformSafeUnload runs from MainThread or ShutdownThread.
        break;
    }
    return TRUE;
}

static bool IsGameWindowMinimized() {
    HWND hGame = FindWindowW(L"FFXIVGAME", nullptr);
    return hGame ? (IsIconic(hGame) != 0) : false;
}