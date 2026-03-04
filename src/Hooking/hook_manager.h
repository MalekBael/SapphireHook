#pragma once
#include "../Logger/Logger.h"
#include "../Core/SafeMemory.h"
#include <unordered_map>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <span>
#include <filesystem>
#include <atomic>
#include <functional>
#include <map>
#include <thread>
#include <optional>

namespace SapphireHook {

    class ServiceManager;
    struct HookInfo;
    class IHook;

    struct HookInfo {
        std::string name{};
        std::string module_name{};
        std::string assembly_name{};
        uintptr_t address = 0;
        uintptr_t rva = 0;
        void* original_function = nullptr;
        void* detour_function = nullptr;
        bool is_enabled = false;
        std::chrono::time_point<std::chrono::steady_clock> created_time = std::chrono::steady_clock::now();

        bool is_validated = false;
        std::string validation_error{};

        std::vector<uint8_t> original_bytes{};
        size_t hook_size = 0;

        HookInfo() = default;
        HookInfo(const std::string& hookName, uintptr_t hookAddress,
            const std::string& moduleName = "", const std::string& assemblyName = "");
    };

    class IHook {
    public:
        virtual ~IHook() = default;
        virtual bool Enable() = 0;
        virtual bool Disable() = 0;
        virtual bool IsEnabled() const = 0;
        virtual bool IsDisposed() const = 0;
        virtual uintptr_t GetAddress() const = 0;
        virtual const std::string& GetName() const = 0;
        virtual void Dispose() = 0;
    };

    struct HookStatistics {
        size_t totalHooks = 0;
        size_t enabledHooks = 0;
        size_t disabledHooks = 0;
        size_t failedHooks = 0;
        std::chrono::system_clock::time_point lastUpdate{};
        std::map<std::string, size_t> hooksByModule{};
        std::map<std::string, size_t> hooksByAssembly{};

        HookStatistics() = default;
        void Update(const std::vector<HookInfo>& hooks);
        std::string ToDebugString() const;
    };

    class HookManager {
    private:
        static inline std::unordered_map<std::string, std::unique_ptr<HookInfo>> s_tracked_hooks;
        static inline std::unordered_map<uintptr_t, std::string> s_address_to_name;
        static inline std::mutex s_hooks_mutex;
        static inline HookStatistics s_statistics;
        static inline std::atomic<bool> s_shutdown_in_progress;
        static inline std::filesystem::path s_cache_directory;
        static inline std::map<std::string, uintptr_t> s_cached_addresses;

    public:
        static std::unordered_map<std::string, std::unique_ptr<HookInfo>>& GetTrackedHooks()
        {
            return s_tracked_hooks;
        }

        static std::unordered_map<uintptr_t, std::string>& GetAddressToName()
        {
            return s_address_to_name;
        }

        static std::mutex& GetHooksMutex()
        {
            return s_hooks_mutex;
        }

        static HookStatistics& GetStatistics()
        {
            return s_statistics;
        }

        static std::atomic<bool>& GetShutdownFlag()
        {
            return s_shutdown_in_progress;
        }

        static std::filesystem::path& GetCacheDirectory()
        {
            return s_cache_directory;
        }

        static std::map<std::string, uintptr_t>& GetCachedAddresses()
        {
            return s_cached_addresses;
        }

        static void Initialize();
        static void Shutdown();

        static bool RegisterHook(const std::string& name, uintptr_t address, void* original,
            const std::string& assemblyName = "");

        static bool IsAddressHooked(uintptr_t address);
        static bool ValidateHookAddress(uintptr_t address);

        static void CleanupAllHooks();

        static HookStatistics GetHookStatistics();
        static std::vector<HookInfo> GetDetailedHookInfo();
        static size_t GetTotalCallCount();
        static std::chrono::milliseconds GetTotalExecutionTime();

        static void SetCacheDirectory(const std::filesystem::path& cacheDir);
        static bool LoadHookCache();

        static uintptr_t AddressToRVA(uintptr_t address);
        static bool IsValidHookTarget(uintptr_t address);

        static void RegisterWithServiceManager();

    private:
        static void UpdateStatistics();

        static bool IsMemoryExecutable(uintptr_t address, size_t size = 16);
        static bool IsAddressInValidRange(uintptr_t address);
    };

    bool FindAndHookIPC();
    bool FindAndHookDispatcher();
    const char* GetOpcodeName(uint16_t opcode);      
    
    bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize);

    typedef void(__fastcall* HandleIPC_t)(void* thisPtr, uint32_t actorId, void* packetData);

    extern float g_SpeedMultiplier;
    extern HandleIPC_t originalHandleIPC;

    void __fastcall HookedHandleIPC(void* thisPtr, uint32_t actorId, void* packetData);
    
    bool InjectServerPacket(uint16_t opcode, const void* payload, size_t payloadSize);
    
    bool IsIPCHandlerReady();
    
    void* GetCachedIPCThisPtr();

}   

void InitHooks();