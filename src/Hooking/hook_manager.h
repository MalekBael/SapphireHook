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

    // Forward declarations
    class ServiceManager;
    struct HookInfo;
    class IHook;

    // Simplified Hook information structure
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

        // Hook validation
        bool is_validated = false;
        std::string validation_error{};

        // Debugging support
        std::vector<uint8_t> original_bytes{};
        size_t hook_size = 0;

        // Constructors
        HookInfo() = default;
        HookInfo(const std::string& hookName, uintptr_t hookAddress,
            const std::string& moduleName = "", const std::string& assemblyName = "");
    };

    // Simplified Hook interface
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

    // Simplified Hook statistics
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

    // Simplified HookManager
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
        // ===== SAFE STATIC VARIABLE ACCESS FUNCTIONS =====
        // These provide thread-safe access to static variables to prevent crash during registration

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

        // Core functionality
        static void Initialize();
        static void Shutdown();

        // Hook management
        static bool RegisterHook(const std::string& name, uintptr_t address, void* original,
            const std::string& assemblyName = "");

        // Address validation and safety
        static bool IsAddressHooked(uintptr_t address);
        static bool ValidateHookAddress(uintptr_t address);

        // Cleanup
        static void CleanupAllHooks();

        // Performance monitoring
        static HookStatistics GetHookStatistics();
        static std::vector<HookInfo> GetDetailedHookInfo();
        static size_t GetTotalCallCount();
        static std::chrono::milliseconds GetTotalExecutionTime();

        // Cache management
        static void SetCacheDirectory(const std::filesystem::path& cacheDir);
        static bool LoadHookCache();

        // Utility functions
        static uintptr_t AddressToRVA(uintptr_t address);
        static bool IsValidHookTarget(uintptr_t address);

        // Service integration
        static void RegisterWithServiceManager();

    private:
        // Internal hook management
        static void UpdateStatistics();

        // Safety and validation
        static bool IsMemoryExecutable(uintptr_t address, size_t size = 16);
        static bool IsAddressInValidRange(uintptr_t address);
    };

    // Forward declarations for hook functions
    bool FindAndHookIPC();
    bool FindAndHookDispatcher();
    const char* GetOpcodeName(uint16_t opcode); // now resolved through centralized OpcodeNames
    
    // Module information utility
    bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize);

    // IPC Hook type definitions
    // FFXIV 3.35 64-bit: sub_140DD9430(thisPtr, actorId, packetData)
    //   - a1 (rcx): thisPtr/handler context
    //   - a2 (edx): actorId/index (unsigned int)
    //   - a3 (r8):  packet data pointer, opcode at *(uint16_t*)(a3+2)
    typedef void(__fastcall* HandleIPC_t)(void* thisPtr, uint32_t actorId, void* packetData);

    // Global variables declarations
    extern float g_SpeedMultiplier;
    extern HandleIPC_t originalHandleIPC;

    // Hook function declarations
    void __fastcall HookedHandleIPC(void* thisPtr, uint32_t actorId, void* packetData);
    
    // ============================================================================
    // Server→Client Packet Injection
    // ============================================================================
    
    /**
     * @brief Inject a server-to-client packet directly into the game's IPC handler
     * @param opcode The IPC opcode to inject
     * @param payload Pointer to the packet payload data
     * @param payloadSize Size of the payload in bytes
     * @return true if injection succeeded, false otherwise
     * 
     * This calls the game's actual IPC handler as if the server sent the packet.
     * The game client will process it normally, triggering UI updates, state changes, etc.
     * 
     * IMPORTANT: The IPC handler must have been called at least once (game received any packet)
     * before this function can be used, as it needs the cached 'thisPtr'.
     */
    bool InjectServerPacket(uint16_t opcode, const void* payload, size_t payloadSize);
    
    /**
     * @brief Check if the IPC handler is ready for packet injection
     * @return true if InjectServerPacket() can be called
     */
    bool IsIPCHandlerReady();
    
    /**
     * @brief Get the cached IPC handler thisPtr (for debugging)
     */
    void* GetCachedIPCThisPtr();

} // namespace SapphireHook

// Global functions for backward compatibility
void InitHooks();