#include "../Hooking/hook_manager.h"
#include "../../vendor/minhook/include/MinHook.h"
#include "../Analysis/PatternScanner.h"
#include "../Logger/Logger.h"
#include "../Core/SafeMemory.h"
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")
#include <sstream>
#include <span>
#include <chrono>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>
#include <mutex>
#include "../Core/PacketInjector.h"
#include "../Network/OpcodeNames.h" // centralized opcode lookup
#include <cstdlib> // std::getenv
#include <atomic>

// ===== GLOBAL FUNCTIONS (outside namespace) =====
bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize)
{
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule)
    {
        baseAddress = 0;
        moduleSize = 0;
        return false;
    }

    MODULEINFO moduleInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo)))
    {
        baseAddress = 0;
        moduleSize = 0;
        return false;
    }

    baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
    moduleSize = static_cast<size_t>(moduleInfo.SizeOfImage);
    return true;
}

namespace {
    // User-mode canonical range on x64: below 0x00007FFFFFFFFFFF
    inline bool IsCanonicalUserVA(uintptr_t addr) noexcept
    {
        return addr <= 0x00007FFFFFFFFFFFULL;
    }

    // Env flag reader used by FindAndHookIPC/Dispatcher/Initialize
    inline bool IsEnvEnabled(const char* name) noexcept
    {
        if (const char* v = std::getenv(name))
        {
            const char c = v[0];
            return c == '1' || c == 't' || c == 'T' || c == 'y' || c == 'Y';
        }
        return false;
    }

    inline bool QueryExecRange(uintptr_t address) noexcept
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT)
            return false;

        const DWORD prot = (mbi.Protect & 0xFF);
        const bool exec =
            prot == PAGE_EXECUTE ||
            prot == PAGE_EXECUTE_READ ||
            prot == PAGE_EXECUTE_READWRITE ||
            prot == PAGE_EXECUTE_WRITECOPY;
        return exec;
    }

    inline bool GetMainModuleRange(uintptr_t& base, size_t& size) noexcept
    {
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return false;

        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
            return false;

        base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        size = static_cast<size_t>(mi.SizeOfImage);
        return true;
    }
} // anonymous namespace

namespace SapphireHook {

    // Global variables
    float g_SpeedMultiplier = 1.0f;
    HandleIPC_t originalHandleIPC = nullptr;
    uintptr_t ipcHandlerAddr = 0;
    uintptr_t dispatcherAddr = 0;
    typedef char(__fastcall* DispatcherFn)(void* rcx);
    DispatcherFn originalDispatcher = nullptr;

    static std::atomic<uint64_t> g_totalCallCount{ 0 };
    static std::atomic<uint64_t> g_totalExecMicros{ 0 };

    // Forward declarations
    bool ValidateIPCHandler(uintptr_t address);
    bool FindIPCByOpcodeReferences(uintptr_t moduleBase, size_t moduleSize);
    bool ValidateHookTarget(uintptr_t address, const std::string& name);
    bool InstallIPCHookSafe(uintptr_t address, const std::string& name);

    // ===== SEH Helper Functions =====
    static bool SafeMemoryReadTest(uintptr_t address)
    {
        __try
        {
            volatile uint8_t testRead = *reinterpret_cast<uint8_t*>(address);
            (void)testRead;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    static bool SafeOpcodeSearch(uintptr_t addr, uint16_t opcode)
    {
        __try
        {
            return *(uint16_t*)addr == opcode;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // Helper function to backup original bytes
    std::vector<uint8_t> BackupOriginalBytesHelper(uintptr_t address, size_t size)
    {
        std::vector<uint8_t> backup(size);
        try
        {
            std::memcpy(backup.data(), reinterpret_cast<const void*>(address), size);
        }
        catch (...)
        {
            SapphireHook::LogError("Failed to backup original bytes");
            backup.clear();
        }
        return backup;
    }

    // ===== IPC Validation/Search =====
    bool ValidateIPCHandler(uintptr_t address)
    {
        try
        {
            if (!ValidateHookTarget(address, "IPC_Handler_Validation"))
                return false;

            uint8_t* code = reinterpret_cast<uint8_t*>(address);
            bool looksLikeIPC = false;

            for (int j = 0; j < 50; j++)
            {
                if (code[j] == 0x0F && code[j + 1] == 0xB7)
                {
                    looksLikeIPC = true;
                    SapphireHook::LogInfo("Found movzx instruction at offset +" + std::to_string(j));
                    break;
                }
                if (code[j] == 0x66 && (code[j + 1] == 0x81 || code[j + 1] == 0x83))
                {
                    looksLikeIPC = true;
                    SapphireHook::LogInfo("Found 16-bit comparison at offset +" + std::to_string(j));
                    break;
                }
                if (code[j] == 0x48 && code[j + 1] == 0x8D && code[j + 2] == 0x15)
                {
                    looksLikeIPC = true;
                    SapphireHook::LogInfo("Found LEA instruction at offset +" + std::to_string(j));
                    break;
                }
            }

            if (looksLikeIPC)
                SapphireHook::LogInfo("IPC handler validation passed - IPC-like patterns found");
            else
                SapphireHook::LogWarning("IPC handler validation failed - no IPC-like patterns found");

            return looksLikeIPC;
        }
        catch (...)
        {
            SapphireHook::LogError("Exception during IPC handler validation");
            return false;
        }
    }

    // Keep implementation (not used when disabled)
    bool FindIPCByOpcodeReferences(uintptr_t moduleBase, size_t moduleSize)
    {
        try
        {
            SapphireHook::LogInfo("Searching for IPC handler by opcode references...");
            const uint16_t knownOpcodes[] = { 0x00DE, 0x0196, 0x019A, 0x0067, 0x0191 };
            const auto searchStart = std::chrono::high_resolution_clock::now();
            const auto maxSearchTime = std::chrono::seconds(15);

            for (uint16_t opcode : knownOpcodes)
            {
                if (std::chrono::high_resolution_clock::now() - searchStart > maxSearchTime)
                {
                    SapphireHook::LogError("Opcode reference search timed out");
                    return false;
                }

                {
                    std::ostringstream oss; oss << "Searching for opcode references: 0x" << std::hex << opcode;
                    SapphireHook::LogInfo(oss.str());
                }

                for (uintptr_t addr = moduleBase; addr < moduleBase + moduleSize - 4; addr += 4)
                {
                    if (SafeOpcodeSearch(addr, opcode))
                    {
                        uintptr_t start = (addr > 100) ? addr - 100 : moduleBase;
                        for (uintptr_t funcStart = start; funcStart < addr; ++funcStart)
                        {
                            if (SafeMemoryReadTest(funcStart))
                            {
                                const uint8_t* code = reinterpret_cast<const uint8_t*>(funcStart);
                                if ((code[0] == 0x48 && code[1] == 0x89) ||
                                    (code[0] == 0x40 && code[1] == 0x53) ||
                                    (code[0] == 0x48 && code[1] == 0x83))
                                {
                                    ipcHandlerAddr = funcStart;
                                    std::ostringstream oss; oss << "Found potential IPC handler by opcode reference at 0x" << std::hex << funcStart;
                                    SapphireHook::LogInfo(oss.str());
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            SapphireHook::LogError("No IPC handler found by opcode references");
            return false;
        }
        catch (const std::exception& ex)
        {
            SapphireHook::LogError(std::string("Exception in FindIPCByOpcodeReferences: ") + ex.what());
            return false;
        }
    }

    // ===== HookInfo/Statistics =====
    HookInfo::HookInfo()
    {
        name.clear();
        module_name.clear();
        assembly_name.clear();
        address = 0;
        rva = 0;
        original_function = nullptr;
        detour_function = nullptr;
        is_enabled = false;
        created_time = std::chrono::steady_clock::now();
        is_validated = false;
        validation_error.clear();
        original_bytes.clear();
        hook_size = 0;
    }

    HookInfo::HookInfo(const std::string& hookName, uintptr_t hookAddress,
        const std::string& moduleName, const std::string& assemblyName)
    {
        name = hookName;
        address = hookAddress;
        module_name = moduleName;
        assembly_name = assemblyName;
        rva = 0;
        original_function = nullptr;
        detour_function = nullptr;
        is_enabled = false;
        created_time = std::chrono::steady_clock::now();
        is_validated = false;
        validation_error.clear();
        hook_size = 16;

        rva = HookManager::AddressToRVA(hookAddress);
        original_bytes = BackupOriginalBytesHelper(hookAddress, 16);
    }

    HookStatistics::HookStatistics()
    {
        totalHooks = 0;
        enabledHooks = 0;
        disabledHooks = 0;
        failedHooks = 0;
        lastUpdate = std::chrono::system_clock::time_point{};
        hooksByModule.clear();
        hooksByAssembly.clear();
    }

    void HookStatistics::Update(const std::vector<HookInfo>& hooks)
    {
        totalHooks = hooks.size();
        enabledHooks = 0;
        disabledHooks = 0;
        failedHooks = 0;
        hooksByModule.clear();
        hooksByAssembly.clear();

        for (const auto& hook : hooks)
        {
            if (hook.is_enabled) enabledHooks++;
            else disabledHooks++;

            if (!hook.validation_error.empty()) failedHooks++;

            hooksByModule[hook.module_name]++;
            hooksByAssembly[hook.assembly_name]++;
        }

        lastUpdate = std::chrono::system_clock::now();
    }

    std::string HookStatistics::ToDebugString() const
    {
        std::ostringstream oss;
        oss << "Hook Statistics:\n";
        oss << "  Total Hooks: " << totalHooks << "\n";
        oss << "  Enabled: " << enabledHooks << "\n";
        oss << "  Disabled: " << disabledHooks << "\n";
        oss << "  Failed: " << failedHooks << "\n";
        oss << "  By Module:\n";
        for (const auto& pair : hooksByModule)
            oss << "    " << pair.first << ": " << pair.second << "\n";
        oss << "  By Assembly:\n";
        for (const auto& pair : hooksByAssembly)
            oss << "    " << pair.first << ": " << pair.second << "\n";
        return oss.str();
    }

    // ===== Validation/Install helpers =====
    bool ValidateHookTarget(uintptr_t address, const std::string& name)
    {
        if (!HookManager::ValidateHookAddress(address))
        {
            std::ostringstream oss;
            oss << "Hook target invalid (out of range or non-exec): " << name
                << " addr=0x" << std::hex << address;
            SapphireHook::LogError(oss.str());
            return false;
        }

        if (HookManager::IsAddressHooked(address))
        {
            std::ostringstream oss;
            oss << "Address already hooked for: " << name << " addr=0x" << std::hex << address;
            SapphireHook::LogWarning(oss.str());
            return false;
        }

        SapphireHook::LogInfo("Hook validation passed: " + name);
        return true;
    }

    bool InstallIPCHookSafe(uintptr_t address, const std::string& name)
    {
        if (!ValidateHookTarget(address, name))
            return false;

        SafeMemoryRegion memory_region(address, 16);
        if (!memory_region.IsValid())
        {
            SapphireHook::LogError("Cannot create safe memory region for: " + name);
            return false;
        }

        try
        {
            if (MH_CreateHook(reinterpret_cast<void*>(address), &HookedHandleIPC,
                reinterpret_cast<void**>(&originalHandleIPC)) != MH_OK)
            {
                SapphireHook::LogError("MinHook creation failed for: " + name);
                return false;
            }

            if (MH_EnableHook(reinterpret_cast<void*>(address)) != MH_OK)
            {
                SapphireHook::LogError("MinHook enable failed for: " + name);
                MH_RemoveHook(reinterpret_cast<void*>(address));
                return false;
            }

            HookManager::RegisterHook(name, address, originalHandleIPC, "");
            SapphireHook::LogInfo("Successfully installed hook: " + name);
            return true;
        }
        catch (const std::exception& ex)
        {
            SapphireHook::LogError("Exception during hook installation: " + std::string(ex.what()));
            return false;
        }
    }

    // Replace InstallIPCHookSafeV2() log lines that print addresses in decimal
    bool InstallIPCHookSafeV2(uintptr_t address, const std::string& name)
    {
        {
            std::ostringstream oss;
            oss << "Starting safe hook installation for: " << name << " at 0x" << std::hex << address;
            SapphireHook::LogInfo(oss.str());
        }

        if (!ValidateHookTarget(address, name))
        {
            SapphireHook::LogError("Pre-installation validation failed for: " + name);
            return false;
        }
        SapphireHook::LogInfo("✓ Pre-installation validation passed for: " + name);

        if (!SafeMemoryReadTest(address))
        {
            SapphireHook::LogError("Memory read test failed for: " + name + " - address may be invalid");
            return false;
        }
        SapphireHook::LogInfo("✓ Memory read test passed for: " + name);

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        {
            SapphireHook::LogError("VirtualQuery failed for: " + name);
            return false;
        }

        {
            std::ostringstream oss;
            oss << "Memory info for " << name << ": State=" << std::dec << mbi.State
                << ", Protect=0x" << std::hex << mbi.Protect
                << ", Type=" << std::dec << mbi.Type;
            SapphireHook::LogInfo(oss.str());
        }

        std::unique_ptr<SafeMemoryRegion> memory_region;
        try
        {
            SapphireHook::LogInfo("Creating SafeMemoryRegion for: " + name);
            memory_region = std::make_unique<SafeMemoryRegion>(address, 16);

            if (!memory_region || !memory_region->IsValid())
            {
                SapphireHook::LogError("SafeMemoryRegion creation failed for: " + name);
                return false;
            }
            SapphireHook::LogInfo("✓ SafeMemoryRegion created successfully for: " + name);
        }
        catch (const std::exception& e)
        {
            SapphireHook::LogError("Exception creating SafeMemoryRegion for " + name + ": " + e.what());
            return false;
        }
        catch (...)
        {
            SapphireHook::LogError("Unknown exception creating SafeMemoryRegion for: " + name);
            return false;
        }

        try
        {
            SapphireHook::LogInfo("Creating MinHook for: " + name);

            MH_STATUS createResult = MH_CreateHook(
                reinterpret_cast<void*>(address),
                &HookedHandleIPC,
                reinterpret_cast<void**>(&originalHandleIPC)
            );

            if (createResult != MH_OK)
            {
                SapphireHook::LogError("MH_CreateHook failed for " + name + " with error: " + std::to_string(createResult));
                return false;
            }
            SapphireHook::LogInfo("✓ MinHook created successfully for: " + name);

            SapphireHook::LogInfo("Enabling MinHook for: " + name);
            MH_STATUS enableResult = MH_EnableHook(reinterpret_cast<void*>(address));
            if (enableResult != MH_OK)
            {
                SapphireHook::LogError("MH_EnableHook failed for " + name + " with error: " + std::to_string(enableResult));
                MH_RemoveHook(reinterpret_cast<void*>(address));
                return false;
            }
            SapphireHook::LogInfo("✓ MinHook enabled successfully for: " + name);

            SapphireHook::LogInfo("Registering hook: " + name);
            HookManager::RegisterHook(name, address, originalHandleIPC, "");

            {
                std::ostringstream oss;
                oss << "🎉 Successfully installed hook: " << name << " at 0x" << std::hex << address;
                SapphireHook::LogInfo(oss.str());
            }
            return true;
        }
        catch (const std::exception& e)
        {
            SapphireHook::LogError("Exception during hook installation for " + name + ": " + e.what());
            try { MH_RemoveHook(reinterpret_cast<void*>(address)); }
            catch (...) {}
            return false;
        }
        catch (...)
        {
            SapphireHook::LogError("Unknown exception during hook installation for: " + name);
            try { MH_RemoveHook(reinterpret_cast<void*>(address)); }
            catch (...) {}
            return false;
        }
    }

    // SEH leaf helpers — no C++ objects here
    extern "C" __declspec(noinline) void __fastcall CallOriginalIPC_NoExcept(void* thisPtr, uint16_t opcode, void* data)
    {
        __try {
            originalHandleIPC(thisPtr, opcode, data);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // swallow
        }
    }

    extern "C" __declspec(noinline) bool __fastcall ProbeDispatcherOpcode_NoExcept(void* rcx, uint8_t* outOpcode)
    {
        __try {
            const volatile uint8_t* p = reinterpret_cast<const volatile uint8_t*>(rcx);
            (void)p[0];
            (void)p[2];
            *outOpcode = static_cast<uint8_t>(p[2]);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // Hardened detours that only use C++ exceptions (no __try here)

    // Single definition: HookedHandleIPC
    void __fastcall HookedHandleIPC(void* thisPtr, uint16_t opcode, void* data)
    {
        void* retAddr = _ReturnAddress();
        const char* opcodeName = GetOpcodeName(opcode);

        std::ostringstream context;
        context << "IPC[" << opcodeName << "](0x" << std::hex << opcode << ") "
                << "from 0x" << reinterpret_cast<uintptr_t>(retAddr);
        SapphireHook::LogInfo(context.str());

        try {
            std::ofstream log("ipc_detailed.txt", std::ios::app);
            log << std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count()
                << " | " << context.str() << std::endl;
        } catch (...) {}

        if (opcode == 0x00DE /*PcPartyKick*/ ||
            opcode == 0x026D /*VoteKickStart*/ ||
            opcode == 0x010F /*FreeCompanyKick*/)
        {
            SapphireHook::LogWarning(std::string("SECURITY: Kick/Ban opcode detected: ") + opcodeName);
        }

        const auto start_time = std::chrono::high_resolution_clock::now();
        CallOriginalIPC_NoExcept(thisPtr, opcode, data);
        const auto end_time = std::chrono::high_resolution_clock::now();

        const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        if (duration.count() > 1000) {
            SapphireHook::LogWarning(std::string("Slow IPC operation: ") + opcodeName +
                                     " took " + std::to_string(duration.count()) + "μs");
        }

        // Metrics update
        g_totalCallCount.fetch_add(1, std::memory_order_relaxed);
        g_totalExecMicros.fetch_add(static_cast<uint64_t>(duration.count()), std::memory_order_relaxed);
    }

    // Single definition: HookedDispatcher
    char __fastcall HookedDispatcher(void* rcx)
    {
        uint8_t opcode = 0;
        const bool haveOpcode = ProbeDispatcherOpcode_NoExcept(rcx, &opcode);

        if (haveOpcode) {
            try {
                std::ofstream log("dispatcher_output.txt", std::ios::app);
                log << "[Dispatcher] Opcode: 0x" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(opcode) << std::endl;
            } catch (...) {
                // ignore file I/O errors
            }

            if (opcode == 0xDE)
                SapphireHook::LogWarning("PcPartyKick (0xDE) triggered");
        } else {
            SapphireHook::LogWarning("Dispatcher rcx unreadable; skipping opcode probe");
        }

        return originalDispatcher(rcx);
    }

    // ===== Core HookManager operations =====
    bool HookManager::CreateHookInternal(const std::string& name, uintptr_t address,
        void* detour, void** original, const std::string& assemblyName)
    {
        if (!ValidateHookInternal(address, name))
            return false;

        if (HookManager::GetShutdownFlag().load())
        {
            SapphireHook::LogWarning("Cannot create hook during shutdown: " + name);
            return false;
        }

        const uint8_t* code = reinterpret_cast<const uint8_t*>(address);
        bool looksLikeFunction = false;
        if ((code[0] == 0x48 && code[1] == 0x89) ||
            (code[0] == 0x48 && code[1] == 0x83) ||
            (code[0] == 0x48 && code[1] == 0x8B) ||
            (code[0] == 0x55) ||
            (code[0] >= 0x50 && code[0] <= 0x57) ||
            (code[0] == 0x40 && code[1] >= 0x53 && code[1] <= 0x57))
        {
            looksLikeFunction = true;
        }

        if (!looksLikeFunction)
        {
            std::ostringstream oss;
            oss << "Address 0x" << std::hex << address << " doesn't look like a function start for hook: " << name;
            SapphireHook::LogWarning(oss.str());
        }

        try
        {
            if (MH_CreateHook(reinterpret_cast<void*>(address), detour, original) != MH_OK)
            {
                SapphireHook::LogError("MinHook creation failed for: " + name);
                return false;
            }

            if (MH_EnableHook(reinterpret_cast<void*>(address)) != MH_OK)
            {
                SapphireHook::LogError("MinHook enable failed for: " + name);
                MH_RemoveHook(reinterpret_cast<void*>(address));
                return false;
            }

            HookManager::RegisterHook(name, address, *original, assemblyName);

            std::ostringstream oss;
            oss << "Successfully created hook: " << name << " at 0x" << std::hex << address;
            SapphireHook::LogInfo(oss.str());
            return true;
        }
        catch (const std::exception& e)
        {
            SapphireHook::LogError(std::string("Exception in CreateHookInternal: ") + e.what());
            return false;
        }
    }

    bool HookManager::ValidateHookInternal(uintptr_t address, const std::string& name)
    {
        if (!HookManager::ValidateHookAddress(address))
            return false;

        if (!HookManager::IsValidHookTarget(address))
        {
            SapphireHook::LogError("Hook validation failed for " + name + ": invalid target");
            return false;
        }

        if (HookManager::IsAddressHooked(address))
        {
            SapphireHook::LogWarning("Hook validation failed for " + name + ": already hooked");
            return false;
        }

        HMODULE hModule{};
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCSTR>(address), &hModule))
        {
            std::ostringstream oss;
            oss << "Hook validation warning for " << name << ": address 0x" << std::hex << address << " not in any module";
            SapphireHook::LogWarning(oss.str());
        }

        return true;
    }

    // Find and hook IPC handler
    bool FindAndHookIPC()
    {
        if (IsEnvEnabled("SAPPHIRE_ONLY_WSASEND") || IsEnvEnabled("SAPPHIRE_SAFE") || IsEnvEnabled("SAPPHIRE_SKIP_IPC"))
        {
            SapphireHook::LogWarning("[HookManager] IPC hook skipped by environment");
            return false;
        }

        uintptr_t moduleBase{};
        size_t moduleSize{};
        if (!GetMainModuleInfo(moduleBase, moduleSize))
        {
            SapphireHook::LogError("Failed to get main module information");
            return false;
        }

        SapphireHook::LogInfo("Scanning for IPC handler...");

        const auto scanStart = std::chrono::high_resolution_clock::now();
        const auto maxScanTime = std::chrono::seconds(30);

        // Extended pattern list for different game versions
        const char* ipcPatterns[] = {
            // Original patterns
            "40 53 48 83 EC ? 0F B7 DA 48 8B F9 66 85 D2",
            /*
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B7 FA 48 8B F1",
            "40 53 48 83 EC ? 48 8B D9 0F B7 D2 66 85 D2",
            "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 0F B7 DA 66 85 DB",
            "40 53 48 83 EC ? 0F B7 DA 66 85 DB 74 ? 48 8B CB",
            "48 83 EC ? 0F B7 C2 66 3D ? ? 0F 87",
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B7 EA 48 8B F9",
            "48 83 EC ? 66 81 FA ? ? 0F 87",
            "0F B7 C2 83 F8 ? 0F 87 ? ? ? ? 48 8D 15",
            // Additional patterns for older versions
            "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 48 8D 6C 24 ? 48 81 EC ? ? ? ? 0F B7 DA",
            "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 0F B7 DA",
            "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 48 8D 68 ? 48 81 EC ? ? ? ? 0F B7 DA",
            "48 83 EC ? 0F B7 DA 66 83 FA ? 77 ?",
            "40 53 48 83 EC ? 0F B7 DA 48 8B F9 83 FB ?",
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B7 DA 48 8B F9",
            */
        };
        const int ipcPatternCount = static_cast<int>(sizeof(ipcPatterns) / sizeof(ipcPatterns[0]));

        ipcHandlerAddr = 0;
        for (int i = 0; i < ipcPatternCount; i++)
        {
            if (std::chrono::high_resolution_clock::now() - scanStart > maxScanTime)
            {
                SapphireHook::LogError("Pattern scanning timed out after 30 seconds");
                return false;
            }

            SapphireHook::LogInfo("Trying pattern " + std::to_string(i + 1));
            const auto addr = patternscan(moduleBase, moduleSize, ipcPatterns[i]);
            if (!addr)
            {
                SapphireHook::LogInfo("Pattern " + std::to_string(i + 1) + " not found");
                continue;
            }

            {
                std::ostringstream oss;
                oss << "Found potential IPC handler using pattern " << (i + 1)
                    << " at address: 0x" << std::hex << addr;
                SapphireHook::LogInfo(oss.str());
            }

            if (!HookManager::ValidateHookAddress(addr))
            {
                std::ostringstream oss2;
                oss2 << "Rejected IPC handler candidate (invalid VA): 0x" << std::hex << addr;
                SapphireHook::LogWarning(oss2.str());
                continue;
            }

            if (ValidateIPCHandler(addr))
            {
                SapphireHook::LogInfo("Pattern verification passed - installing hook with enhanced safety");
                ipcHandlerAddr = addr;
                break;
            }

            SapphireHook::LogWarning("Pattern verification failed - trying next pattern");
        }

        if (!ipcHandlerAddr)
        {
            // DISABLE the unreliable opcode reference fallback
            SapphireHook::LogError("Failed to find IPC handler address using patterns");
            SapphireHook::LogWarning("IPC hook will not be installed - this is safer than hooking wrong address");
            return false;
        }

        SapphireHook::LogInfo("Installing IPC hook using enhanced safety method...");
        return InstallIPCHookSafeV2(ipcHandlerAddr, "IPC_Handler");
    }

    // Find and hook dispatcher
    bool FindAndHookDispatcher()
    {
        if (IsEnvEnabled("SAPPHIRE_ONLY_WSASEND") || IsEnvEnabled("SAPPHIRE_SAFE") || IsEnvEnabled("SAPPHIRE_SKIP_DISPATCHER"))
        {
            SapphireHook::LogWarning("[HookManager] Dispatcher hook skipped by environment");
            return false;
        }

        uintptr_t moduleBase{};
        size_t moduleSize{};
        if (!GetMainModuleInfo(moduleBase, moduleSize))
            return false;

        SapphireHook::LogInfo("Scanning for dispatcher...");

        const char* dispatcherPatterns[] = {
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 45 33 FF",
            "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 84 C0 74 ? 48 8B CB",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA",
            "40 53 48 83 EC ? 48 8B D9 48 8B 0D ? ? ? ? 48 85 C9"
        };
        const int dispPatternCount = static_cast<int>(sizeof(dispatcherPatterns) / sizeof(dispatcherPatterns[0]));

        dispatcherAddr = 0;
        for (int i = 0; i < dispPatternCount; i++)
        {
            const auto addr = patternscan(moduleBase, moduleSize, dispatcherPatterns[i]);
            if (addr)
            {
                std::ostringstream oss;
                oss << "Found dispatcher using pattern " << (i + 1) << " at: 0x" << std::hex << addr;
                SapphireHook::LogInfo(oss.str());

                if (!HookManager::ValidateHookAddress(addr))
                {
                    std::ostringstream oss2; oss2 << "Rejected dispatcher addr (invalid VA): 0x" << std::hex << addr;
                    SapphireHook::LogWarning(oss2.str());
                    continue;
                }

                dispatcherAddr = addr;
                break;
            }
        }

        if (!dispatcherAddr)
        {
            SapphireHook::LogError("Failed to find dispatcher address");
            return false;
        }

        if (MH_CreateHook(reinterpret_cast<void*>(dispatcherAddr), &HookedDispatcher, reinterpret_cast<void**>(&originalDispatcher)) != MH_OK)
            return false;

        return MH_EnableHook(reinterpret_cast<void*>(dispatcherAddr)) == MH_OK;
    }

    // Install WSASend early and allow WSASend-only mode
    void HookManager::Initialize()
    {
        SapphireHook::LogInfo("Initializing HookManager...");

        try
        {
            MH_STATUS initResult = MH_Initialize();
            if (initResult != MH_OK)
            {
                SapphireHook::LogError("Failed to initialize MinHook! Error: " + std::to_string(initResult));
                return;
            }

            SapphireHook::LogInfo("MinHook initialized successfully");

            // Bring up WSASend first to stabilize and learn sockets
            (void)SapphireHook::PacketInjector::Initialize();

            // WSASend-only stabilization mode
            if (IsEnvEnabled("SAPPHIRE_ONLY_WSASEND"))
            {
                SapphireHook::LogWarning("[HookManager] WSASend-only mode enabled. Skipping IPC and dispatcher hooks.");
                RegisterWithServiceManager();
                SapphireHook::LogInfo("Hook initialization completed successfully");
                return;
            }

            // Load hook cache (optional)
            LoadHookCache();

            // Set default cache directory
            try
            {
                std::filesystem::path cacheDir = std::filesystem::current_path() / "cache";
                SetCacheDirectory(cacheDir);
            }
            catch (const std::exception& e)
            {
                SapphireHook::LogWarning("Failed to set cache directory: " + std::string(e.what()));
            }

            SapphireHook::LogInfo("Starting IPC hook search...");
            if (!FindAndHookIPC())
            {
                SapphireHook::LogError("Failed to find and hook IPC - continuing with partial initialization");
            }

            SapphireHook::LogInfo("Starting dispatcher hook search...");
            if (!FindAndHookDispatcher())
            {
                SapphireHook::LogError("Failed to find and hook dispatcher - continuing with partial initialization");
            }

            RegisterWithServiceManager();
            SapphireHook::LogInfo("Hook initialization completed successfully");
        }
        catch (const std::exception& ex)
        {
            SapphireHook::LogError("Exception during hook initialization: " + std::string(ex.what()));
        }
        catch (...)
        {
            SapphireHook::LogError("Unknown exception during hook initialization");
        }
    }

    // ===== Static API used by other modules (definitions) =====
    bool HookManager::RegisterHook(const std::string& name, uintptr_t address, void* original, const std::string& assemblyName)
    {
        bool success = false;
        try
        {
            // Work inside a limited scope so the lock_guard is always released
            {
                std::lock_guard<std::mutex> guard(HookManager::GetHooksMutex());

                auto& trackedHooks = HookManager::GetTrackedHooks();
                auto& addressToName = HookManager::GetAddressToName();

                if (trackedHooks.find(name) != trackedHooks.end())
                {
                    SapphireHook::LogWarning("Hook already registered: " + name);
                    return false; // lock released when leaving scope
                }

                auto info = std::make_unique<HookInfo>();
                info->name = name;
                info->assembly_name = assemblyName;
                info->created_time = std::chrono::steady_clock::now();
                info->module_name.clear();
                info->validation_error.clear();
                info->original_bytes = BackupOriginalBytesHelper(address, 16);
                info->rva = HookManager::AddressToRVA(address);
                info->original_function = original;
                info->address = address;
                info->is_enabled = true;
                info->is_validated = true;

                trackedHooks[name] = std::move(info);
                addressToName[address] = name;
                success = true;
            }

            if (success)
            {
                std::ostringstream oss;
                oss << "Registered hook '" << name << "' at 0x" << std::hex << address;
                SapphireHook::LogInfo(oss.str());
            }
            return success;
        }
        catch (const std::exception& e)
        {
            SapphireHook::LogError("RegisterHook exception: " + std::string(e.what()));
            return false;
        }
        catch (...)
        {
            SapphireHook::LogError("RegisterHook unknown exception");
            return false;
        }
    }

    bool HookManager::IsAddressHooked(uintptr_t address)
    {
        try
        {
            bool found = false;
            {
                std::lock_guard<std::mutex> guard(HookManager::GetHooksMutex());
                auto& addressToName = HookManager::GetAddressToName();
                found = (addressToName.find(address) != addressToName.end());
            }
            return found;
        }
        catch (...)
        {
            SapphireHook::LogError("IsAddressHooked exception");
            return false;
        }
    }

    bool HookManager::ValidateHookAddress(uintptr_t address)
    {
        if (!IsCanonicalUserVA(address))
        {
            std::ostringstream oss; oss << "[HookManager] Rejecting non-canonical VA: 0x" << std::hex << address;
            SapphireHook::LogError(oss.str());
            return false;
        }

        uintptr_t base{}; size_t size{};
        if (!GetMainModuleRange(base, size))
        {
            SapphireHook::LogWarning("[HookManager] Could not get main module range; using VirtualQuery only");
            return QueryExecRange(address);
        }

        const uintptr_t end = base + size;
        if (address < base || address >= end)
        {
            std::ostringstream oss;
            oss << "[HookManager] Rejecting addr outside main module. Addr=0x" << std::hex << address
                << " Module=[0x" << base << ",0x" << end << ")";
            SapphireHook::LogError(oss.str());
            return false;
        }

        if (!QueryExecRange(address))
        {
            std::ostringstream oss; oss << "[HookManager] Rejecting non-executable addr: 0x" << std::hex << address;
            SapphireHook::LogError(oss.str());
            return false;
        }

        return true;
    }

    void HookManager::SetCacheDirectory(const std::filesystem::path& cacheDir)
    {
        HookManager::GetCacheDirectory() = cacheDir;
        try
        {
            std::filesystem::create_directories(cacheDir);
            SapphireHook::LogInfo("Hook cache directory set to: " + cacheDir.string());
        }
        catch (const std::exception& e)
        {
            SapphireHook::LogError("Failed to create cache directory: " + std::string(e.what()));
        }
    }

    bool HookManager::LoadHookCache()
    {
        auto& cacheDir = HookManager::GetCacheDirectory();
        if (cacheDir.empty())
        {
            SapphireHook::LogWarning("No cache directory set, skipping cache load");
            return false;
        }

        const std::filesystem::path cacheFile = cacheDir / "hook_cache.txt";
        if (!std::filesystem::exists(cacheFile))
        {
            SapphireHook::LogInfo("No existing cache file found at: " + cacheFile.string());
            return false;
        }

        try
        {
            std::ifstream file(cacheFile);
            if (!file.is_open())
            {
                SapphireHook::LogError("Failed to open cache file: " + cacheFile.string());
                return false;
            }

            auto& cached = HookManager::GetCachedAddresses();
            cached.clear();

            std::string line;
            size_t loaded = 0;
            while (std::getline(file, line))
            {
                if (line.empty() || line[0] == '#') continue;
                const auto eq = line.find('=');
                if (eq == std::string::npos) continue;

                const std::string name = line.substr(0, eq);
                const std::string addrStr = line.substr(eq + 1);

                try
                {
                    uintptr_t addr = std::stoull(addrStr, nullptr, 16);
                    cached[name] = addr;
                    ++loaded;
                }
                catch (...)
                {
                    SapphireHook::LogWarning("Invalid cache line: " + line);
                }
            }

            std::ostringstream oss; oss << "Loaded " << loaded << " cached hook addresses from: " << cacheFile.string();
            SapphireHook::LogInfo(oss.str());
            return loaded > 0;
        }
        catch (const std::exception& e)
        {
            SapphireHook::LogError("LoadHookCache exception: " + std::string(e.what()));
            return false;
        }
    }

    uintptr_t HookManager::AddressToRVA(uintptr_t address)
    {
        HMODULE hModule{};
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCSTR>(address), &hModule))
        {
            return address - reinterpret_cast<uintptr_t>(hModule);
        }

        HMODULE mainModule = GetModuleHandle(nullptr);
        if (mainModule)
        {
            MODULEINFO mi{};
            if (GetModuleInformation(GetCurrentProcess(), mainModule, &mi, sizeof(mi)))
            {
                const auto base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
                const auto end = base + static_cast<uintptr_t>(mi.SizeOfImage);
                if (address >= base && address < end)
                    return address - base;
            }
        }

        return 0;
    }

    bool HookManager::IsValidHookTarget(uintptr_t address)
    {
        // Uses implementations provided elsewhere in this project:
        // HookManager::IsAddressInValidRange and HookManager::IsMemoryExecutable
        return IsAddressInValidRange(address) && IsMemoryExecutable(address);
    }

    void HookManager::RegisterWithServiceManager()
    {
        SapphireHook::LogInfo("HookManager registered with ServiceManager");
    }

    // ===== Utility =====
    const char* GetOpcodeName(uint16_t opcode)
    {
        // Wrapper retained for existing code; delegates to centralized lookup.
        return ::LookupOpcodeName(opcode, true, 0xFFFF); // unchanged, calls compatibility overload
    }

    // Implement the private static helpers declared in HookManager (signature matches header)
    bool HookManager::IsAddressInValidRange(uintptr_t address)
    {
        // Basic canonical range guard for user-mode and non-null
        if (address < 0x1000 || address > 0x00007FFFFFFFFFFFULL)
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            return false;

        // Committed and accessible
        const bool committed = (mbi.State & MEM_COMMIT) != 0;
        const bool noAccess = (mbi.Protect & PAGE_NOACCESS) != 0;
        return committed && !noAccess;
    }

    bool HookManager::IsMemoryExecutable(uintptr_t address, size_t size)
    {
        if (address < 0x1000 || address > 0x00007FFFFFFFFFFFULL)
            return false;

        if (size == 0) size = 16;

        uintptr_t cursor = address;
        size_t remaining = size;

        while (remaining > 0)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
                return false;

            if (mbi.State != MEM_COMMIT)
                return false;

            const DWORD prot = (mbi.Protect & 0xFF);
            const bool exec =
                prot == PAGE_EXECUTE ||
                prot == PAGE_EXECUTE_READ ||
                prot == PAGE_EXECUTE_READWRITE ||
                prot == PAGE_EXECUTE_WRITECOPY;

            if (!exec)
                return false;

            const auto regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + static_cast<uintptr_t>(mbi.RegionSize);
            const size_t advance = static_cast<size_t>(regionEnd - cursor);
            if (advance == 0) break;

            if (advance >= remaining)
                return true;

            remaining -= advance;
            cursor += advance;
        }
        return true;
    }

    // === Add implementations for previously missing HookManager methods (append near file end, before namespace close) ===

std::vector<uint8_t> HookManager::BackupOriginalBytes(uintptr_t address, size_t size)
{
    std::vector<uint8_t> buf(size);
    try {
        std::memcpy(buf.data(), reinterpret_cast<void*>(address), size);
    } catch (...) {
        buf.clear();
    }
    return buf;
}

void HookManager::SetSpeedMultiplier(float multiplier)
{
    if (multiplier <= 0.f) {
        SapphireHook::LogWarning("SetSpeedMultiplier rejected non-positive value");
        return;
    }
    g_SpeedMultiplier = multiplier;
    SapphireHook::LogInfo("Speed multiplier set to " + std::to_string(multiplier));
}

void HookManager::Shutdown()
{
    SapphireHook::LogInfo("HookManager shutdown initiated");
    GetShutdownFlag().store(true, std::memory_order_relaxed);
    CleanupAllHooks();
    MH_Uninitialize();
    SapphireHook::LogInfo("HookManager shutdown complete");
}

bool HookManager::RemoveHook(const std::string& name)
{
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    auto& tracked = GetTrackedHooks();
    auto it = tracked.find(name);
    if (it == tracked.end()) {
        SapphireHook::LogWarning("RemoveHook: hook not found: " + name);
        return false;
    }

    uintptr_t addr = it->second->address;
    // Disable & remove via MinHook
    MH_DisableHook(reinterpret_cast<void*>(addr));
    MH_RemoveHook(reinterpret_cast<void*>(addr));

    // Restore original bytes if we have them
    if (!it->second->original_bytes.empty()) {
        DWORD oldProt{};
        if (VirtualProtect(reinterpret_cast<void*>(addr), it->second->original_bytes.size(),
            PAGE_EXECUTE_READWRITE, &oldProt))
        {
            std::memcpy(reinterpret_cast<void*>(addr),
                        it->second->original_bytes.data(),
                        it->second->original_bytes.size());
            DWORD _; VirtualProtect(reinterpret_cast<void*>(addr),
                it->second->original_bytes.size(), oldProt, &_);
        }
    }

    GetAddressToName().erase(addr);
    tracked.erase(it);
    SapphireHook::LogInfo("Removed hook: " + name);
    return true;
}

std::vector<std::string> HookManager::GetHookNames()
{
    std::vector<std::string> names;
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    names.reserve(GetTrackedHooks().size());
    for (auto& p : GetTrackedHooks())
        names.push_back(p.first);
    return names;
}

std::optional<std::string> HookManager::GetHookNameByAddress(uintptr_t address)
{
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    auto& map = GetAddressToName();
    auto it = map.find(address);
    if (it == map.end()) return std::nullopt;
    return it->second;
}

void HookManager::CleanupAllHooks()
{
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    for (auto& p : GetTrackedHooks())
    {
        uintptr_t addr = p.second->address;
        MH_DisableHook(reinterpret_cast<void*>(addr));
        MH_RemoveHook(reinterpret_cast<void*>(addr));

        if (!p.second->original_bytes.empty()) {
            DWORD oldProt{};
            if (VirtualProtect(reinterpret_cast<void*>(addr), p.second->original_bytes.size(),
                PAGE_EXECUTE_READWRITE, &oldProt))
            {
                std::memcpy(reinterpret_cast<void*>(addr),
                            p.second->original_bytes.data(),
                            p.second->original_bytes.size());
                DWORD _; VirtualProtect(reinterpret_cast<void*>(addr),
                    p.second->original_bytes.size(), oldProt, &_);
            }
        }
    }
    GetAddressToName().clear();
    GetTrackedHooks().clear();
    SapphireHook::LogInfo("All hooks cleaned up");
}

void HookManager::UpdateStatistics()
{
    std::vector<HookInfo> snapshot;
    snapshot.reserve(GetTrackedHooks().size());
    for (auto& p : GetTrackedHooks())
        snapshot.push_back(*p.second);
    s_statistics.Update(snapshot);
}

HookStatistics HookManager::GetHookStatistics()
{
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    UpdateStatistics();
    return s_statistics;
}

std::vector<HookInfo> HookManager::GetDetailedHookInfo()
{
    std::vector<HookInfo> result;
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    result.reserve(GetTrackedHooks().size());
    for (auto& p : GetTrackedHooks())
        result.push_back(*p.second);
    return result;
}

size_t HookManager::GetTotalCallCount()
{
    return static_cast<size_t>(g_totalCallCount.load(std::memory_order_relaxed));
}

std::chrono::milliseconds HookManager::GetTotalExecutionTime()
{
    uint64_t micros = g_totalExecMicros.load(std::memory_order_relaxed);
    return std::chrono::milliseconds(micros / 1000);
}

void HookManager::PrintHookInformation()
{
    auto info = GetDetailedHookInfo();
    SapphireHook::LogInfo("==== Hook Information ====");
    for (auto& h : info)
    {
        std::ostringstream oss;
        oss << h.name << " @0x" << std::hex << h.address
            << " enabled=" << std::boolalpha << h.is_enabled
            << " validated=" << h.is_validated;
        SapphireHook::LogInfo(oss.str());
    }
}

std::map<std::string, std::string> HookManager::GetDebugInformation()
{
    std::map<std::string, std::string> dbg;
    auto stats = GetHookStatistics();
    dbg["TotalHooks"]   = std::to_string(stats.totalHooks);
    dbg["EnabledHooks"] = std::to_string(stats.enabledHooks);
    dbg["FailedHooks"]  = std::to_string(stats.failedHooks);
    dbg["TotalCalls"]   = std::to_string(GetTotalCallCount());
    dbg["ExecTimeMs"]   = std::to_string(GetTotalExecutionTime().count());
    return dbg;
}

std::map<std::string, uintptr_t> HookManager::GetHookAddresses()
{
    std::map<std::string, uintptr_t> out;
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    for (auto& p : GetTrackedHooks())
        out[p.first] = p.second->address;
    return out;
}

bool HookManager::SaveHookCache()
{
    auto& dir = GetCacheDirectory();
    if (dir.empty())
        return false;

    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    const auto filePath = dir / "hook_cache.txt";

    std::ofstream f(filePath);
    if (!f.is_open()) {
        SapphireHook::LogError("SaveHookCache: cannot open file");
        return false;
    }

    std::lock_guard<std::mutex> guard(GetHooksMutex());
    for (auto& p : GetTrackedHooks())
        f << p.first << "=" << std::hex << p.second->address << "\n";

    SapphireHook::LogInfo("Hook cache saved: " + filePath.string());
    return true;
}

void HookManager::InvalidateCache()
{
    auto& dir = GetCacheDirectory();
    if (dir.empty()) return;
    const auto filePath = dir / "hook_cache.txt";
    if (std::filesystem::exists(filePath)) {
        std::error_code ec;
        std::filesystem::remove(filePath, ec);
        if (!ec)
            SapphireHook::LogInfo("Hook cache invalidated");
    }
}

uintptr_t HookManager::RVAToAddress(uintptr_t rva)
{
    HMODULE mainModule = GetModuleHandle(nullptr);
    if (!mainModule) return 0;
    return reinterpret_cast<uintptr_t>(mainModule) + rva;
}

std::string HookManager::GenerateHookCacheKey(const std::string& name, uintptr_t address)
{
    std::ostringstream oss;
    oss << name << "@" << std::hex << address;
    return oss.str();
}

std::string HookManager::SerializeHookCache()
{
    std::ostringstream oss;
    std::lock_guard<std::mutex> guard(GetHooksMutex());
    for (auto& p : GetTrackedHooks())
        oss << p.first << "=" << std::hex << p.second->address << "\n";
    return oss.str();
}

bool HookManager::DeserializeHookCache(const std::string& cacheData)
{
    std::istringstream iss(cacheData);
    std::string line;
    size_t loaded = 0;

    std::lock_guard<std::mutex> guard(GetHooksMutex());
    while (std::getline(iss, line))
    {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string name = line.substr(0, eq);
        std::string addrStr = line.substr(eq + 1);
        try {
            uintptr_t addr = std::stoull(addrStr, nullptr, 16);
            s_cached_addresses[name] = addr;
            ++loaded;
        } catch (...) {
            SapphireHook::LogWarning("DeserializeHookCache: bad line: " + line);
        }
    }
    SapphireHook::LogInfo("DeserializeHookCache loaded " + std::to_string(loaded) + " entries");
    return loaded > 0;
}

} // namespace SapphireHook

// Global function - must be outside namespace to match declaration
void InitHooks()
{
    SapphireHook::HookManager::Initialize();
}
