#include "../Hooking/hook_manager.h"
#include <MinHook.h>
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
#include "../Network/OpcodeNames.h"
#include <cstdlib>
#include <atomic>

namespace {   
    inline bool IsCanonicalUserVA(uintptr_t addr) noexcept {
        return addr <= 0x00007FFFFFFFFFFFULL;
    }

    inline bool IsEnvEnabled(const char* name) noexcept {
        if (const char* v = std::getenv(name)) {
            const char c = v[0];
            return c == '1' || c == 't' || c == 'T' || c == 'y' || c == 'Y';
        }
        return false;
    }

    inline bool QueryExecRange(uintptr_t address) noexcept {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT) return false;
        const DWORD prot = (mbi.Protect & 0xFF);
        return prot == PAGE_EXECUTE ||
            prot == PAGE_EXECUTE_READ ||
            prot == PAGE_EXECUTE_READWRITE ||
            prot == PAGE_EXECUTE_WRITECOPY;
    }
}   

namespace SapphireHook {

    bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize) {
        baseAddress = 0;
        moduleSize = 0;
        HMODULE hModule = ::GetModuleHandleW(nullptr);
        if (!hModule) return false;
        MODULEINFO mi{};
        if (!::GetModuleInformation(::GetCurrentProcess(), hModule, &mi, sizeof(mi)))
            return false;
        baseAddress = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        moduleSize = static_cast<size_t>(mi.SizeOfImage);
        return true;
    }

    float g_SpeedMultiplier = 1.0f;
    HandleIPC_t originalHandleIPC = nullptr;
    uintptr_t ipcHandlerAddr = 0;
    uintptr_t dispatcherAddr = 0;
    using DispatcherFn = char(__fastcall*)(void* rcx);
    DispatcherFn originalDispatcher = nullptr;
    static std::atomic<uint64_t> g_totalCallCount{ 0 };
    static std::atomic<uint64_t> g_totalExecMicros{ 0 };

    bool ValidateIPCHandler(uintptr_t address);
    bool FindIPCByOpcodeReferences(uintptr_t moduleBase, size_t moduleSize);
    bool ValidateHookTarget(uintptr_t address, const std::string& name);

    static bool SafeMemoryReadTest(uintptr_t address) {
        __try {
            volatile uint8_t v = *reinterpret_cast<uint8_t*>(address);
            (void)v;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    static bool SafeOpcodeSearch(uintptr_t addr, uint16_t opcode) {
        __try {
            return *(uint16_t*)addr == opcode;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    std::vector<uint8_t> BackupOriginalBytesHelper(uintptr_t address, size_t size) {
        std::vector<uint8_t> backup(size);
        try {
            std::memcpy(backup.data(), reinterpret_cast<const void*>(address), size);
        }
        catch (...) {
            LogError("Failed to backup original bytes");
            backup.clear();
        }
        return backup;
    }

    bool ValidateIPCHandler(uintptr_t address) {
        try {
            if (!ValidateHookTarget(address, "IPC_Handler_Validation"))
                return false;

            auto* code = reinterpret_cast<uint8_t*>(address);
            bool looksLikeIPC = false;

            for (int j = 0; j < 50; ++j) {
                if (code[j] == 0x0F && code[j + 1] == 0xB7) { looksLikeIPC = true; LogInfo("Found movzx at +" + std::to_string(j)); break; }
                if (code[j] == 0x66 && (code[j + 1] == 0x81 || code[j + 1] == 0x83)) { looksLikeIPC = true; LogInfo("Found 16-bit cmp at +" + std::to_string(j)); break; }
                if (code[j] == 0x48 && code[j + 1] == 0x8D && code[j + 2] == 0x15) { looksLikeIPC = true; LogInfo("Found LEA at +" + std::to_string(j)); break; }
            }

            if (looksLikeIPC) LogInfo("IPC handler validation passed");
            else LogWarning("IPC handler validation failed");
            return looksLikeIPC;
        }
        catch (...) {
            LogError("Exception during IPC handler validation");
            return false;
        }
    }

    bool FindIPCByOpcodeReferences(uintptr_t moduleBase, size_t moduleSize) {
        try {
            LogInfo("Searching for IPC handler by opcode references...");
            const uint16_t knownOpcodes[] = { 0x00DE,0x0196,0x019A,0x0067,0x0191 };
            const auto start = std::chrono::high_resolution_clock::now();
            const auto timeout = std::chrono::seconds(15);

            for (uint16_t opcode : knownOpcodes) {
                if (std::chrono::high_resolution_clock::now() - start > timeout) {
                    LogError("Opcode reference search timed out");
                    return false;
                }
                {
                    std::ostringstream oss; oss << "Searching opcode 0x" << std::hex << opcode;
                    LogInfo(oss.str());
                }
                for (uintptr_t addr = moduleBase; addr < moduleBase + moduleSize - 4; addr += 4) {
                    if (!SafeOpcodeSearch(addr, opcode)) continue;
                    uintptr_t backStart = (addr > 100) ? addr - 100 : moduleBase;
                    for (uintptr_t scan = backStart; scan < addr; ++scan) {
                        if (!SafeMemoryReadTest(scan)) continue;
                        const uint8_t* c = reinterpret_cast<const uint8_t*>(scan);
                        if ((c[0] == 0x48 && c[1] == 0x89) ||
                            (c[0] == 0x40 && c[1] == 0x53) ||
                            (c[0] == 0x48 && c[1] == 0x83)) {
                            ipcHandlerAddr = scan;
                            std::ostringstream oss; oss << "Found potential IPC handler @0x" << std::hex << scan;
                            LogInfo(oss.str());
                            return true;
                        }
                    }
                }
            }
            LogError("No IPC handler found by opcode references");
            return false;
        }
        catch (const std::exception& e) {
            LogError(std::string("Exception in FindIPCByOpcodeReferences: ") + e.what());
            return false;
        }
    }

    HookInfo::HookInfo(const std::string& hookName, uintptr_t hookAddress,
        const std::string& moduleName, const std::string& assemblyName)
        : name(hookName), module_name(moduleName), assembly_name(assemblyName),
          address(hookAddress), rva(HookManager::AddressToRVA(hookAddress)),
          hook_size(16), original_bytes(BackupOriginalBytesHelper(hookAddress, 16)),
          created_time(std::chrono::steady_clock::now()) {}

    void HookStatistics::Update(const std::vector<HookInfo>& hooks) {
        totalHooks = hooks.size();
        enabledHooks = disabledHooks = failedHooks = 0;
        hooksByModule.clear(); hooksByAssembly.clear();
        for (auto& h : hooks) {
            if (h.is_enabled) ++enabledHooks; else ++disabledHooks;
            if (!h.validation_error.empty()) ++failedHooks;
            hooksByModule[h.module_name]++; hooksByAssembly[h.assembly_name]++;
        }
        lastUpdate = std::chrono::system_clock::now();
    }

    std::string HookStatistics::ToDebugString() const {
        std::ostringstream oss;
        oss << "Hook Statistics:\n"
            << "  Total Hooks: " << totalHooks << "\n"
            << "  Enabled: " << enabledHooks << "\n"
            << "  Disabled: " << disabledHooks << "\n"
            << "  Failed: " << failedHooks << "\n"
            << "  By Module:\n";
        for (auto& m : hooksByModule) oss << "    " << m.first << ": " << m.second << "\n";
        oss << "  By Assembly:\n";
        for (auto& a : hooksByAssembly) oss << "    " << a.first << ": " << a.second << "\n";
        return oss.str();
    }

    bool ValidateHookTarget(uintptr_t address, const std::string& name) {
        if (!HookManager::ValidateHookAddress(address)) {
            std::ostringstream oss; oss << "Hook target invalid: " << name << " 0x" << std::hex << address;
            LogError(oss.str());
            return false;
        }
        if (HookManager::IsAddressHooked(address)) {
            std::ostringstream oss; oss << "Already hooked: " << name << " 0x" << std::hex << address;
            LogWarning(oss.str());
            return false;
        }
        LogInfo("Hook validation passed: " + name);
        return true;
    }

    bool InstallIPCHookSafe(uintptr_t address, const std::string& name) {
        {
            std::ostringstream oss; oss << "Starting safe hook installation for " << name
                << " at 0x" << std::hex << address;
            LogInfo(oss.str());
        }
        if (!ValidateHookTarget(address, name)) {
            LogError("Pre-installation validation failed for: " + name);
            return false;
        }
        LogInfo("✓ Pre-installation validation passed: " + name);

        if (!SafeMemoryReadTest(address)) {
            LogError("Memory read test failed for: " + name);
            return false;
        }
        LogInfo("✓ Memory read test passed: " + name);

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
            LogError("VirtualQuery failed for: " + name);
            return false;
        }
        {
            std::ostringstream oss;
            oss << "Memory info " << name << ": State=" << std::dec << mbi.State
                << " Protect=0x" << std::hex << mbi.Protect << " Type=" << std::dec << mbi.Type;
            LogInfo(oss.str());
        }

        std::unique_ptr<SafeMemoryRegion> region;
        try {
            region = std::make_unique<SafeMemoryRegion>(address, 16);
            if (!region || !region->IsValid()) {
                LogError("SafeMemoryRegion creation failed for: " + name);
                return false;
            }
            LogInfo("✓ SafeMemoryRegion created: " + name);
        }
        catch (const std::exception& e) {
            LogError("Exception creating SafeMemoryRegion " + name + ": " + e.what());
            return false;
        }
        catch (...) {
            LogError("Unknown exception creating SafeMemoryRegion for " + name);
            return false;
        }

        try {
            MH_STATUS createRes = MH_CreateHook(reinterpret_cast<void*>(address),
                &HookedHandleIPC,
                reinterpret_cast<void**>(&originalHandleIPC));
            if (createRes != MH_OK) {
                LogError("MH_CreateHook failed for " + name + " err=" + std::to_string(createRes));
                return false;
            }
            LogInfo("✓ MinHook created: " + name);

            MH_STATUS enableRes = MH_EnableHook(reinterpret_cast<void*>(address));
            if (enableRes != MH_OK) {
                LogError("MH_EnableHook failed for " + name + " err=" + std::to_string(enableRes));
                MH_RemoveHook(reinterpret_cast<void*>(address));
                return false;
            }
            LogInfo("✓ MinHook enabled: " + name);

            HookManager::RegisterHook(name, address, originalHandleIPC, "");
            {
                std::ostringstream oss; oss << "🎉 Installed hook " << name << " at 0x" << std::hex << address;
                LogInfo(oss.str());
            }
            return true;
        }
        catch (const std::exception& e) {
            LogError("Exception installing hook " + name + ": " + e.what());
            try { MH_RemoveHook(reinterpret_cast<void*>(address)); }
            catch (...) {}
            return false;
        }
        catch (...) {
            LogError("Unknown exception installing hook " + name);
            try { MH_RemoveHook(reinterpret_cast<void*>(address)); }
            catch (...) {}
            return false;
        }
    }

    extern "C" __declspec(noinline) void __fastcall CallOriginalIPC_NoExcept(void* thisPtr, uint16_t opcode, void* data) {
        __try { originalHandleIPC(thisPtr, opcode, data); }
        __except (EXCEPTION_EXECUTE_HANDLER) {   }
    }

    extern "C" __declspec(noinline) bool __fastcall ProbeDispatcherOpcode_NoExcept(void* rcx, uint8_t* outOpcode) {
        __try {
            const volatile uint8_t* p = reinterpret_cast<const volatile uint8_t*>(rcx);
            (void)p[0]; (void)p[2];
            *outOpcode = static_cast<uint8_t>(p[2]);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    void __fastcall HookedHandleIPC(void* thisPtr, uint16_t opcode, void* data) {
        void* retAddr = _ReturnAddress();
        const char* opcodeName = GetOpcodeName(opcode);

        std::ostringstream ctx;
        ctx << "IPC[" << opcodeName << "](0x" << std::hex << opcode << ") from 0x"
            << reinterpret_cast<uintptr_t>(retAddr);
        LogInfo(ctx.str());

        try {
            std::ofstream log("ipc_detailed.txt", std::ios::app);
            log << std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()
                << " | " << ctx.str() << "\n";
        }
        catch (...) {}

        if (opcode == 0x00DE || opcode == 0x026D || opcode == 0x010F)
            LogWarning(std::string("SECURITY: Kick/Ban opcode detected: ") + opcodeName);

        const auto start = std::chrono::high_resolution_clock::now();
        CallOriginalIPC_NoExcept(thisPtr, opcode, data);
        const auto end = std::chrono::high_resolution_clock::now();
        auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        if (dur.count() > 1000)
            LogWarning(std::string("Slow IPC operation: ") + opcodeName + " took " + std::to_string(dur.count()) + "µs");

        g_totalCallCount.fetch_add(1, std::memory_order_relaxed);
        g_totalExecMicros.fetch_add(static_cast<uint64_t>(dur.count()), std::memory_order_relaxed);
    }

    char __fastcall HookedDispatcher(void* rcx) {
        uint8_t opcode = 0;
        bool ok = ProbeDispatcherOpcode_NoExcept(rcx, &opcode);
        if (ok) {
            try {
                std::ofstream log("dispatcher_output.txt", std::ios::app);
                log << "[Dispatcher] Opcode: 0x" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(opcode) << "\n";
            }
            catch (...) {}
            if (opcode == 0xDE) LogWarning("PcPartyKick (0xDE) triggered");
        }
        else {
            LogWarning("Dispatcher rcx unreadable; skipping opcode probe");
        }
        return originalDispatcher(rcx);
    }

    bool FindAndHookIPC() {
        if (IsEnvEnabled("SAPPHIRE_ONLY_WSASEND") ||
            IsEnvEnabled("SAPPHIRE_SAFE") ||
            IsEnvEnabled("SAPPHIRE_SKIP_IPC")) {
            LogWarning("[HookManager] IPC hook skipped by environment");
            return false;
        }

        uintptr_t moduleBase{};
        size_t moduleSize{};
        if (!GetMainModuleInfo(moduleBase, moduleSize)) {
            LogError("Failed to get main module information");
            return false;
        }

        LogInfo("Scanning for IPC handler...");
        const auto scanStart = std::chrono::high_resolution_clock::now();
        const auto maxScanTime = std::chrono::seconds(30);

        const char* patterns[] = {
            "40 53 48 83 EC ? 0F B7 DA 48 8B F9 66 85 D2",
        };
        const int patternCount = static_cast<int>(sizeof(patterns) / sizeof(patterns[0]));

        ipcHandlerAddr = 0;
        for (int i = 0; i < patternCount; ++i) {
            if (std::chrono::high_resolution_clock::now() - scanStart > maxScanTime) {
                LogError("Pattern scanning timed out (IPC)");
                return false;
            }
            LogInfo("Trying pattern " + std::to_string(i + 1));
            auto addr = patternscan(moduleBase, moduleSize, patterns[i]);
            if (!addr) {
                LogInfo("Pattern " + std::to_string(i + 1) + " not found");
                continue;
            }
            {
                std::ostringstream oss;
                oss << "Found potential IPC handler via pattern " << (i + 1) << " @0x" << std::hex << addr;
                LogInfo(oss.str());
            }
            if (!HookManager::ValidateHookAddress(addr)) {
                std::ostringstream oss;
                oss << "Rejected candidate (invalid VA) 0x" << std::hex << addr;
                LogWarning(oss.str());
                continue;
            }
            if (ValidateIPCHandler(addr)) {
                LogInfo("Pattern verification passed");
                ipcHandlerAddr = addr;
                break;
            }
            LogWarning("Pattern verification failed - trying next");
        }

        if (!ipcHandlerAddr) {
            LogError("Failed to find IPC handler");
            LogWarning("Skipping IPC hook (safer than hooking wrong addr)");
            return false;
        }

        LogInfo("Installing IPC hook...");
        return InstallIPCHookSafe(ipcHandlerAddr, "IPC_Handler");
    }

    bool FindAndHookDispatcher() {
        if (IsEnvEnabled("SAPPHIRE_ONLY_WSASEND") ||
            IsEnvEnabled("SAPPHIRE_SAFE") ||
            IsEnvEnabled("SAPPHIRE_SKIP_DISPATCHER")) {
            LogWarning("[HookManager] Dispatcher hook skipped by environment");
            return false;
        }

        uintptr_t moduleBase{};
        size_t moduleSize{};
        if (!GetMainModuleInfo(moduleBase, moduleSize))
            return false;

        LogInfo("Scanning for dispatcher...");

        const char* dispatcherPatterns[] = {
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 45 33 FF",
            "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 84 C0 74 ? 48 8B CB",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA",
            "40 53 48 83 EC ? 48 8B D9 48 8B 0D ? ? ? ? 48 85 C9"
        };
        const int count = static_cast<int>(sizeof(dispatcherPatterns) / sizeof(dispatcherPatterns[0]));

        dispatcherAddr = 0;
        for (int i = 0; i < count; ++i) {
            auto addr = patternscan(moduleBase, moduleSize, dispatcherPatterns[i]);
            if (!addr) continue;
            std::ostringstream oss;
            oss << "Found dispatcher pattern " << (i + 1) << " @0x" << std::hex << addr;
            LogInfo(oss.str());
            if (!HookManager::ValidateHookAddress(addr)) {
                std::ostringstream oss2; oss2 << "Rejected dispatcher addr 0x" << std::hex << addr;
                LogWarning(oss2.str());
                continue;
            }
            dispatcherAddr = addr;
            break;
        }

        if (!dispatcherAddr) {
            LogError("Failed to find dispatcher");
            return false;
        }

        if (MH_CreateHook(reinterpret_cast<void*>(dispatcherAddr), &HookedDispatcher,
            reinterpret_cast<void**>(&originalDispatcher)) != MH_OK)
            return false;
        return MH_EnableHook(reinterpret_cast<void*>(dispatcherAddr)) == MH_OK;
    }

    void HookManager::Initialize() {
        LogInfo("Initializing HookManager...");
        try {
            if (MH_Initialize() != MH_OK) {
                LogError("Failed to initialize MinHook");
                return;
            }
            LogInfo("MinHook initialized");

            (void)PacketInjector::Initialize();

            if (IsEnvEnabled("SAPPHIRE_ONLY_WSASEND")) {
                LogWarning("[HookManager] WSASend-only mode active");
                RegisterWithServiceManager();
                LogInfo("Hook initialization (WSASend-only) complete");
                return;
            }

            LoadHookCache();

            try {
                std::filesystem::path cacheDir = std::filesystem::current_path() / "cache";
                SetCacheDirectory(cacheDir);
            }
            catch (const std::exception& e) {
                LogWarning("Failed to set cache directory: " + std::string(e.what()));
            }

            LogInfo("Starting IPC hook search...");
            if (!FindAndHookIPC())
                LogError("IPC hook not installed");

            LogInfo("Starting dispatcher hook search...");
            if (!FindAndHookDispatcher())
                LogError("Dispatcher hook not installed");

            RegisterWithServiceManager();
            LogInfo("Hook initialization complete");
        }
        catch (const std::exception& e) {
            LogError(std::string("Exception during hook initialization: ") + e.what());
        }
        catch (...) {
            LogError("Unknown exception during hook initialization");
        }
    }

    bool HookManager::RegisterHook(const std::string& name, uintptr_t address,
        void* original, const std::string& assemblyName) {
        try {
            std::lock_guard<std::mutex> guard(GetHooksMutex());
            auto& tracked = GetTrackedHooks();
            auto& addrMap = GetAddressToName();

            if (tracked.find(name) != tracked.end()) {
                LogWarning("Hook already registered: " + name);
                return false;
            }

            auto info = std::make_unique<HookInfo>();
            info->name = name;
            info->assembly_name = assemblyName;
            info->created_time = std::chrono::steady_clock::now();
            info->original_bytes = BackupOriginalBytesHelper(address, 16);
            info->rva = HookManager::AddressToRVA(address);
            info->original_function = original;
            info->address = address;
            info->is_enabled = true;
            info->is_validated = true;

            addrMap[address] = name;
            tracked[name] = std::move(info);

            std::ostringstream oss;
            oss << "Registered hook '" << name << "' at 0x" << std::hex << address;
            LogInfo(oss.str());
            return true;
        }
        catch (const std::exception& e) {
            LogError("RegisterHook exception: " + std::string(e.what()));
            return false;
        }
        catch (...) {
            LogError("RegisterHook unknown exception");
            return false;
        }
    }

    bool HookManager::IsAddressHooked(uintptr_t address) {
        try {
            std::lock_guard<std::mutex> guard(GetHooksMutex());
            return GetAddressToName().find(address) != GetAddressToName().end();
        }
        catch (...) {
            LogError("IsAddressHooked exception");
            return false;
        }
    }

    bool HookManager::ValidateHookAddress(uintptr_t address) {
        if (!IsCanonicalUserVA(address)) {
            std::ostringstream oss; oss << "[HookManager] Reject non-canonical 0x" << std::hex << address;
            LogError(oss.str());
            return false;
        }
        uintptr_t base{}; size_t size{};
        if (!GetMainModuleInfo(base, size)) {
            LogWarning("[HookManager] Falling back to VirtualQuery only");
            return QueryExecRange(address);
        }
        const uintptr_t end = base + size;
        if (address < base || address >= end) {
            std::ostringstream oss;
            oss << "[HookManager] Reject outside main module 0x" << std::hex << address
                << " Module=[0x" << base << ",0x" << end << ")";
            LogError(oss.str());
            return false;
        }
        if (!QueryExecRange(address)) {
            std::ostringstream oss;
            oss << "[HookManager] Reject non-executable 0x" << std::hex << address;
            LogError(oss.str());
            return false;
        }
        return true;
    }

    void HookManager::SetCacheDirectory(const std::filesystem::path& cacheDir) {
        HookManager::GetCacheDirectory() = cacheDir;
        try {
            std::filesystem::create_directories(cacheDir);
            LogInfo("Hook cache directory: " + cacheDir.string());
        }
        catch (const std::exception& e) {
            LogError("Failed to create cache directory: " + std::string(e.what()));
        }
    }

    bool HookManager::LoadHookCache() {
        auto& dir = GetCacheDirectory();
        if (dir.empty()) {
            LogWarning("No cache directory set; skip cache load");
            return false;
        }
        auto file = dir / "hook_cache.txt";
        if (!std::filesystem::exists(file)) {
            LogInfo("No existing hook cache at: " + file.string());
            return false;
        }
        try {
            std::ifstream f(file);
            if (!f.is_open()) {
                LogError("Failed to open cache file: " + file.string());
                return false;
            }
            auto& cached = GetCachedAddresses();
            cached.clear();
            std::string line; size_t loaded = 0;
            while (std::getline(f, line)) {
                if (line.empty() || line[0] == '#') continue;
                auto eq = line.find('=');
                if (eq == std::string::npos) continue;
                std::string name = line.substr(0, eq);
                std::string addrStr = line.substr(eq + 1);
                try {
                    uintptr_t addr = std::stoull(addrStr, nullptr, 16);
                    cached[name] = addr;
                    ++loaded;
                }
                catch (...) {
                    LogWarning("Invalid cache line: " + line);
                }
            }
            std::ostringstream oss; oss << "Loaded " << loaded << " cached hook addresses";
            LogInfo(oss.str());
            return loaded > 0;
        }
        catch (const std::exception& e) {
            LogError("LoadHookCache exception: " + std::string(e.what()));
            return false;
        }
    }

    uintptr_t HookManager::AddressToRVA(uintptr_t address) {
        HMODULE hMod{};
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCSTR>(address), &hMod)) {
            return address - reinterpret_cast<uintptr_t>(hMod);
        }
        HMODULE mainModule = GetModuleHandle(nullptr);
        if (mainModule) {
            MODULEINFO mi{};
            if (GetModuleInformation(GetCurrentProcess(), mainModule, &mi, sizeof(mi))) {
                auto base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
                auto end = base + static_cast<uintptr_t>(mi.SizeOfImage);
                if (address >= base && address < end)
                    return address - base;
            }
        }
        return 0;
    }

    bool HookManager::IsValidHookTarget(uintptr_t address) {
        return IsAddressInValidRange(address) && IsMemoryExecutable(address);
    }

    void HookManager::RegisterWithServiceManager() {
        LogInfo("HookManager registered with ServiceManager");
    }

    const char* GetOpcodeName(uint16_t opcode) {
        return ::LookupOpcodeName(opcode, true, 0xFFFF);
    }

    bool HookManager::IsAddressInValidRange(uintptr_t address) {
        if (address < 0x1000 || address > 0x00007FFFFFFFFFFFULL) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            return false;
        const bool committed = (mbi.State & MEM_COMMIT) != 0;
        const bool noAccess = (mbi.Protect & PAGE_NOACCESS) != 0;
        return committed && !noAccess;
    }

    bool HookManager::IsMemoryExecutable(uintptr_t address, size_t size) {
        if (address < 0x1000 || address > 0x00007FFFFFFFFFFFULL) return false;
        if (size == 0) size = 16;
        uintptr_t cursor = address;
        size_t remaining = size;
        while (remaining > 0) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
                return false;
            if (mbi.State != MEM_COMMIT) return false;
            DWORD prot = (mbi.Protect & 0xFF);
            bool exec = prot == PAGE_EXECUTE ||
                prot == PAGE_EXECUTE_READ ||
                prot == PAGE_EXECUTE_READWRITE ||
                prot == PAGE_EXECUTE_WRITECOPY;
            if (!exec) return false;

            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + static_cast<uintptr_t>(mbi.RegionSize);
            size_t advance = static_cast<size_t>(regionEnd - cursor);
            if (advance == 0) break;
            if (advance >= remaining) return true;
            remaining -= advance;
            cursor += advance;
        }
        return true;
    }

    void HookManager::Shutdown() {
        LogInfo("HookManager shutdown initiated");
        GetShutdownFlag().store(true, std::memory_order_relaxed);
        CleanupAllHooks();
        MH_Uninitialize();
        LogInfo("HookManager shutdown complete");
    }

    void HookManager::CleanupAllHooks() {
        std::lock_guard<std::mutex> guard(GetHooksMutex());
        for (auto& p : GetTrackedHooks()) {
            uintptr_t addr = p.second->address;
            MH_DisableHook(reinterpret_cast<void*>(addr));
            MH_RemoveHook(reinterpret_cast<void*>(addr));
            if (!p.second->original_bytes.empty()) {
                DWORD oldProt{};
                if (VirtualProtect(reinterpret_cast<void*>(addr), p.second->original_bytes.size(),
                    PAGE_EXECUTE_READWRITE, &oldProt)) {
                    std::memcpy(reinterpret_cast<void*>(addr),
                        p.second->original_bytes.data(),
                        p.second->original_bytes.size());
                    DWORD tmp; VirtualProtect(reinterpret_cast<void*>(addr),
                        p.second->original_bytes.size(), oldProt, &tmp);
                }
            }
        }
        GetAddressToName().clear();
        GetTrackedHooks().clear();
        LogInfo("All hooks cleaned up");
    }

    void HookManager::UpdateStatistics() {
        std::vector<HookInfo> snapshot;
        {
            std::lock_guard<std::mutex> guard(GetHooksMutex());
            snapshot.reserve(GetTrackedHooks().size());
            for (auto& p : GetTrackedHooks())
                snapshot.push_back(*p.second);
        }
        s_statistics.Update(snapshot);
    }

    HookStatistics HookManager::GetHookStatistics() {
        std::lock_guard<std::mutex> guard(GetHooksMutex());
        UpdateStatistics();
        return s_statistics;
    }

    std::vector<HookInfo> HookManager::GetDetailedHookInfo() {
        std::vector<HookInfo> result;
        std::lock_guard<std::mutex> guard(GetHooksMutex());
        result.reserve(GetTrackedHooks().size());
        for (auto& p : GetTrackedHooks())
            result.push_back(*p.second);
        return result;
    }

    size_t HookManager::GetTotalCallCount() {
        return static_cast<size_t>(g_totalCallCount.load(std::memory_order_relaxed));
    }

    std::chrono::milliseconds HookManager::GetTotalExecutionTime() {
        uint64_t micros = g_totalExecMicros.load(std::memory_order_relaxed);
        return std::chrono::milliseconds(micros / 1000);
    }

}   

void InitHooks() {
    SapphireHook::HookManager::Initialize();
}