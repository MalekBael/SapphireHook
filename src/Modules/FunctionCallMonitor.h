#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <atomic>
#include <memory>
#include <future>
#include <unordered_map>
#include <cstdint>         

#include "FunctionDatabase.h"
#include "SignatureDatabase.h"
#include "../Analysis/FunctionScanner.h"
#include "../UI/UIModule.h"

// Forward declarations for types only used via std::shared_ptr in this header.
namespace SapphireHook {
    class FunctionAnalyzer;
    class AdvancedHookManager;
    class MemoryScanner;
    class StringXrefAnalyzer;
    class LiveTraceMonitor;
}

struct FunctionCall {
    std::string functionName;
    uintptr_t address;
    std::chrono::steady_clock::time_point timestamp;
    std::string context;
    FunctionCall() : address(0) {}
};

class FunctionCallMonitor : public SapphireHook::UIModule {
public:
    static FunctionCallMonitor* s_instance;

    // Convenience accessor for global callbacks (VEH/MinHook)
    static FunctionCallMonitor* GetInstance() { return s_instance; }

    FunctionCallMonitor();
    ~FunctionCallMonitor();

    // UIModule interface
    const char* GetName() const override { return "function_monitor"; }
    const char* GetDisplayName() const override { return "Function Call Monitor"; }
    void Initialize() override;
    void RenderMenu() override;
    void RenderWindow() override;
    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

    // Core monitoring functionality
    void AddFunctionCall(const std::string& name, uintptr_t address, const std::string& context);
    void ClearCalls();
    void SetDiscoveredFunctions(const std::vector<uintptr_t>& functions);
    std::string ResolveFunctionName(uintptr_t address) const;

    // Hook management
    void SetRealHookingEnabled(bool enabled);
    bool CreateFunctionHook(uintptr_t address, const std::string& name, const std::string& context);
    bool CreateSafeLoggingHook(uintptr_t address, const std::string& name, const std::string& context);
    bool CreateRealLoggingHook(uintptr_t address, const std::string& name, const std::string& context);
    bool HasReplayForAddress(uintptr_t address) const;
    bool TriggerMinHookedFunction(uintptr_t address);
    void UnhookAllFunctions();
    void HookRandomFunctions(int count);
    void HookFunctionByAddress(uintptr_t address, const std::string& name);

    // Database management
    void ReloadDatabase();
    void ReloadSignatureDatabase();
    void LoadDatabasesWithErrorHandling();
    void ValidateDatabase();

    // Memory and address utilities
    bool IsSafeMemoryAddress(const void* address, size_t size);
    bool IsSafeAddress(uintptr_t address);
    uintptr_t FindFunctionStart(uintptr_t address);
    bool IsLikelyFunctionStart(uintptr_t address) const;
    bool IsLikelyFunctionStart(const uint8_t* code, size_t maxSize) const;
    bool IsValidMemoryAddress(uintptr_t address, size_t size);
    bool IsCommittedMemory(uintptr_t address, size_t size) const;
    bool IsExecutableMemory(uintptr_t address) const;

    // Address resolution
    uintptr_t ResolveManualAddress(const std::string& input);
    bool ParseAddressInput(const std::string& input, uintptr_t& result);
    uintptr_t ConvertRVAToRuntimeAddress(uintptr_t rva);

    // Analysis and debugging
    bool ValidateAndDebugAddress(uintptr_t address, const std::string& name);
    void DebugAddressSource(uintptr_t address, const std::string& name);
    void DebugIdaAddress(const std::string& address);
    void VerifyDatabaseLoading();
    void TestAndDebugEmbeddedData();
    std::string ExtractFunctionNameFromMemory(uintptr_t address);
    bool IsValidString(const char* str, size_t maxLen) const;

    // Signature operations (delegated to FunctionAnalyzer)
    void InitializeWithSignatures();
    void StartAsyncSignatureResolution();
    void IntegrateSignaturesWithDatabase();
    void DiscoverFunctionsFromSignatures();
    void DiagnoseSignatureIssues();
    void EnhancedSignatureResolution();
    void DebugSignatureScanning();

    // Type-based discovery (delegated to FunctionAnalyzer)
    void InitializeWithTypeInformation();
    void DiscoverFunctionsByType(const std::string& className);
    void AnalyzeVirtualFunctionTables();
    void GenerateTypeBasedHooks();

    // Legacy scanning methods (for compatibility - will delegate to tools)
    std::vector<uintptr_t> ScanForFunctionsByStrings(const std::vector<std::string>& searchStrings);
    std::vector<uintptr_t> ScanForAllInterestingFunctions();
    std::vector<uintptr_t> ScanForAllFunctions();
    std::vector<SapphireHook::StringScanResult> ScanMemoryForFunctionStrings(const std::vector<std::string>& targetStrings);
    std::future<std::vector<uintptr_t>> StartAsyncScan();
    std::future<std::vector<uintptr_t>> StartAsyncScanWithStrings(const std::vector<std::string>& targetStrings);
    void StopScan();

    // Legacy scanning helpers (thin pass-throughs to FunctionScanner)
    void ScanAllFunctions();
    void ScanExportedFunctions(std::vector<uintptr_t>& functions);
    void ScanCallTargets(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
    void ScanSafeRegion(uintptr_t baseAddr, size_t size, std::vector<uintptr_t>& functions);
    void ScanForFunctionPrologues(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
    void ScanForUIFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);
    void ScanForNetworkFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);
    void ScanForGameplayFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);

    // Hook system setup
    void SetupFunctionHooks();
    void HookCommonAPIs();

    // Global callback for hooks
    static __declspec(noinline) void __stdcall FunctionHookCallback(uintptr_t returnAddress, uintptr_t functionAddress);

    // Access to tool modules (for integration if needed)
    std::shared_ptr<SapphireHook::MemoryScanner> GetMemoryScanner() { return m_memoryScanner; }
    std::shared_ptr<SapphireHook::StringXrefAnalyzer> GetStringAnalyzer() { return m_stringAnalyzer; }
    std::shared_ptr<SapphireHook::LiveTraceMonitor> GetLiveMonitor() { return m_liveMonitor; }

    // Allow ModuleManager to set tool modules after construction
    void SetToolModules(std::shared_ptr<SapphireHook::MemoryScanner> scanner,
        std::shared_ptr<SapphireHook::StringXrefAnalyzer> analyzer,
        std::shared_ptr<SapphireHook::LiveTraceMonitor> monitor);

private:
    // Render methods for UI tabs/sections
    void RenderFunctionListWithPagination();
    void RenderFunctionDatabaseBrowser();
    void RenderSignatureDatabaseBrowser();
    void RenderManualHookSection();
    void RenderEnhancedFunctionSearch();

    // The following were defined in the cpp but not declared; add them
    void RenderCombinedDatabaseView();
    void RenderSignatureSection();
    void RenderTypeAwareFunctionSearch();
    void RenderClassHierarchyView();
    void RenderVirtualFunctionTable();
    void RenderPaginationControls();

    // Core components
    SapphireHook::FunctionDatabase m_functionDB;
    SapphireHook::SignatureDatabase m_signatureDB;
    bool m_functionDatabaseLoaded = false;
    bool m_signatureDatabaseLoaded = false;
    bool m_useSignatureDatabase = false;

    // Analyzer components
    std::shared_ptr<SapphireHook::FunctionScanner> m_functionScanner;
    std::shared_ptr<SapphireHook::FunctionAnalyzer> m_functionAnalyzer;
    std::shared_ptr<SapphireHook::AdvancedHookManager> m_hookManager;

    // Tool modules (extracted functionality)
    std::shared_ptr<SapphireHook::MemoryScanner> m_memoryScanner;
    std::shared_ptr<SapphireHook::StringXrefAnalyzer> m_stringAnalyzer;
    std::shared_ptr<SapphireHook::LiveTraceMonitor> m_liveMonitor;

    // Function call recording
    mutable std::mutex m_callsMutex;
    std::vector<FunctionCall> m_functionCalls;
    std::vector<uintptr_t> m_discoveredFunctions;
    std::map<uintptr_t, std::string> m_detectedFunctionNames;

    // UI state
    bool m_windowOpen = false;
    int m_maxEntries = 500;
    bool m_autoScroll = true;
    bool m_showAddresses = true;
    bool m_showTimestamps = true;
    int m_displayStartIndex = 0;
    int m_displayPageSize = 100;
    bool m_useFunctionDatabase = true;
    bool m_enableRealHooking = false;

    // MinHook support
    std::unordered_map<uintptr_t, void*> m_activeHooks;
    bool m_hooksInitialized = false;
    bool InstallSimpleHook(uintptr_t address, const std::string& name);
    void RemoveAllHooks();

    // Helper methods
    void UpdateTemporaryFunctionDatabase(const std::map<uintptr_t, std::string>& detectedFunctions);
    std::string ScanForNearbyStrings(uintptr_t address, size_t searchRadius = 1024) const;

    // Export helper (defined in .cpp)
    bool WriteTextFileUTF8(const std::string& userPathOrFilename,
        const std::string& content,
        bool overwrite,
        std::string& err);
};