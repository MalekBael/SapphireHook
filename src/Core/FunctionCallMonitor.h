#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <atomic>
#include <thread>
#include <memory>
#include <future>

// Include the full definitions for classes used as member variables
#include "FunctionDatabase.h"
#include "SignatureDatabase.h"
#include "FunctionScanner.h"  // This will bring in StringScanResult
#include "../UI/UIModule.h"

// Forward declarations for new classes
namespace SapphireHook {
    class FunctionAnalyzer;
    class AdvancedHookManager;
    
    // StringScanResult is now defined in FunctionScanner.h
    // Remove the duplicate definition from here
}

// Structure for function call records
struct FunctionCall {
    std::string functionName;
    uintptr_t address;
    std::chrono::steady_clock::time_point timestamp;
    std::string context;

    FunctionCall() : address(0) {}
};

// Main function call monitoring class
class FunctionCallMonitor : public SapphireHook::UIModule {
public:
    static FunctionCallMonitor* s_instance;

    FunctionCallMonitor();
    ~FunctionCallMonitor() = default;

    // UIModule interface implementation
    const char* GetName() const override { return "function_monitor"; }
    const char* GetDisplayName() const override { return "Function Call Monitor"; }
    void Initialize() override;
    void RenderMenu() override;
    void RenderWindow() override;
    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

    // Function call tracking
    void AddFunctionCall(const std::string& name, uintptr_t address, const std::string& context);
    void ClearCalls();
    void SetDiscoveredFunctions(const std::vector<uintptr_t>& functions);

    // Function name resolution
    std::string ResolveFunctionName(uintptr_t address) const;

    // Function hooking
    bool CreateFunctionHook(uintptr_t address, const std::string& name, const std::string& context);
    bool CreateSafeLoggingHook(uintptr_t address, const std::string& name, const std::string& context);
    bool CreateRealLoggingHook(uintptr_t address, const std::string& name, const std::string& context);

    // Function scanning and discovery (delegated to FunctionScanner)
    std::vector<uintptr_t> ScanForFunctionsByStrings(const std::vector<std::string>& searchStrings);
    std::vector<uintptr_t> ScanForAllInterestingFunctions();
    std::vector<uintptr_t> ScanForAllFunctions();
    std::vector<SapphireHook::StringScanResult> ScanMemoryForFunctionStrings(const std::vector<std::string>& targetStrings);

    // Database operations
    void ReloadDatabase();
    void ReloadSignatureDatabase();
    void LoadDatabasesWithErrorHandling();

    // Memory safety and analysis (delegated to FunctionScanner)
    bool IsSafeMemoryAddress(const void* address, size_t size);
    bool IsSafeAddress(uintptr_t address);
    uintptr_t FindFunctionStart(uintptr_t address);

    // FunctionScanner delegations
    bool IsLikelyFunctionStart(uintptr_t address) const;
    bool IsLikelyFunctionStart(const uint8_t* code, size_t maxSize) const;
    std::string ScanForNearbyStrings(uintptr_t address, size_t searchRadius = 1024) const;

    // Address parsing and conversion (delegated to FunctionAnalyzer)
    uintptr_t ResolveManualAddress(const std::string& input);
    bool ParseAddressInput(const std::string& input, uintptr_t& result);
    uintptr_t ConvertRVAToRuntimeAddress(uintptr_t rva);

    // Validation and debugging (delegated to FunctionAnalyzer)
    bool ValidateAndDebugAddress(uintptr_t address, const std::string& name);
    void DebugAddressSource(uintptr_t address, const std::string& name);
    void DebugIdaAddress(const std::string& address);

    // Database operations (delegated to FunctionAnalyzer)
    void VerifyDatabaseLoading();
    void TestAndDebugEmbeddedData();

    // Async operations (delegated to FunctionScanner)
    std::future<std::vector<uintptr_t>> StartAsyncScan();
    std::future<std::vector<uintptr_t>> StartAsyncScanWithStrings(const std::vector<std::string>& targetStrings);
    void StopScan();

    // String-based function discovery (delegated to FunctionScanner)
    std::string ExtractFunctionNameFromMemory(uintptr_t address);

    // Memory analysis (delegated to FunctionScanner)
    bool IsValidString(const char* str, size_t maxLen) const;
    bool IsCommittedMemory(uintptr_t address, size_t size) const;
    bool IsExecutableMemory(uintptr_t address) const;

    // Signature-based analysis (delegated to FunctionAnalyzer)
    void InitializeWithSignatures();
    void StartAsyncSignatureResolution();
    void IntegrateSignaturesWithDatabase();
    void DiscoverFunctionsFromSignatures();

    // Type-based analysis (delegated to FunctionAnalyzer)
    void InitializeWithTypeInformation();
    void DiscoverFunctionsByType(const std::string& className);
    void AnalyzeVirtualFunctionTables();
    void GenerateTypeBasedHooks();

    // Diagnostics (delegated to FunctionAnalyzer)
    void DiagnoseSignatureIssues();
    void EnhancedSignatureResolution();
    void DebugSignatureScanning();

    // UI rendering methods
    void RenderDataBrowser();
    void RenderFunctionDatabaseBrowser();
    void RenderSignatureDatabaseBrowser();
    void RenderCombinedDatabaseView();
    void RenderFunctionListWithPagination();
    void RenderPaginationControls();
    void RenderSignatureSection();
    void RenderEnhancedFunctionSearch();
    void RenderTypeAwareFunctionSearch();
    void RenderClassHierarchyView();
    void RenderVirtualFunctionTable();
    void RenderEnhancedDatabaseSearch();
    void RenderManualHookSection();

    // Specialized scanning methods (delegated to FunctionScanner)
    void ScanAllFunctions();
    void ScanExportedFunctions(std::vector<uintptr_t>& functions);
    void ScanCallTargets(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
    void ScanSafeRegion(uintptr_t baseAddr, size_t size, std::vector<uintptr_t>& functions);
    void ScanForFunctionPrologues(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
    void ScanForUIFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);
    void ScanForNetworkFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);
    void ScanForGameplayFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);

    // Database integration 
    void UpdateTemporaryFunctionDatabase(const std::map<uintptr_t, std::string>& detectedFunctions);

    // Hook management delegated to AdvancedHookManager
    void ValidateDatabase();
    void SetupFunctionHooks();
    void HookCommonAPIs();
    void HookFunctionByAddress(uintptr_t address, const std::string& name);
    void HookRandomFunctions(int count);
    void UnhookAllFunctions();
    bool IsValidMemoryAddress(uintptr_t address, size_t size);

    // Static hook callback
    static __declspec(noinline) void __stdcall FunctionHookCallback(uintptr_t returnAddress, uintptr_t functionAddress);

private:
    // Database instances (member variables)
    SapphireHook::FunctionDatabase m_functionDB;
    SapphireHook::SignatureDatabase m_signatureDB;
    bool m_functionDatabaseLoaded = false;
    bool m_signatureDatabaseLoaded = false;
    bool m_useSignatureDatabase = false;

    // Specialized helper classes (delegated functionality)
    std::shared_ptr<SapphireHook::FunctionScanner> m_functionScanner;
    std::shared_ptr<SapphireHook::FunctionAnalyzer> m_functionAnalyzer;
    std::shared_ptr<SapphireHook::AdvancedHookManager> m_hookManager;

    // Function call tracking
    mutable std::mutex m_callsMutex;
    std::vector<FunctionCall> m_functionCalls;
    std::vector<uintptr_t> m_discoveredFunctions;
    std::map<uintptr_t, std::string> m_detectedFunctionNames;

    // UI state
    bool m_windowOpen;
    int m_maxEntries;
    bool m_autoScroll;
    bool m_showAddresses;
    bool m_showTimestamps;
    int m_displayStartIndex = 0;
    int m_displayPageSize = 100;

    // Configuration
    bool m_useFunctionDatabase;
    bool m_enableRealHooking;
};