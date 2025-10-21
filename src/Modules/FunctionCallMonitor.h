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
#include <unordered_map>
#include <unordered_set>   
#include <cstdint>         

#include "FunctionDatabase.h"
#include "SignatureDatabase.h"
#include "../Analysis/FunctionScanner.h"
#include "../UI/UIModule.h"

// Forward declarations for types only used via std::shared_ptr in this header.
// Their full definitions are included in the .cpp (FunctionAnalyzer.h) or
// defined inside the .cpp (AdvancedHookManager).
namespace SapphireHook {
    class FunctionAnalyzer;
    class AdvancedHookManager;
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

    FunctionCallMonitor();
    ~FunctionCallMonitor(); // changed from = default

    const char* GetName() const override { return "function_monitor"; }
    const char* GetDisplayName() const override { return "Function Call Monitor"; }
    void Initialize() override;
    void RenderMenu() override;
    void RenderWindow() override;
    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

    void AddFunctionCall(const std::string& name, uintptr_t address, const std::string& context);
    void ClearCalls();
    void SetDiscoveredFunctions(const std::vector<uintptr_t>& functions);
    std::string ResolveFunctionName(uintptr_t address) const;

    bool CreateFunctionHook(uintptr_t address, const std::string& name, const std::string& context);
    bool CreateSafeLoggingHook(uintptr_t address, const std::string& name, const std::string& context);
    bool CreateRealLoggingHook(uintptr_t address, const std::string& name, const std::string& context);

    std::vector<uintptr_t> ScanForFunctionsByStrings(const std::vector<std::string>& searchStrings);
    std::vector<uintptr_t> ScanForAllInterestingFunctions();
    std::vector<uintptr_t> ScanForAllFunctions();
    std::vector<SapphireHook::StringScanResult> ScanMemoryForFunctionStrings(const std::vector<std::string>& targetStrings);

    void ReloadDatabase();
    void ReloadSignatureDatabase();
    void LoadDatabasesWithErrorHandling();

    bool IsSafeMemoryAddress(const void* address, size_t size);
    bool IsSafeAddress(uintptr_t address);
    uintptr_t FindFunctionStart(uintptr_t address);

    bool IsLikelyFunctionStart(uintptr_t address) const;
    bool IsLikelyFunctionStart(const uint8_t* code, size_t maxSize) const;
    std::string ScanForNearbyStrings(uintptr_t address, size_t searchRadius = 1024) const;

    uintptr_t ResolveManualAddress(const std::string& input);
    bool ParseAddressInput(const std::string& input, uintptr_t& result);
    uintptr_t ConvertRVAToRuntimeAddress(uintptr_t rva);

    bool ValidateAndDebugAddress(uintptr_t address, const std::string& name);
    void DebugAddressSource(uintptr_t address, const std::string& name);
    void DebugIdaAddress(const std::string& address);

    void VerifyDatabaseLoading();
    void TestAndDebugEmbeddedData();

    std::future<std::vector<uintptr_t>> StartAsyncScan();
    std::future<std::vector<uintptr_t>> StartAsyncScanWithStrings(const std::vector<std::string>& targetStrings);
    void StopScan();

    std::string ExtractFunctionNameFromMemory(uintptr_t address);
    bool IsValidString(const char* str, size_t maxLen) const;
    bool IsCommittedMemory(uintptr_t address, size_t size) const;
    bool IsExecutableMemory(uintptr_t address) const;

    void InitializeWithSignatures();
    void StartAsyncSignatureResolution();
    void IntegrateSignaturesWithDatabase();
    void DiscoverFunctionsFromSignatures();

    void InitializeWithTypeInformation();
    void DiscoverFunctionsByType(const std::string& className);
    void AnalyzeVirtualFunctionTables();
    void GenerateTypeBasedHooks();

    void DiagnoseSignatureIssues();
    void EnhancedSignatureResolution();
    void DebugSignatureScanning();

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
    void RenderMemoryScanTab();

    void ScanAllFunctions();
    void ScanExportedFunctions(std::vector<uintptr_t>& functions);
    void ScanCallTargets(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
    void ScanSafeRegion(uintptr_t baseAddr, size_t size, std::vector<uintptr_t>& functions);
    void ScanForFunctionPrologues(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
    void ScanForUIFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);
    void ScanForNetworkFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);
    void ScanForGameplayFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions);

    void UpdateTemporaryFunctionDatabase(const std::map<uintptr_t, std::string>& detectedFunctions);

    void ValidateDatabase();
    void SetupFunctionHooks();
    void HookCommonAPIs();
    void HookFunctionByAddress(uintptr_t address, const std::string& name);
    void HookRandomFunctions(int count);
    void UnhookAllFunctions();
    bool IsValidMemoryAddress(uintptr_t address, size_t size);

    static __declspec(noinline) void __stdcall FunctionHookCallback(uintptr_t returnAddress, uintptr_t functionAddress);

    void StartMemoryScan(const std::vector<std::string>& targetStrings,
        bool scanPrologues,
        bool scanStrings);
    void UpdateMemoryScanAsync();

    // Live trace methods
    void RenderLiveCallTrace();
    void StartLiveCapture();
    void StopLiveCapture();
    void ClearLiveTrace();
    static void LiveTraceCallback(uintptr_t address, uintptr_t returnAddress);

    // Expose this so the global detour can log calls safely.
    void RecordRealFunctionCall(uintptr_t address, uintptr_t returnAddr);

private:

    // Add these new members for sampling-based monitoring
    std::thread m_samplingThread;
    std::atomic<bool> m_samplingActive{ false };

    // New methods for stack sampling
    void WalkCallStack(uintptr_t stackPointer, std::vector<uintptr_t>& addresses, size_t maxFrames);
    void SampleActiveModuleFunctions();
    void RebuildAnchorStringMatches();
    void SelectFunctionForAnalysis(uintptr_t address);
    std::string GenerateFunctionAnalysis(uintptr_t address,
        const std::vector<std::string>* tags = nullptr);
    std::string GetPrologueBytes(uintptr_t address, size_t maxLen = 16);
    bool DisassembleSnippet(uintptr_t address, std::string& out, int maxInstr = 12, size_t maxBytes = 96);
    void BuildMultiDiff();
    std::string BuildMultiDiffText(const std::vector<uintptr_t>& addrs);
    std::string BuildSingleExport(uintptr_t address);
    std::string BuildDiffExport();
    bool WriteTextFileUTF8(const std::string& path, const std::string& content, bool overwrite, std::string& err);

    SapphireHook::FunctionDatabase m_functionDB;
    SapphireHook::SignatureDatabase m_signatureDB;
    bool m_functionDatabaseLoaded = false;
    bool m_signatureDatabaseLoaded = false;
    bool m_useSignatureDatabase = false;

    std::shared_ptr<SapphireHook::FunctionScanner>       m_functionScanner;
    std::shared_ptr<SapphireHook::FunctionAnalyzer>      m_functionAnalyzer;
    std::shared_ptr<SapphireHook::AdvancedHookManager>   m_hookManager;

    mutable std::mutex m_callsMutex;
    std::vector<FunctionCall> m_functionCalls;
    std::vector<uintptr_t> m_discoveredFunctions;
    std::map<uintptr_t, std::string> m_detectedFunctionNames;

    bool m_windowOpen;
    int  m_maxEntries;
    bool m_autoScroll;
    bool m_showAddresses;
    bool m_showTimestamps;
    int  m_displayStartIndex = 0;
    int  m_displayPageSize = 100;
    bool m_useFunctionDatabase;
    bool m_enableRealHooking;

    struct MemoryScanState {
        // Phase control
        bool running = false;
        bool cancelled = false;
        bool scanPrologues = false;
        bool scanStrings = false;

        // NEW flags / state
        bool anchorsRebuilt = false;
        bool prologueCompleted = false;
        bool stringCompleted = false;
        bool uiFreeze = false;        // freeze UI updates (virtualized list)
        bool rowsCacheDirty = false;  // row cache needs rebuild

        uint64_t lastStatusBuildTick = 0; // throttled status text rebuild

        // Async work
        std::future<std::vector<uintptr_t>> prologueFuture;
        std::future<std::vector<SapphireHook::StringScanResult>> stringFuture;

        // Collected results
        std::vector<uintptr_t> prologueFunctions;
        std::vector<SapphireHook::StringScanResult> stringHits;

        // Timing / status
        std::chrono::steady_clock::time_point startTime{};
        std::string status;

        // Incremental progress
        std::atomic<size_t> prologueProcessed{ 0 };
        std::atomic<size_t> prologueTotal{ 0 };
        std::atomic<size_t> stringProcessed{ 0 };
        std::atomic<size_t> stringTotal{ 0 };

        // Phase text (debug)
        std::string lastProloguePhase;
        std::string lastStringPhase;
        std::mutex phaseMutex;

        // Row cache for virtualized rendering
        struct RowCache {
            uintptr_t addr{};
            std::string addrText;
            std::string name;
            std::string tagsShort;
        };
        std::vector<RowCache> rowCache;
        std::string filterText;

        MemoryScanState() = default;
        MemoryScanState(const MemoryScanState&) = delete;
        MemoryScanState& operator=(const MemoryScanState&) = delete;

        MemoryScanState(MemoryScanState&& other) noexcept {
            *this = std::move(other);
        }

        MemoryScanState& operator=(MemoryScanState&& other) noexcept {
            if (this == &other) return *this;

            running = other.running;
            cancelled = other.cancelled;
            scanPrologues = other.scanPrologues;
            scanStrings = other.scanStrings;
            anchorsRebuilt = other.anchorsRebuilt;
            prologueCompleted = other.prologueCompleted;
            stringCompleted = other.stringCompleted;
            uiFreeze = other.uiFreeze;
            rowsCacheDirty = other.rowsCacheDirty;
            lastStatusBuildTick = other.lastStatusBuildTick;

            prologueFuture = std::move(other.prologueFuture);
            stringFuture = std::move(other.stringFuture);
            prologueFunctions = std::move(other.prologueFunctions);
            stringHits = std::move(other.stringHits);

            startTime = other.startTime;
            status = std::move(other.status);

            prologueProcessed.store(other.prologueProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            prologueTotal.store(other.prologueTotal.load(std::memory_order_relaxed), std::memory_order_relaxed);
            stringProcessed.store(other.stringProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            stringTotal.store(other.stringTotal.load(std::memory_order_relaxed), std::memory_order_relaxed);

            {
                std::scoped_lock lk(other.phaseMutex);
                lastProloguePhase = std::move(other.lastProloguePhase);
                lastStringPhase = std::move(other.lastStringPhase);
            }

            rowCache = std::move(other.rowCache);
            filterText = std::move(other.filterText);

            // Reset source
            other.running = false;
            other.cancelled = false;
            other.scanPrologues = false;
            other.scanStrings = false;
            other.anchorsRebuilt = false;
            other.prologueCompleted = false;
            other.stringCompleted = false;
            other.uiFreeze = false;
            other.rowsCacheDirty = false;
            other.lastStatusBuildTick = 0;
            other.status.clear();
            other.prologueFunctions.clear();
            other.stringHits.clear();
            other.rowCache.clear();
            other.filterText.clear();
            other.prologueProcessed.store(0, std::memory_order_relaxed);
            other.prologueTotal.store(0, std::memory_order_relaxed);
            other.stringProcessed.store(0, std::memory_order_relaxed);
            other.stringTotal.store(0, std::memory_order_relaxed);
            {
                std::scoped_lock lk(other.phaseMutex);
                other.lastProloguePhase.clear();
                other.lastStringPhase.clear();
            }
            return *this;
        }

        void Reset() { *this = MemoryScanState{}; }
    } m_memScan;

    std::unordered_map<uintptr_t, std::vector<std::string>> m_memScanTags;
    std::vector<uintptr_t> m_memScanMerged;
    bool m_memScanDirty = false;

    uintptr_t    m_selectedFunctionAddress{ 0 };
    std::string  m_selectedFunctionAnalysis;
    bool         m_showAnalysisPanel{ true };
    bool         m_showDisassembly{ true };
    std::string  m_selectedDisasm;

    bool m_multiSelectMode{ false };
    std::vector<uintptr_t> m_multiSelected;
    std::string m_multiDiffText;
    bool m_showMultiDiff{ false };

    char m_analysisExportPath[260]{};
    bool m_exportOverwriteConfirm{ false };
    std::string m_lastAnalysisExportStatus;

    // Live trace structures
    struct LiveTraceEntry
    {
        uintptr_t address;
        uintptr_t callerAddress;
        std::string functionName;
        std::chrono::steady_clock::time_point timestamp;
        uint32_t threadId;   // was DWORD; use std types to avoid <Windows.h> in header
        int callCount;
    };


    struct LiveTraceState
    {
        bool capturing = false;
        bool autoScroll = true;
        int captureRateMs = 16;
        size_t maxEntries = 1000;

        std::vector<LiveTraceEntry> entries;
        std::unordered_set<uintptr_t> uniqueFunctions; // requires <unordered_set>
        size_t totalCalls = 0;
        float callsPerSecond = 0.0f;

        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point lastUpdateTime;

        std::mutex mutex;
    } m_liveTrace;

    // Live trace helper methods
    void InstallLiveTraceHook(uintptr_t address);
    void RemoveLiveTraceHooks();
    void HookCommonAPIsForTrace();
    void StartSimulationMode();

    // MinHook support (keep these private)
    std::unordered_map<uintptr_t, void*> m_activeHooks;
    bool m_hooksInitialized = false;
    bool InstallSimpleHook(uintptr_t address, const std::string& name);
    void RemoveAllHooks();
};