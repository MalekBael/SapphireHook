#pragma once

#include "../UI/UIModule.h"
#include "../Analysis/PatternScanner.h"
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <deque>

namespace SapphireHook {

/**
 * @brief UI module for async pattern/signature scanning
 * 
 * Provides a dedicated interface for:
 * - Single pattern scans with real-time progress
 * - Batch signature scanning from database
 * - Job queue visualization
 * - Result caching and statistics
 */
class SignatureScannerModule : public UIModule {
public:
    const char* GetName() const override { return "signature_scanner"; }
    const char* GetDisplayName() const override { return "Signature Scanner"; }

    void Initialize() override;
    void Shutdown() override;

    void RenderMenu() override;
    void RenderWindow() override;

    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
    bool m_windowOpen = false;
    bool m_initialized = false;

    // Pattern input
    char m_patternInput[512] = "";
    char m_nameInput[128] = "Custom Scan";
    int m_priority = 0;
    bool m_findAll = false;

    // Active job tracking
    struct JobDisplay {
        uint32_t jobId = 0;
        std::string name;
        std::string pattern;
        AsyncScanStatus status = AsyncScanStatus::Pending;
        float progress = 0.0f;
        std::chrono::steady_clock::time_point startTime;
        std::optional<AsyncScanResult> result;
    };
    std::mutex m_jobsMutex;
    std::deque<JobDisplay> m_activeJobs;
    std::deque<AsyncScanResult> m_completedResults;
    static constexpr size_t kMaxCompletedResults = 100;
    static constexpr size_t kMaxActiveJobs = 50;

    // Batch scanning
    struct BatchEntry {
        std::string name;
        std::string pattern;
        bool selected = true;
    };
    std::vector<BatchEntry> m_batchPatterns;
    char m_batchNameInput[128] = "";
    char m_batchPatternInput[512] = "";
    std::atomic<bool> m_batchInProgress{false};
    std::atomic<int> m_batchCompleted{0};
    std::atomic<int> m_batchTotal{0};

    // Statistics
    std::atomic<uint64_t> m_totalScans{0};
    std::atomic<uint64_t> m_successfulScans{0};
    std::atomic<double> m_totalScanTimeMs{0.0};

    // UI state
    int m_selectedTab = 0;
    bool m_autoScroll = true;
    char m_resultFilter[128] = "";

    // ========== Signature Discovery ==========
    struct DiscoveredSignature {
        uintptr_t address = 0;
        std::string signature;           // IDA-style pattern with wildcards
        std::string rawBytes;            // Raw hex bytes (no wildcards)
        std::string suggestedName;       // Auto-generated name
        size_t byteCount = 0;
        bool isUnique = false;           // True if pattern is unique in module
        bool selected = false;
    };
    
    std::vector<DiscoveredSignature> m_discoveredSigs;
    std::mutex m_discoveryMutex;
    std::atomic<bool> m_discoveryInProgress{false};
    std::atomic<int> m_discoveryProgress{0};
    std::atomic<int> m_discoveryTotal{0};
    
    // Validation progress (async)
    std::atomic<bool> m_validationInProgress{false};
    std::atomic<int> m_validationProgress{0};
    std::atomic<int> m_validationTotal{0};
    
    // Discovery settings
    int m_sigLength = 16;                // Bytes to extract per signature
    int m_maxFunctions = 500;            // Max functions to discover
    bool m_autoWildcard = true;          // Auto-wildcard relative offsets
    bool m_onlyUnique = false;           // Filter to unique sigs only
    bool m_skipCommonPrologues = false;  // Skip very common patterns
    char m_discoveryFilter[128] = "";
    
    // Prologue patterns to search for
    struct ProloguePattern {
        const char* name;
        const char* pattern;
        bool enabled = true;
    };
    std::vector<ProloguePattern> m_prologuePatterns;

    // ========== RTTI Scanner ==========
    struct RTTIClass {
        uintptr_t typeDescriptor = 0;    // Address of type descriptor
        uintptr_t vtable = 0;            // Address of vtable (if found)
        std::string mangledName;         // Raw mangled name
        std::string demangledName;       // Demangled class name
        std::string hierarchy;           // Parent classes
        bool selected = false;
    };
    
    std::vector<RTTIClass> m_rttiClasses;
    std::mutex m_rttiMutex;
    std::atomic<bool> m_rttiScanInProgress{false};
    std::atomic<int> m_rttiScanProgress{0};
    std::atomic<int> m_rttiScanTotal{0};
    char m_rttiFilter[128] = "";
    bool m_rttiShowOnlyWithVtable = false;

    // ========== VTable Scanner ==========
    struct VTableEntry {
        uintptr_t vtableAddress = 0;     // Address of vtable
        uintptr_t rttiAddress = 0;       // Associated RTTI (if any)
        std::string className;           // Class name from RTTI
        std::vector<uintptr_t> functions; // Function pointers in vtable
        size_t functionCount = 0;
        bool selected = false;
    };
    
    std::vector<VTableEntry> m_vtables;
    std::mutex m_vtableMutex;
    std::atomic<bool> m_vtableScanInProgress{false};
    std::atomic<int> m_vtableScanProgress{0};
    std::atomic<int> m_vtableScanTotal{0};
    char m_vtableFilter[128] = "";
    int m_vtableMinFunctions = 3;        // Minimum functions to consider a vtable
    int m_vtableMaxFunctions = 200;      // Maximum functions to extract
    int m_selectedVtableIdx = -1;        // For showing vtable details

    // ========== Static Pointer Scanner ==========
    struct StaticPointer {
        uintptr_t instructionAddress = 0; // Address of the instruction
        uintptr_t targetAddress = 0;      // Computed target (RIP + offset)
        std::string instructionBytes;     // Raw instruction bytes
        std::string pattern;              // Generated signature
        std::string suggestedName;        // Auto-generated name
        std::string accessType;           // MOV, LEA, CMP, etc.
        bool isUnique = false;
        bool selected = false;
    };
    
    std::vector<StaticPointer> m_staticPointers;
    std::mutex m_staticMutex;
    std::atomic<bool> m_staticScanInProgress{false};
    std::atomic<int> m_staticScanProgress{0};
    std::atomic<int> m_staticScanTotal{0};
    char m_staticFilter[128] = "";
    bool m_staticOnlyUnique = false;
    
    // Static pointer patterns to scan for
    struct StaticPointerPattern {
        const char* name;
        const char* pattern;
        const char* accessType;
        bool enabled = true;
    };
    std::vector<StaticPointerPattern> m_staticPatterns;

    // Rendering helpers
    void RenderSingleScanTab();
    void RenderBatchScanTab();
    void RenderResultsTab();
    void RenderStatisticsTab();
    void RenderDiscoveryTab();
    void RenderRTTITab();
    void RenderVTableTab();
    void RenderStaticPointerTab();
    void RenderJobQueue();

    // Actions
    void StartSingleScan();
    void StartBatchScan();
    void CancelAllScans();
    void ClearResults();
    void ExportResults();
    void ImportPatternsFromDatabase();
    
    // Discovery actions
    void StartDiscovery();
    void CancelDiscovery();
    void ClearDiscoveredSigs();
    void ExportDiscoveredSigs();
    std::string GenerateSignature(uintptr_t address, size_t length, bool autoWildcard);
    void ValidateSignatureUniqueness();
    
    // RTTI actions
    void StartRTTIScan();
    void CancelRTTIScan();
    void ClearRTTIResults();
    void ExportRTTIResults();
    std::string DemangleName(const std::string& mangled);
    
    // VTable actions
    void StartVTableScan();
    void CancelVTableScan();
    void ClearVTableResults();
    void ExportVTableResults();
    bool IsValidFunctionPointer(uintptr_t addr, uintptr_t moduleBase, size_t moduleSize);
    
    // Static pointer actions
    void StartStaticPointerScan();
    void CancelStaticPointerScan();
    void ClearStaticPointerResults();
    void ExportStaticPointerResults();
    void ValidateStaticPointerUniqueness();

    // Callbacks
    void OnScanProgress(uint32_t jobId, float progress);
    void OnScanComplete(uint32_t jobId, const AsyncScanResult& result);

    // Helpers
    void AddCompletedResult(const AsyncScanResult& result);
    void CleanupOldJobs();
    std::string FormatDuration(double ms) const;
    std::string FormatAddress(uintptr_t addr) const;
    ImVec4 GetStatusColor(AsyncScanStatus status) const;
    const char* GetStatusText(AsyncScanStatus status) const;
};

} // namespace SapphireHook
