#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>
#include <thread>
#include <future>

namespace SapphireHook {

    // Forward declarations
    class FunctionDatabase;
    class SignatureDatabase;

    // Structure for string scan results - defined here to avoid circular dependencies
    struct StringScanResult {
        uintptr_t stringAddress;
        uintptr_t nearbyFunctionAddress;
        std::string foundString;
        std::string scanType;
        int confidence;

        StringScanResult() = default;
        StringScanResult(uintptr_t strAddr, uintptr_t funcAddr, const std::string& str,
            const std::string& type, int conf)
            : stringAddress(strAddr), nearbyFunctionAddress(funcAddr), foundString(str),
            scanType(type), confidence(conf)
        {
        }
    };

    // New: results for name-driven scans
    struct NameScanResult {
        uintptr_t functionAddress{}; // initialize
        std::string matchedName;   // original function name the anchor came from
        std::string anchor;        // string literal matched in data
        int confidence = 90;
    };

    // Memory analysis and function scanning utilities
    class FunctionScanner {
    public:
        // Scan configuration
        struct ScanConfig {
            bool includeStringBasedScan = true;
            bool includePrologueBasedScan = true;
            bool includeDatabaseFunctions = true;
            bool includeSignatureFunctions = true;
            size_t maxResults = 20000;
            int minConfidence = 5;
            std::chrono::milliseconds timeout{ 30000 };
            bool enableProgressReporting = true;
        };

        // Progress callback for long-running operations
        using ProgressCallback = std::function<void(size_t processed, size_t total, const std::string& phase)>;
        
        // Result callback for streaming results as they're found
        using ResultCallback = std::function<void(uintptr_t address)>;

        FunctionScanner();
        ~FunctionScanner();

        // Memory safety and validation
        bool IsSafeMemoryAddress(const void* address, size_t size) const;
        bool IsCommittedMemory(uintptr_t address, size_t size) const;
        bool IsExecutableMemory(uintptr_t address) const;
        bool IsValidMemoryAddress(uintptr_t address, size_t size) const;

        // String analysis
        bool IsValidString(const char* str, size_t maxLen) const;
        std::string ExtractFunctionNameFromMemory(uintptr_t address) const;
        std::string ScanForNearbyStrings(uintptr_t address, size_t searchRadius = 1024) const;

        // Function detection heuristics
        bool IsLikelyFunctionStart(uintptr_t address) const;
        bool IsLikelyFunctionStart(const uint8_t* code, size_t maxSize) const;
        uintptr_t FindFunctionStart(uintptr_t address) const;

        // Core scanning methods
        std::vector<StringScanResult> ScanMemoryForFunctionStrings(
            const std::vector<std::string>& targetStrings = {},
            ProgressCallback progress = nullptr) const;

        std::vector<uintptr_t> ScanForFunctionsByStrings(
            const std::vector<std::string>& searchStrings,
            ProgressCallback progress = nullptr) const;

        std::vector<uintptr_t> ScanForAllInterestingFunctions(
            const ScanConfig& config = ScanConfig{},
            ProgressCallback progress = nullptr,
            ResultCallback onResult = nullptr) const;

        std::vector<uintptr_t> ScanForAllFunctions(
            const ScanConfig& config = ScanConfig{},
            ProgressCallback progress = nullptr) const;

        // Async scanning support
        std::future<std::vector<uintptr_t>> StartAsyncScan(
            const ScanConfig& config = ScanConfig{},
            ProgressCallback progress = nullptr);

        std::future<std::vector<uintptr_t>> StartAsyncScanWithStrings(
            const std::vector<std::string>& targetStrings,
            const ScanConfig& config = ScanConfig{},
            ProgressCallback progress = nullptr);

        void StopScan();
        bool IsScanInProgress() const;

        // Module-specific scanning
        void ScanSafeRegion(uintptr_t baseAddr, size_t size, std::vector<uintptr_t>& functions) const;
        void ScanForFunctionPrologues(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions) const;
        void ScanExportedFunctions(std::vector<uintptr_t>& functions) const;
        void ScanCallTargets(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions) const;

        // Specialized function type scanning
        void ScanForUIFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions) const;
        void ScanForNetworkFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions) const;
        void ScanForGameplayFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions) const;

        // Integration with databases
        void SetFunctionDatabase(std::shared_ptr<FunctionDatabase> database);
        void SetSignatureDatabase(std::shared_ptr<SignatureDatabase> database);

        // Results management
        void UpdateTemporaryFunctionDatabase(const std::map<uintptr_t, std::string>& detectedFunctions);
        const std::map<uintptr_t, std::string>& GetDetectedFunctionNames() const;

        // New: name-driven discovery
        std::vector<NameScanResult> AutoScanFunctionsByNames(
            const std::vector<std::string>& functionNames,
            ProgressCallback progress = nullptr) const;

        std::vector<NameScanResult> AutoScanFunctionsFromDatabase(
            ProgressCallback progress = nullptr) const;

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace SapphireHook