#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <span>
#include <string_view>
#include <optional>
#include <concepts>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <future>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <chrono>

// Windows PE headers for string xref functionality
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winnt.h>

// Protect against Windows max macro
#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

// C++23 feature detection and fallbacks
#if __cpp_lib_expected >= 202202L
#include <expected>
#define SAPPHIRE_HAS_EXPECTED 1
#else
#define SAPPHIRE_HAS_EXPECTED 0
#endif

#if __cpp_lib_stacktrace >= 202011L
#include <stacktrace>
#define SAPPHIRE_HAS_STACKTRACE 1
#else
#define SAPPHIRE_HAS_STACKTRACE 0
#endif

#if __cpp_lib_print >= 202207L
#include <print>
#define SAPPHIRE_HAS_PRINT 1
#else
#define SAPPHIRE_HAS_PRINT 0
#include <cstdio>  // Fallback to printf
#endif

namespace SapphireHook {

    // Error types for better error handling
    enum class ScanError {
        InvalidPattern,
        NotFound,
        MemoryAccessViolation,
        InvalidAddress,
        CacheCorrupted,
        ModuleNotFound
    };

    // Helper to convert ScanError to string
    inline const char* ToString(ScanError error)
    {
        switch (error)
        {
        case ScanError::InvalidPattern: return "Invalid Pattern";
        case ScanError::NotFound: return "Pattern Not Found";
        case ScanError::MemoryAccessViolation: return "Memory Access Violation";
        case ScanError::InvalidAddress: return "Invalid Address";
        case ScanError::CacheCorrupted: return "Cache Corrupted";
        case ScanError::ModuleNotFound: return "Module Not Found";
        default: return "Unknown Error";
        }
    }

#if SAPPHIRE_HAS_EXPECTED
    // C++23 std::expected
    template<typename T>
    using Expected = std::expected<T, ScanError>;
#else
    // Fallback: custom expected-like class with proper initialization
    template<typename T>
    class Expected {
        std::optional<T> m_value;
        ScanError m_error = ScanError::NotFound;
        bool m_hasError;

    public:
        Expected(T value) : m_value(std::move(value)), m_hasError(false) {}
        Expected(ScanError error) : m_error(error), m_hasError(true) {}

        bool has_value() const { return !m_hasError; }
        explicit operator bool() const { return has_value(); }

        const T& value() const { return *m_value; }
        T& value() { return *m_value; }
        const T& operator*() const { return value(); }
        T& operator*() { return value(); }

        ScanError error() const { return m_error; }
    };
#endif

    // Modern C++20/23 memory buffer class
    class MemoryBuffer {
    private:
        std::unique_ptr<uint8_t[]> m_data;
        size_t m_size;

    public:
        explicit MemoryBuffer(size_t size) : m_size(size)
        {
            m_data = std::make_unique<uint8_t[]>(size);
        }

        // C++20 span interface
        std::span<uint8_t> GetSpan() const
        {
            return std::span<uint8_t>(m_data.get(), m_size);
        }

        std::span<const uint8_t> GetConstSpan() const
        {
            return std::span<const uint8_t>(m_data.get(), m_size);
        }

        // Raw access
        uint8_t* Data() const { return m_data.get(); }
        size_t Size() const { return m_size; }

        // Iterator support for C++20 ranges
        uint8_t* begin() const { return m_data.get(); }
        uint8_t* end() const { return m_data.get() + m_size; }

        // Element access
        uint8_t& operator[](size_t index) { return m_data[index]; }
        const uint8_t& operator[](size_t index) const { return m_data[index]; }

        // Utility methods
        void Zero() { std::memset(m_data.get(), 0, m_size); }
        void Fill(uint8_t value) { std::memset(m_data.get(), value, m_size); }
    };

    // C++20 concept for scannable memory ranges
    template<typename T>
    concept ScanableMemory = requires(T t)
    {
        { t.data() } -> std::convertible_to<const uint8_t*>;
        { t.size() } -> std::convertible_to<size_t>;
    };

    // ===== STRING XREF FUNCTIONALITY =====

    // String cross-reference result
    struct StringXrefResult {
        std::string text;
        uintptr_t stringAddress = 0;
        uintptr_t referenceAddress = 0;
        bool isUtf16 = false;
        
        explicit operator bool() const { return !text.empty() && stringAddress != 0; }
    };

    // Function to strings mapping result
    struct FunctionStringMap {
        // Function start -> strings it references
        std::unordered_map<uintptr_t, std::vector<std::string>> functionsToStrings;
        // String text -> function starts referencing it
        std::unordered_map<std::string, std::vector<uintptr_t>> stringsToFunctions;
        size_t asciiStringCount = 0;
        size_t utf16StringCount = 0;
    };

    // PE section information
    struct PESection {
        std::byte* baseAddress = nullptr;
        size_t size = 0;
        std::string name;
        
        explicit operator bool() const { return baseAddress != nullptr && size > 0; }
    };



    // Legacy PatternScanner class - enhanced with caching support
    class PatternScanner {
    public:
        // Pattern result with proper initialization
        struct ScanResult {
            uintptr_t address = 0;
            size_t offset = 0;
            std::vector<uint8_t> matched_bytes;
            bool fromCache = false;

            // Default constructor
            ScanResult() = default;

            // Constructor with parameters
            ScanResult(uintptr_t addr, size_t off) : address(addr), offset(off) {}

            explicit operator bool() const { return address != 0; }
        };

        // Modern pattern parsing with string_view
        static std::optional<std::vector<int>> PatternToBytes(std::string_view pattern);

        // Enhanced pattern scanning with multiple overloads (C++20 style)
        static std::optional<ScanResult> ScanPattern(uintptr_t start, size_t length, std::string_view pattern);
        static std::optional<ScanResult> ScanPattern(const MemoryBuffer& buffer, std::string_view pattern);

        // C++20 concepts-based scanning
        template<ScanableMemory T>
        static std::optional<ScanResult> ScanPattern(const T& memory, std::string_view pattern)
        {
            return ScanPattern(reinterpret_cast<uintptr_t>(memory.data()), memory.size(), pattern);
        }

        // Find all pattern matches
        static std::vector<ScanResult> ScanAllPatterns(uintptr_t start, size_t length, std::string_view pattern);
        static std::vector<ScanResult> ScanAllPatterns(const MemoryBuffer& buffer, std::string_view pattern);

        // Advanced pattern matching with masks
        static std::optional<ScanResult> ScanPatternWithMask(uintptr_t start, size_t length,
            std::span<const uint8_t> pattern,
            std::span<const bool> mask);

        // Module scanning utilities
        static std::optional<ScanResult> ScanModule(const wchar_t* moduleName, std::string_view pattern);
        static std::optional<ScanResult> ScanMainModule(std::string_view pattern);

        // C++23 style expected variants
        static Expected<ScanResult> ScanPatternExpected(uintptr_t start, size_t length, std::string_view pattern);
        static Expected<ScanResult> ScanPatternExpected(const MemoryBuffer& buffer, std::string_view pattern);

        // C++23 concepts-based expected scanning
        template<ScanableMemory T>
        static Expected<ScanResult> ScanPatternExpected(const T& memory, std::string_view pattern)
        {
            return ScanPatternExpected(reinterpret_cast<uintptr_t>(memory.data()), memory.size(), pattern);
        }

        // ===== STRING XREF FUNCTIONALITY =====

        // PE section utilities
        static PESection GetPESection(HMODULE module, const char* sectionName);
        
        // String enumeration
        static std::vector<std::pair<uintptr_t, std::string>> EnumerateAsciiStrings(
            HMODULE module, size_t minLength = 6);
        static std::vector<std::pair<uintptr_t, std::string>> EnumerateUtf16Strings(
            HMODULE module, size_t minLength = 6);
        
        // RIP-relative instruction analysis
        static bool ParseRipRelativeInstruction(const std::byte* instruction, 
            uintptr_t& target, size_t& instructionLength);
        static std::vector<uintptr_t> FindRipReferencesTo(HMODULE module, uintptr_t targetAddress);
        
        // Function analysis
        static uintptr_t GetFunctionStartFromRva(HMODULE module, uint32_t rva);
        static std::vector<uintptr_t> FindFunctionsReferencingString(HMODULE module, std::string_view searchString);
        
        // High-level string cross-reference mapping
        static FunctionStringMap MapFunctionsToStrings(HMODULE module, size_t minStringLength = 6);
        static std::optional<StringXrefResult> GuessNameFromStringReferences(
            uintptr_t functionAddress, size_t maxScanBytes = 0x300);

        // Enhanced error logging (with fallback)
        static void LogScanError(ScanError error, std::string_view context);

    private:
        static bool CompareBytes(const uint8_t* data, const std::vector<int>& pattern);
        
        // String xref helpers
        static std::vector<std::byte*> FindAsciiInBuffer(std::byte* buffer, size_t length, std::string_view needle);
        static std::vector<std::byte*> FindUtf16InBuffer(std::byte* buffer, size_t length, std::wstring_view needle);
    };

    // =========================================================================
    // ASYNC PATTERN SCANNING
    // =========================================================================

    /// @brief Status of an async scan job
    enum class AsyncScanStatus {
        Pending,        ///< Waiting to start
        Running,        ///< Currently scanning
        Completed,      ///< Finished successfully
        Cancelled,      ///< Cancelled by user
        Failed          ///< Failed with error
    };

    /// @brief Convert AsyncScanStatus to string
    inline const char* ToString(AsyncScanStatus status) {
        switch (status) {
            case AsyncScanStatus::Pending: return "Pending";
            case AsyncScanStatus::Running: return "Running";
            case AsyncScanStatus::Completed: return "Completed";
            case AsyncScanStatus::Cancelled: return "Cancelled";
            case AsyncScanStatus::Failed: return "Failed";
            default: return "Unknown";
        }
    }

    /// @brief Result of an async scan operation
    struct AsyncScanResult {
        uint32_t jobId = 0;
        std::string name;                       ///< User-provided name for this scan
        std::string pattern;                    ///< The pattern that was scanned
        AsyncScanStatus status = AsyncScanStatus::Pending;
        std::optional<PatternScanner::ScanResult> result;  ///< The scan result (if found)
        std::vector<PatternScanner::ScanResult> allResults; ///< All matches (if scanning for all)
        ScanError error = ScanError::NotFound;  ///< Error code if failed
        std::string errorMessage;               ///< Detailed error message
        
        // Timing info
        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point endTime;
        
        /// @brief Get scan duration in milliseconds
        double GetDurationMs() const {
            auto end = (status == AsyncScanStatus::Running) 
                ? std::chrono::steady_clock::now() 
                : endTime;
            return std::chrono::duration<double, std::milli>(end - startTime).count();
        }
        
        bool IsComplete() const {
            return status == AsyncScanStatus::Completed || 
                   status == AsyncScanStatus::Cancelled || 
                   status == AsyncScanStatus::Failed;
        }
        
        bool WasSuccessful() const {
            return status == AsyncScanStatus::Completed && result.has_value();
        }
    };

    /// @brief Progress callback for async scans
    /// @param jobId The job ID
    /// @param current Current progress (bytes scanned or patterns completed)
    /// @param total Total amount to scan
    /// @param currentPattern Name/pattern currently being scanned
    using AsyncScanProgressCallback = std::function<void(
        uint32_t jobId, 
        size_t current, 
        size_t total, 
        const std::string& currentPattern)>;

    /// @brief Completion callback for async scans
    using AsyncScanCompletionCallback = std::function<void(const AsyncScanResult& result)>;

    /// @brief Configuration for an async scan job
    struct AsyncScanConfig {
        std::string name;                       ///< Friendly name for this scan
        std::string pattern;                    ///< Pattern to scan for
        bool findAll = false;                   ///< Find all matches vs first match
        bool useCache = true;                   ///< Use cached results if available
        int priority = 0;                       ///< Higher = scanned first
        size_t chunkSize = 0x100000;            ///< Bytes per chunk (1MB default) for progress
        AsyncScanProgressCallback onProgress;   ///< Progress callback (optional)
        AsyncScanCompletionCallback onComplete; ///< Completion callback (optional)
    };

    /// @brief Batch scan configuration
    struct BatchScanConfig {
        std::vector<AsyncScanConfig> patterns;  ///< Patterns to scan
        bool stopOnFirstMatch = false;          ///< Stop all scans when one matches
        int maxConcurrent = 0;                  ///< Max concurrent scans (0 = auto)
        AsyncScanProgressCallback onProgress;   ///< Overall progress callback
        std::function<void(const std::vector<AsyncScanResult>&)> onComplete; ///< Batch completion
    };

    /// @brief Async pattern scanner with background thread pool
    class AsyncPatternScanner {
    public:
        /// @brief Get singleton instance
        static AsyncPatternScanner& GetInstance();

        /// @brief Initialize the async scanner
        /// @param threadCount Number of worker threads (0 = auto-detect)
        void Initialize(size_t threadCount = 0);

        /// @brief Shutdown and wait for all jobs to complete
        void Shutdown();

        /// @brief Check if initialized
        bool IsInitialized() const { return m_initialized.load(); }

        // ========== Single Pattern Scanning ==========

        /// @brief Queue a single pattern scan
        /// @param config Scan configuration
        /// @return Job ID for tracking
        uint32_t QueueScan(const AsyncScanConfig& config);

        /// @brief Queue a simple pattern scan with defaults
        /// @param name Friendly name
        /// @param pattern Pattern string
        /// @param onComplete Completion callback
        /// @return Job ID
        uint32_t QueueScan(const std::string& name, const std::string& pattern,
                          AsyncScanCompletionCallback onComplete = nullptr);

        /// @brief Scan main module async (convenience)
        uint32_t ScanMainModuleAsync(const std::string& name, const std::string& pattern,
                                     AsyncScanCompletionCallback onComplete = nullptr);

        // ========== Batch Scanning ==========

        /// @brief Queue multiple patterns for scanning
        /// @param config Batch configuration
        /// @return Vector of job IDs
        std::vector<uint32_t> QueueBatchScan(const BatchScanConfig& config);

        /// @brief Scan multiple patterns with simple config
        std::vector<uint32_t> QueueBatchScan(
            const std::vector<std::pair<std::string, std::string>>& namesAndPatterns,
            std::function<void(const std::vector<AsyncScanResult>&)> onComplete = nullptr);

        // ========== Job Management ==========

        /// @brief Cancel a specific job
        /// @param jobId Job to cancel
        /// @return True if cancellation was requested
        bool CancelJob(uint32_t jobId);

        /// @brief Cancel all pending and running jobs
        void CancelAllJobs();

        /// @brief Get status of a job
        std::optional<AsyncScanResult> GetJobResult(uint32_t jobId) const;

        /// @brief Check if a job is complete
        bool IsJobComplete(uint32_t jobId) const;

        /// @brief Wait for a job to complete
        /// @param jobId Job to wait for
        /// @param timeoutMs Timeout in milliseconds (0 = wait forever)
        /// @return Result if completed, nullopt if timed out
        std::optional<AsyncScanResult> WaitForJob(uint32_t jobId, uint32_t timeoutMs = 0);

        /// @brief Wait for all jobs to complete
        void WaitForAllJobs();

        /// @brief Get all completed results
        std::vector<AsyncScanResult> GetCompletedResults() const;

        /// @brief Clear completed results from memory
        void ClearCompletedResults();

        // ========== Statistics ==========

        /// @brief Get number of pending jobs
        size_t GetPendingCount() const;

        /// @brief Alias for GetPendingCount
        size_t GetPendingJobCount() const { return GetPendingCount(); }

        /// @brief Get number of running jobs
        size_t GetRunningCount() const;

        /// @brief Get total jobs processed
        size_t GetTotalProcessed() const { return m_totalProcessed.load(); }

        /// @brief Get worker thread count
        size_t GetThreadCount() const { return m_workers.size(); }

        // ========== Caching ==========

        /// @brief Enable/disable result caching
        void SetCachingEnabled(bool enabled) { m_cachingEnabled = enabled; }
        bool IsCachingEnabled() const { return m_cachingEnabled; }

        /// @brief Clear the result cache
        void ClearCache();

        /// @brief Get cached result for a pattern
        std::optional<PatternScanner::ScanResult> GetCachedResult(const std::string& pattern) const;

        /// @brief Get cache hit count
        size_t GetCacheHitCount() const { return m_cacheHits.load(); }

        /// @brief Get cache miss count
        size_t GetCacheMissCount() const { return m_cacheMisses.load(); }

    private:
        AsyncPatternScanner() = default;
        ~AsyncPatternScanner();
        AsyncPatternScanner(const AsyncPatternScanner&) = delete;
        AsyncPatternScanner& operator=(const AsyncPatternScanner&) = delete;

        /// @brief Internal job representation
        struct ScanJob {
            uint32_t id = 0;
            AsyncScanConfig config;
            std::atomic<bool> cancelled{false};
            std::promise<AsyncScanResult> promise;
            std::shared_future<AsyncScanResult> future;
        };

        void WorkerThread();
        void ProcessJob(std::shared_ptr<ScanJob> job);
        AsyncScanResult ExecuteScan(std::shared_ptr<ScanJob> job);
        uint32_t GenerateJobId();

        std::atomic<bool> m_initialized{false};
        std::atomic<bool> m_shutdownRequested{false};
        std::atomic<uint32_t> m_nextJobId{1};
        std::atomic<size_t> m_totalProcessed{0};
        std::atomic<size_t> m_runningCount{0};

        // Thread pool
        std::vector<std::thread> m_workers;
        
        // Job queue (priority queue)
        mutable std::mutex m_queueMutex;
        std::condition_variable m_queueCondition;
        std::vector<std::shared_ptr<ScanJob>> m_pendingJobs;  // Sorted by priority

        // Results storage
        mutable std::mutex m_resultsMutex;
        std::unordered_map<uint32_t, AsyncScanResult> m_results;
        std::unordered_map<uint32_t, std::shared_ptr<ScanJob>> m_activeJobs;

        // Caching
        bool m_cachingEnabled = true;
        mutable std::mutex m_cacheMutex;
        std::unordered_map<std::string, PatternScanner::ScanResult> m_cache;
        mutable std::atomic<size_t> m_cacheHits{0};
        mutable std::atomic<size_t> m_cacheMisses{0};

        // Module info (cached on init)
        uintptr_t m_moduleBase = 0;
        size_t m_moduleSize = 0;
    };

} // namespace SapphireHook

// Legacy C-style functions for backward compatibility
extern "C" {
    bool PatternToBytes(const char* pattern, std::vector<int>& bytes);
    uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern);
    uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize);
}