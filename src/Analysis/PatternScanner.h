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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winnt.h>

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

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
#include <cstdio>     
#endif

namespace SapphireHook {

    enum class ScanError {
        InvalidPattern,
        NotFound,
        MemoryAccessViolation,
        InvalidAddress,
        CacheCorrupted,
        ModuleNotFound
    };

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
    template<typename T>
    using Expected = std::expected<T, ScanError>;
#else
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

    class MemoryBuffer {
    private:
        std::unique_ptr<uint8_t[]> m_data;
        size_t m_size;

    public:
        explicit MemoryBuffer(size_t size) : m_size(size)
        {
            m_data = std::make_unique<uint8_t[]>(size);
        }

        std::span<uint8_t> GetSpan() const
        {
            return std::span<uint8_t>(m_data.get(), m_size);
        }

        std::span<const uint8_t> GetConstSpan() const
        {
            return std::span<const uint8_t>(m_data.get(), m_size);
        }

        uint8_t* Data() const { return m_data.get(); }
        size_t Size() const { return m_size; }

        uint8_t* begin() const { return m_data.get(); }
        uint8_t* end() const { return m_data.get() + m_size; }

        uint8_t& operator[](size_t index) { return m_data[index]; }
        const uint8_t& operator[](size_t index) const { return m_data[index]; }

        void Zero() { std::memset(m_data.get(), 0, m_size); }
        void Fill(uint8_t value) { std::memset(m_data.get(), value, m_size); }
    };

    template<typename T>
    concept ScanableMemory = requires(T t)
    {
        { t.data() } -> std::convertible_to<const uint8_t*>;
        { t.size() } -> std::convertible_to<size_t>;
    };

    struct StringXrefResult {
        std::string text;
        uintptr_t stringAddress = 0;
        uintptr_t referenceAddress = 0;
        bool isUtf16 = false;
        
        explicit operator bool() const { return !text.empty() && stringAddress != 0; }
    };

    struct FunctionStringMap {
        std::unordered_map<uintptr_t, std::vector<std::string>> functionsToStrings;
        std::unordered_map<std::string, std::vector<uintptr_t>> stringsToFunctions;
        size_t asciiStringCount = 0;
        size_t utf16StringCount = 0;
    };

    struct PESection {
        std::byte* baseAddress = nullptr;
        size_t size = 0;
        std::string name;
        
        explicit operator bool() const { return baseAddress != nullptr && size > 0; }
    };



    class PatternScanner {
    public:
        struct ScanResult {
            uintptr_t address = 0;
            size_t offset = 0;
            std::vector<uint8_t> matched_bytes;
            bool fromCache = false;

            ScanResult() = default;

            ScanResult(uintptr_t addr, size_t off) : address(addr), offset(off) {}

            explicit operator bool() const { return address != 0; }
        };

        static std::optional<std::vector<int>> PatternToBytes(std::string_view pattern);

        static std::optional<ScanResult> ScanPattern(uintptr_t start, size_t length, std::string_view pattern);
        static std::optional<ScanResult> ScanPattern(const MemoryBuffer& buffer, std::string_view pattern);

        template<ScanableMemory T>
        static std::optional<ScanResult> ScanPattern(const T& memory, std::string_view pattern)
        {
            return ScanPattern(reinterpret_cast<uintptr_t>(memory.data()), memory.size(), pattern);
        }

        static std::vector<ScanResult> ScanAllPatterns(uintptr_t start, size_t length, std::string_view pattern);
        static std::vector<ScanResult> ScanAllPatterns(const MemoryBuffer& buffer, std::string_view pattern);

        static std::optional<ScanResult> ScanPatternWithMask(uintptr_t start, size_t length,
            std::span<const uint8_t> pattern,
            std::span<const bool> mask);

        static std::optional<ScanResult> ScanModule(const wchar_t* moduleName, std::string_view pattern);
        static std::optional<ScanResult> ScanMainModule(std::string_view pattern);

        static Expected<ScanResult> ScanPatternExpected(uintptr_t start, size_t length, std::string_view pattern);
        static Expected<ScanResult> ScanPatternExpected(const MemoryBuffer& buffer, std::string_view pattern);

        template<ScanableMemory T>
        static Expected<ScanResult> ScanPatternExpected(const T& memory, std::string_view pattern)
        {
            return ScanPatternExpected(reinterpret_cast<uintptr_t>(memory.data()), memory.size(), pattern);
        }

        static PESection GetPESection(HMODULE module, const char* sectionName);
        
        static std::vector<std::pair<uintptr_t, std::string>> EnumerateAsciiStrings(
            HMODULE module, size_t minLength = 6);
        static std::vector<std::pair<uintptr_t, std::string>> EnumerateUtf16Strings(
            HMODULE module, size_t minLength = 6);
        
        static bool ParseRipRelativeInstruction(const std::byte* instruction, 
            uintptr_t& target, size_t& instructionLength);
        static std::vector<uintptr_t> FindRipReferencesTo(HMODULE module, uintptr_t targetAddress);
        
        static uintptr_t GetFunctionStartFromRva(HMODULE module, uint32_t rva);
        static std::vector<uintptr_t> FindFunctionsReferencingString(HMODULE module, std::string_view searchString);
        
        static FunctionStringMap MapFunctionsToStrings(HMODULE module, size_t minStringLength = 6);
        static std::optional<StringXrefResult> GuessNameFromStringReferences(
            uintptr_t functionAddress, size_t maxScanBytes = 0x300);

        static void LogScanError(ScanError error, std::string_view context);

    private:
        static bool CompareBytes(const uint8_t* data, const std::vector<int>& pattern);
        
        static std::vector<std::byte*> FindAsciiInBuffer(std::byte* buffer, size_t length, std::string_view needle);
        static std::vector<std::byte*> FindUtf16InBuffer(std::byte* buffer, size_t length, std::wstring_view needle);
    };

    enum class AsyncScanStatus {
        Pending,           
        Running,          
        Completed,        
        Cancelled,         
        Failed             
    };

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

    struct AsyncScanResult {
        uint32_t jobId = 0;
        std::string name;                            
        std::string pattern;                         
        AsyncScanStatus status = AsyncScanStatus::Pending;
        std::optional<PatternScanner::ScanResult> result;       
        std::vector<PatternScanner::ScanResult> allResults;       
        ScanError error = ScanError::NotFound;      
        std::string errorMessage;                  
        
        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point endTime;
        
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

    using AsyncScanProgressCallback = std::function<void(
        uint32_t jobId, 
        size_t current, 
        size_t total, 
        const std::string& currentPattern)>;

    using AsyncScanCompletionCallback = std::function<void(const AsyncScanResult& result)>;

    struct AsyncScanConfig {
        std::string name;                            
        std::string pattern;                        
        bool findAll = false;                         
        bool useCache = true;                        
        int priority = 0;                           
        size_t chunkSize = 0x100000;                   
        AsyncScanProgressCallback onProgress;      
        AsyncScanCompletionCallback onComplete;    
    };

    struct BatchScanConfig {
        std::vector<AsyncScanConfig> patterns;     
        bool stopOnFirstMatch = false;                
        int maxConcurrent = 0;                        
        AsyncScanProgressCallback onProgress;      
        std::function<void(const std::vector<AsyncScanResult>&)> onComplete;   
    };

    class AsyncPatternScanner {
    public:
        static AsyncPatternScanner& GetInstance();

        void Initialize(size_t threadCount = 0);

        void Shutdown();

        bool IsInitialized() const { return m_initialized.load(); }

        uint32_t QueueScan(const AsyncScanConfig& config);

        uint32_t QueueScan(const std::string& name, const std::string& pattern,
                          AsyncScanCompletionCallback onComplete = nullptr);

        uint32_t ScanMainModuleAsync(const std::string& name, const std::string& pattern,
                                     AsyncScanCompletionCallback onComplete = nullptr);

        std::vector<uint32_t> QueueBatchScan(const BatchScanConfig& config);

        std::vector<uint32_t> QueueBatchScan(
            const std::vector<std::pair<std::string, std::string>>& namesAndPatterns,
            std::function<void(const std::vector<AsyncScanResult>&)> onComplete = nullptr);

        bool CancelJob(uint32_t jobId);

        void CancelAllJobs();

        std::optional<AsyncScanResult> GetJobResult(uint32_t jobId) const;

        bool IsJobComplete(uint32_t jobId) const;

        std::optional<AsyncScanResult> WaitForJob(uint32_t jobId, uint32_t timeoutMs = 0);

        void WaitForAllJobs();

        std::vector<AsyncScanResult> GetCompletedResults() const;

        void ClearCompletedResults();

        size_t GetPendingCount() const;

        size_t GetPendingJobCount() const { return GetPendingCount(); }

        size_t GetRunningCount() const;

        size_t GetTotalProcessed() const { return m_totalProcessed.load(); }

        size_t GetThreadCount() const { return m_workers.size(); }

        void SetCachingEnabled(bool enabled) { m_cachingEnabled = enabled; }
        bool IsCachingEnabled() const { return m_cachingEnabled; }

        void ClearCache();

        std::optional<PatternScanner::ScanResult> GetCachedResult(const std::string& pattern) const;

        size_t GetCacheHitCount() const { return m_cacheHits.load(); }

        size_t GetCacheMissCount() const { return m_cacheMisses.load(); }

    private:
        AsyncPatternScanner() = default;
        ~AsyncPatternScanner();
        AsyncPatternScanner(const AsyncPatternScanner&) = delete;
        AsyncPatternScanner& operator=(const AsyncPatternScanner&) = delete;

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

        std::vector<std::thread> m_workers;
        
        mutable std::mutex m_queueMutex;
        std::condition_variable m_queueCondition;
        std::vector<std::shared_ptr<ScanJob>> m_pendingJobs;     

        mutable std::mutex m_resultsMutex;
        std::unordered_map<uint32_t, AsyncScanResult> m_results;
        std::unordered_map<uint32_t, std::shared_ptr<ScanJob>> m_activeJobs;

        bool m_cachingEnabled = true;
        mutable std::mutex m_cacheMutex;
        std::unordered_map<std::string, PatternScanner::ScanResult> m_cache;
        mutable std::atomic<size_t> m_cacheHits{0};
        mutable std::atomic<size_t> m_cacheMisses{0};

        uintptr_t m_moduleBase = 0;
        size_t m_moduleSize = 0;
    };

}   

extern "C" {
    bool PatternToBytes(const char* pattern, std::vector<int>& bytes);
    uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern);
    uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize);
}