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
#include <filesystem>
#include <chrono>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <mutex>
#include <fstream>
#include <thread>
#include <limits>
#include <future>
#include <functional>

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

    // Forward declarations
    class EnhancedPatternScanner;
    class PatternScanner;
    struct ScanCacheEntry;
    struct ScanMetrics;

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

    // Cache entry structure with proper initialization
    struct ScanCacheEntry {
        std::string gameVersion;
        uintptr_t moduleBase = 0;
        size_t moduleSize = 0;
        std::string moduleHash;
        std::unordered_map<std::string, uintptr_t> resolvedPatterns;
        std::chrono::system_clock::time_point cacheTime;

        // Default constructor with proper initialization
        ScanCacheEntry() = default;

        // Serialization helpers
        std::string ToJson() const;
        static std::optional<ScanCacheEntry> FromJson(const std::string& json);
    };

    // Performance metrics structure - Fixed to avoid Windows max macro
    struct ScanMetrics {
        size_t totalScans = 0;
        size_t cacheHits = 0;
        size_t cacheMisses = 0;
        std::chrono::milliseconds totalScanTime = std::chrono::milliseconds(0);
        std::chrono::milliseconds averageScanTime = std::chrono::milliseconds(0);

        // Use explicit value instead of ::max() to avoid Windows macro conflict
        std::chrono::milliseconds fastestScan = std::chrono::milliseconds(std::numeric_limits<long long>::max());
        std::chrono::milliseconds slowestScan = std::chrono::milliseconds(0);

        void RecordScan(std::chrono::milliseconds duration, bool fromCache);
        void Reset();
        double GetCacheHitRate() const;
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

    // ===== ASYNC PATTERN SCANNING COMPONENTS =====

    // Cancellation token inspired by Dalamud's approach
    class CancellationToken {
    private:
        std::shared_ptr<std::atomic<bool>> m_cancelled;

    public:
        CancellationToken() : m_cancelled(std::make_shared<std::atomic<bool>>(false)) {}

        void Cancel() { m_cancelled->store(true); }
        bool IsCancelled() const { return m_cancelled->load(); }

        // For timeout-based cancellation
        static CancellationToken CreateWithTimeout(std::chrono::milliseconds timeout)
        {
            CancellationToken token;

            // Start a timer thread that will cancel after timeout
            std::thread([token_ptr = token.m_cancelled, timeout]()
                {
                    std::this_thread::sleep_for(timeout);
                    token_ptr->store(true);
                }).detach();

            return token;
        }
    };

    // ===== CORE SCANNER INTERFACES =====

    // Interface inspired by Dalamud's ISigScanner
    class ISigScanner {
    public:
        virtual ~ISigScanner() = default;
        virtual std::optional<uintptr_t> ScanText(std::string_view pattern) = 0;
        virtual std::optional<uintptr_t> ScanData(std::string_view pattern) = 0;
        virtual uintptr_t GetSearchBase() const = 0;
        virtual size_t GetSearchSize() const = 0;
        virtual bool Is32BitProcess() const = 0;
        virtual const ScanMetrics& GetMetrics() const = 0;
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

        // Global scanner instance management
        static std::shared_ptr<EnhancedPatternScanner> GetGlobalScanner();
        static void SetGlobalScanner(std::shared_ptr<EnhancedPatternScanner> scanner);

    private:
        static bool CompareBytes(const uint8_t* data, const std::vector<int>& pattern);
        static std::shared_ptr<EnhancedPatternScanner> s_globalScanner;
        static std::mutex s_globalScannerMutex;
        
        // String xref helpers
        static std::vector<std::byte*> FindAsciiInBuffer(std::byte* buffer, size_t length, std::string_view needle);
        static std::vector<std::byte*> FindUtf16InBuffer(std::byte* buffer, size_t length, std::wstring_view needle);
    };

    // Async scanner result with detailed error information - NOW properly defined after PatternScanner
    struct AsyncScanResult {
        std::optional<PatternScanner::ScanResult> result;
        ScanError error = ScanError::NotFound;
        std::chrono::milliseconds duration{ 0 };
        bool was_cancelled = false;
        std::string pattern;

        explicit operator bool() const
        {
            return result.has_value() && !was_cancelled;
        }
    };

    // Enhanced pattern scanner with C++20/23 features and Dalamud-inspired caching
    class EnhancedPatternScanner : public ISigScanner {
    public:
        // Pattern result with proper initialization
        struct ScanResult {
            uintptr_t address = 0;
            size_t offset = 0;
            std::vector<uint8_t> matched_bytes;
            bool fromCache = false;
            std::chrono::milliseconds scanTime = std::chrono::milliseconds(0);

            // Default constructor
            ScanResult() = default;

            // Constructor with parameters
            ScanResult(uintptr_t addr, size_t off) : address(addr), offset(off) {}

            explicit operator bool() const { return address != 0; }
        };

    private:
        // Module information
        uintptr_t m_moduleBase = 0;
        size_t m_moduleSize = 0;
        uintptr_t m_textSection = 0;
        size_t m_textSize = 0;
        uintptr_t m_dataSection = 0;
        size_t m_dataSize = 0;

        // Caching system inspired by Dalamud
        std::filesystem::path m_cacheFile;
        std::optional<ScanCacheEntry> m_loadedCache;
        std::string m_gameVersion;
        bool m_enableCaching = true;
        mutable std::mutex m_cacheMutex;

        // Performance metrics
        mutable ScanMetrics m_metrics;
        mutable std::mutex m_metricsMutex;

    public:
        explicit EnhancedPatternScanner(bool enableCaching = true,
            const std::filesystem::path& cacheFile = "scanner_cache.json");

        // Core scanning interface (ISigScanner implementation)
        std::optional<uintptr_t> ScanText(std::string_view pattern) override;
        std::optional<uintptr_t> ScanData(std::string_view pattern) override;
        uintptr_t GetSearchBase() const override { return m_moduleBase; }
        size_t GetSearchSize() const override { return m_moduleSize; }
        bool Is32BitProcess() const override;
        const ScanMetrics& GetMetrics() const override;

        // Enhanced scanning methods
        std::optional<ScanResult> ScanModule(std::string_view pattern);
        std::optional<ScanResult> ScanRegion(uintptr_t base, size_t size, std::string_view pattern);

        // Multi-pattern scanning inspired by Dalamud's batch operations
        std::map<std::string, uintptr_t> ScanMultiple(const std::map<std::string, std::string>& patterns);

        // Cache management inspired by Dalamud's approach
        bool LoadCache();
        bool SaveCache() const;
        void ClearCache();
        bool IsCacheValid() const;
        void InvalidateCache();

        // Performance and debugging
        void ResetMetrics();
        std::map<std::string, std::string> GetDebugInfo() const;

        // Version tracking inspired by Dalamud
        std::string GetGameVersion() const;
        bool IsVersionCompatible(const std::string& version) const;

    private:
        bool InitializeModule();
        bool ParsePESection();
        std::optional<ScanResult> ScanRegionInternal(uintptr_t base, size_t size,
            std::string_view pattern, bool useCache = true);
        std::string GenerateCacheKey(std::string_view pattern) const;
        std::string CalculateModuleHash() const;
        bool IsPatternCached(const std::string& cacheKey, uintptr_t& result) const;
        void CachePattern(const std::string& cacheKey, uintptr_t result);
    };

    // ===== ASYNC PATTERN SCANNING =====

    // Async pattern scanner with Dalamud-inspired error handling
    class AsyncPatternScanner {
    public:
        // Configuration for scanning behavior
        struct ScanConfig {
            std::chrono::milliseconds timeout{ 5000 };  // 5 second default timeout
            bool enable_logging = true;
            size_t chunk_size = 1024 * 1024;  // 1MB chunks for progress reporting
            std::chrono::milliseconds progress_interval{ 100 };  // Progress callback interval
        };

        // Progress callback type
        using ProgressCallback = std::function<void(size_t processed, size_t total, std::string_view current_pattern)>;

        // Async scan with proper cancellation and error handling
        static std::future<AsyncScanResult> ScanPatternAsync(
            uintptr_t start,
            size_t length,
            std::string_view pattern,
            CancellationToken cancellation = CancellationToken{},
            const ScanConfig& config = ScanConfig{},
            ProgressCallback progress = nullptr
        );

        // Async module scan with automatic module resolution
        static std::future<AsyncScanResult> ScanModuleAsync(
            const wchar_t* moduleName,
            std::string_view pattern,
            CancellationToken cancellation = CancellationToken{},
            const ScanConfig& config = ScanConfig{},
            ProgressCallback progress = nullptr
        );

        // Scan multiple patterns concurrently (inspired by Dalamud's batch operations)
        static std::future<std::vector<AsyncScanResult>> ScanPatternsAsync(
            uintptr_t start,
            size_t length,
            const std::vector<std::string>& patterns,
            CancellationToken cancellation = CancellationToken{},
            const ScanConfig& config = ScanConfig{},
            ProgressCallback progress = nullptr
        );

    private:
        static AsyncScanResult PerformScan(
            uintptr_t start,
            size_t length,
            std::string_view pattern,
            CancellationToken cancellation,
            const ScanConfig& config,
            ProgressCallback progress
        );

        static bool ValidateMemoryRegion(uintptr_t start, size_t length);
        static void LogScanStart(std::string_view pattern, uintptr_t start, size_t length);
        static void LogScanResult(const AsyncScanResult& result);
    };

    // RAII scan operation manager (inspired by Dalamud's service management)
    class ScanOperation {
    private:
        std::future<AsyncScanResult> m_future;
        CancellationToken m_cancellation;
        std::string m_pattern;
        std::chrono::steady_clock::time_point m_startTime;

    public:
        ScanOperation(std::future<AsyncScanResult> future,
            CancellationToken cancellation,
            std::string pattern)
            : m_future(std::move(future))
            , m_cancellation(cancellation)
            , m_pattern(std::move(pattern))
            , m_startTime(std::chrono::steady_clock::now())
        {
        }

        // Check if scan is complete
        bool IsReady(std::chrono::milliseconds timeout = std::chrono::milliseconds{ 0 }) const
        {
            return m_future.wait_for(timeout) == std::future_status::ready;
        }

        // Get result (blocks until complete)
        AsyncScanResult GetResult()
        {
            return m_future.get();
        }

        // Try to get result without blocking
        std::optional<AsyncScanResult> TryGetResult()
        {
            if (IsReady())
            {
                return GetResult();
            }
            return std::nullopt;
        }

        // Cancel the operation
        void Cancel();

        // Get elapsed time
        std::chrono::milliseconds GetElapsedTime() const
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - m_startTime);
        }

        const std::string& GetPattern() const { return m_pattern; }
    };

    // ===== MODULE INFORMATION & FACTORY =====

    // Module information with RAII and enhanced capabilities
    class ModuleInfo {
    private:
        uintptr_t m_baseAddress = 0;
        size_t m_size = 0;
        std::wstring m_name;
        std::string m_version;
        std::string m_hash;
        std::chrono::system_clock::time_point m_scanned;

    public:
        explicit ModuleInfo(const wchar_t* moduleName = nullptr);

        uintptr_t BaseAddress() const { return m_baseAddress; }
        size_t Size() const { return m_size; }
        const std::wstring& Name() const { return m_name; }
        const std::string& Version() const { return m_version; }
        const std::string& Hash() const { return m_hash; }
        std::chrono::system_clock::time_point ScannedTime() const { return m_scanned; }

        // Create a memory buffer from this module
        std::unique_ptr<MemoryBuffer> CreateBuffer() const;

        // Direct pattern scanning (C++20 style)
        std::optional<PatternScanner::ScanResult> ScanPattern(std::string_view pattern) const;
        std::vector<PatternScanner::ScanResult> ScanAllPatterns(std::string_view pattern) const;

        // C++23 style expected variants
        Expected<PatternScanner::ScanResult> ScanPatternExpected(std::string_view pattern) const;

        // Enhanced debugging
        std::map<std::string, std::string> GetDebugInfo() const;

        explicit operator bool() const { return m_baseAddress != 0; }

    private:
        void CalculateModuleHash();
        std::string GetModuleVersion() const;
    };

    // Scanner factory inspired by Dalamud's service patterns
    class ScannerFactory {
    public:
        static std::shared_ptr<EnhancedPatternScanner> CreateCachedScanner(
            const std::filesystem::path& cacheDir = "cache",
            const std::string& gameVersion = "");

        static std::shared_ptr<EnhancedPatternScanner> CreateMemoryOnlyScanner();

        // Create scanner for specific module
        static std::shared_ptr<EnhancedPatternScanner> CreateModuleScanner(
            const std::wstring& moduleName,
            bool enableCaching = true);
    };

} // namespace SapphireHook

// Legacy C-style functions for backward compatibility
extern "C" {
    bool PatternToBytes(const char* pattern, std::vector<int>& bytes);
    uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern);
    uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize);
}