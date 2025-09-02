#pragma once
#include "patternscanner.h"
#include "../src/Logger/Logger.h"
#include <future>
#include <atomic>
#include <chrono>
#include <thread>

namespace SapphireHook {

    // Async scanner result with detailed error information
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
        void Cancel()
        {
            LogWarning("Cancelling scan operation for pattern: " + m_pattern);  // FIXED: Concatenate strings instead of using format placeholders
            m_cancellation.Cancel();
        }

        // Get elapsed time
        std::chrono::milliseconds GetElapsedTime() const
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - m_startTime);
        }

        const std::string& GetPattern() const { return m_pattern; }
    };

} // namespace SapphireHook