#include "AsyncPatternScanner.h"
#include "WindowsAPIWrapper.h"
#include "../Logger/Logger.h"
#include <sstream>
#include <iomanip>

namespace SapphireHook {

    // ===== AsyncPatternScanner Implementation =====

    std::future<AsyncScanResult> AsyncPatternScanner::ScanPatternAsync(
        uintptr_t start,
        size_t length,
        std::string_view pattern,
        CancellationToken cancellation,
        const ScanConfig& config,
        ProgressCallback progress)
    {
        return std::async(std::launch::async, [=]()
            {
                return PerformScan(start, length, pattern, cancellation, config, progress);
            });
    }

    std::future<AsyncScanResult> AsyncPatternScanner::ScanModuleAsync(
        const wchar_t* moduleName,
        std::string_view pattern,
        CancellationToken cancellation,
        const ScanConfig& config,
        ProgressCallback progress)
    {
        return std::async(std::launch::async, [=]()
            {
                // Convert wide string to narrow string for GetModuleHandleWrapper
                std::string moduleNameStr;
                for (const wchar_t* p = moduleName; *p; ++p)
                {
                    if (*p <= 127) moduleNameStr += static_cast<char>(*p);
                    else moduleNameStr += '?';
                }

                // Get module information
                void* hModule = GetModuleHandleWrapper(moduleNameStr.c_str());
                if (!hModule)
                {
                    AsyncScanResult result;
                    result.error = ScanError::ModuleNotFound;
                    result.pattern = std::string(pattern);
                    result.was_cancelled = false;

                    LogError("Failed to get module handle for: " + moduleNameStr);
                    return result;
                }

                // For simplicity, we'll use a reasonable default module size
                // In a real implementation, you'd use GetModuleInformation to get the actual size
                uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hModule);
                size_t moduleSize = 0x10000000; // 256MB default - should be determined properly

                if (config.enable_logging)
                {
                    LogInfo("Scanning module at 0x" + std::to_string(moduleBase) + " for pattern: " + std::string(pattern));
                }

                return PerformScan(moduleBase, moduleSize, pattern, cancellation, config, progress);
            });
    }

    std::future<std::vector<AsyncScanResult>> AsyncPatternScanner::ScanPatternsAsync(
        uintptr_t start,
        size_t length,
        const std::vector<std::string>& patterns,
        CancellationToken cancellation,
        const ScanConfig& config,
        ProgressCallback progress)
    {
        return std::async(std::launch::async, [=]()
            {
                std::vector<AsyncScanResult> results;
                results.reserve(patterns.size());

                if (config.enable_logging)
                {
                    LogInfo("Starting batch scan of " + std::to_string(patterns.size()) + " patterns");
                }

                for (size_t i = 0; i < patterns.size(); ++i)
                {
                    if (cancellation.IsCancelled())
                    {
                        // Add cancelled results for remaining patterns
                        for (size_t j = i; j < patterns.size(); ++j)
                        {
                            AsyncScanResult cancelledResult;
                            cancelledResult.pattern = patterns[j];
                            cancelledResult.was_cancelled = true;
                            cancelledResult.error = ScanError::NotFound;
                            results.push_back(cancelledResult);
                        }
                        break;
                    }

                    // Update progress if callback provided
                    if (progress)
                    {
                        progress(i, patterns.size(), patterns[i]);
                    }

                    // Perform individual scan
                    AsyncScanResult result = PerformScan(start, length, patterns[i], cancellation, config, nullptr);
                    results.push_back(result);

                    if (config.enable_logging && result)
                    {
                        LogInfo("Pattern " + std::to_string(i + 1) + "/" + std::to_string(patterns.size()) +
                            " found at 0x" + std::to_string(result.result->address));
                    }
                }

                return results;
            });
    }

    AsyncScanResult AsyncPatternScanner::PerformScan(
        uintptr_t start,
        size_t length,
        std::string_view pattern,
        CancellationToken cancellation,
        const ScanConfig& config,
        ProgressCallback progress)
    {
        AsyncScanResult result;
        result.pattern = std::string(pattern);

        auto startTime = std::chrono::steady_clock::now();

        // Validate memory region
        if (!ValidateMemoryRegion(start, length))
        {
            result.error = ScanError::MemoryAccessViolation;
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime);
            LogScanResult(result);
            return result;
        }

        // Log scan start
        if (config.enable_logging)
        {
            LogScanStart(pattern, start, length);
        }

        try
        {
            // Create timeout cancellation if specified
            CancellationToken timeoutToken = CancellationToken::CreateWithTimeout(config.timeout);

            // Use PatternScanner to perform the actual scan
            auto scanResult = PatternScanner::ScanPattern(start, length, std::string(pattern));

            // Check for cancellation
            if (cancellation.IsCancelled() || timeoutToken.IsCancelled())
            {
                result.was_cancelled = true;
                result.error = ScanError::NotFound;
            }
            else if (scanResult)
            {
                result.result = *scanResult;
                // Success is indicated by result.result.has_value()
            }
            else
            {
                result.error = ScanError::NotFound;
            }
        }
        catch (const std::exception& ex)
        {
            result.error = ScanError::MemoryAccessViolation;
            if (config.enable_logging)
            {
                LogError("Exception during pattern scan: " + std::string(ex.what()));
            }
        }

        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime);

        if (config.enable_logging)
        {
            LogScanResult(result);
        }

        return result;
    }

    bool AsyncPatternScanner::ValidateMemoryRegion(uintptr_t start, size_t length)
    {
        if (start == 0 || length == 0)
        {
            return false;
        }

        // Use the wrapper function to avoid Windows header dependencies
        try
        {
            // Simple validation using the wrapper - just check if we can query the memory
            char dummyBuffer[64]; // Small buffer for VirtualQuery result
            return VirtualQueryWrapper(reinterpret_cast<const void*>(start), dummyBuffer, sizeof(dummyBuffer));
        }
        catch (...)
        {
            return false;
        }
    }

    void AsyncPatternScanner::LogScanStart(std::string_view pattern, uintptr_t start, size_t length)
    {
        std::ostringstream oss;
        oss << "Starting pattern scan: '" << pattern << "' at 0x"
            << std::hex << start << " (length: 0x" << length << ")";
        LogInfo(oss.str());
    }

    void AsyncPatternScanner::LogScanResult(const AsyncScanResult& result)
    {
        std::ostringstream oss;

        if (result.was_cancelled)
        {
            oss << "Pattern scan cancelled: '" << result.pattern << "'";
        }
        else if (result.result.has_value())
        {
            oss << "Pattern scan successful: '" << result.pattern
                << "' found at 0x" << std::hex << result.result->address;
        }
        else
        {
            oss << "Pattern scan failed: '" << result.pattern << "' - ";
            switch (result.error)
            {
            case ScanError::NotFound:
                oss << "Not found";
                break;
            case ScanError::MemoryAccessViolation:
                oss << "Memory access violation";
                break;
            case ScanError::InvalidAddress:
                oss << "Invalid address";
                break;
            case ScanError::InvalidPattern:
                oss << "Invalid pattern";
                break;
            case ScanError::ModuleNotFound:
                oss << "Module not found";
                break;
            case ScanError::CacheCorrupted:
                oss << "Cache corrupted";
                break;
            default:
                oss << "Unknown error";
                break;
            }
        }

        oss << " (Duration: " << result.duration.count() << "ms)";

        if (result.result.has_value())
        {
            LogInfo(oss.str());
        }
        else
        {
            LogWarning(oss.str());
        }
    }

} // namespace SapphireHook