#pragma once
#include <string_view>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>
#include <mutex>
#include <memory>
#include <filesystem>
#include <exception>
#include <cstdarg>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <type_traits>

#ifdef _WIN32
#include <windows.h>
#include <evntprov.h>
#endif

namespace SapphireHook {

    // Log levels
    enum class LogLevel : int {
        Debug = 0,
        Information = 1,
        Warning = 2,
        Error = 3,
        Fatal = 4
    };

    constexpr const char* LogLevelToString(LogLevel level)
    {
        switch (level)
        {
        case LogLevel::Debug:       return "DEBUG";
        case LogLevel::Information: return "INFO ";
        case LogLevel::Warning:     return "WARN ";
        case LogLevel::Error:       return "ERROR";
        case LogLevel::Fatal:       return "FATAL";
        default:                    return "UNKNW";
        }
    }

    // Log categories
    enum class LogCategory : uint32_t {
        General = 1 << 0,
        Network = 1 << 1,
        Packets = 1 << 2,
        UI = 1 << 3,
        Hooks = 1 << 4,
        Performance = 1 << 5,
        Debug = 1 << 6,
        All = 0xFFFFFFFF
    };

    inline LogCategory operator|(LogCategory lhs, LogCategory rhs) {
        return static_cast<LogCategory>(
            static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs)
            );
    }

    inline LogCategory operator&(LogCategory lhs, LogCategory rhs) {
        return static_cast<LogCategory>(
            static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs)
            );
    }

    inline LogCategory& operator|=(LogCategory& lhs, LogCategory rhs) {
        lhs = lhs | rhs;
        return lhs;
    }

    // Context key-value aggregator
    class LogContext {
    private:
        std::unordered_map<std::string, std::string> m_data;

    public:
        LogContext& Add(const std::string& key, const std::string& value) {
            m_data[key] = value;
            return *this;
        }

        template<typename T>
        LogContext& Add(const std::string& key, const T& value) {
            if constexpr (std::is_same_v<T, std::string>) {
                m_data[key] = value;
            }
            else if constexpr (std::is_same_v<T, const char*>) {
                m_data[key] = std::string(value);
            }
            else if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>) {
                m_data[key] = std::to_string(value);
            }
            else {
                std::ostringstream oss;
                oss << value;
                m_data[key] = oss.str();
            }
            return *this;
        }

        std::string ToString() const {
            std::ostringstream oss;
            bool first = true;
            for (const auto& [key, value] : m_data) {
                if (!first) oss << ", ";
                oss << key << "=" << value;
                first = false;
            }
            return oss.str();
        }
    };

    struct LoggerConfig;

    class BinaryLogger {
    private:
        void* m_mappedMemory = nullptr;
        size_t m_mappedSize = 0;
        std::atomic<size_t> m_writeOffset{ 0 };

    public:
        bool Initialize(const std::string& filename, size_t size = 100 * 1024 * 1024);
        void LogBinary(const void* data, size_t size, uint32_t type);
        void Flush();
    };

    class Logger {
    private:
        static std::unique_ptr<Logger> s_instance;
        static std::mutex s_mutex;

        std::ofstream m_logFile;
        std::mutex m_logMutex;
        LogLevel m_minimumLevel = LogLevel::Information;
        bool m_logToConsole = true;
        bool m_logToFile = true;

        bool m_fallbackMode = false;
        std::filesystem::path m_fallbackPath;

        std::thread m_asyncThread;
        std::atomic<bool> m_asyncRunning{ false };
        mutable std::mutex m_asyncMutex;
        std::condition_variable m_asyncCondition;
        std::queue<std::string> m_asyncQueue;
        static constexpr size_t MAX_ASYNC_QUEUE_SIZE = 10000;

        struct LoggerMetrics {
            std::atomic<uint64_t> totalMessages{ 0 };
            std::atomic<uint64_t> droppedMessages{ 0 };
            std::atomic<uint64_t> avgWriteTimeNs{ 0 };
            std::atomic<uint64_t> maxWriteTimeNs{ 0 };
            std::chrono::steady_clock::time_point startTime;

            void Reset() {
                totalMessages = 0;
                droppedMessages = 0;
                avgWriteTimeNs = 0;
                maxWriteTimeNs = 0;
                startTime = std::chrono::steady_clock::now();
            }

            double GetMessagesPerSecond() const {
                auto elapsed = std::chrono::steady_clock::now() - startTime;
                auto seconds = std::chrono::duration<double>(elapsed).count();
                return seconds > 0 ? totalMessages.load() / seconds : 0.0;
            }
        };

        LoggerMetrics m_metrics;
        uint32_t m_enabledCategories = static_cast<uint32_t>(LogCategory::All);

        size_t m_maxFileSize = 50 * 1024 * 1024;
        size_t m_maxFiles = 10;
        size_t m_currentFileSize = 0;

#ifdef _WIN32
        bool m_etwEnabled = false;
        REGHANDLE m_etwHandle = 0;
#endif

    public:
        Logger() = default;
        ~Logger();

        static bool Initialize(const std::filesystem::path& logPath,
            bool enableConsole = true,
            LogLevel minLevel = LogLevel::Information);

        static Logger& Instance();

        void Debug(const std::string& message);
        void Information(const std::string& message);
        void Warning(const std::string& message);
        void Error(const std::string& message);
        void Fatal(const std::string& message);

        void DebugF(const char* format, ...);
        void InformationF(const char* format, ...);
        void WarningF(const char* format, ...);
        void ErrorF(const char* format, ...);
        void FatalF(const char* format, ...);

        void InfoWithContext(const std::string& message, const LogContext& context);
        void ErrorWithContext(const std::string& message, const LogContext& context);

        void InfoCategory(LogCategory category, const std::string& message);
        void ErrorCategory(LogCategory category, const std::string& message);

        static std::string HexFormat(uintptr_t value);
        static std::string FormatSocket(uint64_t socket);
        static std::string FormatBytes(size_t bytes);

        void LogException(const std::exception& ex, std::string_view context = "");

        void SetMinimumLevel(LogLevel level) { m_minimumLevel = level; }
        void SetConsoleOutput(bool enable) { m_logToConsole = enable; }
        void SetFileOutput(bool enable) { m_logToFile = enable; }
        void SetAsyncLogging(bool enable);
        void FlushAsync();

        const LoggerMetrics& GetMetrics() const { return m_metrics; }
        void ResetMetrics() { m_metrics.Reset(); }

        void SetEnabledCategories(uint32_t categories) { m_enabledCategories = categories; }
        void EnableCategory(LogCategory category) { m_enabledCategories |= static_cast<uint32_t>(category); }
        void DisableCategory(LogCategory category) { m_enabledCategories &= ~static_cast<uint32_t>(category); }
        bool IsEnabledCategory(LogCategory category) const {
            return (m_enabledCategories & static_cast<uint32_t>(category)) != 0;
        }

        void SetLogRotation(size_t maxFileSize, size_t maxFiles) {
            m_maxFileSize = maxFileSize;
            m_maxFiles = maxFiles;
        }

        BinaryLogger& GetBinaryLogger() {
            static BinaryLogger instance;
            return instance;
        }

        void ApplyConfig(const LoggerConfig& config);

#ifdef _WIN32
        bool EnableETW(const std::string& providerName);
        void LogETW(LogLevel level, const std::string& message);
#endif

        // Correlation timeout helper (instance method)
        void DebugPacketCorrelationTimeout(uint16_t requestOpcode, uint64_t connectionId, uint64_t ageMs) {
            if (LogLevel::Debug < m_minimumLevel) return;
            std::ostringstream oss;
            oss << "[CorrelationTimeout] conn=" << connectionId
                << " opcode=0x" << std::uppercase << std::hex << std::setw(4)
                << std::setfill('0') << requestOpcode
                << std::dec << " age=" << ageMs << "ms without response";
            WriteLog(LogLevel::Debug, oss.str());
        }

    private:
        void WriteLog(LogLevel level, const std::string& message);
        std::string GetTimestamp() const;
        void InitializeFallbackLogging();
        std::string FormatString(const char* format, va_list args);
        void RotateLogFile();
        void CompressOldLog(const std::filesystem::path& logPath);
    };

    struct LoggerConfig {
        std::filesystem::path logPath = "logs/sapphire.log";
        bool enableFileLogging = true;
        bool enableConsoleLogging = true;
        bool enableAsyncLogging = true;
        size_t asyncQueueSize = 10000;
        size_t maxFileSize = 50 * 1024 * 1024;
        size_t maxFiles = 10;
        bool enableCompression = true;
        LogLevel minLevel = LogLevel::Information;
        uint32_t enabledCategories = static_cast<uint32_t>(LogCategory::All);
        bool includeTimestamp = true;
        bool includeThreadId = true;
        bool includeFunction = false;
        std::string timestampFormat = "%Y-%m-%d %H:%M:%S.%f";

        bool LoadFromFile(const std::filesystem::path& configPath) {
            (void)configPath;
            return true;
        }
        bool SaveToFile(const std::filesystem::path& configPath) {
            (void)configPath;
            return true;
        }
    };

    // Shims
    inline void LogDebug(const std::string& message) { Logger::Instance().Debug(message); }
    inline void LogInfo(const std::string& message) { Logger::Instance().Information(message); }
    inline void LogWarning(const std::string& message) { Logger::Instance().Warning(message); }
    inline void LogError(const std::string& message) { Logger::Instance().Error(message); }
    inline void LogFatal(const std::string& message) { Logger::Instance().Fatal(message); }

    inline void LogInfoWithContext(const std::string& message, const LogContext& context) {
        Logger::Instance().InfoWithContext(message, context);
    }
    inline void LogErrorWithContext(const std::string& message, const LogContext& context) {
        Logger::Instance().ErrorWithContext(message, context);
    }

    inline void LogDebugF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        Logger::Instance().DebugF(format, args);
        va_end(args);
    }
    inline void LogInfoF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        Logger::Instance().InformationF(format, args);
        va_end(args);
    }
    inline void LogWarningF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        Logger::Instance().WarningF(format, args);
        va_end(args);
    }
    inline void LogErrorF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        Logger::Instance().ErrorF(format, args);
        va_end(args);
    }
    inline void LogFatalF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        Logger::Instance().FatalF(format, args);
        va_end(args);
    }

    // Free-function style correlation timeout shim (calls instance method)
    inline void DebugPacketCorrelationTimeout(uint16_t requestOpcode, uint64_t connectionId, uint64_t ageMs) {
        Logger::Instance().DebugPacketCorrelationTimeout(requestOpcode, connectionId, ageMs);
    }

    inline void LogException(const std::exception& ex, std::string_view ctx = {}) {
        Logger::Instance().LogException(ex, ctx);
    }

} // namespace SapphireHook