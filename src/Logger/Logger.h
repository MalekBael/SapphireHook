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
#include <exception> // ensure this is present

namespace SapphireHook {

    // Log levels inspired by Dalamud's approach
    enum class LogLevel : int {
        Debug = 0,
        Information = 1,
        Warning = 2,
        Error = 3,
        Fatal = 4
    };

    // Convert log level to string
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

    // Simplified thread-safe logger without template complexity
    class Logger {
    private:
        static std::unique_ptr<Logger> s_instance;
        static std::mutex s_mutex;

        std::ofstream m_logFile;
        std::mutex m_logMutex;
        LogLevel m_minimumLevel = LogLevel::Information;
        bool m_logToConsole = true;
        bool m_logToFile = true;
        std::string m_logPrefix = "[SapphireHook]";

        // Fallback logging like Dalamud does
        bool m_fallbackMode = false;
        std::filesystem::path m_fallbackPath;

    public:
        Logger() = default;
        ~Logger();

        // Initialize logging (inspired by Dalamud's InitLogging)
        static bool Initialize(const std::filesystem::path& logPath,
            bool enableConsole = true,
            LogLevel minLevel = LogLevel::Information);

        // Get singleton instance
        static Logger& Instance();

        // Simplified logging methods - just take strings
        void Debug(const std::string& message);
        void Information(const std::string& message);
        void Warning(const std::string& message);
        void Error(const std::string& message);
        void Fatal(const std::string& message);

        // Exception logging
        void LogException(const std::exception& ex, std::string_view context = "");

        // Settings
        void SetMinimumLevel(LogLevel level) { m_minimumLevel = level; }
        void SetConsoleOutput(bool enable) { m_logToConsole = enable; }
        void SetFileOutput(bool enable) { m_logToFile = enable; }

    private:
        void WriteLog(LogLevel level, const std::string& message);
        std::string GetTimestamp() const;
        void InitializeFallbackLogging();
    };

    // Global convenience functions - inline shims
    inline void LogDebug(const std::string& message)   { Logger::Instance().Debug(message); }
    inline void LogInfo(const std::string& message)    { Logger::Instance().Information(message); }
    inline void LogWarning(const std::string& message) { Logger::Instance().Warning(message); }
    inline void LogError(const std::string& message)   { Logger::Instance().Error(message); }
    inline void LogFatal(const std::string& message)   { Logger::Instance().Fatal(message); }

    // Optional: free shim if some sites call LogException at namespace scope
    inline void LogException(const std::exception& ex, std::string_view ctx = {})
    {
        Logger::Instance().LogException(ex, ctx);
    }

} // namespace SapphireHook