#include "Logger.h"
#include <windows.h>
#include <iomanip>

namespace SapphireHook {

    std::unique_ptr<Logger> Logger::s_instance;
    std::mutex Logger::s_mutex;

    Logger::~Logger()
    {
        if (m_logFile.is_open())
        {
            Information("Logger shutdown");
            m_logFile.close();
        }
    }

    bool Logger::Initialize(const std::filesystem::path& logPath,
        bool enableConsole,
        LogLevel minLevel)
    {
        std::lock_guard<std::mutex> lock(s_mutex);

        if (s_instance)
        {
            return false; // Already initialized
        }

        s_instance = std::make_unique<Logger>();
        s_instance->m_logToConsole = enableConsole;
        s_instance->m_minimumLevel = minLevel;

        // Try to open log file (with Dalamud-style fallback)
        try
        {
            std::filesystem::create_directories(logPath.parent_path());
            s_instance->m_logFile.open(logPath, std::ios::out | std::ios::app);

            if (!s_instance->m_logFile.is_open())
            {
                s_instance->InitializeFallbackLogging();
            }
        }
        catch (const std::exception& ex)
        {
            s_instance->InitializeFallbackLogging();
            s_instance->LogException(ex, "Failed to open primary log file");
        }

        s_instance->Information("=== SapphireHook Logger Initialized ===");
        s_instance->Information("Console output: " + std::string(enableConsole ? "enabled" : "disabled"));
        s_instance->Information("Log level: " + std::string(LogLevelToString(minLevel)));

        return true;
    }

    Logger& Logger::Instance()
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        if (!s_instance)
        {
            // Emergency fallback initialization
            s_instance = std::make_unique<Logger>();
            s_instance->InitializeFallbackLogging();
        }
        return *s_instance;
    }

    // Simplified logging methods
    void Logger::Debug(const std::string& message)
    {
        WriteLog(LogLevel::Debug, message);
    }

    void Logger::Information(const std::string& message)
    {
        WriteLog(LogLevel::Information, message);
    }

    void Logger::Warning(const std::string& message)
    {
        WriteLog(LogLevel::Warning, message);
    }

    void Logger::Error(const std::string& message)
    {
        WriteLog(LogLevel::Error, message);
    }

    void Logger::Fatal(const std::string& message)
    {
        WriteLog(LogLevel::Fatal, message);
    }

    void Logger::WriteLog(LogLevel level, const std::string& message)
    {
        if (level < m_minimumLevel) return;

        std::lock_guard<std::mutex> lock(m_logMutex);

        const std::string timestamp = GetTimestamp();
        
        std::ostringstream oss;
        oss << timestamp << " [" << LogLevelToString(level) << "] " 
            << m_logPrefix << " " << message;
        const std::string logLine = oss.str();

        // Console output
        if (m_logToConsole)
        {
            if (level >= LogLevel::Error)
            {
                std::cerr << logLine << std::endl;
            }
            else
            {
                std::cout << logLine << std::endl;
            }
        }

        // File output
        if (m_logToFile && m_logFile.is_open())
        {
            m_logFile << logLine << std::endl;
            m_logFile.flush(); // Immediate flush for crashes
        }
    }

    std::string Logger::GetTimestamp() const
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    void Logger::InitializeFallbackLogging()
    {
        m_fallbackMode = true;

        // Create fallback log in temp directory (like Dalamud does)
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);

        std::wostringstream woss;
        woss << tempPath << L"SapphireHook."
            << std::put_time(&tm, L"%Y%m%d.%H%M%S")
            << L"." << GetCurrentProcessId() << L".log";

        m_fallbackPath = woss.str();

        try
        {
            m_logFile.open(m_fallbackPath, std::ios::out | std::ios::app);
            if (m_logFile.is_open())
            {
                Information("Using fallback log file: " + m_fallbackPath.string());
            }
        }
        catch (const std::exception& ex)
        {
            // If even fallback fails, disable file logging
            m_logToFile = false;
            if (m_logToConsole)
            {
                std::cerr << "[SapphireHook] FATAL: Could not create fallback log: "
                    << ex.what() << std::endl;
            }
        }
    }

    inline void Logger::LogException(const std::exception& ex, std::string_view context)
    {
        if (!context.empty())
            Error(std::string("Exception in ") + std::string(context) + ": " + ex.what());
        else
            Error(std::string("Exception: ") + ex.what());
    }

} // namespace SapphireHook