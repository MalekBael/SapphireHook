#include "Logger.h"
#include <windows.h>
#include <iomanip>
#include <cstdarg>
#include <filesystem>
#include <fstream>
#include <algorithm>

namespace SapphireHook {

    std::unique_ptr<Logger> Logger::s_instance;
    std::mutex Logger::s_mutex;

    Logger::~Logger()
    {
        if (m_asyncRunning) {
            SetAsyncLogging(false);
        }

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
            return false;
        }

        s_instance = std::make_unique<Logger>();
        s_instance->m_logToConsole = enableConsole;
        s_instance->m_minimumLevel = minLevel;
        s_instance->m_metrics.Reset();

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
            s_instance = std::make_unique<Logger>();
            s_instance->InitializeFallbackLogging();
            s_instance->m_metrics.Reset();
        }
        return *s_instance;
    }

    void Logger::Debug(const std::string& message) { WriteLog(LogLevel::Debug, message); }
    void Logger::Information(const std::string& message) { WriteLog(LogLevel::Information, message); }
    void Logger::Warning(const std::string& message) { WriteLog(LogLevel::Warning, message); }
    void Logger::Error(const std::string& message) { WriteLog(LogLevel::Error, message); }
    void Logger::Fatal(const std::string& message) { WriteLog(LogLevel::Fatal, message); }

    void Logger::DebugF(const char* format, ...)
    {
        if (LogLevel::Debug < m_minimumLevel) return;
        va_list args;
        va_start(args, format);
        std::string message = FormatString(format, args);
        va_end(args);
        WriteLog(LogLevel::Debug, message);
    }

    void Logger::InformationF(const char* format, ...)
    {
        if (LogLevel::Information < m_minimumLevel) return;
        va_list args;
        va_start(args, format);
        std::string message = FormatString(format, args);
        va_end(args);
        WriteLog(LogLevel::Information, message);
    }

    void Logger::WarningF(const char* format, ...)
    {
        if (LogLevel::Warning < m_minimumLevel) return;
        va_list args;
        va_start(args, format);
        std::string message = FormatString(format, args);
        va_end(args);
        WriteLog(LogLevel::Warning, message);
    }

    void Logger::ErrorF(const char* format, ...)
    {
        if (LogLevel::Error < m_minimumLevel) return;
        va_list args;
        va_start(args, format);
        std::string message = FormatString(format, args);
        va_end(args);
        WriteLog(LogLevel::Error, message);
    }

    void Logger::FatalF(const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        std::string message = FormatString(format, args);
        va_end(args);
        WriteLog(LogLevel::Fatal, message);
    }

    void Logger::InfoWithContext(const std::string& message, const LogContext& context)
    {
        WriteLog(LogLevel::Information, message + " [" + context.ToString() + "]");
    }

    void Logger::ErrorWithContext(const std::string& message, const LogContext& context)
    {
        WriteLog(LogLevel::Error, message + " [" + context.ToString() + "]");
    }


    void Logger::InfoCategory(LogCategory category, const std::string& message)
    {
        if (m_enabledCategories & static_cast<uint32_t>(category)) {
            WriteLog(LogLevel::Information, message);
        }
    }

    void Logger::ErrorCategory(LogCategory category, const std::string& message)
    {
        if (m_enabledCategories & static_cast<uint32_t>(category)) {
            WriteLog(LogLevel::Error, message);
        }
    }


    void Logger::SetAsyncLogging(bool enable)
    {
        if (enable && !m_asyncRunning) {
            m_asyncRunning = true;
            m_asyncThread = std::thread([this]() {
                while (m_asyncRunning) {
                    std::unique_lock<std::mutex> lock(m_asyncMutex);
                    m_asyncCondition.wait(lock, [this] {
                        return !m_asyncQueue.empty() || !m_asyncRunning;
                    });

                    while (!m_asyncQueue.empty()) {
                        std::string msg = m_asyncQueue.front();
                        m_asyncQueue.pop();
                        lock.unlock();


                        if (m_logToFile && m_logFile.is_open()) {
                            m_logFile << msg << std::endl;
                            m_logFile.flush();
                        }
                        if (m_logToConsole) {
                            std::cout << msg << std::endl;
                        }

                        lock.lock();
                    }
                }
            });
        }
        else if (!enable && m_asyncRunning) {
            m_asyncRunning = false;
            m_asyncCondition.notify_all();
            if (m_asyncThread.joinable()) {
                m_asyncThread.join();
            }
        }
    }

    void Logger::FlushAsync()
    {
        if (m_asyncRunning) {
            m_asyncCondition.notify_all();
        }
    }


    std::string Logger::HexFormat(uintptr_t value)
    {
        std::stringstream ss;
        ss << "0x" << std::hex << std::uppercase << value;
        return ss.str();
    }

    std::string Logger::FormatSocket(uint64_t socket)
    {
        return "socket_" + std::to_string(socket);
    }

    std::string Logger::FormatBytes(size_t bytes)
    {
        if (bytes < 1024) return std::to_string(bytes) + " B";
        if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + " KB";
        return std::to_string(bytes / (1024 * 1024)) + " MB";
    }

    void Logger::WriteLog(LogLevel level, const std::string& message)
    {
        if (level < m_minimumLevel) return;

        auto start = std::chrono::high_resolution_clock::now();

        std::lock_guard<std::mutex> lock(m_logMutex);

        const std::string timestamp = GetTimestamp();

        std::ostringstream oss;
        oss << timestamp << " [" << LogLevelToString(level) << "] " << message;
        const std::string logLine = oss.str();


        m_metrics.totalMessages.fetch_add(1, std::memory_order_relaxed);

        if (m_asyncRunning && m_asyncQueue.size() < MAX_ASYNC_QUEUE_SIZE) {
            std::lock_guard<std::mutex> asyncLock(m_asyncMutex);
            m_asyncQueue.push(logLine);
            m_asyncCondition.notify_one();
        }
        else {

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

            if (m_logToFile && m_logFile.is_open())
            {
                m_logFile << logLine << std::endl;
                m_logFile.flush(); 

                m_currentFileSize += logLine.length() + 1; 
                if (m_currentFileSize > m_maxFileSize) {
                    RotateLogFile();
                }
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        uint64_t durationNs = static_cast<uint64_t>(duration.count());

        uint64_t oldMax = m_metrics.maxWriteTimeNs.load();
        while (durationNs > oldMax && !m_metrics.maxWriteTimeNs.compare_exchange_weak(oldMax, durationNs)) {}

        uint64_t oldAvg = m_metrics.avgWriteTimeNs.load();
        uint64_t newAvg = (oldAvg + durationNs) / 2;
        m_metrics.avgWriteTimeNs.store(newAvg, std::memory_order_relaxed);
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

    std::string Logger::FormatString(const char* format, va_list args)
    {
        va_list args_copy;
        va_copy(args_copy, args);
        int size = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);

        if (size <= 0) return std::string();

        std::string result(size, '\0');
        vsnprintf(&result[0], size + 1, format, args);

        return result;
    }

    void Logger::RotateLogFile()
    {
        if (!m_logFile.is_open()) return;

        m_logFile.close();

        for (int i = static_cast<int>(m_maxFiles) - 1; i >= 1; --i) {
            std::filesystem::path oldFile = m_fallbackPath.string() + "." + std::to_string(i);
            std::filesystem::path newFile = m_fallbackPath.string() + "." + std::to_string(i + 1);

            if (std::filesystem::exists(oldFile)) {
                std::filesystem::rename(oldFile, newFile);
            }
        }

        if (std::filesystem::exists(m_fallbackPath)) {
            std::filesystem::path backup = m_fallbackPath.string() + ".1";
            std::filesystem::rename(m_fallbackPath, backup);
        }

        m_logFile.open(m_fallbackPath, std::ios::out | std::ios::app);
        m_currentFileSize = 0;
    }

    void Logger::CompressOldLog(const std::filesystem::path& logPath)
    {
        // Implementation would use zlib or similar to compress old logs
        // For now, just a placeholder
        (void)logPath;
    }

    void Logger::InitializeFallbackLogging()
    {
        m_fallbackMode = true;

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
            m_logToFile = false;
            if (m_logToConsole)
            {
                std::cerr << "[SapphireHook] FATAL: Could not create fallback log: "
                    << ex.what() << std::endl;
            }
        }
    }

    void Logger::LogException(const std::exception& ex, std::string_view context)
    {
        if (!context.empty())
            Error(std::string("Exception in ") + std::string(context) + ": " + ex.what());
        else
            Error(std::string("Exception: ") + ex.what());
    }

#ifdef _WIN32
    bool Logger::EnableETW(const std::string& providerName)
    {
        (void)providerName;
        return false;
    }

    void Logger::LogETW(LogLevel level, const std::string& message)
    {
        (void)level;
        (void)message;
    }
#endif


    bool BinaryLogger::Initialize(const std::string& filename, size_t size)
    {
        (void)filename;
        (void)size;
        return false; // Placeholder
    }

    void BinaryLogger::LogBinary(const void* data, size_t size, uint32_t type)
    {
        (void)data;
        (void)size;
        (void)type;
    }

    void BinaryLogger::Flush()
    {
        // Placeholder
    }

    void Logger::ApplyConfig(const LoggerConfig& config) {
        SetMinimumLevel(config.minLevel); 
        SetConsoleOutput(config.enableConsoleLogging);
        SetFileOutput(config.enableFileLogging);
        SetAsyncLogging(config.enableAsyncLogging);
        SetEnabledCategories(config.enabledCategories);
        SetLogRotation(config.maxFileSize, config.maxFiles);
    }

} // namespace SapphireHook