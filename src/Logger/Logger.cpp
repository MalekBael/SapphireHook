#include "Logger.h"
#include <windows.h>
#include <iomanip>
#include <cstdarg>
#include <filesystem>
#include <sstream>
#include <chrono>
#include <iostream>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/async.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/sinks/wincolor_sink.h>

namespace {

static std::filesystem::path BuildTempSapphireDir() {
    wchar_t tempPathW[MAX_PATH]{};
    DWORD len = GetTempPathW(MAX_PATH, tempPathW);
    std::filesystem::path base =
        (len == 0 || len > MAX_PATH)
            ? std::filesystem::temp_directory_path()
            : std::filesystem::path(tempPathW);
    return base / "SapphireHook";
}

}  

namespace SapphireHook {

std::unique_ptr<Logger> Logger::s_instance;
std::mutex Logger::s_mutex;
std::atomic<bool> Logger::s_shuttingDown{ false };

void Logger::PrepareForShutdown() {
    s_shuttingDown.store(true, std::memory_order_release);
}

std::filesystem::path Logger::GetDefaultTempDir() {
    return BuildTempSapphireDir();
}

bool Logger::EnsureDir(const std::filesystem::path& dir, bool create, bool& createdFlag) {
    createdFlag = false;
    if (std::filesystem::exists(dir)) return true;
    if (!create) return false;
    try {
        if (std::filesystem::create_directories(dir)) createdFlag = true;
        return std::filesystem::exists(dir);
    } catch (...) {
        return false;
    }
}

Logger::Logger() {
    m_metrics.Reset();
}

Logger::~Logger() {
    if (m_logger) {
        m_logger->info("Logger shutdown");
        m_logger->flush();
    }
    spdlog::shutdown();
}

void Logger::RecreateLogger() {
    std::vector<spdlog::sink_ptr> sinks;

    if (m_logToConsole) {
        auto console_sink = std::make_shared<spdlog::sinks::wincolor_stdout_sink_mt>();
        console_sink->set_level(ToSpdlogLevel(m_minimumLevel));
        
        console_sink->set_color(spdlog::level::trace,    FOREGROUND_INTENSITY);                                       
        console_sink->set_color(spdlog::level::debug,    FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);  
        console_sink->set_color(spdlog::level::info,     FOREGROUND_GREEN | FOREGROUND_INTENSITY);                     
        console_sink->set_color(spdlog::level::warn,     FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);   
        console_sink->set_color(spdlog::level::err,      FOREGROUND_RED | FOREGROUND_INTENSITY);                       
        console_sink->set_color(spdlog::level::critical, BACKGROUND_RED | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);    
        
        sinks.push_back(console_sink);
    }

#ifdef _DEBUG
    auto msvc_sink = std::make_shared<spdlog::sinks::msvc_sink_mt>();
    msvc_sink->set_level(ToSpdlogLevel(m_minimumLevel));
    sinks.push_back(msvc_sink);
#endif

    if (m_logToFile && !m_logFilePath.empty()) {
        try {
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                m_logFilePath.string(),
                m_maxFileSize,
                m_maxFiles
            );
            file_sink->set_level(ToSpdlogLevel(m_minimumLevel));
            sinks.push_back(file_sink);
        } catch (const std::exception& ex) {
            if (m_logToConsole) {
                std::cerr << "[SapphireHook] Failed to create log file: " << ex.what() << std::endl;
            }
        }
    }

    m_logger = std::make_shared<spdlog::logger>("sapphire", sinks.begin(), sinks.end());
    m_logger->set_level(ToSpdlogLevel(m_minimumLevel));

    m_logger->set_pattern("%Y-%m-%d %H:%M:%S.%e [%l] %v");

    m_logger->flush_on(spdlog::level::warn);

    spdlog::set_default_logger(m_logger);
}

static bool IsLikelyFilePath(const std::filesystem::path& p) {
    return p.has_extension();
}

bool Logger::Initialize(const std::filesystem::path& pathOrFile,
                        bool enableConsole,
                        LogLevel minLevel,
                        bool treatAsDirectory,
                        bool createDirectoryIfMissing)
{
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_instance) return false;

    s_instance = std::make_unique<Logger>();
    s_instance->m_logToConsole = enableConsole;
    s_instance->m_minimumLevel = minLevel;
    s_instance->m_metrics.Reset();

    const char* envDir = std::getenv("SAPPHIREHOOK_LOG_DIR");
    bool envNoCreate = std::getenv("SAPPHIREHOOK_LOG_NOCREATE") != nullptr;

    std::filesystem::path baseDir;
    bool created = false;
    bool custom = false;

    if (envDir && *envDir) {
        baseDir = std::filesystem::path(envDir);
        custom = true;
        if (!EnsureDir(baseDir, !envNoCreate, created)) {
            baseDir = GetDefaultTempDir();
            EnsureDir(baseDir, true, created);
            custom = false;
        }
    } else if (treatAsDirectory) {
        baseDir = pathOrFile;
        custom = true;
        if (!EnsureDir(baseDir, createDirectoryIfMissing, created)) {
            baseDir = GetDefaultTempDir();
            EnsureDir(baseDir, true, created);
            custom = false;
        }
    } else {
        baseDir = GetDefaultTempDir();
        EnsureDir(baseDir, true, created);
    }

    s_instance->m_logDirectory = baseDir;
    s_instance->m_customDirectory = custom;
    s_instance->m_createdDirectory = created;

    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&tt);

    std::string fileBase;
    if (!treatAsDirectory && !custom && IsLikelyFilePath(pathOrFile))
        fileBase = pathOrFile.stem().string();
    else
        fileBase = "SapphireHook";

    std::ostringstream name;
    name << fileBase << "."
         << std::put_time(&tm, "%Y%m%d.%H%M%S")
         << "." << GetCurrentProcessId() << ".log";

    s_instance->m_logFilePath = baseDir / name.str();

    s_instance->RecreateLogger();

    s_instance->Information("=== SapphireHook Logger Initialized (spdlog backend) ===");
    s_instance->Information("Log file: " + s_instance->m_logFilePath.string());
    s_instance->Information("Console output: " + std::string(enableConsole ? "enabled" : "disabled"));
    s_instance->Information("Log level: " + std::string(LogLevelToString(minLevel)));
    s_instance->Information("Directory path: " + s_instance->m_logDirectory.string());
    return true;
}

Logger& Logger::Instance() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_instance) {
        s_instance = std::make_unique<Logger>();
        s_instance->m_logDirectory = GetDefaultTempDir();
        bool created = false;
        EnsureDir(s_instance->m_logDirectory, true, created);
        s_instance->m_createdDirectory = created;

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&t);
        std::ostringstream name;
        name << "SapphireHook."
             << std::put_time(&tm, "%Y%m%d.%H%M%S")
             << "." << GetCurrentProcessId() << ".log";
        s_instance->m_logFilePath = s_instance->m_logDirectory / name.str();

        s_instance->RecreateLogger();
    }
    return *s_instance;
}

void Logger::Debug(const std::string& m) { WriteLog(LogLevel::Debug, m); }
void Logger::Information(const std::string& m) { WriteLog(LogLevel::Information, m); }
void Logger::Warning(const std::string& m) { WriteLog(LogLevel::Warning, m); }
void Logger::Error(const std::string& m) { WriteLog(LogLevel::Error, m); }
void Logger::Fatal(const std::string& m) { WriteLog(LogLevel::Fatal, m); }

void Logger::DebugF(const char* fmt, ...) {
    if (LogLevel::Debug < m_minimumLevel) return;
    va_list a; va_start(a, fmt);
    std::string msg = FormatString(fmt, a);
    va_end(a);
    WriteLog(LogLevel::Debug, msg);
}

void Logger::InformationF(const char* fmt, ...) {
    if (LogLevel::Information < m_minimumLevel) return;
    va_list a; va_start(a, fmt);
    std::string msg = FormatString(fmt, a);
    va_end(a);
    WriteLog(LogLevel::Information, msg);
}

void Logger::WarningF(const char* fmt, ...) {
    if (LogLevel::Warning < m_minimumLevel) return;
    va_list a; va_start(a, fmt);
    std::string msg = FormatString(fmt, a);
    va_end(a);
    WriteLog(LogLevel::Warning, msg);
}

void Logger::ErrorF(const char* fmt, ...) {
    if (LogLevel::Error < m_minimumLevel) return;
    va_list a; va_start(a, fmt);
    std::string msg = FormatString(fmt, a);
    va_end(a);
    WriteLog(LogLevel::Error, msg);
}

void Logger::InfoWithContext(const std::string& m, const LogContext& ctx) {
    WriteLog(LogLevel::Information, m + " [" + ctx.ToString() + "]");
}

void Logger::ErrorWithContext(const std::string& m, const LogContext& ctx) {
    WriteLog(LogLevel::Error, m + " [" + ctx.ToString() + "]");
}

void Logger::SetAsyncLogging(bool enable) {
    if (enable != m_asyncEnabled) {
        m_asyncEnabled = enable;
        if (enable) {
            spdlog::init_thread_pool(8192, 1);
        }
    }
}

void Logger::SetMinimumLevel(LogLevel level) {
    m_minimumLevel = level;
    if (m_logger) {
        m_logger->set_level(ToSpdlogLevel(level));
    }
}

std::string Logger::HexFormat(uintptr_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

void Logger::WriteLog(LogLevel level, const std::string& message) {
    if (s_shuttingDown.load(std::memory_order_acquire)) return;      
    if (level < m_minimumLevel) return;
    if (!m_logger) return;

    m_metrics.totalMessages.fetch_add(1, std::memory_order_relaxed);

    switch (level) {
    case LogLevel::Debug:
        m_logger->debug("{}", message);
        break;
    case LogLevel::Information:
        m_logger->info("{}", message);
        break;
    case LogLevel::Warning:
        m_logger->warn("{}", message);
        break;
    case LogLevel::Error:
        m_logger->error("{}", message);
        break;
    case LogLevel::Fatal:
        m_logger->critical("{}", message);
        break;
    }
}

std::string Logger::FormatString(const char* format, va_list args) {
    va_list copy;
    va_copy(copy, args);
    int size = vsnprintf(nullptr, 0, format, copy);
    va_end(copy);
    if (size <= 0) return {};
    std::string result(size, '\0');
    vsnprintf(&result[0], size + 1, format, args);
    return result;
}

void Logger::LogException(const std::exception& ex, std::string_view ctx) {
    if (!ctx.empty()) 
        Error(std::string("Exception in ") + std::string(ctx) + ": " + ex.what());
    else 
        Error(std::string("Exception: ") + ex.what());
}

void Logger::DebugPacketCorrelationTimeout(uint16_t requestOpcode, uint64_t connectionId, uint64_t ageMs) {
    if (LogLevel::Debug < m_minimumLevel) return;
    std::ostringstream oss;
    oss << "[CorrelationTimeout] conn=" << connectionId
        << " opcode=0x" << std::uppercase << std::hex << std::setw(4)
        << std::setfill('0') << requestOpcode
        << std::dec << " age=" << ageMs << "ms without response";
    WriteLog(LogLevel::Debug, oss.str());
}

bool BinaryLogger::Initialize(const std::string&, size_t) { return false; }
void BinaryLogger::LogBinary(const void*, size_t, uint32_t) {}
void BinaryLogger::Flush() {}

void Logger::ApplyConfig(const LoggerConfig& cfg) {
    SetMinimumLevel(cfg.minLevel);
    SetConsoleOutput(cfg.enableConsoleLogging);
    SetFileOutput(cfg.enableFileLogging);
    SetAsyncLogging(cfg.enableAsyncLogging);
    SetEnabledCategories(cfg.enabledCategories);
    SetLogRotation(cfg.maxFileSize, cfg.maxFiles);
}

void Logger::ReattachConsole() {
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    std::ios::sync_with_stdio(true);
    std::cout.clear();
    std::cerr.clear();
    
    RecreateLogger();
}

void Logger::AnnounceLogFileLocation(bool force) {
    static std::atomic<bool> announced{ false };
    if (!(force || !announced.exchange(true))) return;
    Information("Log file created: " + m_logFilePath.string());
    Information("Log directory: " + m_logDirectory.string());
    Information(std::string("Custom directory: ") + (m_customDirectory ? "yes" : "no"));
    Information(std::string("Directory created this run: ") + (m_createdDirectory ? "yes" : "no"));
}

}   