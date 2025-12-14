#include "Logger.h"
#include <windows.h>
#include <iomanip>
#include <cstdarg>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <sstream>

namespace {

// Build %TEMP%\SapphireHook directory
static std::filesystem::path BuildTempSapphireDir() {
    wchar_t tempPathW[MAX_PATH]{};
    DWORD len = GetTempPathW(MAX_PATH, tempPathW);
    std::filesystem::path base =
        (len == 0 || len > MAX_PATH)
            ? std::filesystem::temp_directory_path()
            : std::filesystem::path(tempPathW);
    return base / "SapphireHook";
}

} // namespace

namespace SapphireHook {

std::unique_ptr<Logger> Logger::s_instance;
std::mutex Logger::s_mutex;

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

Logger::~Logger() {
    if (m_asyncRunning) {
        SetAsyncLogging(false);
    }
    if (m_logFile.is_open()) {
        Information("Logger shutdown");
        m_logFile.close();
    }
}

static bool IsLikelyFilePath(const std::filesystem::path& p) {
    // Heuristic: if has extension OR ends with known log-ish extension, treat as file
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

    // Environment variable override (takes precedence)
    const char* envDir = std::getenv("SAPPHIREHOOK_LOG_DIR");
    bool envNoCreate = std::getenv("SAPPHIREHOOK_LOG_NOCREATE") != nullptr;

    std::filesystem::path baseDir;
    bool created = false;
    bool custom = false;

    if (envDir && *envDir) {
        baseDir = std::filesystem::path(envDir);
        custom = true;
        if (!EnsureDir(baseDir, !envNoCreate, created)) {
            // fallback
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
        // pathOrFile intended as filename -> always use default temp SapphireHook dir
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
    else if (treatAsDirectory || custom)
        fileBase = "SapphireHook";
    else
        fileBase = "SapphireHook";

    std::ostringstream name;
    name << fileBase << "."
         << std::put_time(&tm, "%Y%m%d.%H%M%S")
         << "." << GetCurrentProcessId() << ".log";

    std::filesystem::path runLogPath = baseDir / name.str();

    try {
        s_instance->m_fallbackPath = runLogPath;
        s_instance->m_logFile.open(runLogPath, std::ios::out | std::ios::app);
        if (!s_instance->m_logFile.is_open()) {
            s_instance->InitializeFallbackLogging();
        } else {
            s_instance->Information("Using log file: " + runLogPath.string());
            if (custom)
                s_instance->Information("Custom log directory in use");
        }
    } catch (const std::exception& ex) {
        s_instance->InitializeFallbackLogging();
        s_instance->LogException(ex, "Failed to open run log file");
    }

    s_instance->Information("=== SapphireHook Logger Initialized ===");
    s_instance->Information("Console output: " + std::string(enableConsole ? "enabled" : "disabled"));
    s_instance->Information("Log level: " + std::string(LogLevelToString(minLevel)));
    s_instance->Information(std::string("Directory created: ") + (s_instance->m_createdDirectory ? "yes" : "no"));
    s_instance->Information(std::string("Directory path: ") + s_instance->m_logDirectory.string());
    return true;
}

Logger& Logger::Instance() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_instance) {
        s_instance = std::make_unique<Logger>();
        s_instance->InitializeFallbackLogging();
        s_instance->m_metrics.Reset();
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
                    if (m_logToConsole) std::cout << msg << std::endl;
                    lock.lock();
                }
            }
        });
    } else if (!enable && m_asyncRunning) {
        m_asyncRunning = false;
        m_asyncCondition.notify_all();
        if (m_asyncThread.joinable()) m_asyncThread.join();
    }
}



std::string Logger::HexFormat(uintptr_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}


void Logger::WriteLog(LogLevel level, const std::string& message) {
    if (level < m_minimumLevel) return;
    auto start = std::chrono::high_resolution_clock::now();
    std::lock_guard<std::mutex> lock(m_logMutex);

    const std::string timestamp = GetTimestamp();
    std::ostringstream oss;
    oss << timestamp << " [" << LogLevelToString(level) << "] " << message;
    std::string logLine = oss.str();

    m_metrics.totalMessages.fetch_add(1, std::memory_order_relaxed);

    if (m_asyncRunning && m_asyncQueue.size() < MAX_ASYNC_QUEUE_SIZE) {
        std::lock_guard<std::mutex> aLock(m_asyncMutex);
        m_asyncQueue.push(logLine);
        m_asyncCondition.notify_one();
    } else {
        if (m_logToConsole) {
            if (level >= LogLevel::Error) std::cerr << logLine << std::endl;
            else std::cout << logLine << std::endl;
        }
        if (m_logToFile && m_logFile.is_open()) {
            m_logFile << logLine << std::endl;
            m_logFile.flush();
            m_currentFileSize += logLine.length() + 1;
            if (m_currentFileSize > m_maxFileSize) RotateLogFile();
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    uint64_t durationNs = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    uint64_t oldMax = m_metrics.maxWriteTimeNs.load();
    while (durationNs > oldMax && !m_metrics.maxWriteTimeNs.compare_exchange_weak(oldMax, durationNs)) {}
    uint64_t oldAvg = m_metrics.avgWriteTimeNs.load();
    m_metrics.avgWriteTimeNs.store((oldAvg + durationNs) / 2, std::memory_order_relaxed);
}

std::string Logger::GetTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
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

void Logger::RotateLogFile() {
    if (!m_logFile.is_open()) return;
    m_logFile.close();
    for (int i = (int)m_maxFiles - 1; i >= 1; --i) {
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



void Logger::InitializeFallbackLogging() {
    m_fallbackMode = true;
    std::filesystem::path dir = GetDefaultTempDir();
    bool created = false;
    EnsureDir(dir, true, created);
    m_logDirectory = dir;
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&t);
    std::wostringstream woss;
    woss << L"SapphireHook."
         << std::put_time(&tm, L"%Y%m%d.%H%M%S")
         << L"." << GetCurrentProcessId() << L".log";
    m_fallbackPath = dir / woss.str();
    try {
        m_logFile.open(m_fallbackPath, std::ios::out | std::ios::app);
        if (m_logFile.is_open()) {
            Information("Using fallback log file: " + m_fallbackPath.string());
        }
    } catch (const std::exception& ex) {
        m_logToFile = false;
        if (m_logToConsole) {
            std::cerr << "[SapphireHook] FATAL: Could not create fallback log: " << ex.what() << std::endl;
        }
    }
}

void Logger::LogException(const std::exception& ex, std::string_view ctx) {
    if (!ctx.empty()) Error(std::string("Exception in ") + std::string(ctx) + ": " + ex.what());
    else Error(std::string("Exception: ") + ex.what());
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
}

void Logger::AnnounceLogFileLocation(bool force) {
    static std::atomic<bool> announced{ false };
    if (!(force || !announced.exchange(true))) return;
    Information("Log file created: " + m_fallbackPath.string());
    Information("Log directory: " + m_logDirectory.string());
    Information(std::string("Custom directory: ") + (m_customDirectory ? "yes" : "no"));
    Information(std::string("Directory created this run: ") + (m_createdDirectory ? "yes" : "no"));
    wchar_t tempPathW[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPathW)) {
        std::filesystem::path tempDir(tempPathW);
        std::string tempDirStr = tempDir.string();
        if (m_logDirectory.string().rfind(tempDirStr, 0) == 0) {
            Information("Log directory resides under %TEMP% (" + tempDirStr + ")");
        }
    }
}

} // namespace SapphireHook