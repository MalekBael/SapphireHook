#pragma once
#include <string_view>
#include <string>
#include <sstream>
#include <iostream>
#include <mutex>
#include <memory>
#include <filesystem>
#include <exception>
#include <cstdarg>
#include <atomic>
#include <unordered_map>
#include <type_traits>
#include <iomanip>

// spdlog - SPDLOG_USE_STD_FORMAT is defined by the NuGet package
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>

#ifdef _WIN32
#include <windows.h>
#endif

namespace SapphireHook {
	/// @brief Log levels matching spdlog levels for easy conversion
	enum class LogLevel : int {
		Debug = 0,       // spdlog::level::debug
		Information = 1, // spdlog::level::info
		Warning = 2,     // spdlog::level::warn
		Error = 3,       // spdlog::level::err
		Fatal = 4        // spdlog::level::critical
	};

	constexpr const char* LogLevelToString(LogLevel level) {
		switch (level) {
		case LogLevel::Debug:       return "DEBUG";
		case LogLevel::Information: return "INFO ";
		case LogLevel::Warning:     return "WARN ";
		case LogLevel::Error:       return "ERROR";
		case LogLevel::Fatal:       return "FATAL";
		default:                    return "UNKNW";
		}
	}

	/// @brief Convert our LogLevel to spdlog level
	inline spdlog::level::level_enum ToSpdlogLevel(LogLevel level) {
		switch (level) {
		case LogLevel::Debug:       return spdlog::level::debug;
		case LogLevel::Information: return spdlog::level::info;
		case LogLevel::Warning:     return spdlog::level::warn;
		case LogLevel::Error:       return spdlog::level::err;
		case LogLevel::Fatal:       return spdlog::level::critical;
		default:                    return spdlog::level::info;
		}
	}

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
		return static_cast<LogCategory>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
	}
	inline LogCategory operator&(LogCategory lhs, LogCategory rhs) {
		return static_cast<LogCategory>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
	}
	inline LogCategory& operator|=(LogCategory& lhs, LogCategory rhs) {
		lhs = lhs | rhs; return lhs;
	}

	/// @brief Structured logging context for key-value pairs
	class LogContext {
		std::unordered_map<std::string, std::string> m_data;
	public:
		LogContext& Add(const std::string& key, const std::string& value) {
			m_data[key] = value; return *this;
		}
		template<typename T>
		LogContext& Add(const std::string& key, const T& value) {
			if constexpr (std::is_same_v<T, std::string>) m_data[key] = value;
			else if constexpr (std::is_same_v<T, const char*>) m_data[key] = std::string(value);
			else if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>) m_data[key] = std::to_string(value);
			else { std::ostringstream oss; oss << value; m_data[key] = oss.str(); }
			return *this;
		}
		std::string ToString() const {
			std::ostringstream oss; bool first = true;
			for (const auto& [k, v] : m_data) { if (!first) oss << ", "; oss << k << "=" << v; first = false; }
			return oss.str();
		}
	};

	struct LoggerConfig;

	/// @brief Binary logger for high-volume data (stub implementation)
	class BinaryLogger {
		void* m_mappedMemory = nullptr;
		size_t m_mappedSize = 0;
		std::atomic<size_t> m_writeOffset{ 0 };
	public:
		bool Initialize(const std::string& filename, size_t size = 100 * 1024 * 1024);
		void LogBinary(const void* data, size_t size, uint32_t type);
		void Flush();
	};

	/// @brief Main logger class backed by spdlog
	/// Provides a stable API while leveraging spdlog for performance and features
	class Logger {
		static std::unique_ptr<Logger> s_instance;
		static std::mutex s_mutex;

		std::shared_ptr<spdlog::logger> m_logger;         // Main logger (multi-sink)
		LogLevel m_minimumLevel = LogLevel::Information;
		bool m_logToConsole = true;
		bool m_logToFile = true;
		bool m_asyncEnabled = false;

		std::filesystem::path m_logDirectory;
		std::filesystem::path m_logFilePath;
		bool m_customDirectory = false;
		bool m_createdDirectory = false;

		struct LoggerMetrics {
			std::atomic<uint64_t> totalMessages{ 0 };
			std::atomic<uint64_t> droppedMessages{ 0 };
			std::atomic<uint64_t> avgWriteTimeNs{ 0 };
			std::atomic<uint64_t> maxWriteTimeNs{ 0 };
			std::chrono::steady_clock::time_point startTime;
			void Reset() {
				totalMessages = 0; droppedMessages = 0;
				avgWriteTimeNs = 0; maxWriteTimeNs = 0;
				startTime = std::chrono::steady_clock::now();
			}
			double GetMessagesPerSecond() const {
				auto elapsed = std::chrono::steady_clock::now() - startTime;
				auto sec = std::chrono::duration<double>(elapsed).count();
				return sec > 0 ? totalMessages.load() / sec : 0.0;
			}
		};

		LoggerMetrics m_metrics;
		uint32_t m_enabledCategories = static_cast<uint32_t>(LogCategory::All);
		size_t m_maxFileSize = 50 * 1024 * 1024;
		size_t m_maxFiles = 10;

	public:
		Logger();
		~Logger();

		/// @brief Initialize the logger with optional configuration
		static bool Initialize(const std::filesystem::path& pathOrFile,
			bool enableConsole = true,
			LogLevel minLevel = LogLevel::Information,
			bool treatAsDirectory = false,
			bool createDirectoryIfMissing = true);

		static Logger& Instance();

		// Core logging methods
		void Debug(const std::string& message);
		void Information(const std::string& message);
		void Warning(const std::string& message);
		void Error(const std::string& message);
		void Fatal(const std::string& message);

		// Printf-style logging
		void DebugF(const char* format, ...);
		void InformationF(const char* format, ...);
		void WarningF(const char* format, ...);
		void ErrorF(const char* format, ...);

		// Context-aware logging
		void InfoWithContext(const std::string& message, const LogContext& context);
		void ErrorWithContext(const std::string& message, const LogContext& context);

		/// @brief Format an address as hex string
		static std::string HexFormat(uintptr_t value);

		/// @brief Log an exception with optional context
		void LogException(const std::exception& ex, std::string_view context = "");

		// Configuration setters
		void SetMinimumLevel(LogLevel level);
		void SetConsoleOutput(bool enable) { m_logToConsole = enable; }
		void SetFileOutput(bool enable) { m_logToFile = enable; }
		void SetAsyncLogging(bool enable);

		// Configuration getters
		bool IsConsoleOutputEnabled() const { return m_logToConsole; }
		bool IsFileOutputEnabled() const { return m_logToFile; }
		LogLevel GetMinimumLevel() const { return m_minimumLevel; }
		const std::filesystem::path& GetLogFilePath() const { return m_logFilePath; }
		const std::filesystem::path& GetLogDirectory() const { return m_logDirectory; }
		bool IsCustomDirectory() const { return m_customDirectory; }
		bool WasDirectoryCreated() const { return m_createdDirectory; }

		void AnnounceLogFileLocation(bool force = false);

		const LoggerMetrics& GetMetrics() const { return m_metrics; }
		void ResetMetrics() { m_metrics.Reset(); }

		// Category filtering
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

		void DebugPacketCorrelationTimeout(uint16_t requestOpcode, uint64_t connectionId, uint64_t ageMs);

		void ReattachConsole();

		/// @brief Get default temp directory: %TEMP%\SapphireHook
		static std::filesystem::path GetDefaultTempDir();

		/// @brief Get the underlying spdlog logger (for advanced use)
		std::shared_ptr<spdlog::logger> GetSpdLogger() const { return m_logger; }

	private:
		void WriteLog(LogLevel level, const std::string& message);
		std::string FormatString(const char* format, va_list args);
		static bool EnsureDir(const std::filesystem::path& dir, bool create, bool& createdFlag);
		void RecreateLogger();
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
		bool LoadFromFile(const std::filesystem::path& configPath) { (void)configPath; return true; }
		bool SaveToFile(const std::filesystem::path& configPath) { (void)configPath; return true; }
	};

	// Convenience free functions - these are the primary API used throughout the codebase
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

	inline void DebugPacketCorrelationTimeout(uint16_t requestOpcode, uint64_t connectionId, uint64_t ageMs) {
		Logger::Instance().DebugPacketCorrelationTimeout(requestOpcode, connectionId, ageMs);
	}
	inline void LogException(const std::exception& ex, std::string_view ctx = {}) {
		Logger::Instance().LogException(ex, ctx);
	}
} // namespace SapphireHook