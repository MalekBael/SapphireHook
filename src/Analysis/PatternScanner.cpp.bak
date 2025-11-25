#include "PatternScanner.h"
#include "../Logger/Logger.h"
#include "../Helper/WindowsAPIWrapper.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <regex>
#include <random>
#include <locale>
#include <codecvt>

#include <iostream>

namespace SapphireHook {

    std::shared_ptr<EnhancedPatternScanner> PatternScanner::s_globalScanner;
    std::mutex PatternScanner::s_globalScannerMutex;

    std::string ScanCacheEntry::ToJson() const
    {
        std::ostringstream json;
        json << "{\n";
        json << "  \"gameVersion\": \"" << gameVersion << "\",\n";
        json << "  \"moduleBase\": \"0x" << std::hex << moduleBase << "\",\n";
        json << "  \"moduleSize\": " << std::dec << moduleSize << ",\n";
        json << "  \"moduleHash\": \"" << moduleHash << "\",\n";
        json << "  \"cacheTime\": " << std::chrono::duration_cast<std::chrono::seconds>(cacheTime.time_since_epoch()).count() << ",\n";
        json << "  \"resolvedPatterns\": {\n";

        bool first = true;
        for (const auto& pair : resolvedPatterns)
        {
            if (!first) json << ",\n";
            json << "    \"" << pair.first << "\": \"0x" << std::hex << pair.second << "\"";
            first = false;
        }
        json << "\n  }\n";
        json << "}";
        return json.str();
    }

    std::optional<ScanCacheEntry> ScanCacheEntry::FromJson(const std::string& json)
    {
        ScanCacheEntry entry;

        try
        {
            std::regex versionRegex("\"gameVersion\":\\s*\"([^\"]*)\"");
            std::smatch match;
            if (std::regex_search(json, match, versionRegex))
            {
                entry.gameVersion = match[1].str();
            }

            std::regex baseRegex("\"moduleBase\":\\s*\"0x([0-9a-fA-F]+)\"");
            if (std::regex_search(json, match, baseRegex))
            {
                entry.moduleBase = std::stoull(match[1].str(), nullptr, 16);
            }

            std::regex sizeRegex("\"moduleSize\":\\s*(\\d+)");
            if (std::regex_search(json, match, sizeRegex))
            {
                entry.moduleSize = std::stoull(match[1].str());
            }

            std::regex hashRegex("\"moduleHash\":\\s*\"([^\"]*)\"");
            if (std::regex_search(json, match, hashRegex))
            {
                entry.moduleHash = match[1].str();
            }

            std::regex timeRegex("\"cacheTime\":\\s*(\\d+)");
            if (std::regex_search(json, match, timeRegex))
            {
                auto timeValue = std::stoll(match[1].str());
                entry.cacheTime = std::chrono::system_clock::from_time_t(timeValue);
            }

            std::regex patternRegex("\"([^\"]+)\":\\s*\"0x([0-9a-fA-F]+)\"");
            std::sregex_iterator iter(json.begin(), json.end(), patternRegex);
            std::sregex_iterator end;

            for (; iter != end; ++iter)
            {
                std::string pattern = (*iter)[1].str();
                uintptr_t address = std::stoull((*iter)[2].str(), nullptr, 16);
                if (pattern != "gameVersion" && pattern != "moduleBase" &&
                    pattern != "moduleHash" && pattern != "cacheTime")
                {
                    entry.resolvedPatterns[pattern] = address;
                }
            }

            return entry;
        }
        catch (const std::exception& e)
        {
            LogError("Failed to parse cache JSON: " + std::string(e.what()));
            return std::nullopt;
        }
    }

    void ScanMetrics::RecordScan(std::chrono::milliseconds duration, bool fromCache)
    {
        totalScans++;

        if (fromCache)
        {
            cacheHits++;
        }
        else
        {
            cacheMisses++;
            totalScanTime += duration;

            if (duration < fastestScan) fastestScan = duration;
            if (duration > slowestScan) slowestScan = duration;
        }

        if (totalScans > 0)
        {
            averageScanTime = totalScanTime / (totalScans - cacheHits);
        }
    }

    void ScanMetrics::Reset()
    {
        totalScans = 0;
        cacheHits = 0;
        cacheMisses = 0;
        totalScanTime = std::chrono::milliseconds{ 0 };
        averageScanTime = std::chrono::milliseconds{ 0 };
        fastestScan = std::chrono::milliseconds::max();
        slowestScan = std::chrono::milliseconds{ 0 };
    }

    double ScanMetrics::GetCacheHitRate() const
    {
        if (totalScans == 0) return 0.0;
        return static_cast<double>(cacheHits) / totalScans * 100.0;
    }

    EnhancedPatternScanner::EnhancedPatternScanner(bool enableCaching, const std::filesystem::path& cacheFile)
        : m_moduleBase(0), m_moduleSize(0), m_textSection(0), m_textSize(0),
        m_dataSection(0), m_dataSize(0), m_enableCaching(enableCaching), m_cacheFile(cacheFile)
    {

        if (!InitializeModule())
        {
            LogError("Failed to initialize module for pattern scanner");
            return;
        }

        if (m_enableCaching && !m_cacheFile.empty())
        {
            LoadCache();
        }

        LogInfo("EnhancedPatternScanner initialized - Base: 0x" + std::to_string(m_moduleBase) +
            ", Size: " + std::to_string(m_moduleSize));
    }

    std::optional<uintptr_t> EnhancedPatternScanner::ScanText(std::string_view pattern)
    {
        auto result = ScanRegion(m_textSection, m_textSize, pattern);
        return result ? std::optional<uintptr_t>(result->address) : std::nullopt;
    }

    std::optional<uintptr_t> EnhancedPatternScanner::ScanData(std::string_view pattern)
    {
        auto result = ScanRegion(m_dataSection, m_dataSize, pattern);
        return result ? std::optional<uintptr_t>(result->address) : std::nullopt;
    }

    bool EnhancedPatternScanner::Is32BitProcess() const
    {
        return sizeof(void*) == 4;
    }

    const ScanMetrics& EnhancedPatternScanner::GetMetrics() const
    {
        std::lock_guard<std::mutex> lock(m_metricsMutex);
        return m_metrics;
    }

    std::optional<EnhancedPatternScanner::ScanResult> EnhancedPatternScanner::ScanModule(std::string_view pattern)
    {
        return ScanRegionInternal(m_moduleBase, m_moduleSize, pattern, true);
    }

    std::optional<EnhancedPatternScanner::ScanResult> EnhancedPatternScanner::ScanRegion(uintptr_t base, size_t size, std::string_view pattern)
    {
        return ScanRegionInternal(base, size, pattern, true);
    }

    std::map<std::string, uintptr_t> EnhancedPatternScanner::ScanMultiple(const std::map<std::string, std::string>& patterns)
    {
        std::map<std::string, uintptr_t> results;

        for (const auto& pair : patterns)
        {
            auto result = ScanModule(pair.second);
            if (result)
            {
                results[pair.first] = result->address;
            }
        }

        return results;
    }

    bool EnhancedPatternScanner::LoadCache()
    {
        if (!m_enableCaching || m_cacheFile.empty()) return false;

        try
        {
            if (!std::filesystem::exists(m_cacheFile))
            {
                LogInfo("Cache file does not exist: " + m_cacheFile.string());
                return false;
            }

            std::ifstream file(m_cacheFile);
            if (!file.is_open())
            {
                LogError("Failed to open cache file: " + m_cacheFile.string());
                return false;
            }

            const std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

            auto cache = ScanCacheEntry::FromJson(content);
            if (!cache)
            {
                LogError("Failed to parse cache file");
                return false;
            }

            if (!IsCacheValid())
            {
                LogWarning("Cache is invalid, will be regenerated");
                return false;
            }

            {
                std::lock_guard<std::mutex> guard(m_cacheMutex);
                m_loadedCache = cache;
            }

            LogInfo("Loaded pattern cache with " + std::to_string(cache->resolvedPatterns.size()) + " patterns");
            return true;
        }
        catch (const std::exception& e)
        {
            LogError("Exception loading cache: " + std::string(e.what()));
            return false;
        }
    }

    bool EnhancedPatternScanner::SaveCache() const
    {
        if (!m_enableCaching || m_cacheFile.empty()) return false;

        std::string json;
        {
            std::lock_guard<std::mutex> guard(m_cacheMutex);
            if (!m_loadedCache) return false;
            json = m_loadedCache->ToJson();
        }

        try
        {
            std::filesystem::create_directories(m_cacheFile.parent_path());

            std::ofstream file(m_cacheFile);
            if (!file.is_open())
            {
                LogError("Failed to create cache file: " + m_cacheFile.string());
                return false;
            }

            file << json;
            file.close();

            LogInfo("Saved pattern cache with " + std::to_string(m_loadedCache->resolvedPatterns.size()) + " patterns");
            return true;
        }
        catch (const std::exception& e)
        {
            LogError("Exception saving cache: " + std::string(e.what()));
            return false;
        }
    }

    void EnhancedPatternScanner::ClearCache()
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_loadedCache.reset();

        if (!m_cacheFile.empty() && std::filesystem::exists(m_cacheFile))
        {
            std::filesystem::remove(m_cacheFile);
        }

        LogInfo("Pattern cache cleared");
    }

    bool EnhancedPatternScanner::IsCacheValid() const
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        if (!m_loadedCache) return false;

        if (m_loadedCache->moduleBase != m_moduleBase || m_loadedCache->moduleSize != m_moduleSize)
        {
            LogInfo("Cache invalid: module base/size changed");
            return false;
        }

        std::string currentVersion = GetGameVersion();
        if (m_loadedCache->gameVersion != currentVersion)
        {
            LogInfo("Cache invalid: game version changed from " + m_loadedCache->gameVersion + " to " + currentVersion);
            return false;
        }

        std::string currentHash = CalculateModuleHash();
        if (m_loadedCache->moduleHash != currentHash)
        {
            LogInfo("Cache invalid: module hash changed");
            return false;
        }

        return true;
    }

    void EnhancedPatternScanner::InvalidateCache()
    {
        ClearCache();
    }

    void EnhancedPatternScanner::ResetMetrics()
    {
        std::lock_guard<std::mutex> lock(m_metricsMutex);
        m_metrics.Reset();
    }

    std::map<std::string, std::string> EnhancedPatternScanner::GetDebugInfo() const
    {
        std::map<std::string, std::string> info;

        info["ModuleBase"] = "0x" + std::to_string(m_moduleBase);
        info["ModuleSize"] = std::to_string(m_moduleSize);
        info["TextSection"] = "0x" + std::to_string(m_textSection);
        info["TextSize"] = std::to_string(m_textSize);
        info["DataSection"] = "0x" + std::to_string(m_dataSection);
        info["DataSize"] = std::to_string(m_dataSize);
        info["CachingEnabled"] = m_enableCaching ? "true" : "false";
        info["CacheFile"] = m_cacheFile.string();
        info["GameVersion"] = GetGameVersion();

        std::lock_guard<std::mutex> lock(m_metricsMutex);
        info["TotalScans"] = std::to_string(m_metrics.totalScans);
        info["CacheHits"] = std::to_string(m_metrics.cacheHits);
        info["CacheHitRate"] = std::to_string(m_metrics.GetCacheHitRate()) + "%";

        return info;
    }

    std::string EnhancedPatternScanner::GetGameVersion() const
    {
        return "1.0.0.0";        
    }

    bool EnhancedPatternScanner::IsVersionCompatible(const std::string& version) const
    {
        return GetGameVersion() == version;
    }

    bool EnhancedPatternScanner::InitializeModule()
    {
        size_t moduleSize = 0;
        uintptr_t moduleBase = GetModuleBaseAddress(L"ffxiv_dx11.exe", moduleSize);

        if (moduleBase == 0)
        {
            LogError("Failed to get module base address");
            return false;
        }

        m_moduleBase = moduleBase;
        m_moduleSize = moduleSize;

        return ParsePESection();
    }

    bool EnhancedPatternScanner::ParsePESection()
    {
        m_textSection = m_moduleBase + 0x1000;    
        m_textSize = m_moduleSize / 2;           
        m_dataSection = m_textSection + m_textSize;
        m_dataSize = m_moduleSize / 4;           

        LogInfo("PE sections: .text=0x" + std::to_string(m_textSection) +
            " (size=" + std::to_string(m_textSize) +
            "), .data=0x" + std::to_string(m_dataSection) +
            " (size=" + std::to_string(m_dataSize) + ")");

        return true;
    }

    std::optional<EnhancedPatternScanner::ScanResult> EnhancedPatternScanner::ScanRegionInternal(
        uintptr_t base, size_t size, std::string_view pattern, bool useCache)
    {

        auto start = std::chrono::high_resolution_clock::now();

        if (useCache && m_enableCaching)
        {
            uintptr_t cachedResult = 0;
            std::string cacheKey = GenerateCacheKey(pattern);

            if (IsPatternCached(cacheKey, cachedResult))
            {
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                std::lock_guard<std::mutex> lock(m_metricsMutex);
                m_metrics.RecordScan(duration, true);

                ScanResult result;
                result.address = cachedResult;
                result.fromCache = true;
                result.scanTime = duration;
                return result;
            }
        }

        auto legacyResult = PatternScanner::ScanPattern(base, size, pattern);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::lock_guard<std::mutex> lock(m_metricsMutex);
        m_metrics.RecordScan(duration, false);

        if (legacyResult)
        {
            ScanResult result;
            result.address = legacyResult->address;
            result.offset = legacyResult->offset;
            result.matched_bytes = legacyResult->matched_bytes;
            result.fromCache = false;
            result.scanTime = duration;

            if (useCache && m_enableCaching)
            {
                CachePattern(GenerateCacheKey(pattern), result.address);
            }

            return result;
        }

        return std::nullopt;
    }

    std::string EnhancedPatternScanner::GenerateCacheKey(std::string_view pattern) const
    {
        return std::string(pattern);
    }

    std::string EnhancedPatternScanner::CalculateModuleHash() const
    {
        std::hash<std::string> hasher;
        std::string data = std::to_string(m_moduleBase) + std::to_string(m_moduleSize);
        return std::to_string(hasher(data));
    }

    bool EnhancedPatternScanner::IsPatternCached(const std::string& cacheKey, uintptr_t& result) const
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        if (!m_loadedCache) return false;

        auto it = m_loadedCache->resolvedPatterns.find(cacheKey);
        if (it != m_loadedCache->resolvedPatterns.end())
        {
            result = it->second;
            return true;
        }

        return false;
    }

    void EnhancedPatternScanner::CachePattern(const std::string& cacheKey, uintptr_t result)
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);

        if (!m_loadedCache)
        {
            m_loadedCache = ScanCacheEntry{};
            m_loadedCache->gameVersion = GetGameVersion();
            m_loadedCache->moduleBase = m_moduleBase;
            m_loadedCache->moduleSize = m_moduleSize;
            m_loadedCache->moduleHash = CalculateModuleHash();
            m_loadedCache->cacheTime = std::chrono::system_clock::now();
        }

        m_loadedCache->resolvedPatterns[cacheKey] = result;
    }

    std::optional<std::vector<int>> PatternScanner::PatternToBytes(std::string_view pattern)
    {
        std::vector<int> bytes;
        std::string patternStr(pattern);

        size_t start = 0;
        size_t end = 0;

        while (end != std::string::npos)
        {
            end = patternStr.find(' ', start);
            std::string token = patternStr.substr(start, (end == std::string::npos) ? std::string::npos : end - start);

            token.erase(0, token.find_first_not_of(" \t\r\n"));
            token.erase(token.find_last_not_of(" \t\r\n") + 1);

            if (!token.empty())
            {
                if (token == "?" || token == "??")
                {
                    bytes.push_back(-1);
                }
                else
                {
                    try
                    {
                        int byte = std::stoi(token, nullptr, 16);
                        if (byte >= 0 && byte <= 255)
                        {
                            bytes.push_back(byte);
                        }
                        else
                        {
                            return std::nullopt;
                        }
                    }
                    catch (...)
                    {
                        return std::nullopt;
                    }
                }
            }

            start = (end == std::string::npos) ? end : end + 1;
        }

        return bytes;
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanPattern(uintptr_t start, size_t length, std::string_view pattern)
    {
        auto bytes = PatternToBytes(pattern);
        if (!bytes) return std::nullopt;

        const uint8_t* memory = reinterpret_cast<const uint8_t*>(start);

        for (size_t i = 0; i <= length - bytes->size(); ++i)
        {
            if (CompareBytes(memory + i, *bytes))
            {
                ScanResult result;
                result.address = start + i;
                result.offset = i;
                result.matched_bytes.assign(memory + i, memory + i + bytes->size());
                return result;
            }
        }

        return std::nullopt;
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanPattern(const MemoryBuffer& buffer, std::string_view pattern)
    {
        return ScanPattern(reinterpret_cast<uintptr_t>(buffer.Data()), buffer.Size(), pattern);
    }

    std::vector<PatternScanner::ScanResult> PatternScanner::ScanAllPatterns(uintptr_t start, size_t length, std::string_view pattern)
    {
        std::vector<ScanResult> results;
        auto bytes = PatternToBytes(pattern);
        if (!bytes) return results;

        const uint8_t* memory = reinterpret_cast<const uint8_t*>(start);

        for (size_t i = 0; i <= length - bytes->size(); ++i)
        {
            if (CompareBytes(memory + i, *bytes))
            {
                ScanResult result;
                result.address = start + i;
                result.offset = i;
                result.matched_bytes.assign(memory + i, memory + i + bytes->size());
                results.push_back(result);
            }
        }

        return results;
    }

    std::vector<PatternScanner::ScanResult> PatternScanner::ScanAllPatterns(const MemoryBuffer& buffer, std::string_view pattern)
    {
        return ScanAllPatterns(reinterpret_cast<uintptr_t>(buffer.Data()), buffer.Size(), pattern);
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanPatternWithMask(uintptr_t start, size_t length,
        std::span<const uint8_t> pattern, std::span<const bool> mask)
    {

        if (pattern.size() != mask.size()) return std::nullopt;

        const uint8_t* memory = reinterpret_cast<const uint8_t*>(start);

        for (size_t i = 0; i <= length - pattern.size(); ++i)
        {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); ++j)
            {
                if (mask[j] && memory[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                ScanResult result;
                result.address = start + i;
                result.offset = i;
                result.matched_bytes.assign(memory + i, memory + i + pattern.size());
                return result;
            }
        }

        return std::nullopt;
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanModule(const wchar_t* moduleName, std::string_view pattern)
    {
        size_t moduleSize = 0;
        uintptr_t moduleBase = GetModuleBaseAddress(moduleName, moduleSize);

        if (moduleBase == 0) return std::nullopt;

        return ScanPattern(moduleBase, moduleSize, pattern);
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanMainModule(std::string_view pattern)
    {
        return ScanModule(L"ffxiv_dx11.exe", pattern);
    }

    Expected<PatternScanner::ScanResult> PatternScanner::ScanPatternExpected(uintptr_t start, size_t length, std::string_view pattern)
    {
        auto result = ScanPattern(start, length, pattern);
        if (result)
        {
            return Expected<ScanResult>(*result);
        }
        else
        {
            return Expected<ScanResult>(ScanError::NotFound);
        }
    }

    Expected<PatternScanner::ScanResult> PatternScanner::ScanPatternExpected(const MemoryBuffer& buffer, std::string_view pattern)
    {
        return ScanPatternExpected(reinterpret_cast<uintptr_t>(buffer.Data()), buffer.Size(), pattern);
    }

    void PatternScanner::LogScanError(ScanError error, std::string_view context)
    {
#if SAPPHIRE_HAS_PRINT && SAPPHIRE_HAS_STACKTRACE
        auto trace = std::stacktrace::current();
        std::println("[PatternScanner] Error: {} in context: {}", ToString(error), context);
        std::println("Stack trace:");
        for (const auto& entry : trace)
        {
            std::println("  {}", entry.description());
        }
#elif SAPPHIRE_HAS_PRINT
        std::println("[PatternScanner] Error: {} in context: {}", ToString(error), context);
#else
        printf("[PatternScanner] Error: %s in context: %.*s\n",
            ToString(error), static_cast<int>(context.size()), context.data());
#endif
    }

    std::shared_ptr<EnhancedPatternScanner> PatternScanner::GetGlobalScanner()
    {
        std::lock_guard<std::mutex> lock(s_globalScannerMutex);
        return s_globalScanner;
    }

    void PatternScanner::SetGlobalScanner(std::shared_ptr<EnhancedPatternScanner> scanner)
    {
        std::lock_guard<std::mutex> lock(s_globalScannerMutex);
        s_globalScanner = scanner;
    }

    bool PatternScanner::CompareBytes(const uint8_t* data, const std::vector<int>& pattern)
    {
        for (size_t i = 0; i < pattern.size(); ++i)
        {
            if (pattern[i] != -1 && static_cast<uint8_t>(pattern[i]) != data[i])
            {
                return false;
            }
        }
        return true;
    }

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
                std::string moduleNameStr;
                for (const wchar_t* p = moduleName; *p; ++p)
                {
                    if (*p <= 127) moduleNameStr += static_cast<char>(*p);
                    else moduleNameStr += '?';
                }

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

                uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hModule);
                size_t moduleSize = 0x10000000;        

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

                    if (progress)
                    {
                        progress(i, patterns.size(), patterns[i]);
                    }

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

        if (!ValidateMemoryRegion(start, length))
        {
            result.error = ScanError::MemoryAccessViolation;
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime);
            LogScanResult(result);
            return result;
        }

        if (config.enable_logging)
        {
            LogScanStart(pattern, start, length);
        }

        try
        {
            CancellationToken timeoutToken = CancellationToken::CreateWithTimeout(config.timeout);

            auto scanResult = PatternScanner::ScanPattern(start, length, std::string(pattern));

            if (cancellation.IsCancelled() || timeoutToken.IsCancelled())
            {
                result.was_cancelled = true;
                result.error = ScanError::NotFound;
            }
            else if (scanResult)
            {
                result.result = *scanResult;
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

        try
        {
            char dummyBuffer[64];      
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

    PESection PatternScanner::GetPESection(HMODULE module, const char* sectionName)
    {
        PESection result;

        auto base = reinterpret_cast<std::byte*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return result;

        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            char secName[9] = { 0 };
            std::memcpy(secName, sec[i].Name, 8);

            if (std::string_view(secName) == sectionName)
            {
                result.baseAddress = base + sec[i].VirtualAddress;
                result.size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                result.name = secName;
                break;
            }
        }

        return result;
    }

    std::vector<std::byte*> PatternScanner::FindAsciiInBuffer(std::byte* buffer, size_t length, std::string_view needle)
    {
        std::vector<std::byte*> hits;
        if (needle.empty() || !buffer || length < needle.size()) return hits;

        auto* b = reinterpret_cast<const char*>(buffer);
        auto* e = b + length - needle.size() + 1;

        for (auto* p = b; p < e; ++p)
        {
            if (p[0] == needle[0] && std::memcmp(p, needle.data(), needle.size()) == 0)
            {
                hits.push_back(reinterpret_cast<std::byte*>(const_cast<char*>(p)));
            }
        }

        return hits;
    }

    std::vector<std::byte*> PatternScanner::FindUtf16InBuffer(std::byte* buffer, size_t length, std::wstring_view needle)
    {
        std::vector<std::byte*> hits;
        if (needle.empty() || !buffer) return hits;

        const size_t needleBytes = needle.size() * sizeof(wchar_t);
        if (length < needleBytes) return hits;

        auto* b = reinterpret_cast<const wchar_t*>(buffer);
        auto wlen = length / sizeof(wchar_t);
        auto* e = b + wlen - needle.size() + 1;

        for (auto* p = b; p < e; ++p)
        {
            if (p[0] == needle[0] && std::memcmp(p, needle.data(), needleBytes) == 0)
            {
                hits.push_back(reinterpret_cast<std::byte*>(const_cast<wchar_t*>(p)));
            }
        }

        return hits;
    }

    bool PatternScanner::ParseRipRelativeInstruction(const std::byte* instruction, uintptr_t& target, size_t& instructionLength)
    {
        const bool hasRex = (instruction[0] >= std::byte{ 0x40 } && instruction[0] <= std::byte{ 0x4F });
        const size_t opOffset = hasRex ? 1 : 0;
        const size_t modrmOffset = opOffset + 1;
        const size_t dispOffset = modrmOffset + 1;
        const size_t minLength = hasRex ? 7 : 6;

        const std::byte opcode = instruction[opOffset];
        if (!(opcode == std::byte{ 0x8D } || opcode == std::byte{ 0x8B })) return false;

        const unsigned modrm = static_cast<unsigned>(instruction[modrmOffset]);
        const unsigned mod = (modrm >> 6) & 0x3;
        const unsigned rm = modrm & 0x7;
        if (!(mod == 0 && rm == 5)) return false;    

        const int32_t displacement = *reinterpret_cast<const int32_t*>(instruction + dispOffset);
        const auto* nextInstruction = instruction + minLength;
        const auto nextAddress = reinterpret_cast<uintptr_t>(nextInstruction);

        target = static_cast<uintptr_t>(static_cast<intptr_t>(nextAddress) + displacement);
        instructionLength = minLength;
        return true;
    }

    std::vector<uintptr_t> PatternScanner::FindRipReferencesTo(HMODULE module, uintptr_t targetAddress)
    {
        std::vector<uintptr_t> references;

        auto textSection = GetPESection(module, ".text");
        if (!textSection || textSection.size < 6) return references;

        const auto* begin = textSection.baseAddress;
        const auto* end = textSection.baseAddress + textSection.size - 6;    

        for (const auto* p = begin; p <= end; ++p)
        {
            uintptr_t target = 0;
            size_t instructionLength = 0;

            if (!ParseRipRelativeInstruction(p, target, instructionLength)) continue;

            if (target == targetAddress)
            {
                references.push_back(reinterpret_cast<uintptr_t>(p));
            }
        }

        return references;
    }

    uintptr_t PatternScanner::GetFunctionStartFromRva(HMODULE module, uint32_t rva)
    {
        auto base = reinterpret_cast<std::byte*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

        const IMAGE_DATA_DIRECTORY& exceptionDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exceptionDir.VirtualAddress == 0 || exceptionDir.Size == 0) return 0;

        using RUNTIME_FUNCTION = IMAGE_RUNTIME_FUNCTION_ENTRY;
        auto* runtimeFunctions = reinterpret_cast<RUNTIME_FUNCTION*>(base + exceptionDir.VirtualAddress);
        auto count = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

        size_t low = 0, high = count;
        while (low < high)
        {
            size_t mid = (low + high) / 2;
            auto begin = runtimeFunctions[mid].BeginAddress;
            auto end = runtimeFunctions[mid].EndAddress;

            if (rva < begin)
            {
                high = mid;
            }
            else if (rva >= end)
            {
                low = mid + 1;
            }
            else
            {
                return reinterpret_cast<uintptr_t>(module) + begin;
            }
        }
        return 0;
    }

    std::vector<std::pair<uintptr_t, std::string>> PatternScanner::EnumerateAsciiStrings(HMODULE module, size_t minLength)
    {
        std::vector<std::pair<uintptr_t, std::string>> result;

        auto rdataSection = GetPESection(module, ".rdata");
        if (!rdataSection) return result;

        const auto* bytes = reinterpret_cast<const unsigned char*>(rdataSection.baseAddress);
        size_t i = 0;

        while (i < rdataSection.size)
        {
            size_t start = i;
            size_t length = 0;

            while (i < rdataSection.size)
            {
                unsigned char c = bytes[i];
                if (c >= 0x20 && c <= 0x7E)   
                {
                    ++i;
                    ++length;
                }
                else
                {
                    break;
                }
            }

            if (length >= minLength && i < rdataSection.size && bytes[i] == 0x00)
            {
                auto address = reinterpret_cast<uintptr_t>(rdataSection.baseAddress + start);
                std::string text(reinterpret_cast<const char*>(bytes + start), length);
                result.emplace_back(address, std::move(text));
                ++i;    
            }
            else
            {
                if (i < rdataSection.size && bytes[i] == 0x00) ++i;
                else i = start + 1;
            }
        }

        return result;
    }

    std::vector<std::pair<uintptr_t, std::string>> PatternScanner::EnumerateUtf16Strings(HMODULE module, size_t minLength)
    {
        std::vector<std::pair<uintptr_t, std::string>> result;

        auto rdataSection = GetPESection(module, ".rdata");
        if (!rdataSection || rdataSection.size < 4) return result;

        const auto* bytes = reinterpret_cast<const unsigned char*>(rdataSection.baseAddress);
        size_t i = 0;

        while (i + 1 < rdataSection.size)
        {
            size_t start = i;
            size_t charCount = 0;

            while (i + 1 < rdataSection.size)
            {
                unsigned char low = bytes[i];
                unsigned char high = bytes[i + 1];

                if (high == 0x00 && low >= 0x20 && low <= 0x7E)    
                {
                    i += 2;
                    ++charCount;
                }
                else
                {
                    break;
                }
            }

            if (charCount >= minLength && i + 1 < rdataSection.size &&
                bytes[i] == 0x00 && bytes[i + 1] == 0x00)
            {
                auto address = reinterpret_cast<uintptr_t>(rdataSection.baseAddress + start);

                std::string text;
                text.reserve(charCount);
                for (size_t j = 0; j < charCount; ++j)
                {
                    text.push_back(static_cast<char>(bytes[start + j * 2]));
                }

                result.emplace_back(address, std::move(text));
                i += 2;     
            }
            else
            {
                if (i + 1 < rdataSection.size && bytes[i] == 0x00 && bytes[i + 1] == 0x00) i += 2;
                else ++i;
            }
        }

        return result;
    }

    std::vector<uintptr_t> PatternScanner::FindFunctionsReferencingString(HMODULE module, std::string_view searchString)
    {
        std::vector<uintptr_t> result;

        auto rdataSection = GetPESection(module, ".rdata");
        if (!rdataSection) return result;

        auto asciiHits = FindAsciiInBuffer(rdataSection.baseAddress, rdataSection.size, searchString);

        std::wstring wideNeedle(searchString.begin(), searchString.end());
        auto utf16Hits = FindUtf16InBuffer(rdataSection.baseAddress, rdataSection.size, wideNeedle);

        std::vector<uintptr_t> targets;
        targets.reserve(asciiHits.size() + utf16Hits.size());

        for (auto* ptr : asciiHits)
        {
            targets.push_back(reinterpret_cast<uintptr_t>(ptr));
        }
        for (auto* ptr : utf16Hits)
        {
            targets.push_back(reinterpret_cast<uintptr_t>(ptr));
        }

        for (auto address : targets)
        {
            auto references = FindRipReferencesTo(module, address);
            for (auto ref : references)
            {
                auto rva = static_cast<uint32_t>(ref - reinterpret_cast<uintptr_t>(module));
                auto functionStart = GetFunctionStartFromRva(module, rva);
                if (functionStart != 0)
                {
                    result.push_back(functionStart);
                }
            }
        }

        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());

        return result;
    }

    FunctionStringMap PatternScanner::MapFunctionsToStrings(HMODULE module, size_t minStringLength)
    {
        FunctionStringMap result;

        auto asciiStrings = EnumerateAsciiStrings(module, minStringLength);
        auto utf16Strings = EnumerateUtf16Strings(module, minStringLength);

        result.asciiStringCount = asciiStrings.size();
        result.utf16StringCount = utf16Strings.size();

        std::unordered_map<uintptr_t, std::unordered_set<std::string>> functionStringsSeen;

        auto processString = [&](uintptr_t stringAddress, const std::string& text)
            {
                auto references = FindRipReferencesTo(module, stringAddress);
                for (auto ref : references)
                {
                    auto rva = static_cast<uint32_t>(ref - reinterpret_cast<uintptr_t>(module));
                    auto functionStart = GetFunctionStartFromRva(module, rva);
                    if (!functionStart) continue;

                    auto& seenStrings = functionStringsSeen[functionStart];
                    if (seenStrings.insert(text).second)
                    {
                        result.functionsToStrings[functionStart].push_back(text);
                    }

                    auto& functionVector = result.stringsToFunctions[text];
                    if (functionVector.empty() || functionVector.back() != functionStart)
                    {
                        functionVector.push_back(functionStart);
                    }
                }
            };

        for (const auto& [addr, text] : asciiStrings)
        {
            processString(addr, text);
        }
        for (const auto& [addr, text] : utf16Strings)
        {
            processString(addr, text);
        }

        for (auto& [func, strings] : result.functionsToStrings)
        {
            std::sort(strings.begin(), strings.end());
            strings.erase(std::unique(strings.begin(), strings.end()), strings.end());
        }
        for (auto& [text, functions] : result.stringsToFunctions)
        {
            std::sort(functions.begin(), functions.end());
            functions.erase(std::unique(functions.begin(), functions.end()), functions.end());
        }

        return result;
    }

    std::optional<StringXrefResult> PatternScanner::GuessNameFromStringReferences(uintptr_t functionAddress, size_t maxScanBytes)
    {
        auto textSection = GetPESection(GetModuleHandleW(nullptr), ".text");
        auto rdataSection = GetPESection(GetModuleHandleW(nullptr), ".rdata");
        if (!textSection || !rdataSection) return std::nullopt;

        if (functionAddress < reinterpret_cast<uintptr_t>(textSection.baseAddress) ||
            functionAddress >= reinterpret_cast<uintptr_t>(textSection.baseAddress) + textSection.size)
        {
            return std::nullopt;
        }

        const auto* code = reinterpret_cast<const std::byte*>(functionAddress);
        const auto* textEnd = textSection.baseAddress + textSection.size;
        const size_t maxScan = std::min(maxScanBytes,
            static_cast<size_t>(textEnd - reinterpret_cast<const std::byte*>(code)));

        std::string bestCandidate;
        uintptr_t bestStringAddress = 0;
        uintptr_t bestReferenceAddress = 0;
        bool bestIsUtf16 = false;

        for (size_t i = 0; i + 6 <= maxScan; )
        {
            uintptr_t target = 0;
            size_t instructionLength = 0;

            if (!ParseRipRelativeInstruction(code + i, target, instructionLength))
            {
                ++i;
                continue;
            }
            i += instructionLength;

            if (target < reinterpret_cast<uintptr_t>(rdataSection.baseAddress) ||
                target >= reinterpret_cast<uintptr_t>(rdataSection.baseAddress) + rdataSection.size)
            {
                continue;
            }

            const char* str = reinterpret_cast<const char*>(target);
            std::string candidate;

            size_t maxLen = std::min<size_t>(128,
                reinterpret_cast<const char*>(rdataSection.baseAddress + rdataSection.size) - str);

            for (size_t j = 0; j < maxLen; ++j)
            {
                char c = str[j];
                if (c == '\0') break;
                if (c < 0x20 || c > 0x7E)    
                {
                    candidate.clear();
                    break;
                }
                candidate.push_back(c);
            }

            bool isUtf16 = false;
            if (candidate.empty())
            {
                const unsigned char* ptr = reinterpret_cast<const unsigned char*>(target);
                std::string utf8Candidate;
                maxLen = std::min<size_t>(256,
                    reinterpret_cast<const unsigned char*>(rdataSection.baseAddress + rdataSection.size) - ptr);

                for (size_t j = 0; j + 1 < maxLen; j += 2)
                {
                    unsigned char low = ptr[j], high = ptr[j + 1];
                    if (low == 0x00 && high == 0x00) break;   
                    if (high != 0x00 || low < 0x20 || low > 0x7E)    
                    {
                        utf8Candidate.clear();
                        break;
                    }
                    utf8Candidate.push_back(static_cast<char>(low));
                }

                if (!utf8Candidate.empty())
                {
                    candidate = std::move(utf8Candidate);
                    isUtf16 = true;
                }
                else
                {
                    continue;
                }
            }

            while (!candidate.empty() &&
                (candidate.back() == '.' || candidate.back() == ':' || candidate.back() == ' '))
            {
                candidate.pop_back();
            }

            if (!candidate.empty() && (bestCandidate.empty() || candidate.size() > bestCandidate.size()))
            {
                bestCandidate = candidate;
                bestStringAddress = target;
                bestReferenceAddress = functionAddress + i - instructionLength;
                bestIsUtf16 = isUtf16;
            }
        }

        if (bestCandidate.empty()) return std::nullopt;

        StringXrefResult result;
        result.text = bestCandidate;
        result.stringAddress = bestStringAddress;
        result.referenceAddress = bestReferenceAddress;
        result.isUtf16 = bestIsUtf16;

        return result;
    }

    void ScanOperation::Cancel()
    {
        LogWarning("Cancelling scan operation for pattern: " + m_pattern);
        m_cancellation.Cancel();
    }

    ModuleInfo::ModuleInfo(const wchar_t* moduleName)
        : m_baseAddress(0), m_size(0), m_scanned(std::chrono::system_clock::now())
    {
        if (moduleName)
        {
            m_name = moduleName;
        }
        else
        {
            m_name = L"ffxiv_dx11.exe";
        }

        size_t moduleSize = 0;
        m_baseAddress = GetModuleBaseAddress(m_name.c_str(), moduleSize);
        m_size = moduleSize;

        if (m_baseAddress != 0)
        {
            CalculateModuleHash();
            m_version = GetModuleVersion();
        }
    }

    std::unique_ptr<MemoryBuffer> ModuleInfo::CreateBuffer() const
    {
        if (m_baseAddress == 0 || m_size == 0) return nullptr;

        auto buffer = std::make_unique<MemoryBuffer>(m_size);
        std::memcpy(buffer->Data(), reinterpret_cast<const void*>(m_baseAddress), m_size);
        return buffer;
    }

    std::optional<PatternScanner::ScanResult> ModuleInfo::ScanPattern(std::string_view pattern) const
    {
        if (m_baseAddress == 0) return std::nullopt;
        return PatternScanner::ScanPattern(m_baseAddress, m_size, pattern);
    }

    std::vector<PatternScanner::ScanResult> ModuleInfo::ScanAllPatterns(std::string_view pattern) const
    {
        if (m_baseAddress == 0) return {};
        return PatternScanner::ScanAllPatterns(m_baseAddress, m_size, pattern);
    }

    Expected<PatternScanner::ScanResult> ModuleInfo::ScanPatternExpected(std::string_view pattern) const
    {
        if (m_baseAddress == 0) return Expected<PatternScanner::ScanResult>(ScanError::ModuleNotFound);
        return PatternScanner::ScanPatternExpected(m_baseAddress, m_size, pattern);
    }

    std::map<std::string, std::string> ModuleInfo::GetDebugInfo() const
    {
        std::map<std::string, std::string> info;

        std::string nameStr;
        nameStr.reserve(m_name.size());
        for (wchar_t wc : m_name)
        {
            if (wc <= 127)
            {     
                nameStr.push_back(static_cast<char>(wc));
            }
            else
            {
                nameStr.push_back('?');     
            }
        }

        info["Name"] = nameStr;
        info["BaseAddress"] = "0x" + std::to_string(m_baseAddress);
        info["Size"] = std::to_string(m_size);
        info["Version"] = m_version;
        info["Hash"] = m_hash;

        auto scannedTime = std::chrono::system_clock::to_time_t(m_scanned);
        info["ScannedTime"] = std::to_string(scannedTime);

        return info;
    }

    void ModuleInfo::CalculateModuleHash()
    {
        std::hash<std::string> hasher;
        std::string data = std::to_string(m_baseAddress) + std::to_string(m_size);
        m_hash = std::to_string(hasher(data));
    }

    std::string ModuleInfo::GetModuleVersion() const
    {
        return "1.0.0.0";
    }

    std::shared_ptr<EnhancedPatternScanner> ScannerFactory::CreateCachedScanner(
        const std::filesystem::path& cacheDir, const std::string& gameVersion)
    {
        std::filesystem::create_directories(cacheDir);
        std::filesystem::path cacheFile = cacheDir / "pattern_cache.json";

        auto scanner = std::make_shared<EnhancedPatternScanner>(true, cacheFile);
        return scanner;
    }

    std::shared_ptr<EnhancedPatternScanner> ScannerFactory::CreateMemoryOnlyScanner()
    {
        return std::make_shared<EnhancedPatternScanner>(false);
    }

    std::shared_ptr<EnhancedPatternScanner> ScannerFactory::CreateModuleScanner(
        const std::wstring& moduleName, bool enableCaching)
    {
        std::filesystem::path cacheFile;
        if (enableCaching)
        {
            std::string moduleNameStr;
            moduleNameStr.reserve(moduleName.size());
            for (wchar_t wc : moduleName)
            {
                if (wc <= 127)
                {     
                    moduleNameStr.push_back(static_cast<char>(wc));
                }
                else
                {
                    moduleNameStr.push_back('_');     
                }
            }
            cacheFile = "cache/" + moduleNameStr + "_cache.json";
        }

        return std::make_shared<EnhancedPatternScanner>(enableCaching, cacheFile);
    }

}   

extern "C" {
    bool PatternToBytes(const char* pattern, std::vector<int>& bytes)
    {
        auto result = SapphireHook::PatternScanner::PatternToBytes(pattern);
        if (result)
        {
            bytes = *result;
            return true;
        }
        return false;
    }

    uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern)
    {
        auto result = SapphireHook::PatternScanner::ScanPattern(start, length, pattern);
        return result ? result->address : 0;
    }

    uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize)
    {
        outSize = 0x10000000;  
        return 0x140000000;      
    }
}
