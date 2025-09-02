#include "patternscanner.h"
#include "../Logger/Logger.h"
#include "../Core/WindowsAPIWrapper.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <regex>
#include <random>
#include <locale>
#include <codecvt>

// JSON serialization libraries (simple implementation)
#include <iostream>

namespace SapphireHook {

    // Static member definitions
    std::shared_ptr<EnhancedPatternScanner> PatternScanner::s_globalScanner;
    std::mutex PatternScanner::s_globalScannerMutex;

    // ===== ScanCacheEntry Implementation =====

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
        // Simple JSON parsing implementation
        ScanCacheEntry entry;

        try
        {
            // Extract gameVersion
            std::regex versionRegex("\"gameVersion\":\\s*\"([^\"]*)\"");
            std::smatch match;
            if (std::regex_search(json, match, versionRegex))
            {
                entry.gameVersion = match[1].str();
            }

            // Extract moduleBase
            std::regex baseRegex("\"moduleBase\":\\s*\"0x([0-9a-fA-F]+)\"");
            if (std::regex_search(json, match, baseRegex))
            {
                entry.moduleBase = std::stoull(match[1].str(), nullptr, 16);
            }

            // Extract moduleSize
            std::regex sizeRegex("\"moduleSize\":\\s*(\\d+)");
            if (std::regex_search(json, match, sizeRegex))
            {
                entry.moduleSize = std::stoull(match[1].str());
            }

            // Extract moduleHash
            std::regex hashRegex("\"moduleHash\":\\s*\"([^\"]*)\"");
            if (std::regex_search(json, match, hashRegex))
            {
                entry.moduleHash = match[1].str();
            }

            // Extract cacheTime
            std::regex timeRegex("\"cacheTime\":\\s*(\\d+)");
            if (std::regex_search(json, match, timeRegex))
            {
                auto timeValue = std::stoll(match[1].str());
                entry.cacheTime = std::chrono::system_clock::from_time_t(timeValue);
            }

            // Extract resolved patterns
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

    // ===== ScanMetrics Implementation =====

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

    // ===== EnhancedPatternScanner Implementation =====

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

            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

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

            std::lock_guard<std::mutex> lock(m_cacheMutex);
            m_loadedCache = cache;

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
        if (!m_enableCaching || m_cacheFile.empty() || !m_loadedCache) return false;

        try
        {
            // Ensure directory exists
            std::filesystem::create_directories(m_cacheFile.parent_path());

            std::ofstream file(m_cacheFile);
            if (!file.is_open())
            {
                LogError("Failed to create cache file: " + m_cacheFile.string());
                return false;
            }

            std::lock_guard<std::mutex> lock(m_cacheMutex);
            file << m_loadedCache->ToJson();
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

        // Check module base and size
        if (m_loadedCache->moduleBase != m_moduleBase || m_loadedCache->moduleSize != m_moduleSize)
        {
            LogInfo("Cache invalid: module base/size changed");
            return false;
        }

        // Check game version
        std::string currentVersion = GetGameVersion();
        if (m_loadedCache->gameVersion != currentVersion)
        {
            LogInfo("Cache invalid: game version changed from " + m_loadedCache->gameVersion + " to " + currentVersion);
            return false;
        }

        // Check module hash
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
        // Try to get version from module version info
        return "1.0.0.0"; // Placeholder - would implement proper version detection
    }

    bool EnhancedPatternScanner::IsVersionCompatible(const std::string& version) const
    {
        return GetGameVersion() == version;
    }

    // Private method implementations

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
        // Simplified PE parsing - would implement full PE header parsing
        // For now, assume standard layout
        m_textSection = m_moduleBase + 0x1000; // Standard .text offset
        m_textSize = m_moduleSize / 2;         // Rough estimate
        m_dataSection = m_textSection + m_textSize;
        m_dataSize = m_moduleSize / 4;         // Rough estimate

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

        // Check cache first
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

        // Perform actual scan
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

            // Cache the result
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
        // Simplified hash calculation - would implement proper SHA1
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

    // ===== PatternScanner Implementation =====

    std::optional<std::vector<int>> PatternScanner::PatternToBytes(std::string_view pattern)
    {
        std::vector<int> bytes;
        std::string patternStr(pattern);
        
        // Split the pattern by spaces manually
        size_t start = 0;
        size_t end = 0;
        
        while (end != std::string::npos)
        {
            end = patternStr.find(' ', start);
            std::string token = patternStr.substr(start, (end == std::string::npos) ? std::string::npos : end - start);
            
            // Trim whitespace
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
        // Fallback to printf
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

    // ===== ModuleInfo Implementation =====

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

        // Convert wide string to narrow string without codecvt (deprecated in C++17)
        std::string nameStr;
        nameStr.reserve(m_name.size());
        for (wchar_t wc : m_name)
        {
            if (wc <= 127)
            { // Only convert ASCII characters
                nameStr.push_back(static_cast<char>(wc));
            }
            else
            {
                nameStr.push_back('?'); // Replace non-ASCII with '?'
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
        // Simplified hash calculation
        std::hash<std::string> hasher;
        std::string data = std::to_string(m_baseAddress) + std::to_string(m_size);
        m_hash = std::to_string(hasher(data));
    }

    std::string ModuleInfo::GetModuleVersion() const
    {
        // Would implement proper version info extraction
        return "1.0.0.0";
    }

    // ===== ScannerFactory Implementation =====

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

        // Would implement module-specific scanner
        std::filesystem::path cacheFile;
        if (enableCaching)
        {
            // Convert wide string to narrow string for file path
            std::string moduleNameStr;
            moduleNameStr.reserve(moduleName.size());
            for (wchar_t wc : moduleName)
            {
                if (wc <= 127)
                { // Only convert ASCII characters
                    moduleNameStr.push_back(static_cast<char>(wc));
                }
                else
                {
                    moduleNameStr.push_back('_'); // Replace non-ASCII with '_'
                }
            }
            cacheFile = "cache/" + moduleNameStr + "_cache.json";
        }

        return std::make_shared<EnhancedPatternScanner>(enableCaching, cacheFile);
    }

} // namespace SapphireHook

// Legacy C-style function implementations
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
        // Implementation would use Windows API to get module info
        // Placeholder implementation
        outSize = 0x10000000; // 256MB
        return 0x140000000;   // Typical base address
    }
}