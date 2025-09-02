#pragma once
#include <string>
#include <map>
#include <vector>
#include <filesystem>
#include <chrono>
#include <optional>

namespace SapphireHook {

    // Inspired by Dalamud's signature caching approach
    struct FunctionInfo {
        std::string name;
        std::string description;
        std::string category;
        uintptr_t address = 0;

        // NEW: Add caching metadata inspired by Dalamud
        std::string gameVersion;           // Track which game version this was resolved for
        std::chrono::system_clock::time_point resolvedTime;  // When it was resolved
        bool fromCache = false;            // Whether this came from cache
        std::string originalSignature;    // Original pattern that found this

        FunctionInfo() = default;
        FunctionInfo(const std::string& n, const std::string& d, const std::string& c)
            : name(n), description(d), category(c)
        {
        }
    };

    // NEW: Cache management inspired by Dalamud's TargetSigScanner approach
    struct CacheEntry {
        std::string gameVersion;
        uintptr_t moduleBase;
        size_t moduleSize;
        std::string moduleHash;  // SHA1 of game executable
        std::map<std::string, uintptr_t> resolvedAddresses;
        std::chrono::system_clock::time_point cacheTime;
    };

    class FunctionDatabase {
    private:
        std::map<uintptr_t, FunctionInfo> m_functions;
        std::map<std::string, std::string> m_categories;
        std::string m_databasePath;
        uintptr_t m_runtimeBaseAddress = 0;
        uintptr_t m_idaBaseAddress = 0x7FF749030000; // IDA static base from your script

        // NEW: Caching system inspired by Dalamud
        std::filesystem::path m_cacheDirectory;
        std::string m_currentGameVersion;
        std::optional<CacheEntry> m_loadedCache;

        // NEW: Performance tracking inspired by Dalamud's timing system
        mutable std::map<std::string, std::chrono::milliseconds> m_performanceMetrics;

        // Simple YAML parsing functions
        std::string Trim(const std::string& str);
        std::pair<std::string, std::string> ParseKeyValue(const std::string& line);
        uintptr_t ParseAddress(const std::string& addrStr);
        bool LoadYamlFile(const std::string& filepath);
        bool SaveYamlFile(const std::string& filepath);

        // JSON parsing functions
        bool LoadJsonFile(const std::string& filepath);
        bool SaveJsonFile(const std::string& filepath);

        // Function categorization
        std::string DetermineCategory(const std::string& functionName);

        // Address conversion functions
        bool InitializeRuntimeBase();
        uintptr_t RvaToRuntimeAddress(uintptr_t rva) const;

        // NEW: Cache management inspired by Dalamud
        bool LoadCache();
        bool SaveCache() const;
        bool IsCacheValid() const;
        std::string CalculateModuleHash() const;
        std::string GetGameVersion() const;

        // NEW: Performance monitoring inspired by Dalamud's timing system
        void StartTiming(const std::string& operation) const;
        void EndTiming(const std::string& operation) const;

    public:
        FunctionDatabase();
        ~FunctionDatabase() = default;

        // Database operations
        bool Load(const std::string& filepath = "data-rva.yml");
        bool Save(const std::string& filepath = "");

        // NEW: Cache operations inspired by Dalamud
        void SetCacheDirectory(const std::filesystem::path& cacheDir);
        bool LoadFromCache();
        bool SaveToCache() const;
        void InvalidateCache();

        // Function management
        void AddFunction(uintptr_t address, const std::string& name,
            const std::string& description = "", const std::string& category = "Unknown");
        void RemoveFunction(uintptr_t address);
        bool HasFunction(uintptr_t address) const;

        // Function retrieval
        FunctionInfo GetFunction(uintptr_t address) const;
        std::string GetFunctionName(uintptr_t address) const;
        std::string GetFunctionDescription(uintptr_t address) const;
        std::string GetFunctionCategory(uintptr_t address) const;
        std::string GetSimpleFunctionName(uintptr_t address) const;

        // Get all functions and categories
        std::map<uintptr_t, FunctionInfo> GetAllFunctions() const;
        std::map<std::string, std::string> GetAllCategories() const;

        // Category management
        void AddCategory(const std::string& name, const std::string& description);
        const std::map<std::string, std::string>& GetCategories() const { return m_categories; }

        // Statistics
        size_t GetFunctionCount() const { return m_functions.size(); }
        size_t GetCategoryCount() const { return m_categories.size(); }
        std::vector<std::string> GetFunctionsByCategory(const std::string& category) const;

        // Address information
        uintptr_t GetRuntimeBaseAddress() const { return m_runtimeBaseAddress; }
        uintptr_t GetIdaBaseAddress() const { return m_idaBaseAddress; }

        // NEW: Performance metrics inspired by Dalamud
        std::map<std::string, std::chrono::milliseconds> GetPerformanceMetrics() const;
        void ResetPerformanceMetrics();

        // NEW: Version tracking inspired by Dalamud
        std::string GetCachedGameVersion() const;
        bool IsVersionCompatible(const std::string& version) const;
    };

} // namespace SapphireHook