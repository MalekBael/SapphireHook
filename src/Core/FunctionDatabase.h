#pragma once
#include <string>
#include <map>
#include <vector>
#include <filesystem>
#include <chrono>
#include <optional>

namespace SapphireHook {

    struct FunctionInfo {
        std::string name;
        std::string description;
        std::string category;
        uintptr_t address = 0;

        std::string gameVersion;                   
        std::chrono::system_clock::time_point resolvedTime;      
        bool fromCache = false;                 
        std::string originalSignature;         

        FunctionInfo() = default;
        FunctionInfo(const std::string& n, const std::string& d, const std::string& c)
            : name(n), description(d), category(c)
        {
        }
    };

    struct CacheEntry {
        std::string gameVersion;
        uintptr_t moduleBase;
        size_t moduleSize;
        std::string moduleHash;      
        std::map<std::string, uintptr_t> resolvedAddresses;
        std::chrono::system_clock::time_point cacheTime;
    };

    class FunctionDatabase {
    private:
        std::map<uintptr_t, FunctionInfo> m_functions;
        std::map<std::string, std::string> m_categories;
        std::string m_databasePath;
        uintptr_t m_runtimeBaseAddress = 0;
        uintptr_t m_idaBaseAddress = 0x7FF749030000;       

        std::filesystem::path m_cacheDirectory;
        std::string m_currentGameVersion;
        std::optional<CacheEntry> m_loadedCache;

        mutable std::map<std::string, std::chrono::milliseconds> m_performanceMetrics;



        std::string Trim(const std::string& str);
        uintptr_t ParseAddress(const std::string& addrStr);

        bool LoadJsonFile(const std::string& filepath);
        bool SaveJsonFile(const std::string& filepath);

        std::string DetermineCategory(const std::string& functionName);

        bool InitializeRuntimeBase();
        uintptr_t RvaToRuntimeAddress(uintptr_t rva) const;



    public:
        FunctionDatabase();
        ~FunctionDatabase() = default;

        bool Load(const std::string& filepath = "data-rva.yml");
        bool Save(const std::string& filepath = "");

        void AddFunction(uintptr_t address, const std::string& name,
            const std::string& description = "", const std::string& category = "Unknown");
        bool HasFunction(uintptr_t address) const;

        FunctionInfo GetFunction(uintptr_t address) const;
        std::string GetFunctionName(uintptr_t address) const;

        std::map<uintptr_t, FunctionInfo> GetAllFunctions() const;
        const std::map<std::string, std::string>& GetCategories() const { return m_categories; }

        size_t GetFunctionCount() const { return m_functions.size(); }
        size_t GetCategoryCount() const { return m_categories.size(); }
        std::vector<std::string> GetFunctionsByCategory(const std::string& category) const;

        uintptr_t GetRuntimeBaseAddress() const { return m_runtimeBaseAddress; }
        uintptr_t GetIdaBaseAddress() const { return m_idaBaseAddress; }


    };

}   