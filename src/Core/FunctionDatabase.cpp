#include "FunctionDatabase.h"
#include "SimpleJSON.h"
#include "../Logger/Logger.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <Psapi.h>
#include <regex>
#include <string>
#include <map>
#include <vector>
#include <cctype>

using namespace SapphireHook;
#include "../Hooking/hook_factory_impl.h"

static std::string FormatHexAddress(uintptr_t address)
{
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << address;
    return ss.str();
}

// --- Heuristic JSON helpers (declared before use) ---

// Helper: parse hex (with/without 0x) or decimal
static uint64_t ParseUintFlexible(const std::string& s)
{
    std::string t = s;
    t.erase(0, t.find_first_not_of(" \t\r\n"));
    t.erase(t.find_last_not_of(" \t\r\n") + 1);
    if (t.empty()) return 0;

    auto hasHexAlpha = std::find_if(t.begin(), t.end(), [](unsigned char c)
        {
            c = static_cast<unsigned char>(std::toupper(c));
            return (c >= 'A' && c <= 'F');
        }) != t.end();

    try
    {
        if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0 || hasHexAlpha)
        {
            std::string hex = (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) ? t.substr(2) : t;
            return std::stoull(hex, nullptr, 16);
        }
        else
        {
            return std::stoull(t, nullptr, 10);
        }
    }
    catch (...)
    {
        return 0;
    }
}

// Heuristic extractor entry type
struct FuncEntry {
    std::string name;
    std::string sheetName;
    std::string signature;
    std::string category;
    uint64_t address = 0; // absolute
    uint64_t rva = 0;     // relative virtual address
};

// Extractor declaration (implementation at bottom of file)
static std::vector<FuncEntry> ExtractFunctionsFromJSONContent(const std::string& content);

FunctionDatabase::FunctionDatabase()
{
    InitializeRuntimeBase();
}

bool FunctionDatabase::InitializeRuntimeBase()
{
    size_t moduleSize;
    if (GetMainModuleInfo(m_runtimeBaseAddress, moduleSize))
    {
        LogInfo("Runtime base address: " + FormatHexAddress(m_runtimeBaseAddress));
        return true;
    }
    else
    {
        LogError("Failed to get main module info");
        return false;
    }
}

uintptr_t FunctionDatabase::RvaToRuntimeAddress(uintptr_t rva) const
{
    if (m_runtimeBaseAddress == 0)
    {
        LogError("Runtime base address not initialized");
        return 0;
    }
    return m_runtimeBaseAddress + rva;
}

uintptr_t FunctionDatabase::ParseAddress(const std::string& addrStr)
{
    try
    {
        std::string cleanAddr = addrStr;
        if (cleanAddr.find("0x") == 0 || cleanAddr.find("0X") == 0)
        {
            cleanAddr = cleanAddr.substr(2);
        }

        return std::stoull(cleanAddr, nullptr, 16);
    }
    catch (...)
    {
        LogError("Failed to parse address: " + addrStr);
        return 0;
    }
}

std::string FunctionDatabase::DetermineCategory(const std::string& functionName)
{
    if (functionName.find("::ExdData::") != std::string::npos)
        return "ExdData";
    else if (functionName.find("Concurrency::") != std::string::npos)
        return "Concurrency";
    else if (functionName.find("Client::") != std::string::npos ||
        functionName.find("au_re_Client::") != std::string::npos ||
        functionName.find("j_au_re_Client::") != std::string::npos)
        return "Client";
    else if (functionName.find("Movement") != std::string::npos ||
        functionName.find("move") != std::string::npos)
        return "Movement";
    else if (functionName.find("Camera") != std::string::npos ||
        functionName.find("camera") != std::string::npos)
        return "Camera";
    else if (functionName.find("Combat") != std::string::npos ||
        functionName.find("action") != std::string::npos)
        return "Combat";
    else if (functionName.find("UI") != std::string::npos ||
        functionName.find("ui") != std::string::npos)
        return "UI";
    else if (functionName.find("Network") != std::string::npos ||
        functionName.find("network") != std::string::npos)
        return "Network";
    else if (functionName.find("au_re_") == 0)
        return "Runtime";
    else if (functionName.find("std::") == 0)
        return "STL";
    else if (functionName.find("sub_") == 0)
        return "Unknown";
    else
        return "System";
}

bool FunctionDatabase::Load(const std::string& filepath)
{
    m_databasePath = filepath;

    std::string extension = filepath.substr(filepath.find_last_of('.'));
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    if (extension == ".json")
    {
        return LoadJsonFile(filepath);
    }
    else if (extension == ".yml" || extension == ".yaml")
    {
        return LoadYamlFile(filepath);
    }
    else
    {
        if (LoadJsonFile(filepath))
            return true;
        return LoadYamlFile(filepath);
    }
}

bool FunctionDatabase::LoadJsonFile(const std::string& filepath)
{
    // Convert to absolute path for better debugging
    std::filesystem::path absolutePath = std::filesystem::absolute(filepath);
    
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        LogError("Could not open JSON file: " + absolutePath.string());
        return false;
    }

    // Clear existing data before loading new data
    m_functions.clear();

    // Read entire file
    std::string content((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    file.close();

    if (content.empty())
    {
        LogError("JSON file is empty: " + absolutePath.string());
        return false;
    }

    LogInfo("Loading function database from JSON: " + absolutePath.string());

    try
    {
        // Parse JSON using namespace qualification
        SapphireHook::SimpleJSON::JSONObject jsonData = SapphireHook::SimpleJSON::Parse(content);
        int functionsLoaded = 0;

        // Load categories section - direct access to avoid GetObject
        if (jsonData.HasKey("categories"))
        {
            auto& categoriesVariant = jsonData.data["categories"];
            if (std::holds_alternative<std::map<std::string, std::string>>(categoriesVariant))
            {
                const std::map<std::string, std::string>& categoriesData =
                    std::get<std::map<std::string, std::string>>(categoriesVariant);

                for (const auto& categoryPair : categoriesData)
                {
                    m_categories[categoryPair.first] = categoryPair.second;
                }
            }
        }

        // Determine if we have structured format (with "functions" key) or flat format
        bool isStructuredFormat = jsonData.HasKey("functions");

        if (isStructuredFormat)
        {
            // Handle structured format: { "functions": { "0x123": "func1", ... }, "categories": {...} }
            auto& functionsVariant = jsonData.data["functions"];
            if (std::holds_alternative<std::map<std::string, std::string>>(functionsVariant))
            {
                const std::map<std::string, std::string>& functionsData =
                    std::get<std::map<std::string, std::string>>(functionsVariant);

                bool isRvaFile = (filepath.find("rva") != std::string::npos ||
                    filepath.find("updated") != std::string::npos);

                for (const auto& functionPair : functionsData)
                {
                    std::string addrStr = functionPair.first;
                    std::string functionName = functionPair.second;

                    if (!addrStr.empty() && !functionName.empty())
                    {
                        uintptr_t addressOrRva = ParseAddress(addrStr);
                        if (addressOrRva != 0)
                        {
                            uintptr_t runtimeAddress;

                            if (isRvaFile)
                            {
                                runtimeAddress = RvaToRuntimeAddress(addressOrRva);
                                if (functionsLoaded < 5)
                                {
                                    LogDebug("RVA " + FormatHexAddress(addressOrRva) + " -> Runtime " +
                                        FormatHexAddress(runtimeAddress) + " (" + functionName + ")");
                                }
                            }
                            else
                            {
                                runtimeAddress = addressOrRva;
                            }

                            // Categorize function
                            std::string category = DetermineCategory(functionName);

                            FunctionInfo info;
                            info.name = functionName;
                            info.description = "";
                            info.category = category;
                            info.address = runtimeAddress;

                            m_functions[runtimeAddress] = info;
                            functionsLoaded++;
                        }
                    }
                }
            }
        }
        else
        {
            // Handle flat format: { "0x123": "func1", "0x456": "func2", ... }
            LogInfo("Detected flat JSON format (no 'functions' key)");

            bool isRvaFile = (filepath.find("rva") != std::string::npos ||
                filepath.find("updated") != std::string::npos);

            // Iterate through all root-level key-value pairs
            for (const auto& pair : jsonData.data)
            {
                const std::string& key = pair.first;
                const auto& value = pair.second;

                // Check if this looks like an address (starts with 0x and has hex characters)
                if (key.rfind("0x", 0) == 0 || key.rfind("0X", 0) == 0)
                {
                    // Check if value is a string (function name)
                    if (std::holds_alternative<std::string>(value))
                    {
                        std::string functionName = std::get<std::string>(value);

                        if (!functionName.empty())
                        {
                            uintptr_t addressOrRva = ParseAddress(key);
                            if (addressOrRva != 0)
                            {
                                uintptr_t runtimeAddress;

                                if (isRvaFile)
                                {
                                    runtimeAddress = RvaToRuntimeAddress(addressOrRva);
                                    if (functionsLoaded < 5)
                                    {
                                        LogDebug("RVA " + FormatHexAddress(addressOrRva) + " -> Runtime " +
                                            FormatHexAddress(runtimeAddress) + " (" + functionName + ")");
                                    }
                                }
                                else
                                {
                                    runtimeAddress = addressOrRva;
                                }

                                // Categorize function
                                std::string category = DetermineCategory(functionName);

                                FunctionInfo info;
                                info.name = functionName;
                                info.description = "";
                                info.category = category;
                                info.address = runtimeAddress;

                                m_functions[runtimeAddress] = info;
                                functionsLoaded++;

                                // Log first few functions for debugging
                                if (functionsLoaded <= 5)
                                {
                                    LogDebug("Loaded function: " + FormatHexAddress(runtimeAddress) + " -> " +
                                        functionName + " [" + category + "]");
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fallback: if nothing loaded via SimpleJSON paths, heuristically parse nested objects
        if (functionsLoaded == 0)
        {
            auto entries = ExtractFunctionsFromJSONContent(content);
            int added = 0;

            const bool isRvaFile = (filepath.find("rva") != std::string::npos ||
                filepath.find("updated") != std::string::npos);

            for (const auto& e : entries)
            {
                uint64_t runtimeAddress = 0;

                if (e.address != 0)
                {
                    runtimeAddress = e.address;
                }
                else if (e.rva != 0)
                {
                    runtimeAddress = RvaToRuntimeAddress(static_cast<uintptr_t>(e.rva));
                    if (added < 5)
                    {
                        LogDebug("RVA " + FormatHexAddress(static_cast<uintptr_t>(e.rva)) +
                            " -> Runtime " + FormatHexAddress(static_cast<uintptr_t>(runtimeAddress)) +
                            " (" + e.name + ")");
                    }
                }
                else if (isRvaFile)
                {
                    continue;
                }
                else
                {
                    continue;
                }

                // Categorize
                std::string category = !e.category.empty() ? e.category : DetermineCategory(e.name);

                // Insert
                FunctionInfo info;
                info.name = e.name;
                info.description = "";
                info.category = category;
                info.address = static_cast<uintptr_t>(runtimeAddress);
                m_functions[info.address] = info;

                // Log first few
                if (++added <= 5)
                {
                    LogDebug("Loaded function (heuristic): " + FormatHexAddress(info.address) +
                        " -> " + info.name + " [" + info.category + "]");
                }
            }

            functionsLoaded = added;
        }

        LogInfo("Successfully loaded " + std::to_string(functionsLoaded) + " functions and " +
            std::to_string(m_categories.size()) + " categories from JSON");

        return functionsLoaded > 0;
    }
    catch (const std::exception& ex)
    {
        LogError("Exception while parsing JSON: " + std::string(ex.what()));
        return false;
    }
}

bool FunctionDatabase::SaveJsonFile(const std::string& filepath)
{
    try
    {
        SimpleJSON::JSONObject jsonData;

        std::map<std::string, std::string> categoriesMap;
        for (const auto& cat : m_categories)
        {
            categoriesMap[cat.first] = cat.second;
        }
        jsonData.data["categories"] = categoriesMap;

        std::map<std::string, std::string> functionsMap;
        for (const auto& func : m_functions)
        {
            std::string addrStr = FormatHexAddress(func.first);
            functionsMap[addrStr] = func.second.name;
        }
        jsonData.data["functions"] = functionsMap;

        std::string jsonString = SimpleJSON::Generate(jsonData);

        std::ofstream file(filepath);
        if (!file.is_open())
        {
            LogError("Failed to open JSON file for writing: " + filepath);
            return false;
        }

        file << jsonString;
        file.close();

        LogInfo("Saved " + std::to_string(m_functions.size()) + " functions to JSON: " + filepath);
        return true;
    }
    catch (const std::exception& ex)
    {
        LogError("Exception while saving JSON: " + std::string(ex.what()));
        return false;
    }
}

bool FunctionDatabase::LoadYamlFile(const std::string& filepath)
{
    LogError("YAML loading not yet implemented for: " + filepath);
    return false;
}

bool FunctionDatabase::SaveYamlFile(const std::string& filepath)
{
    LogError("YAML saving not yet implemented for: " + filepath);
    return false;
}

std::string FunctionDatabase::Trim(const std::string& str)
{
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::pair<std::string, std::string> FunctionDatabase::ParseKeyValue(const std::string& line)
{
    size_t colonPos = line.find(':');
    if (colonPos == std::string::npos)
        return { "", "" };

    std::string key = Trim(line.substr(0, colonPos));
    std::string value = Trim(line.substr(colonPos + 1));
    return { key, value };
}

void FunctionDatabase::AddFunction(uintptr_t address, const std::string& name,
    const std::string& description, const std::string& category)
{
    FunctionInfo info;
    info.name = name;
    info.description = description;
    info.category = category;
    info.address = address;

    m_functions[address] = info;
}

void FunctionDatabase::RemoveFunction(uintptr_t address)
{
    m_functions.erase(address);
}

bool FunctionDatabase::HasFunction(uintptr_t address) const
{
    return m_functions.find(address) != m_functions.end();
}

FunctionInfo FunctionDatabase::GetFunction(uintptr_t address) const
{
    auto it = m_functions.find(address);
    if (it != m_functions.end())
        return it->second;
    return FunctionInfo();
}

std::string FunctionDatabase::GetFunctionName(uintptr_t address) const
{
    auto it = m_functions.find(address);
    if (it != m_functions.end())
        return it->second.name;
    return "";
}

std::string FunctionDatabase::GetFunctionDescription(uintptr_t address) const
{
    auto it = m_functions.find(address);
    if (it != m_functions.end())
        return it->second.description;
    return "";
}

std::string FunctionDatabase::GetFunctionCategory(uintptr_t address) const
{
    auto it = m_functions.find(address);
    if (it != m_functions.end())
        return it->second.category;
    return "Unknown";
}

std::string FunctionDatabase::GetSimpleFunctionName(uintptr_t address) const
{
    std::string name = GetFunctionName(address);
    if (name.empty()) return FormatHexAddress(address);

    size_t pos = name.rfind("::");
    if (pos != std::string::npos) return name.substr(pos + 2);

    pos = name.find_last_of(':');
    if (pos != std::string::npos) return name.substr(pos + 1);

    return name;
}

std::map<uintptr_t, FunctionInfo> FunctionDatabase::GetAllFunctions() const
{
    return m_functions;
}

std::map<std::string, std::string> FunctionDatabase::GetAllCategories() const
{
    return m_categories;
}

void FunctionDatabase::AddCategory(const std::string& name, const std::string& description)
{
    m_categories[name] = description;
}

std::vector<std::string> FunctionDatabase::GetFunctionsByCategory(const std::string& category) const
{
    std::vector<std::string> result;
    for (const auto& func : m_functions)
    {
        if (func.second.category == category)
            result.push_back(func.second.name);
    }
    return result;
}

bool FunctionDatabase::LoadCache() { return false; }
bool FunctionDatabase::SaveCache() const { return false; }
bool FunctionDatabase::IsCacheValid() const { return false; }
std::string FunctionDatabase::CalculateModuleHash() const { return ""; }
std::string FunctionDatabase::GetGameVersion() const { return ""; }
void FunctionDatabase::StartTiming(const std::string& operation) const {}
void FunctionDatabase::EndTiming(const std::string& operation) const {}
void FunctionDatabase::SetCacheDirectory(const std::filesystem::path& cacheDir) {}
bool FunctionDatabase::LoadFromCache() { return false; }
bool FunctionDatabase::SaveToCache() const { return false; }
void FunctionDatabase::InvalidateCache() {}
std::map<std::string, std::chrono::milliseconds> FunctionDatabase::GetPerformanceMetrics() const { return {}; }
void FunctionDatabase::ResetPerformanceMetrics() {}
std::string FunctionDatabase::GetCachedGameVersion() const { return ""; }
bool FunctionDatabase::IsVersionCompatible(const std::string& version) const { return true; }
bool FunctionDatabase::Save(const std::string& filepath)
{
    if (filepath.empty())
        return SaveJsonFile(m_databasePath);
    else
        return SaveJsonFile(filepath);
}

// --- Heuristic JSON extractor implementation (single definition) ---
static std::vector<FuncEntry> ExtractFunctionsFromJSONContent(const std::string& content)
{
    std::vector<FuncEntry> result;

    auto beginOf = [&](const char* key) -> size_t
        {
            size_t pos = content.find(key);
            if (pos == std::string::npos) return 0;
            size_t brace = content.find('{', pos);
            return (brace != std::string::npos) ? brace : 0;
        };

    // Use "functions" block if it exists, else whole document
    size_t start = beginOf("\"functions\"");
    auto beginIt = content.begin() + static_cast<std::ptrdiff_t>(start);

    // Capture "name": { ...object... }
    std::regex entryRe("\"([^\"]+)\"\\s*:\\s*\\{([\\s\\S]*?)\\}");

    auto firstMatch = [](const std::string& s, const std::regex& re) -> std::string
        {
            std::smatch m;
            if (std::regex_search(s, m, re) && m.size() >= 2) return m[1].str();
            return {};
        };

    for (auto it = std::sregex_iterator(beginIt, content.end(), entryRe), end = std::sregex_iterator();
        it != end; ++it)
    {
        FuncEntry e;
        e.name = (*it)[1].str();
        const std::string body = (*it)[2].str();

        // Must have a signature-like field
        e.signature = firstMatch(body, std::regex("\"(?:signature|pattern|aob)\"\\s*:\\s*\"([^\"]+)\""));
        if (e.signature.empty()) continue;

        e.sheetName = firstMatch(body, std::regex("\"sheet_name\"\\s*:\\s*\"([^\"]+)\""));
        e.category = firstMatch(body, std::regex("\"category\"\\s*:\\s*\"([^\"]+)\""));

        // address/rva (string or number)
        std::string addrStr = firstMatch(body, std::regex("\"address\"\\s*:\\s*\"([^\"]+)\""));
        std::string rvaStr = firstMatch(body, std::regex("\"rva(?:_hex)?\"\\s*:\\s*\"([^\"]+)\""));
        if (!addrStr.empty()) e.address = ParseUintFlexible(addrStr);
        if (!rvaStr.empty())  e.rva = ParseUintFlexible(rvaStr);

        std::string addrNum = firstMatch(body, std::regex("\"address\"\\s*:\\s*(\\d+)"));
        std::string rvaNum = firstMatch(body, std::regex("\"rva\"\\s*:\\s*(\\d+)"));
        if (!addrNum.empty() && e.address == 0) e.address = ParseUintFlexible(addrNum);
        if (!rvaNum.empty() && e.rva == 0) e.rva = ParseUintFlexible(rvaNum);

        if (!e.name.empty())
            result.emplace_back(std::move(e));
    }

    LogDebug("Heuristic JSON function extract: " + std::to_string(result.size()) + " entries");
    return result;
}

/* AUTO-INSERTED TYPE SIGNATURE DUMP (REMOVE IF RE-APPEARS)
   If a tool re-injects the “SIGNATURES OF REFERENCED TYPES” block, ensure it is
   wrapped in a comment like this or deleted; it is NOT valid C++ and will break
   IntelliSense / compilation.
*/