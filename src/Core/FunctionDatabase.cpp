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

static std::string FormatHexAddress(uintptr_t address) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(address));
    return std::string(buf);
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

bool FunctionDatabase::Load(const std::string& filename)
{
    // Just use the existing LoadJsonFile function which already works
    return LoadJsonFile(filename);
}

bool FunctionDatabase::LoadJsonFile(const std::string& filepath)
{
    std::filesystem::path absolutePath = std::filesystem::absolute(filepath);
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        LogError("Could not open JSON file: " + absolutePath.string());
        return false;
    }

    m_functions.clear();
    m_categories.clear();

    std::string content((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    file.close();

    if (content.empty())
    {
        LogError("JSON file is empty: " + absolutePath.string());
        return false;
    }

    LogInfo("Loading function database from JSON: " + absolutePath.string());

    int functionsLoaded = 0;

    // Try SimpleJSON first for the common cases
    SapphireHook::SimpleJSON::JSONObject jsonRoot;
    bool parsed = false;
    try {
        jsonRoot = SapphireHook::SimpleJSON::Parse(content);
        parsed = true;
    }
    catch (const std::exception& ex) {
        LogWarning(std::string("SimpleJSON parse failed, will try regex fallback: ") + ex.what());
    }

    auto toRuntime = [&](uintptr_t addrOrRva)->uintptr_t {
        // Treat small values as RVAs automatically; keep file-name based hint too
        const bool nameHintsRva = (filepath.find("rva") != std::string::npos) ||
            (filepath.find("updated") != std::string::npos);
        const bool looksLikeRva = (addrOrRva < 0x0100'0000ULL); // <16MB heuristic
        if ((nameHintsRva || looksLikeRva) && m_runtimeBaseAddress != 0)
            return RvaToRuntimeAddress(addrOrRva);
        return addrOrRva;
        };

    // 1) Structured simple format: { "functions": { "0xADDR": "Name", ... }, "categories": {...} }
    if (parsed && jsonRoot.HasKey("functions"))
    {
        auto& fv = jsonRoot.data["functions"];
        if (std::holds_alternative<std::map<std::string, std::string>>(fv))
        {
            const auto& fnMap = std::get<std::map<std::string, std::string>>(fv);
            for (const auto& [addrStr, funcName] : fnMap)
            {
                if (funcName.empty()) continue;
                uintptr_t addrOrRva = ParseAddress(addrStr);
                if (addrOrRva == 0) continue;

                uintptr_t runtime = toRuntime(addrOrRva);

                FunctionInfo info;
                info.name = funcName;
                info.category = DetermineCategory(funcName);
                info.description = "";
                info.address = runtime;

                m_functions[runtime] = info;
                ++functionsLoaded;

                if (functionsLoaded <= 5)
                    LogDebug("Loaded (map) " + FormatHexAddress(runtime) + " -> " + info.name + " [" + info.category + "]");
            }
        }

        // Categories via SimpleJSON if present
        if (jsonRoot.HasKey("categories"))
        {
            auto& cv = jsonRoot.data["categories"];
            if (std::holds_alternative<std::map<std::string, std::string>>(cv))
            {
                const auto& cats = std::get<std::map<std::string, std::string>>(cv);
                for (const auto& [catName, catDesc] : cats)
                    m_categories[catName] = catDesc;
            }
        }

        if (functionsLoaded > 0)
        {
            LogInfo("Successfully loaded " + std::to_string(functionsLoaded) + " functions and " +
                std::to_string(m_categories.size()) + " categories from JSON (map format)");
            return true;
        }
        // If we got here with 0, fall through to nested-object handling below.
    }

    // 2) Structured nested-object format fallback (manual parse, robust brace/quote aware)
    if (content.find("\"functions\"") != std::string::npos)
    {
        LogInfo("Detected structured JSON format with 'functions' key");
        // Find functions object bounds
        size_t keyPos = content.find("\"functions\"");
        size_t colonPos = (keyPos == std::string::npos) ? std::string::npos : content.find(':', keyPos);
        size_t braceStart = (colonPos == std::string::npos) ? std::string::npos : content.find('{', colonPos);
        if (braceStart != std::string::npos)
        {
            int depth = 1; bool inQuotes = false;
            size_t pos = braceStart + 1, braceEnd = std::string::npos;
            while (pos < content.size() && depth > 0)
            {
                char ch = content[pos];
                if (ch == '"' && (pos == 0 || content[pos - 1] != '\\')) inQuotes = !inQuotes;
                else if (!inQuotes)
                {
                    if (ch == '{') ++depth;
                    else if (ch == '}')
                    {
                        --depth;
                        if (depth == 0) { braceEnd = pos; break; }
                    }
                }
                ++pos;
            }

            if (braceEnd != std::string::npos)
            {
                const std::string section = content.substr(braceStart + 1, braceEnd - braceStart - 1);

                // Walk each entry: "0x...": { ... }  OR  "0x...": "Name"
                size_t searchPos = 0;
                while (true)
                {
                    size_t addrStart = section.find("\"0x", searchPos);
                    if (addrStart == std::string::npos) break;
                    size_t addrEnd = section.find('"', addrStart + 1);
                    if (addrEnd == std::string::npos) break;

                    std::string addrStr = section.substr(addrStart + 1, addrEnd - addrStart - 1);

                    size_t colonAfterAddr = section.find(':', addrEnd);
                    if (colonAfterAddr == std::string::npos) { searchPos = addrEnd + 1; continue; }

                    // Skip whitespace after colon
                    size_t valStart = section.find_first_not_of(" \t\r\n", colonAfterAddr + 1);
                    if (valStart == std::string::npos) { searchPos = addrEnd + 1; continue; }

                    uintptr_t addrOrRva = ParseAddress(addrStr);
                    if (addrOrRva == 0) { searchPos = addrEnd + 1; continue; }

                    // Case A: value is a JSON string => "0x...": "FunctionName"
                    if (section[valStart] == '"')
                    {
                        // Parse string with escape handling
                        size_t p = valStart + 1;
                        std::string funcName;
                        while (p < section.size())
                        {
                            char ch = section[p];
                            if (ch == '"' && section[p - 1] != '\\')
                            {
                                break;
                            }
                            funcName.push_back(ch);
                            ++p;
                        }

                        if (!funcName.empty())
                        {
                            FunctionInfo info;
                            info.name = funcName;
                            info.category = DetermineCategory(funcName);
                            uintptr_t runtime = toRuntime(addrOrRva);
                            info.address = runtime;

                            m_functions[runtime] = info;
                            ++functionsLoaded;

                            if (functionsLoaded <= 5)
                                LogDebug("Loaded (map-fallback) " + FormatHexAddress(runtime) + " -> " + info.name + " [" + info.category + "]");
                        }

                        // Advance past the parsed string value
                        searchPos = (p < section.size()) ? (p + 1) : (addrEnd + 1);
                        continue;
                    }

                    // Case B: value is an object => "0x...": { ... }
                    size_t objStart = (section[valStart] == '{') ? valStart : std::string::npos;
                    if (objStart == std::string::npos) { searchPos = addrEnd + 1; continue; }

                    // Find matching close for this object
                    int d = 1; bool q = false;
                    size_t p = objStart + 1, objEnd = std::string::npos;
                    while (p < section.size() && d > 0)
                    {
                        char ch = section[p];
                        if (ch == '"' && (p == 0 || section[p - 1] != '\\')) q = !q;
                        else if (!q)
                        {
                            if (ch == '{') ++d;
                            else if (ch == '}')
                            {
                                --d;
                                if (d == 0) { objEnd = p; break; }
                            }
                        }
                        ++p;
                    }
                    if (objEnd == std::string::npos) { searchPos = addrEnd + 1; continue; }

                    std::string obj = section.substr(objStart + 1, objEnd - objStart - 1);

                    {
                        FunctionInfo info;
                        std::smatch m;

                        if (std::regex_search(obj, m, std::regex("\"name\"\\s*:\\s*\"([^\"]+)\"")))
                            info.name = m[1].str();
                        if (std::regex_search(obj, m, std::regex("\"category\"\\s*:\\s*\"([^\"]+)\"")))
                            info.category = m[1].str();
                        if (std::regex_search(obj, m, std::regex("\"description\"\\s*:\\s*\"([^\"]+)\"")))
                            info.description = m[1].str();

                        if (!info.name.empty())
                        {
                            uintptr_t runtime = toRuntime(addrOrRva);
                            info.address = runtime;
                            if (info.category.empty())
                                info.category = DetermineCategory(info.name);

                            m_functions[runtime] = info;
                            ++functionsLoaded;

                            if (functionsLoaded <= 5)
                                LogDebug("Loaded (obj) " + FormatHexAddress(runtime) + " -> " + info.name + " [" + info.category + "]");
                        }
                    }

                    searchPos = objEnd + 1;
                }
            }
        }

        // Categories via SimpleJSON if we have it
        if (parsed && jsonRoot.HasKey("categories"))
        {
            auto& cv = jsonRoot.data["categories"];
            if (std::holds_alternative<std::map<std::string, std::string>>(cv))
            {
                const auto& cats = std::get<std::map<std::string, std::string>>(cv);
                for (const auto& [catName, catDesc] : cats)
                    m_categories[catName] = catDesc;
            }
        }
        else
        {
            // Regex fallback for categories
            std::smatch catMatch;
            if (std::regex_search(content, catMatch, std::regex("\"categories\"\\s*:\\s*\\{([^{}]*)\\}")))
            {
                std::string catContent = catMatch[1].str();

                // Keep the regex object alive for the iterator's lifetime
                const std::regex catPairRe(R"CAT("([^"]+)"\s*:\s*"([^"]+)")CAT");

                for (std::sregex_iterator it(catContent.begin(), catContent.end(), catPairRe), end;
                    it != end; ++it)
                {
                    m_categories[(*it)[1].str()] = (*it)[2].str();
                }
            }
        }

        LogInfo("Successfully loaded " + std::to_string(functionsLoaded) + " functions and " +
            std::to_string(m_categories.size()) + " categories from JSON");
        return functionsLoaded > 0;
    }

    // Fallback: no functions loaded from any format
    LogWarning("No functions loaded from JSON file: " + filepath);
    return false;
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



std::string FunctionDatabase::Trim(const std::string& str)
{
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
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



std::map<uintptr_t, FunctionInfo> FunctionDatabase::GetAllFunctions() const
{
    return m_functions;
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


bool FunctionDatabase::Save(const std::string& filepath)
{
    if (filepath.empty())
        return SaveJsonFile(m_databasePath);
    else
        return SaveJsonFile(filepath);
}



/* AUTO-INSERTED TYPE SIGNATURE DUMP (REMOVE IF RE-APPEARS)
   If a tool re-injects the "SIGNATURES OF REFERENCED TYPES" block, ensure it is
   wrapped in a comment like this or deleted; it is NOT valid C++ and will break
   IntelliSense / compilation.
*/