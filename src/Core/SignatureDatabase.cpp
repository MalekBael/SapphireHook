#include "SignatureDatabase.h"
#include "../Analysis/PatternScanner.h"
#include "../Logger/Logger.h"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <regex>
#include <thread>
#include <chrono>
#include "SimpleJSON.h"
#include "../Helper/WindowsApiWrapper.h" // use wrapper, no windows.h

using namespace SapphireHook;

static std::string GetExecutableDirectory()
{
    // Prefer module containing current code; fallback to main module
    void* hModule = nullptr;
    if (!GetModuleHandleExAWrapper(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<const char*>(_ReturnAddress()),
            &hModule))
    {
        hModule = GetGameModuleHandle();
    }

    char buf[4096] = { 0 };
    size_t len = GetModuleFileNameAWrapper(hModule, buf, sizeof(buf));
    if (len == 0 || len >= sizeof(buf)) return {};
    std::string path(buf, len);
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? path : path.substr(0, pos);
}

static std::vector<std::string> BuildSigPathCandidates(const std::string& filepath)
{
    std::vector<std::string> out;
    const bool hasDrive = filepath.size() > 2 && filepath[1] == ':';
    const bool isAbs = hasDrive || (!filepath.empty() && (filepath[0] == '\\' || filepath[0] == '/'));
    auto exeDir = GetExecutableDirectory();

    out.push_back(filepath);
    if (!isAbs && !exeDir.empty())
    {
        out.push_back(exeDir + "\\" + filepath);
        size_t slash = filepath.find_last_of("/\\");
        std::string base = (slash == std::string::npos) ? filepath : filepath.substr(slash + 1);
        out.push_back(exeDir + "\\data\\" + base);
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

// Heuristic helpers for non-standard JSON layouts

static bool LooksLikeAobToken(const std::string& tok)
{
    // Accept single or double wildcard ('?' or '??'), and 2-digit hex bytes.
    if (tok == "?" || tok == "??") return true;
    if (tok.size() == 2 && std::isxdigit(static_cast<unsigned char>(tok[0])) &&
        std::isxdigit(static_cast<unsigned char>(tok[1]))) return true;
    return false;
}

static bool LooksLikeAobString(const std::string& s)
{
    // Must contain at least a few tokens separated by whitespace
    int tokens = 0;
    std::string tok;
    for (size_t i = 0; i <= s.size(); ++i)
    {
        char c = (i < s.size() ? s[i] : ' ');
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        {
            if (!tok.empty())
            {
                if (!LooksLikeAobToken(tok)) return false;
                tokens++;
                tok.clear();
            }
        }
        else
        {
            tok.push_back(c);
        }
    }
    if (!tok.empty())
    {
        if (!LooksLikeAobToken(tok)) return false;
        tokens++;
    }
    return tokens >= 4; // require at least 4 bytes-worth to reduce false positives
}

// Extract nested objects with a signature-like field under known top-level keys
// 1) relaxed regex to allow nested fields inside the function object
static std::map<std::string, std::string> ExtractFunctionSignatureMapFromJSON(const std::string& content)
{
    std::map<std::string, std::string> result;

    size_t pos = content.find("\"functions\"");
    if (pos == std::string::npos) pos = content.find("\"signatures\"");
    if (pos == std::string::npos) pos = content.find("\"sigs\"");
    if (pos == std::string::npos) return result;

    pos = content.find('{', pos);
    if (pos == std::string::npos) return result;

    size_t start = pos;
    int depth = 0;
    bool inStr = false, esc = false;

    for (size_t i = pos; i < content.size(); ++i)
    {
        char c = content[i];
        if (esc) { esc = false; continue; }
        if (c == '\\') { esc = true; continue; }
        if (c == '"') { inStr = !inStr; continue; }
        if (!inStr)
        {
            if (c == '{') depth++;
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    std::string block = content.substr(start, i - start + 1);
                    // allow any content inside the function object until we find "signature"
                    std::regex re("\"([^\"]+)\"\\s*:\\s*\\{[\\s\\S]*?\"(?:signature|pattern|aob)\"\\s*:\\s*\"([^\"]+)\"");
                    for (auto it = std::sregex_iterator(block.begin(), block.end(), re), end = std::sregex_iterator();
                         it != end; ++it)
                    {
                        std::string name = (*it)[1].str();
                        std::string sig = (*it)[2].str();
                        if (!name.empty() && LooksLikeAobString(sig))
                            result[name] = sig;
                    }
                    return result;
                }
            }
        }
    }
    return result;
}

// Extract from arrays of objects: [{"name": "...", "signature|pattern|aob": "..."}]
static std::map<std::string, std::string> ExtractArrayObjectSignatures(const std::string& content)
{
    std::map<std::string, std::string> result;
    std::regex re("\"name\"\\s*:\\s*\"([^\"]+)\"[^\\}]*?\"(?:signature|pattern|aob)\"\\s*:\\s*\"([^\"]+)\"");
    for (auto it = std::sregex_iterator(content.begin(), content.end(), re), end = std::sregex_iterator();
         it != end; ++it)
    {
        std::string name = (*it)[1].str();
        std::string sig = (*it)[2].str();
        if (!name.empty() && LooksLikeAobString(sig))
            result[name] = sig;
    }
    return result;
}

// Extract generic "key":"value" pairs where value looks like an AoB
static std::map<std::string, std::string> ExtractGenericSignaturePairs(const std::string& content)
{
    std::map<std::string, std::string> result;
    std::regex re("\"([^\"]{2,256})\"\\s*:\\s*\"([^\"]{2,1024})\"");
    for (auto it = std::sregex_iterator(content.begin(), content.end(), re), end = std::sregex_iterator();
         it != end; ++it)
    {
        std::string name = (*it)[1].str();
        std::string value = (*it)[2].str();
        if (LooksLikeAobString(value))
            result.emplace(name, value);
    }
    return result;
}

SignatureDatabase::SignatureDatabase()
{
    LoadTypeDefinitions();
}

SignatureDatabase::~SignatureDatabase()
{
    StopAsyncScanning();
    if (m_scanThread.joinable())
    {
        m_scanThread.join();
    }
}

void SignatureDatabase::LoadTypeDefinitions()
{
    m_typeDefinitions["Client::Game::Object::GameObject"] = "GameObject*";
    m_typeDefinitions["Client::Game::Character::Character"] = "Character*";
    m_typeDefinitions["Client::Game::Character::BattleChara"] = "BattleChara*";
    m_typeDefinitions["Client::UI::Agent::AgentInterface"] = "AgentInterface*";
    m_typeDefinitions["Component::GUI::AtkUnitManager"] = "AtkUnitManager*";
    m_typeDefinitions["Component::GUI::AtkResNode"] = "AtkResNode*";
    m_typeDefinitions["Client::Graphics::Scene::Object"] = "SceneObject*";
    m_typeDefinitions["Client::System::Framework::Framework"] = "Framework*";
    m_typeDefinitions["Client::Game::ActionManager"] = "ActionManager*";
    m_typeDefinitions["Client::Game::InventoryManager"] = "InventoryManager*";
    m_typeDefinitions["Client::Network::NetworkModule"] = "NetworkModule*";

    m_classHierarchy["Client::Game::Object::GameObject"] = {
        "Client::Game::Character::Character",
        "Client::Game::Character::BattleChara",
        "Client::Game::Character::Companion"
    };

    m_classHierarchy["Client::UI::Agent::AgentInterface"] = {
        "Client::UI::Agent::AgentContext",
        "Client::UI::Agent::AgentLobby",
        "Client::UI::Agent::AgentSalvage"
    };

    m_classHierarchy["Component::GUI::AtkUnitManager"] = {
        "Component::GUI::AtkUnitBase"
    };

    m_knownClasses["Client::Game::Object::GameObject"] = "Game Object System";
    m_knownClasses["Client::Game::Character::Character"] = "Character System";
    m_knownClasses["Client::Game::Character::BattleChara"] = "Combat System";
    m_knownClasses["Client::UI::Agent::AgentInterface"] = "UI Agent System";
    m_knownClasses["Component::GUI::AtkUnitManager"] = "UI Management";
    m_knownClasses["Component::GUI::AtkResNode"] = "UI Components";
    m_knownClasses["Client::Graphics::Scene::Object"] = "Graphics System";
    m_knownClasses["Client::System::Framework::Framework"] = "Core Framework";
    m_knownClasses["Client::Network::NetworkModule"] = "Network System";
    m_knownClasses["Client::Game::ActionManager"] = "Action System";
    m_knownClasses["Client::Game::InventoryManager"] = "Inventory System";

    m_classCategories["UI"] = {
        "Client::UI::Agent::AgentInterface",
        "Component::GUI::AtkUnitManager",
        "Component::GUI::AtkResNode"
    };

    m_classCategories["Game"] = {
        "Client::Game::Object::GameObject",
        "Client::Game::Character::Character",
        "Client::Game::Character::BattleChara",
        "Client::Game::ActionManager",
        "Client::Game::InventoryManager"
    };

    m_classCategories["Graphics"] = {
        "Client::Graphics::Scene::Object"
    };

    m_classCategories["System"] = {
        "Client::System::Framework::Framework",
        "Client::Network::NetworkModule"
    };

    LogInfo("Loaded " + std::to_string(m_typeDefinitions.size()) + " type definitions, " +
        std::to_string(m_classHierarchy.size()) + " class hierarchies, and " +
        std::to_string(m_knownClasses.size()) + " known classes in " +
        std::to_string(m_classCategories.size()) + " categories");
}

std::string SignatureDatabase::ResolveTypeName(const std::string& rawType)
{
    auto it = m_typeDefinitions.find(rawType);
    if (it != m_typeDefinitions.end())
    {
        return it->second;
    }

    if (rawType.find("::") != std::string::npos)
    {
        size_t lastColon = rawType.find_last_of("::");
        if (lastColon != std::string::npos && lastColon > 0)
        {
            return rawType.substr(lastColon - 1) + "*";
        }
    }

    return rawType;
}

std::string SignatureDatabase::Trim(const std::string& str) const
{
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}



bool SignatureDatabase::Load(const std::string& filepath)
{
    std::string extension = filepath.substr(filepath.find_last_of('.'));
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    if (extension == ".json")
    {
        return LoadFromJSON(filepath);
    }
    else if (extension == ".yml" || extension == ".yaml")
    {
        return LoadSignatureFile(filepath);
    }
    else
    {
        if (LoadFromJSON(filepath))
            return true;
        return LoadSignatureFile(filepath);
    }
}

bool SignatureDatabase::LoadFromJSON(const std::string& filepath)
{
    auto candidates = BuildSigPathCandidates(filepath);
    std::string openedPath;
    std::string content;

    for (const auto& cand : candidates)
    {
        std::ifstream f(cand, std::ios::binary);
        if (!f.is_open()) continue;
        content.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        openedPath = cand;
        break;
    }

    if (openedPath.empty())
    {
        LogError("Could not open signature file (tried " + std::to_string(candidates.size()) + " paths), first: " + filepath);
        return false;
    }

    LogInfo("Loading signature database from JSON: " + openedPath);
    LogInfo("Signature file size: " + std::to_string(content.size()) + " bytes");

    try
    {
        auto jsonData = SimpleJSON::Parse(content);
        int signaturesLoaded = 0;

        LogDebug(std::string("JSON has keys: ")
            + (jsonData.HasKey("global_sigs") ? "global_sigs " : "")
            + (jsonData.HasKey("functions") ? "functions " : "")
            + (jsonData.HasKey("signatures") ? "signatures " : "")
            + (jsonData.HasKey("sigs") ? "sigs " : "")
            + (jsonData.HasKey("classes") ? "classes " : ""));

        // 1) global_sigs (flat map name->pattern)
        if (jsonData.HasKey("global_sigs"))
        {
            auto globalSigs = jsonData.GetObject("global_sigs");
            LogDebug("global_sigs count: " + std::to_string(globalSigs.size()));
            for (const auto& sig : globalSigs)
            {
                const std::string& name = sig.first;
                const std::string& pattern = sig.second;
                if (!name.empty() && LooksLikeAobString(pattern))
                {
                    SignatureInfo info;
                    info.functionName = name;
                    info.signature = pattern;
                    info.className = "Global";
                    info.category = "Global Functions";
                    info.description = "Global function: " + name;
                    m_globalSignatures[name] = info;
                    signaturesLoaded++;
                }
            }
        }

        // 2) functions/signatures/sigs — support flat and nested
        auto getFirstPresentObject = [&](const std::vector<std::string>& keys) -> std::map<std::string, std::string>
        {
            for (const auto& k : keys)
                if (jsonData.HasKey(k)) return jsonData.GetObject(k);
            return {};
        };

        auto flat = getFirstPresentObject({ "functions", "signatures", "sigs" });
        if (!flat.empty())
            LogDebug("function-like(flat) count: " + std::to_string(flat.size()));

        std::map<std::string, std::string> effective;
        if (!flat.empty())
        {
            bool flatHasAob = false;
            for (const auto& kv : flat)
            {
                if (LooksLikeAobString(kv.second)) { flatHasAob = true; break; }
            }
            if (flatHasAob)
            {
                effective = flat;
            }
            else
            {
                LogDebug("Flat map present but values are not AoB strings; attempting nested extraction");
                effective = ExtractFunctionSignatureMapFromJSON(content);
                if (effective.empty())
                    effective = ExtractArrayObjectSignatures(content);
                if (effective.empty())
                    effective = ExtractGenericSignaturePairs(content);
                if (!effective.empty())
                    LogDebug("Heuristically parsed signatures count: " + std::to_string(effective.size()));
            }
        }
        else
        {
            // Try nested under known key, then arrays of objects, then generic pairs
            effective = ExtractFunctionSignatureMapFromJSON(content);
            if (effective.empty())
                effective = ExtractArrayObjectSignatures(content);
            if (effective.empty())
                effective = ExtractGenericSignaturePairs(content);

            if (!effective.empty())
                LogDebug("Heuristically parsed signatures count: " + std::to_string(effective.size()));
        }

        for (const auto& [functionName, pattern] : effective)
        {
            if (!LooksLikeAobString(pattern)) continue;

            SignatureInfo info;
            info.functionName = functionName;
            info.signature = pattern;

            size_t sc = functionName.rfind("::");
            if (sc != std::string::npos)
            {
                std::string className = functionName.substr(0, sc);
                std::string method = functionName.substr(sc + 2);
                info.className = className;
                info.returnType = ResolveTypeName(className);

                bool foundCategory = false;
                for (const auto& [cat, classes] : m_classCategories)
                {
                    if (std::find(classes.begin(), classes.end(), className) != classes.end())
                    { info.category = cat; foundCategory = true; break; }
                }
                if (!foundCategory)
                {
                    if (className.find("ExdData") != std::string::npos) info.category = "ExdData";
                    else if (className.find("Client") != std::string::npos) info.category = "Client";
                    else info.category = "System";
                }

                info.description = "Class method: " + functionName;
                m_classSignatures[className][method] = info;
            }
            else
            {
                info.className = "Global";
                info.category = "Global Functions";
                info.description = "Global function: " + functionName;
                m_globalSignatures[functionName] = info;
            }

            if (++signaturesLoaded <= 5)
                LogDebug("Loaded signature: " + functionName + " -> " + info.signature + " [" + info.category + "]");
        }

        if (jsonData.HasKey("classes"))
        {
            LogInfo("Found classes section in JSON, but nested parsing not fully implemented yet");
        }

        LogInfo("Successfully loaded " + std::to_string(signaturesLoaded) + " signatures from JSON");
        return signaturesLoaded > 0;
    }
    catch (const std::exception& ex)
    {
        LogError("Exception while parsing signature JSON: " + std::string(ex.what()));
        return false;
    }
}

bool SignatureDatabase::ParseSignatureLine(const std::string& line, const std::string& currentClass, bool inGlobalSigs, bool inFunctionSigs)
{
    size_t colonPos = line.find(':');
    if (colonPos == std::string::npos) return false;

    std::string name = Trim(line.substr(0, colonPos));
    std::string signature = Trim(line.substr(colonPos + 1));

    if (signature == "None" || signature == "null" || signature.empty())
    {
        return false;
    }

    SignatureInfo info;
    info.functionName = name;
    info.signature = signature;

    if (inGlobalSigs)
    {
        info.className = "Global";
        info.category = "Global Functions";
        info.description = "Global function: " + name;
        m_globalSignatures[name] = info;
        return true;
    }
    else if (inFunctionSigs && !currentClass.empty())
    {
        info.className = currentClass;

        bool foundCategory = false;
        for (const auto& [category, classes] : m_classCategories)
        {
            if (std::find(classes.begin(), classes.end(), currentClass) != classes.end())
            {
                info.category = category;
                foundCategory = true;
                break;
            }
        }
        if (!foundCategory)
        {
            info.category = "Unknown";
        }

        info.description = currentClass + "::" + name;

        if (name.find("vf") == 0 || name.find("virtual") != std::string::npos)
        {
            info.isVirtual = true;
        }

        info.returnType = ResolveTypeName(currentClass);

        m_classSignatures[currentClass][name] = info;
        return true;
    }

    return false;
}

bool SignatureDatabase::LoadSignatureFile(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        LogError("Failed to open " + filepath);
        return false;
    }

    std::string line;
    std::string currentClass = "";
    bool inFunctionSigs = false;
    bool inGlobalSigs = false;
    size_t globalCount = 0;
    size_t classCount = 0;

    LogInfo("Loading signatures from " + filepath + "...");

    while (std::getline(file, line))
    {
        line = Trim(line);

        if (line.empty() || line[0] == '#' || line.find('!') == 0) continue;

        if (line == "global_sigs:")
        {
            inGlobalSigs = true;
            inFunctionSigs = false;
            currentClass = "";
            LogInfo("Entering global signatures section");
            continue;
        }

        if (line == "classes:")
        {
            inGlobalSigs = false;
            inFunctionSigs = false;
            LogInfo("Entering classes section");
            continue;
        }

        if (line.find("func_sigs:") != std::string::npos)
        {
            inFunctionSigs = true;
            LogInfo("Entering function signatures for class: " + currentClass);
            continue;
        }

        if (line.find(":") != std::string::npos && !inGlobalSigs && !inFunctionSigs)
        {
            size_t colonPos = line.find(":");
            std::string className = Trim(line.substr(0, colonPos));
            if (className.find(' ') != std::string::npos)
            {
                className = className.substr(0, className.find(' '));
            }
            currentClass = className;
            inFunctionSigs = false;
            LogInfo("Found class: " + currentClass);
            continue;
        }

        if ((inGlobalSigs || inFunctionSigs) && line.find(":") != std::string::npos)
        {
            if (ParseSignatureLine(line, currentClass, inGlobalSigs, inFunctionSigs))
            {
                if (inGlobalSigs)
                {
                    globalCount++;
                }
                else
                {
                    classCount++;
                }
            }
        }
    }

    LogInfo("Loaded " + std::to_string(globalCount) + " global signatures and " +
        std::to_string(classCount) + " class function signatures");

    return globalCount > 0 || classCount > 0;
}

void SignatureDatabase::ResolveAllSignatures()
{
    LogInfo("Starting safe signature resolution...");

    size_t moduleSize = 0;
    uintptr_t moduleBase = GetModuleBaseAddress(L"ffxiv_dx11.exe", moduleSize);

    if (moduleBase == 0)
    {
        LogError("Failed to get module base address - aborting signature resolution");
        return;
    }

    char hexBuf[64];
    std::snprintf(hexBuf, sizeof(hexBuf), "Module base: 0x%llX, size: 0x%zX", 
        static_cast<unsigned long long>(moduleBase), moduleSize);
    LogInfo(hexBuf);

    if (moduleSize > 0x50000000)
    {
        LogError("Module size suspiciously large (" + Logger::HexFormat(moduleSize) + ") - aborting");
        return;
    }

    size_t resolved = 0;
    size_t total = m_globalSignatures.size();
    size_t failureCount = 0;
    const size_t maxFailures = 10;

    LogInfo("Scanning " + std::to_string(total) + " global signatures with safety limits");

    for (auto& [name, info] : m_globalSignatures)
    {
        std::this_thread::sleep_for(std::chrono::microseconds(100));

        try
        {
            uintptr_t address = patternscan(moduleBase, moduleSize, info.signature.c_str());
            if (address != 0)
            {
                if (address >= moduleBase && address < (moduleBase + moduleSize))
                {
                    info.resolvedAddress = address;
                    info.isResolved = true;
                    resolved++;
                    LogInfo("Resolved global " + name + " -> " + Logger::HexFormat(address));
                }
                else
                {
                    LogWarning("Signature " + name + " resolved to invalid address " + Logger::HexFormat(address));
                    failureCount++;
                }
            }
            else
            {
                failureCount++;
                if (failureCount > maxFailures)
                {
                    LogError("Too many signature failures (" + std::to_string(failureCount) + ") - stopping to prevent detection");
                    break;
                }
            }
        }
        catch (...)
        {
            LogError("Exception during signature scan for " + name + " - aborting for safety");
            break;
        }
    }

    if (failureCount <= maxFailures && resolved > 0)
    {
        LogInfo("Global signature scan successful, proceeding with class functions");

        for (auto& [className, functions] : m_classSignatures)
        {
            for (auto& [funcName, info] : functions)
            {
                total++;
                std::this_thread::sleep_for(std::chrono::microseconds(50));

                try
                {
                    uintptr_t address = patternscan(moduleBase, moduleSize, info.signature.c_str());
                    if (address != 0 && address >= moduleBase && address < (moduleBase + moduleSize))
                    {
                        info.resolvedAddress = address;
                        info.isResolved = true;
                        resolved++;
                        LogInfo("Resolved " + className + "::" + funcName + " -> " + Logger::HexFormat(address));
                    }
                }
                catch (...)
                {
                    continue;
                }

                if (resolved > 200)
                {
                    LogInfo("Reached resolution limit - stopping for safety");
                    break;
                }
            }
        }
    }
    else
    {
        LogWarning("Skipping class function scanning due to global scan issues");
    }

    float pct = total > 0 ? (static_cast<float>(resolved) / total * 100.0f) : 0.0f;
    LogInfo("Signature resolution complete: " + std::to_string(resolved) + "/" + std::to_string(total) + 
        " (" + std::to_string(static_cast<int>(pct)) + "%)");

    if (resolved < total * 0.1f)
    {
        LogWarning("Low signature resolution rate - may indicate outdated database or anti-tamper interference");
    }
}

void SignatureDatabase::ResolveAllSignaturesAsync(ProgressCallback callback)
{
    if (m_scanInProgress.load())
    {
        LogWarning("Async signature scan already in progress");
        return;
    }

    m_progressCallback = callback;
    m_stopScan = false;
    m_scanInProgress = true;
    m_scannedCount = 0;

    size_t totalSigs = m_globalSignatures.size();
    for (const auto& [className, functions] : m_classSignatures)
    {
        totalSigs += functions.size();
    }
    m_totalCount = totalSigs;

    LogInfo("Starting async signature resolution with " + std::to_string(totalSigs) + " signatures");

    size_t moduleSize = 0;
    uintptr_t moduleBase = GetModuleBaseAddress(L"ffxiv_dx11.exe", moduleSize);

    if (moduleBase == 0)
    {
        LogError("Failed to get module base address - aborting async scan");
        m_scanInProgress = false;
        return;
    }

    m_scanThread = std::thread([this, moduleBase, moduleSize, callback]()
        {
            AsyncScanWorker(moduleBase, moduleSize, callback);
        });

    m_scanThread.detach();
}

void SignatureDatabase::StopAsyncScanning()
{
    if (m_scanInProgress.load())
    {
        LogInfo("Stopping async signature scan...");
        m_stopScan = true;

        int waitCount = 0;
        while (m_scanInProgress.load() && waitCount < 50)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            waitCount++;
        }

        if (m_scanInProgress.load())
        {
            LogWarning("Async scan did not stop gracefully within timeout");
        }
    }
}

void SignatureDatabase::AsyncScanWorker(uintptr_t moduleBase, size_t moduleSize, ProgressCallback callback)
{
    char hexBuf[64];
    std::snprintf(hexBuf, sizeof(hexBuf), "Async worker started - Module: 0x%llX, size: 0x%zX",
        static_cast<unsigned long long>(moduleBase), moduleSize);
    LogInfo(hexBuf);

    if (moduleSize > 0x50000000)
    {
        LogError("Module size suspiciously large - aborting async scan");
        m_scanInProgress = false;
        return;
    }

    size_t resolved = 0;
    size_t failureCount = 0;
    const size_t maxFailures = 20;
    const auto startTime = std::chrono::steady_clock::now();

    try
    {
        LogInfo("Async scanning global signatures...");
        for (auto& [name, info] : m_globalSignatures)
        {
            if (m_stopScan.load()) break;

            size_t currentCount = m_scannedCount.fetch_add(1) + 1;
            if (callback)
            {
                callback(currentCount, m_totalCount.load(), "Global::" + name);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(2));

            try
            {
                uintptr_t address = patternscan(moduleBase, moduleSize, info.signature.c_str());
                if (address != 0 && address >= moduleBase && address < (moduleBase + moduleSize))
                {
                    info.resolvedAddress = address;
                    info.isResolved = true;
                    resolved++;
                    LogInfo("[ASYNC] Resolved global " + name + " -> " + Logger::HexFormat(address));
                }
                else if (address != 0)
                {
                    LogWarning("Async: Global signature " + name + " resolved to invalid address");
                    failureCount++;
                }
                else
                {
                    failureCount++;
                }
            }
            catch (...)
            {
                LogError("Exception during async scan of global signature: " + name);
                failureCount++;
            }

            if (failureCount > maxFailures)
            {
                LogError("Too many failures in async scan - stopping");
                break;
            }

            if ((resolved % 10) == 0)
            {
                LogDebug("Async scan progress: " + std::to_string(resolved) + "/" + std::to_string(m_totalCount.load()));
            }
        }

        if (!m_stopScan.load() && failureCount <= maxFailures)
        {
            LogInfo("Async scanning class function signatures...");

            for (auto& [className, functions] : m_classSignatures)
            {
                if (m_stopScan.load()) break;

                for (auto& [funcName, info] : functions)
                {
                    if (m_stopScan.load()) break;

                    size_t currentCount = m_scannedCount.fetch_add(1) + 1;
                    if (callback)
                    {
                        callback(currentCount, m_totalCount.load(), className + "::" + funcName);
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(1));

                    try
                    {
                        uintptr_t address = patternscan(moduleBase, moduleSize, info.signature.c_str());
                        if (address != 0 && address >= moduleBase && address < (moduleBase + moduleSize))
                        {
                            info.resolvedAddress = address;
                            info.isResolved = true;
                            resolved++;
                            LogInfo("[ASYNC] Resolved " + className + "::" + funcName + " -> " + Logger::HexFormat(address));
                        }
                    }
                    catch (...)
                    {
                        continue;
                    }

                    if (resolved > 300)
                    {
                        LogInfo("Async scan reached resolution limit - stopping");
                        break;
                    }

                    if ((resolved % 5) == 0)
                    {
                        LogDebug("Async scan progress: " + std::to_string(resolved) + "/" + std::to_string(m_totalCount.load()));
                    }
                }
            }
        }
    }
    catch (...)
    {
        LogError("Unhandled exception in async signature worker");
    }

    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);

    if (m_stopScan.load())
    {
        LogInfo("Async signature scan was cancelled by user");
        LogInfo("[ASYNC] Scan cancelled after " + std::to_string(duration.count()) + " seconds");
    }
    else
    {
        LogInfo("Async signature scan completed successfully");
        LogInfo("[ASYNC] Scan complete: " + std::to_string(resolved) + "/" + std::to_string(m_totalCount.load()) +
            " signatures resolved in " + std::to_string(duration.count()) + " seconds (" +
            std::to_string(m_totalCount.load() > 0 ? (float)resolved / m_totalCount.load() * 100.0f : 0.0f) + "%)");
    }

    if (callback)
    {
        callback(m_scannedCount.load(), m_totalCount.load(), m_stopScan.load() ? "Cancelled" : "Complete");
    }

    m_scanInProgress = false;
    LogInfo("Async signature worker finished");
}



std::vector<std::pair<uintptr_t, std::string>> SignatureDatabase::GetResolvedFunctions() const
{
    std::vector<std::pair<uintptr_t, std::string>> result;

    for (const auto& [name, info] : m_globalSignatures)
    {
        if (info.isResolved)
        {
            result.emplace_back(info.resolvedAddress, "Global::" + name);
        }
    }

    for (const auto& [className, functions] : m_classSignatures)
    {
        for (const auto& [funcName, info] : functions)
        {
            if (info.isResolved)
            {
                result.emplace_back(info.resolvedAddress, className + "::" + funcName);
            }
        }
    }

    return result;
}

std::vector<std::pair<uintptr_t, SignatureInfo>> SignatureDatabase::GetResolvedFunctionsWithInfo() const
{
    std::vector<std::pair<uintptr_t, SignatureInfo>> result;

    for (const auto& [name, info] : m_globalSignatures)
    {
        if (info.isResolved)
        {
            result.emplace_back(info.resolvedAddress, info);
        }
    }

    for (const auto& [className, functions] : m_classSignatures)
    {
        for (const auto& [funcName, info] : functions)
        {
            if (info.isResolved)
            {
                result.emplace_back(info.resolvedAddress, info);
            }
        }
    }

    return result;
}



std::vector<SignatureInfo> SignatureDatabase::FindFunctionsByClass(const std::string& className) const
{
    std::vector<SignatureInfo> result;

    auto it = m_classSignatures.find(className);
    if (it != m_classSignatures.end())
    {
        for (const auto& [funcName, info] : it->second)
        {
            if (info.isResolved)
            {
                result.push_back(info);
            }
        }
    }

    return result;
}



std::vector<std::string> SignatureDatabase::GetDerivedClasses(const std::string& baseClass) const
{
    auto it = m_classHierarchy.find(baseClass);
    if (it != m_classHierarchy.end())
    {
        return it->second;
    }
    return {};
}

std::vector<std::string> SignatureDatabase::GetVirtualFunctions(const std::string& className) const
{
    std::vector<std::string> result;

    auto it = m_classSignatures.find(className);
    if (it != m_classSignatures.end())
    {
        for (const auto& [funcName, info] : it->second)
        {
            if (info.isVirtual && info.isResolved)
            {
                result.push_back(funcName);
            }
        }
    }

    return result;
}

std::vector<std::string> SignatureDatabase::GetAllClasses() const
{
    std::vector<std::string> result;
    for (const auto& [className, functions] : m_classSignatures)
    {
        result.push_back(className);
    }
    return result;
}

std::vector<std::string> SignatureDatabase::GetAllCategories() const
{
    std::vector<std::string> result;
    for (const auto& [category, classes] : m_classCategories)
    {
        result.push_back(category);
    }
    return result;
}

size_t SignatureDatabase::GetTotalSignatures() const
{
    size_t total = m_globalSignatures.size();
    for (const auto& [className, functions] : m_classSignatures)
    {
        total += functions.size();
    }
    return total;
}

size_t SignatureDatabase::GetResolvedSignatures() const
{
    size_t resolved = 0;

    for (const auto& [name, info] : m_globalSignatures)
    {
        if (info.isResolved) resolved++;
    }

    for (const auto& [className, functions] : m_classSignatures)
    {
        for (const auto& [funcName, info] : functions)
        {
            if (info.isResolved) resolved++;
        }
    }

    return resolved;
}