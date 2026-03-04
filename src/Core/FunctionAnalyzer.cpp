#include "FunctionAnalyzer.h"
#include "FunctionDatabase.h"
#include "SignatureDatabase.h"
#include "../Analysis/PatternScanner.h"           
#include "../Logger/Logger.h"
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <algorithm>
#include <regex>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <Psapi.h>

namespace SapphireHook {

    extern "C" {
        static bool SafeReadCodeBytes(uintptr_t address, uint8_t* bytes, size_t count)
        {
            __try
            {
                const uint8_t* code = reinterpret_cast<const uint8_t*>(address);
                for (size_t i = 0; i < count; ++i)
                {
                    bytes[i] = code[i];
                }
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        static bool SafeReadMemoryBytes(uintptr_t address, uint8_t* bytes, size_t count)
        {
            __try
            {
                const uint8_t* memory = reinterpret_cast<const uint8_t*>(address);
                for (size_t i = 0; i < count; ++i)
                {
                    bytes[i] = memory[i];
                }
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }
    }

    class FunctionAnalyzer::Impl {
    public:
        std::shared_ptr<FunctionDatabase> m_functionDatabase;
        std::shared_ptr<SignatureDatabase> m_signatureDatabase;

        bool m_databasesInitialized = false;
        bool m_signaturesInitialized = false;
        bool m_typeInfoInitialized = false;

        std::vector<uintptr_t> m_discoveredFunctions;
        std::map<uintptr_t, std::string> m_discoveredFunctionNames;
        std::map<std::string, std::vector<uintptr_t>> m_functionsByType;

        std::map<uintptr_t, std::vector<uintptr_t>> m_vtables;

        Impl() {}
        ~Impl() {}
    };

    FunctionAnalyzer::FunctionAnalyzer() : m_impl(std::make_unique<Impl>()) {}
    FunctionAnalyzer::~FunctionAnalyzer() = default;

    void FunctionAnalyzer::SetFunctionDatabase(std::shared_ptr<FunctionDatabase> database)
    {
        m_impl->m_functionDatabase = database;
        m_impl->m_databasesInitialized = (database != nullptr);
    }

    void FunctionAnalyzer::SetSignatureDatabase(std::shared_ptr<SignatureDatabase> database)
    {
        m_impl->m_signatureDatabase = database;
    }

    uintptr_t FunctionAnalyzer::ResolveManualAddress(const std::string& input)
    {
        uintptr_t result = 0;
        if (ParseAddressInput(input, result))
        {
            return result;
        }
        return 0;
    }

    bool FunctionAnalyzer::ParseAddressInput(const std::string& input, uintptr_t& result)
    {
        std::string trimmed = input;

        trimmed.erase(std::remove_if(trimmed.begin(), trimmed.end(), ::isspace), trimmed.end());

        if (trimmed.find("0x") == 0 || trimmed.find("0X") == 0)
        {
            std::stringstream ss;
            ss << std::hex << trimmed.substr(2);
            ss >> result;
            if (ss.fail()) return false;
            constexpr uintptr_t IDA_BASE = 0x0000000140000000ULL;
            if (result >= IDA_BASE && result < (IDA_BASE + 0x10000000ULL))
            {     
                HMODULE hExe = GetModuleHandle(nullptr);
                if (hExe)
                {
                    const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hExe);
                    result = (result - IDA_BASE) + moduleBase;
                }
            }
            return true;
        }

        std::stringstream ss(trimmed);
        ss >> result;
        if (ss.fail()) return false;
        constexpr uintptr_t IDA_BASE = 0x0000000140000000ULL;
        if (result >= IDA_BASE && result < (IDA_BASE + 0x10000000ULL))
        {
            HMODULE hExe = GetModuleHandle(nullptr);
            if (hExe)
            {
                const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hExe);
                result = (result - IDA_BASE) + moduleBase;
            }
        }
        return true;
    }

    uintptr_t FunctionAnalyzer::ConvertRVAToRuntimeAddress(uintptr_t rva)
    {
        HMODULE hModule = GetModuleHandle(nullptr);
        if (hModule)
        {
            return reinterpret_cast<uintptr_t>(hModule) + rva;
        }
        return rva;
    }

    bool FunctionAnalyzer::ValidateAndDebugAddress(uintptr_t address, const std::string& name)
    {
        LogInfo("=== Address Validation: " + name + " ===");

        std::stringstream ss;
        ss << "0x" << std::hex << std::uppercase << address;
        LogInfo("Address: " + ss.str());

        auto tryRelocateIfNeeded = [&]() -> uintptr_t
            {
                MEMORY_BASIC_INFORMATION mbiPre{};
                if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbiPre, sizeof(mbiPre)) != 0)
                {
                    if (mbiPre.State == MEM_COMMIT) return address;   
                }
                constexpr uintptr_t IDA_BASE = 0x0000000140000000ULL;
                if (address >= IDA_BASE && address < (IDA_BASE + 0x10000000ULL))
                {
                    HMODULE hExe = GetModuleHandle(nullptr);
                    if (hExe)
                    {
                        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hExe);
                        const uintptr_t relocated = (address - IDA_BASE) + moduleBase;
                        MEMORY_BASIC_INFORMATION mbiCheck{};
                        if (VirtualQuery(reinterpret_cast<LPCVOID>(relocated), &mbiCheck, sizeof(mbiCheck)) != 0 &&
                            mbiCheck.State == MEM_COMMIT)
                        {
                            std::stringstream rs;
                            rs << "Relocated IDA address -> runtime: 0x" << std::hex << std::uppercase << relocated
                                << " (moduleBase=0x" << moduleBase << ", delta=0x" << (moduleBase - IDA_BASE) << ")";
                            LogInfo(rs.str());
                            return relocated;
                        }
                    }
                }
                return address;
            };

        address = tryRelocateIfNeeded();

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        {
            ss.str("");
            ss << "Address validation failed: Cannot query memory at 0x" << std::hex << address;
            LogError(ss.str());
            return false;
        }

        ss.str("");
        ss << "Memory state: " << mbi.State;
        LogInfo(ss.str());

        ss.str("");
        ss << "Memory protect: 0x" << std::hex << mbi.Protect;
        LogInfo(ss.str());

        ss.str("");
        ss << "Memory type: " << mbi.Type;
        LogInfo(ss.str());

        if (mbi.State != MEM_COMMIT)
        {
            LogWarning("Address points to uncommitted memory");
            return false;
        }

        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        LogInfo("Is executable: " + std::string(isExecutable ? "Yes" : "No"));

        uint8_t codeBytes[3] = { 0 };
        if (SafeReadCodeBytes(address, codeBytes, 3))
        {
            ss.str("");
            ss << "First bytes: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(codeBytes[0])
                << " 0x" << std::setw(2) << static_cast<int>(codeBytes[1])
                << " 0x" << std::setw(2) << static_cast<int>(codeBytes[2]);
            LogInfo(ss.str());

            bool likelyFunction = false;
            if (codeBytes[0] == 0x48 && codeBytes[1] == 0x89) likelyFunction = true;   
            if (codeBytes[0] == 0x48 && codeBytes[1] == 0x83) likelyFunction = true;   
            if (codeBytes[0] == 0x55) likelyFunction = true;   
            if (codeBytes[0] == 0x53) likelyFunction = true;   

            LogInfo("Looks like function: " + std::string(likelyFunction ? "Yes" : "No"));
        }
        else
        {
            LogError("Exception while reading code at address");
            return false;
        }

        return true;
    }

    void FunctionAnalyzer::DebugAddressSource(uintptr_t address, const std::string& name)
    {
        LogInfo("=== Address Source Debug: " + name + " ===");

        if (m_impl->m_functionDatabase && m_impl->m_functionDatabase->HasFunction(address))
        {
            auto info = m_impl->m_functionDatabase->GetFunction(address);
            LogInfo("Found in Function Database:");
            LogInfo("  Name: " + info.name);
            LogInfo("  Description: " + info.description);
            LogInfo("  Category: " + info.category);
        }

        if (m_impl->m_signatureDatabase)
        {
            auto resolvedFuncs = m_impl->m_signatureDatabase->GetResolvedFunctions();
            auto it = std::find_if(resolvedFuncs.begin(), resolvedFuncs.end(),
                [address](const auto& pair) { return pair.first == address; });

            if (it != resolvedFuncs.end())
            {
                LogInfo("Found in Signature Database: " + it->second);
            }
        }

        HMODULE hModule = nullptr;
        if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(address), &hModule))
        {

            char modulePath[MAX_PATH];
            if (GetModuleFileNameA(hModule, modulePath, MAX_PATH))
            {
                LogInfo("Module: " + std::string(modulePath));

                uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hModule);
                uintptr_t offset = address - moduleBase;

                std::stringstream ss;
                ss << "Module offset: 0x" << std::hex << offset;
                LogInfo(ss.str());
            }
        }
    }

    void FunctionAnalyzer::DebugIdaAddress(const std::string& address)
    {
        LogInfo("=== IDA Address Debug ===");
        LogInfo("IDA Address: " + address);

        uintptr_t addr = 0;
        if (ParseAddressInput(address, addr))
        {
            std::stringstream ss;
            ss << "Parsed address: 0x" << std::hex << addr;
            LogInfo(ss.str());

            uintptr_t runtimeAddr = addr;
            if (addr < 0x10000000ULL)
            {
                runtimeAddr = ConvertRVAToRuntimeAddress(addr);
            }

            ss.str("");
            ss << "Runtime address: 0x" << std::hex << runtimeAddr;
            LogInfo(ss.str());

            ValidateAndDebugAddress(runtimeAddr, "IDA_" + address);
        }
        else
        {
            LogError("Failed to parse IDA address: " + address);
        }
    }

    void FunctionAnalyzer::VerifyDatabaseLoading()
    {
        LogInfo("=== Database Loading Verification ===");

        if (m_impl->m_functionDatabase)
        {
            size_t funcCount = m_impl->m_functionDatabase->GetFunctionCount();
            size_t catCount = m_impl->m_functionDatabase->GetCategoryCount();
            LogInfo("Function Database: " + std::to_string(funcCount) + " functions, " + std::to_string(catCount) + " categories");

            const auto& categories = m_impl->m_functionDatabase->GetCategories();
            for (const auto& catKV : categories)
            {
                const auto& catName = catKV.first;
                auto funcsInCat = m_impl->m_functionDatabase->GetFunctionsByCategory(catName);
                LogInfo("Category '" + catName + "': " + std::to_string(funcsInCat.size()) + " functions");

                size_t maxShow = funcsInCat.size() < static_cast<size_t>(3) ? funcsInCat.size() : static_cast<size_t>(3);
                for (size_t i = 0; i < maxShow; ++i)
                {
                    LogInfo("  - " + funcsInCat[i]);
                }
            }

            m_impl->m_databasesInitialized = true;
        }
        else
        {
            LogWarning("Function Database not available");
        }

        if (m_impl->m_signatureDatabase)
        {
            size_t totalSigs = m_impl->m_signatureDatabase->GetTotalSignatures();
            size_t resolvedSigs = m_impl->m_signatureDatabase->GetResolvedSignatures();
            LogInfo("Signature Database: " + std::to_string(resolvedSigs) + "/" + std::to_string(totalSigs) + " signatures resolved");

            auto resolved = m_impl->m_signatureDatabase->GetResolvedFunctions();
            LogInfo("Sample resolved signatures:");
            size_t shown = 0;
            for (const auto& kv : resolved)
            {
                if (shown++ >= 5) break;

                std::stringstream ss;
                ss << "  0x" << std::hex << kv.first << " -> " << kv.second;
                LogInfo(ss.str());
            }
        }
        else
        {
            LogWarning("Signature Database not available");
        }
    }

    void FunctionAnalyzer::TestAndDebugEmbeddedData()
    {
        LogInfo("=== Embedded Data Testing ===");

        if (!m_impl->m_functionDatabase)
        {
            LogError("No function database available for testing");
            return;
        }

        std::vector<std::string> testCategories = { "UI", "Network", "Gameplay", "System", "Graphics" };

        for (const auto& category : testCategories)
        {
            auto functions = m_impl->m_functionDatabase->GetFunctionsByCategory(category);
            LogInfo("Testing category '" + category + "' (" + std::to_string(functions.size()) + " functions)");

            const size_t limit = (functions.size() < static_cast<size_t>(2)) ? functions.size() : static_cast<size_t>(2);
            for (size_t i = 0; i < limit; ++i)
            {
                LogInfo("  Testing function: " + functions[i]);
            }
        }

        if (m_impl->m_signatureDatabase)
        {
            LogInfo("Testing signature resolution...");
            auto resolvedBefore = m_impl->m_signatureDatabase->GetResolvedSignatures();
            LogInfo("Signatures resolved before test: " + std::to_string(resolvedBefore));
        }

        HMODULE self = GetModuleHandleW(nullptr);
        const size_t minStringLen = 6;    

        auto functionStringMap = PatternScanner::MapFunctionsToStrings(self, minStringLen);

        size_t totalFnRefs = 0;
        for (const auto& kv : functionStringMap.functionsToStrings)
        {
            totalFnRefs += kv.second.size();
        }

        std::stringstream ss;
        ss << "String XREF summary: ASCII=" << functionStringMap.asciiStringCount
           << ", UTF16=" << functionStringMap.utf16StringCount
           << ", FunctionsWithRefs=" << functionStringMap.functionsToStrings.size()
           << ", TotalFn->String edges=" << totalFnRefs;
        LogInfo(ss.str());

        size_t added = 0, preview = 0;
        for (const auto& kv : functionStringMap.functionsToStrings)
        {
            auto fn = kv.first;
            const auto& texts = kv.second;

            if (std::find(m_impl->m_discoveredFunctions.begin(), m_impl->m_discoveredFunctions.end(), fn) == m_impl->m_discoveredFunctions.end())
                m_impl->m_discoveredFunctions.push_back(fn);

            if (!texts.empty())
                m_impl->m_discoveredFunctionNames[fn] = "XRefStr:" + texts.front();

            if (preview++ < 10)
            {
                std::stringstream ps;
                ps << "  0x" << std::hex << std::uppercase << fn << " -> [";

                const size_t three = static_cast<size_t>(3);
                const size_t maxShow = (texts.size() < three) ? texts.size() : three;

                for (size_t i = 0; i < maxShow; ++i)
                {
                    if (i) ps << ", ";
                    ps << texts[i];
                }
                if (texts.size() > three) ps << ", ...";
                ps << "]";
                LogInfo(ps.str());
            }
            ++added;
        }
        LogInfo("Discovered/updated " + std::to_string(added) + " functions via string XREFs.");
    }

    void FunctionAnalyzer::InitializeWithSignatures()
    {
        LogInfo("=== Initializing with Signatures ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available");
            return;
        }

        LogInfo("Starting signature-based initialization...");

        size_t totalSigs = m_impl->m_signatureDatabase->GetTotalSignatures();
        size_t resolvedSigs = m_impl->m_signatureDatabase->GetResolvedSignatures();

        LogInfo("Signature status: " + std::to_string(resolvedSigs) + "/" + std::to_string(totalSigs) + " resolved");

        if (resolvedSigs < totalSigs)
        {
            LogInfo("Attempting to resolve remaining signatures...");
            m_impl->m_signatureDatabase->ResolveAllSignatures();

            size_t newResolved = m_impl->m_signatureDatabase->GetResolvedSignatures();
            LogInfo("Resolution complete: " + std::to_string(newResolved) + "/" + std::to_string(totalSigs) + " resolved");
            LogInfo("Newly resolved: " + std::to_string(newResolved - resolvedSigs) + " signatures");
        }

        m_impl->m_signaturesInitialized = true;
        LogInfo("Signature initialization complete");
    }

    void FunctionAnalyzer::StartAsyncSignatureResolution()
    {
        LogInfo("=== Starting Async Signature Resolution ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available");
            return;
        }

        auto progressCallback = [](size_t current, size_t total, const std::string& currentSig)
            {
                if (current % 10 == 0)
                {        
                    LogInfo("Resolving signatures: " + std::to_string(current) + "/" + std::to_string(total) +
                        " (Current: " + currentSig + ")");
                }
            };

        LogInfo("Starting async signature resolution...");
        m_impl->m_signatureDatabase->ResolveAllSignaturesAsync(progressCallback);
    }

    void FunctionAnalyzer::IntegrateSignaturesWithDatabase()
    {
        LogInfo("=== Integrating Signatures with Database ===");

        if (!m_impl->m_signatureDatabase || !m_impl->m_functionDatabase)
        {
            LogError("Missing required databases for integration");
            return;
        }

        auto resolvedFunctions = m_impl->m_signatureDatabase->GetResolvedFunctions();
        LogInfo("Integrating " + std::to_string(resolvedFunctions.size()) + " resolved signatures...");

        size_t integrated = 0;
        size_t alreadyKnown = 0;

        for (const auto& kv : resolvedFunctions)
        {
            auto address = kv.first;
            const auto& name = kv.second;

            if (m_impl->m_functionDatabase->HasFunction(address))
            {
                alreadyKnown++;
            }
            else
            {
                m_impl->m_functionDatabase->AddFunction(address, name, "Resolved from signature", "Signature");
                integrated++;
            }
        }

        LogInfo("Integration complete:");
        LogInfo("  - New functions added: " + std::to_string(integrated));
        LogInfo("  - Already known functions: " + std::to_string(alreadyKnown));
        LogInfo("  - Total database functions: " + std::to_string(m_impl->m_functionDatabase->GetFunctionCount()));
    }

    void FunctionAnalyzer::DiscoverFunctionsFromSignatures()
    {
        LogInfo("=== Discovering Functions from Signatures ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available");
            return;
        }

        m_impl->m_discoveredFunctions.clear();
        m_impl->m_discoveredFunctionNames.clear();
        m_impl->m_functionsByType.clear();

        auto resolvedFunctions = m_impl->m_signatureDatabase->GetResolvedFunctions();

        LogInfo("Analyzing " + std::to_string(resolvedFunctions.size()) + " signature-resolved functions...");

        for (const auto& kv : resolvedFunctions)
        {
            auto address = kv.first;
            const auto& name = kv.second;

            m_impl->m_discoveredFunctions.push_back(address);
            m_impl->m_discoveredFunctionNames[address] = name;

            std::string category = "Unknown";
            std::string lowerName = name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            if (lowerName.find("ui") != std::string::npos || lowerName.find("gui") != std::string::npos)
            {
                category = "UI";
            }
            else if (lowerName.find("network") != std::string::npos || lowerName.find("socket") != std::string::npos)
            {
                category = "Network";
            }
            else if (lowerName.find("render") != std::string::npos || lowerName.find("draw") != std::string::npos)
            {
                category = "Graphics";
            }
            else if (lowerName.find("sound") != std::string::npos || lowerName.find("audio") != std::string::npos)
            {
                category = "Audio";
            }

            m_impl->m_functionsByType[category].push_back(address);
        }

        LogInfo("Function discovery complete:");
        for (const auto& typeKV : m_impl->m_functionsByType)
        {
            const auto& type = typeKV.first;
            const auto& functions = typeKV.second;
            LogInfo("  " + type + ": " + std::to_string(functions.size()) + " functions");
        }
    }

    void FunctionAnalyzer::InitializeWithTypeInformation()
    {
        LogInfo("=== Initializing with Type Information ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available for type information");
            return;
        }

        auto allClasses = m_impl->m_signatureDatabase->GetAllClasses();
        LogInfo("Found " + std::to_string(allClasses.size()) + " classes in signature database");

        for (const auto& className : allClasses)
        {
            auto classFunctions = m_impl->m_signatureDatabase->FindFunctionsByClass(className);
            LogInfo("Class '" + className + "': " + std::to_string(classFunctions.size()) + " functions");

            std::vector<uintptr_t> classAddresses;
            for (const auto& func : classFunctions)
            {
                if (func.resolvedAddress != 0)
                {
                    classAddresses.push_back(func.resolvedAddress);
                }
            }
            m_impl->m_functionsByType["Class_" + className] = classAddresses;
        }

        m_impl->m_typeInfoInitialized = true;
        LogInfo("Type information initialization complete");
    }

    void FunctionAnalyzer::DiscoverFunctionsByType(const std::string& className)
    {
        LogInfo("=== Discovering Functions by Type: " + className + " ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available");
            return;
        }

        auto classFunctions = m_impl->m_signatureDatabase->FindFunctionsByClass(className);
        LogInfo("Found " + std::to_string(classFunctions.size()) + " functions for class " + className);

        std::vector<uintptr_t> resolvedAddresses;
        for (const auto& func : classFunctions)
        {
            if (func.resolvedAddress != 0)
            {
                resolvedAddresses.push_back(func.resolvedAddress);

                std::stringstream ss;
                ss << "  " << func.functionName << " -> 0x" << std::hex << func.resolvedAddress;
                LogInfo(ss.str());

                m_impl->m_discoveredFunctionNames[func.resolvedAddress] = className + "::" + func.functionName;
            }
            else
            {
                LogInfo("  " + func.functionName + " (unresolved)");
            }
        }

        m_impl->m_functionsByType[className] = resolvedAddresses;

        auto derivedClasses = m_impl->m_signatureDatabase->GetDerivedClasses(className);
        if (!derivedClasses.empty())
        {
            LogInfo("Found " + std::to_string(derivedClasses.size()) + " derived classes:");
            for (const auto& derived : derivedClasses)
            {
                LogInfo("  - " + derived);
            }
        }
    }

    void FunctionAnalyzer::AnalyzeVirtualFunctionTables()
    {
        LogInfo("=== Analyzing Virtual Function Tables ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available for VTable analysis");
            return;
        }

        m_impl->m_vtables.clear();

        auto allClasses = m_impl->m_signatureDatabase->GetAllClasses();

        for (const auto& className : allClasses)
        {
            auto virtualFuncs = m_impl->m_signatureDatabase->GetVirtualFunctions(className);

            if (!virtualFuncs.empty())
            {
                LogInfo("Class " + className + " has " + std::to_string(virtualFuncs.size()) + " virtual functions");

                std::vector<uintptr_t> vtableEntries;

                for (const auto& virtFunc : virtualFuncs)
                {
                    auto classFunctions = m_impl->m_signatureDatabase->FindFunctionsByClass(className);

                    for (const auto& func : classFunctions)
                    {
                        if (func.functionName == virtFunc && func.resolvedAddress != 0)
                        {
                            vtableEntries.push_back(func.resolvedAddress);

                            std::stringstream ss;
                            ss << "  Virtual: " << virtFunc << " -> 0x" << std::hex << func.resolvedAddress;
                            LogInfo(ss.str());
                        }
                    }
                }

                if (!vtableEntries.empty())
                {
                    m_impl->m_vtables[vtableEntries[0]] = vtableEntries;
                }
            }
        }

        LogInfo("VTable analysis complete. Found " + std::to_string(m_impl->m_vtables.size()) + " VTables");
    }

    void FunctionAnalyzer::GenerateTypeBasedHooks()
    {
        LogInfo("=== Generating Type-Based Hooks ===");

        if (!m_impl->m_typeInfoInitialized)
        {
            LogWarning("Type information not initialized. Running initialization first...");
            InitializeWithTypeInformation();
        }

        LogInfo("Generating hooks based on discovered types...");

        size_t totalHooks = 0;
        for (const auto& typeKV : m_impl->m_functionsByType)
        {
            const auto& typeName = typeKV.first;
            const auto& functions = typeKV.second;
            if (functions.empty()) continue;

            LogInfo("Type '" + typeName + "': " + std::to_string(functions.size()) + " potential hooks");

            bool shouldHook = false;
            std::string lowerType = typeName;
            std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), ::tolower);

            if (lowerType.find("ui") != std::string::npos ||
                lowerType.find("input") != std::string::npos ||
                lowerType.find("event") != std::string::npos ||
                lowerType.find("message") != std::string::npos)
            {
                shouldHook = true;
            }

            if (shouldHook)
            {
                for (uintptr_t addr : functions)
                {
                    std::string funcName = "Unknown";
                    auto it = m_impl->m_discoveredFunctionNames.find(addr);
                    if (it != m_impl->m_discoveredFunctionNames.end())
                    {
                        funcName = it->second;
                    }

                    std::stringstream ss;
                    ss << "  Generated hook target: " << funcName << " at 0x" << std::hex << addr;
                    LogInfo(ss.str());
                    totalHooks++;
                }
            }
        }

        LogInfo("Type-based hook generation complete. " + std::to_string(totalHooks) + " potential hooks identified");
    }

    void FunctionAnalyzer::DiagnoseSignatureIssues()
    {
        LogInfo("=== Diagnosing Signature Issues ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available for diagnosis");
            return;
        }

        size_t totalSigs = m_impl->m_signatureDatabase->GetTotalSignatures();
        size_t resolvedSigs = m_impl->m_signatureDatabase->GetResolvedSignatures();
        size_t unresolvedSigs = totalSigs - resolvedSigs;

        LogInfo("Signature Resolution Status:");
        LogInfo("  Total signatures: " + std::to_string(totalSigs));
        LogInfo("  Resolved: " + std::to_string(resolvedSigs));
        LogInfo("  Unresolved: " + std::to_string(unresolvedSigs));

        if (unresolvedSigs > 0)
        {
            LogWarning("Found " + std::to_string(unresolvedSigs) + " unresolved signatures");

            auto allClasses = m_impl->m_signatureDatabase->GetAllClasses();

            for (const auto& className : allClasses)
            {
                auto classFunctions = m_impl->m_signatureDatabase->FindFunctionsByClass(className);

                size_t classTotal = classFunctions.size();
                size_t classResolved = 0;

                for (const auto& func : classFunctions)
                {
                    if (func.resolvedAddress != 0)
                    {
                        classResolved++;
                    }
                }

                if (classTotal > 0)
                {
                    float resolutionRate = (float)classResolved / classTotal * 100.0f;
                    LogInfo("Class " + className + ": " + std::to_string(classResolved) + "/" +
                        std::to_string(classTotal) + " (" + std::to_string(resolutionRate) + "%)");

                    if (resolutionRate < 50.0f)
                    {
                        LogWarning("  Low resolution rate for class " + className);
                    }
                }
            }
        }

        const auto& globalSigs = m_impl->m_signatureDatabase->GetGlobalSignatures();
        for (const auto& kv : globalSigs)
        {
            const auto& name = kv.first;
            const auto& sig  = kv.second;

            if (sig.signature.length() < 10)
            {
                LogWarning("Potentially too generic signature: " + name + " (" + sig.signature + ")");
            }
            if (sig.signature.length() > 100)
            {
                LogWarning("Potentially too specific signature: " + name + " (length: " + std::to_string(sig.signature.length()) + ")");
            }
        }
    }

    void FunctionAnalyzer::EnhancedSignatureResolution()
    {
        LogInfo("=== Enhanced Signature Resolution ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available");
            return;
        }

        LogInfo("Starting enhanced resolution process...");

        m_impl->m_signatureDatabase->ResolveAllSignatures();

        size_t resolvedAfterStandard = m_impl->m_signatureDatabase->GetResolvedSignatures();
        LogInfo("Standard resolution completed: " + std::to_string(resolvedAfterStandard) + " signatures resolved");

        LogInfo("Attempting enhanced resolution techniques...");

        auto allClasses = m_impl->m_signatureDatabase->GetAllClasses();

        for (const auto& className : allClasses)
        {
            auto classFunctions = m_impl->m_signatureDatabase->FindFunctionsByClass(className);

            for (const auto& func : classFunctions)
            {
                if (func.resolvedAddress == 0)
                {
                    LogInfo("Attempting enhanced resolution for " + className + "::" + func.functionName);

                    LogInfo("  Signature: " + func.signature);
                    LogInfo("  Return type: " + func.returnType);

                    if (!func.parameterTypes.empty())
                    {
                        std::string params = "";
                        for (const auto& param : func.parameterTypes)
                        {
                            if (!params.empty()) params += ", ";
                            params += param;
                        }
                        LogInfo("  Parameters: " + params);
                    }
                }
            }
        }

        size_t finalResolved = m_impl->m_signatureDatabase->GetResolvedSignatures();
        if (finalResolved > resolvedAfterStandard)
        {
            LogInfo("Enhanced resolution found " + std::to_string(finalResolved - resolvedAfterStandard) + " additional signatures");
        }
        else
        {
            LogInfo("Enhanced resolution did not find additional signatures");
        }
    }

    void FunctionAnalyzer::DebugSignatureScanning()
    {
        LogInfo("=== Debug Signature Scanning ===");

        if (!m_impl->m_signatureDatabase)
        {
            LogError("No signature database available for debug scanning");
            return;
        }

        LogInfo("Starting debug signature scan...");

        HMODULE hModule = GetModuleHandle(nullptr);
        if (!hModule)
        {
            LogError("Cannot get main module handle");
            return;
        }

        MODULEINFO moduleInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo)))
        {
            LogError("Cannot get module information");
            return;
        }

        uintptr_t moduleBase = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
        size_t moduleSize = moduleInfo.SizeOfImage;

        std::stringstream ss;
        ss << "Scanning module: base=0x" << std::hex << moduleBase << ", size=0x" << moduleSize;
        LogInfo(ss.str());

        auto globalSigs = m_impl->m_signatureDatabase->GetGlobalSignatures();
        size_t debugCount = 0;

        for (const auto& kv : globalSigs)
        {
            const auto& name = kv.first;
            const auto& sig = kv.second;

            if (debugCount++ >= 3) break;

            LogInfo("Debug scanning signature: " + name);
            LogInfo("  Pattern: " + sig.signature);
            LogInfo("  Category: " + sig.category);

            if (sig.resolvedAddress != 0)
            {
                std::stringstream s1;
                s1 << "  Already resolved to: 0x" << std::hex << sig.resolvedAddress;
                LogInfo(s1.str());

                if (sig.resolvedAddress >= moduleBase && sig.resolvedAddress < moduleBase + moduleSize)
                {
                    LogInfo("  Address is within module bounds");

                    uint8_t memoryBytes[2] = { 0 };
                    if (SafeReadMemoryBytes(sig.resolvedAddress, memoryBytes, 2))
                    {
                        std::stringstream s2;
                        s2 << "  First bytes at address: 0x" << std::hex
                            << std::setfill('0') << std::setw(2) << static_cast<int>(memoryBytes[0])
                            << " 0x" << std::setw(2) << static_cast<int>(memoryBytes[1]);
                        LogInfo(s2.str());
                    }
                    else
                    {
                        LogWarning("  Cannot read memory at resolved address");
                    }
                }
                else
                {
                    LogWarning("  Resolved address is outside module bounds");
                }
            }
            else
            {
                LogInfo("  Not yet resolved");
            }
        }

        LogInfo("Debug signature scanning complete");
    }

}   