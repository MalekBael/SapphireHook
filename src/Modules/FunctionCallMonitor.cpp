#include "../Modules/FunctionCallMonitor.h"
#include "../Analysis/PatternScanner.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include "../Core/ResourceLoader.h"
#include "../Analysis/FunctionScanner.h"
#include "FunctionAnalyzer.h"

#include <iomanip>
#include <sstream>
#include <map>
#include <algorithm>
#include <string>
#include <vector>
#include <set>
#include <cstdlib>
#include <cmath>
#include <thread>
#include <chrono>
#include <atomic>
#include <fstream>
#include <regex>
#include <cctype>    
#include <locale>    
#include <random>
#include <future>
#include <unordered_map>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <Psapi.h>

#include "../Helper/WindowsAPIWrapper.h"

#ifdef _MSC_VER
#pragma intrinsic(_ReturnAddress)
#endif

using namespace SapphireHook;

static bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize)
{
    baseAddress = 0;
    moduleSize = 0;

    HMODULE hModule = ::GetModuleHandleW(nullptr);
    if (!hModule)
        return false;

    MODULEINFO moduleInfo{};
    if (!::GetModuleInformation(::GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo)))
        return false;

    baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
    moduleSize = static_cast<size_t>(moduleInfo.SizeOfImage);
    return true;
}

namespace SapphireHook {
    class AdvancedHookManager {
    public:
        struct HookConfig {
            std::string context;
        };

        bool IsSafeAddress(uintptr_t address)
        {
            if (address == 0) return false;

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
                return false;

            const bool committed = (mbi.State == MEM_COMMIT);
            const bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

            uintptr_t base = 0;
            size_t size = 0;
            if (GetMainModuleInfo(base, size) && base != 0 && size != 0)
            {
                if (!(address >= base && address < (base + size)))
                    return false;
            }

            return committed && executable;
        }

        void SetupFunctionHooks() { LogInfo("AdvancedHookManager: SetupFunctionHooks called"); }
        void HookCommonAPIs() { LogInfo("AdvancedHookManager: HookCommonAPIs called"); }
        void HookFunctionByAddress(uintptr_t address, const std::string& name, const HookConfig& config) {
            LogInfo("AdvancedHookManager: HookFunctionByAddress called for " + name + " [" + config.context + "]");
        }
        void HookRandomFunctions(int count) { LogInfo("AdvancedHookManager: HookRandomFunctions called count=" + std::to_string(count)); }
        void UnhookAllFunctions() { LogInfo("AdvancedHookManager: UnhookAllFunctions called"); }
        
        static void FunctionHookCallback(uintptr_t , uintptr_t ) {
            LogDebug("AdvancedHookManager: FunctionHookCallback called");
        }
    };
}

static std::string GetExecutableDirectory()
{
    wchar_t wpath[MAX_PATH] = { 0 };
    DWORD len = ::GetModuleFileNameW(nullptr, wpath, MAX_PATH);
    if (len == 0) return "";

    std::wstring wstr(wpath);
    size_t pos = wstr.find_last_of(L"\\/");

    std::wstring wdir = (pos == std::wstring::npos) ? wstr : wstr.substr(0, pos);
    if (wdir.empty()) return "";

    int needed = WideCharToMultiByte(CP_UTF8, 0, wdir.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return "";

    std::string dir(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wdir.c_str(), -1, &dir[0], needed, nullptr, nullptr);

    if (!dir.empty() && dir.back() == '\0') dir.pop_back();
    return dir;
}

std::string LoadResourceData(const std::string& resourceName)
{
    LogInfo("LoadResourceData: looking for '" + resourceName + "' next to executable");

    std::string exeDir = GetExecutableDirectory();
    if (exeDir.empty())
    {
        LogError("Could not determine executable directory; expecting " + resourceName + " next to ffxiv_dx11.exe");
        return "";
    }

    std::string candidatePath = exeDir + "\\" + resourceName;
    std::ifstream in(candidatePath, std::ios::binary);
    if (!in)
    {
        LogError("Required file not found: " + candidatePath);
        return "";
    }

    std::ostringstream ss;
    ss << in.rdbuf();
    LogInfo("Loaded " + resourceName + " from: " + candidatePath);
    return ss.str();
}

FunctionCallMonitor* FunctionCallMonitor::s_instance = nullptr;

struct HookInfo {
    std::string name;
    std::string context;
    void* originalFunction;
    uintptr_t address;

    HookInfo() : name(""), context(""), originalFunction(nullptr), address(0) {}
    HookInfo(const std::string& n, const std::string& c, void* orig, uintptr_t addr)
        : name(n), context(c), originalFunction(orig), address(addr)
    {
    }
};

static std::map<uintptr_t, HookInfo> g_hookMap;
static std::set<uintptr_t> g_attemptedHooks;
static uintptr_t g_moduleBase = 0;
static size_t g_moduleSize = 0;
static std::map<uintptr_t, void*> g_originalFunctions;

static inline uintptr_t RelocateIfIDA(uintptr_t addr)
{
    constexpr uintptr_t IDA_BASE = 0x0000000140000000ULL;
    if (addr >= IDA_BASE && addr < (IDA_BASE + 0x10000000ULL))   
    {
        if (g_moduleBase != 0) {
            return (addr - IDA_BASE) + g_moduleBase;
        }
    }
    return addr;
}

bool IsLikelyFunctionName(const std::string& str)
{
    if (str.length() < 3 || str.length() > 128) return false;

    std::vector<std::string> commonPrefixes = {
        "get", "set", "is", "has", "can", "should", "will", "create", "destroy",
        "init", "update", "render", "process", "handle", "execute", "run", "start",
        "stop", "pause", "resume", "load", "save", "open", "close", "begin", "end",
        "add", "remove", "delete", "clear", "reset", "enable", "disable", "toggle",
        "find", "search", "locate", "check", "test", "validate", "verify", "parse",
        "build", "construct", "generate", "calculate", "compute", "convert", "transform"
    };

    std::vector<std::string> commonKeywords = {
        "Manager", "Service", "Handler", "Controller", "Processor", "ExdData", "Engine",
        "System", "Factory", "Builder", "Parser", "Scanner", "Monitor", "Logger",
        "Player", "Audio", "Sound", "Music", "Video", "Graphics", "Render", "Draw",
        "Network", "Client", "Server", "Connection", "Socket", "Protocol", "HTTP",
        "UI", "GUI", "Window", "Dialog", "Menu", "Button", "Text", "Input", "Output",
        "File", "Stream", "Buffer", "Cache", "Memory", "Database", "Table", "Query",
        "Event", "Message", "Signal", "Callback", "Listener", "Observer", "Timer",
        "Thread", "Task", "Job", "Worker", "Queue", "Pool", "Lock", "Mutex",
        "Game", "World", "Scene", "Object", "Entity", "Component", "Actor", "Player",
        "Character", "Item", "Weapon", "Skill", "Quest", "Mission", "Level", "Map"
    };

    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
        [](unsigned char c) { return std::tolower(c); });

    for (const auto& prefix : commonPrefixes)
    {
        if (lowerStr.find(prefix) == 0) return true;
    }

    for (const auto& keyword : commonKeywords)
    {
        std::string lowerKeyword = keyword;
        std::transform(lowerKeyword.begin(), lowerKeyword.end(), lowerKeyword.begin(),
            [](unsigned char c) { return std::tolower(c); });
        if (lowerStr.find(lowerKeyword) != std::string::npos) return true;
    }

    bool hasUpperCase = false;
    bool hasLowerCase = false;
    int upperCaseCount = 0;

    for (char c : str)
    {
        unsigned char uc = static_cast<unsigned char>(c);

        if (std::isupper(uc))
        {
            hasUpperCase = true;
            upperCaseCount++;
        }
        if (std::islower(uc)) hasLowerCase = true;
        if (!std::isalnum(uc) && c != '_' && c != ':' && c != '.') return false;
    }

    if (hasUpperCase && hasLowerCase && upperCaseCount >= 2) return true;

    if (str.find("::") != std::string::npos) return true;

    return false;
}

extern "C" bool TestMemoryAccess(const void* address, size_t size)
{
    __try
    {
        volatile unsigned char test = *static_cast<const unsigned char*>(address);
        if (size > 1)
        {
            test = static_cast<const unsigned char*>(address)[size - 1];
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

extern "C" bool AnalyzeFunctionCode(uintptr_t address, bool* looksLikeFunction)
{
    __try
    {
        uint8_t* code = reinterpret_cast<uint8_t*>(address);
        *looksLikeFunction = false;

        if ((code[0] == 0x48 && code[1] == 0x89) ||
            (code[0] == 0x48 && code[1] == 0x83) ||
            (code[0] == 0x40 && code[1] >= 0x53 && code[1] <= 0x57) ||
            (code[0] == 0x48 && code[1] == 0x8B) ||
            (code[0] == 0x55) ||
            (code[0] == 0x53))
        {
            *looksLikeFunction = true;
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

FunctionCallMonitor::FunctionCallMonitor()
    : m_useFunctionDatabase(true), m_maxEntries(500), m_autoScroll(true),
    m_showAddresses(true), m_showTimestamps(true), m_windowOpen(false),
    m_enableRealHooking(false)
{
    m_functionScanner = std::make_shared<SapphireHook::FunctionScanner>();
    m_functionAnalyzer = std::make_shared<SapphireHook::FunctionAnalyzer>();
    m_hookManager = std::make_shared<SapphireHook::AdvancedHookManager>();
}

std::vector<uintptr_t> FunctionCallMonitor::ScanForFunctionsByStrings(const std::vector<std::string>& searchStrings)
{
    return m_functionScanner->ScanForFunctionsByStrings(searchStrings);
}

std::vector<uintptr_t> FunctionCallMonitor::ScanForAllInterestingFunctions()
{
    return m_functionScanner->ScanForAllInterestingFunctions();
}

std::vector<uintptr_t> FunctionCallMonitor::ScanForAllFunctions()
{
    return m_functionScanner->ScanForAllFunctions();
}

std::vector<SapphireHook::StringScanResult> FunctionCallMonitor::ScanMemoryForFunctionStrings(const std::vector<std::string>& targetStrings)
{
    return m_functionScanner->ScanMemoryForFunctionStrings(targetStrings);
}

bool FunctionCallMonitor::IsSafeMemoryAddress(const void* address, size_t size)
{
    return m_functionScanner->IsSafeMemoryAddress(address, size);
}

bool FunctionCallMonitor::IsSafeAddress(uintptr_t address)
{
    return m_hookManager->IsSafeAddress(address);
}

uintptr_t FunctionCallMonitor::FindFunctionStart(uintptr_t address)
{
    return m_functionScanner->FindFunctionStart(address);
}

uintptr_t FunctionCallMonitor::ResolveManualAddress(const std::string& input)
{
    return m_functionAnalyzer->ResolveManualAddress(input);
}

bool FunctionCallMonitor::ParseAddressInput(const std::string& input, uintptr_t& result)
{
    return m_functionAnalyzer->ParseAddressInput(input, result);
}

uintptr_t FunctionCallMonitor::ConvertRVAToRuntimeAddress(uintptr_t rva)
{
    return m_functionAnalyzer->ConvertRVAToRuntimeAddress(rva);
}

void FunctionCallMonitor::RenderMenu()
{
    if (ImGui::MenuItem(GetDisplayName(), nullptr, m_windowOpen))
    {
        m_windowOpen = !m_windowOpen;
        LogInfo("Function Call Monitor menu item clicked! Window is now " +
            std::string(m_windowOpen ? "OPEN" : "CLOSED"));
    }
}

void FunctionCallMonitor::RenderWindow()
{
    if (!m_windowOpen) return;

    ImGui::SetNextWindowSize(ImVec2(1200, 800), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin(GetDisplayName(), &m_windowOpen))
    {
        if (ImGui::BeginTabBar("MainTabs"))
        {
            if (ImGui::BeginTabItem("Function Monitor"))
            {
                RenderFunctionListWithPagination();
                ImGui::EndTabItem();
            }
            
            if (ImGui::BeginTabItem("Data Browser"))
            {
                RenderDataBrowser();
                ImGui::EndTabItem();
            }
            
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void FunctionCallMonitor::RenderDataBrowser()
{
    ImGui::Text("Data Browser");

    if (ImGui::BeginTabBar("DataTabs"))
    {
        if (ImGui::BeginTabItem("Function Database"))
        {
            RenderFunctionDatabaseBrowser();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Signature Database"))
        {
            RenderSignatureDatabaseBrowser();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Search & Scan"))
        {
            RenderEnhancedFunctionSearch();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Combined View"))
        {
            RenderCombinedDatabaseView();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Memory Scan"))
        {
            RenderMemoryScanTab();
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }
}

void FunctionCallMonitor::RenderFunctionDatabaseBrowser()
{
    static char searchBuffer[256] = "";
    static bool showOnlyValid = true;
    static std::string selectedCategory = "All";

    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.8f, 1.0f), "Function Database Browser");
    ImGui::Separator();

    if (m_functionDatabaseLoaded)
    {
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Database Status: LOADED (%zu functions)",
            m_functionDB.GetFunctionCount());
    }
    else
    {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Database Status: NOT LOADED");
        if (ImGui::Button("Reload Database"))
        {
            ReloadDatabase();
        }
        return;
    }

    ImGui::PushItemWidth(200);
    ImGui::InputTextWithHint("##search", "Search functions...", searchBuffer, sizeof(searchBuffer));
    ImGui::SameLine();
    ImGui::Checkbox("Show only valid", &showOnlyValid);
    ImGui::PopItemWidth();

    if (ImGui::BeginCombo("Category", selectedCategory.c_str()))
    {
        if (ImGui::Selectable("All", selectedCategory == "All"))
        {
            selectedCategory = "All";
        }
        auto categories = m_functionDB.GetCategories();
        for (const auto& [catName, catDesc] : categories)
        {
            bool sel = (selectedCategory == catName);
            if (ImGui::Selectable(catName.c_str(), sel))
            {
                selectedCategory = catName;
            }
            if (sel) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
    {
        ReloadDatabase();
    }

    ImGui::Separator();

    if (ImGui::BeginTable("FunctionDatabaseTable", 4,
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders))
    {

        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableHeadersRow();

        auto allFunctions = m_functionDB.GetAllFunctions();
        std::string searchStr = std::string(searchBuffer);
        std::transform(searchStr.begin(), searchStr.end(), searchStr.begin(), ::tolower);

        for (const auto& [address, funcInfo] : allFunctions)
        {
            const uintptr_t relocated = RelocateIfIDA(address);
            if (selectedCategory != "All" && funcInfo.category != selectedCategory)
            {
                continue;
            }

            if (showOnlyValid)
            {
                if (g_moduleBase != 0 && g_moduleSize != 0)
                {
                    if (!(relocated >= g_moduleBase && relocated < (g_moduleBase + g_moduleSize)))
                    {
                        continue;
                    }
                }
                else if (address == 0)
                {
                    continue;
                }
            }

            if (!searchStr.empty())
            {
                std::string lowerName = funcInfo.name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                if (lowerName.find(searchStr) == std::string::npos) continue;
            }

            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::Text("0x%016llX", static_cast<unsigned long long>(relocated));

            ImGui::TableNextColumn();
            ImGui::Text("%s", funcInfo.name.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%s", funcInfo.category.empty() ? "Unknown" : funcInfo.category.c_str());

            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(address));
            if (ImGui::SmallButton("Hook"))
            {
                CreateSafeLoggingHook(relocated, funcInfo.name, "DatabaseBrowser");
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Debug"))
            {
                ValidateAndDebugAddress(relocated, funcInfo.name);
            }
            ImGui::PopID();
        }

        ImGui::EndTable();
    }
}

void FunctionCallMonitor::RenderSignatureDatabaseBrowser()
{
    ImGui::TextColored(ImVec4(0.8f, 0.9f, 1.0f, 1.0f), "Signature Database Browser");
    ImGui::Separator();

    if (!m_signatureDatabaseLoaded)
    {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Signature database not loaded");
        if (ImGui::Button("Reload Signature Database"))
        {
            ReloadSignatureDatabase();
        }
        return;
    }

    const size_t totalSigs = m_signatureDB.GetTotalSignatures();
    const size_t resolvedSigs = m_signatureDB.GetResolvedSignatures();
    ImGui::Text("Resolved: %zu / %zu (%.1f%%)", resolvedSigs, totalSigs, totalSigs ? (100.0f * resolvedSigs / totalSigs) : 0.0f);

    ImGui::SameLine();
    if (ImGui::Button("Resolve All"))
    {
        m_signatureDB.ResolveAllSignatures();
    }
    ImGui::SameLine();
    if (ImGui::Button("Async Resolve"))
    {
        StartAsyncSignatureResolution();
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload"))
    {
        ReloadSignatureDatabase();
    }

    static char searchBuffer[256] = "";
    ImGui::PushItemWidth(250);
    ImGui::InputTextWithHint("##sigsearch", "Filter by name (regex supported)", searchBuffer, sizeof(searchBuffer));
    ImGui::PopItemWidth();

    ImGui::Separator();

    if (ImGui::BeginTable("SignatureResolvedTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableHeadersRow();

        std::string filter = searchBuffer;
        std::transform(filter.begin(), filter.end(), filter.begin(), ::tolower);

        auto resolved = m_signatureDB.GetResolvedFunctions();
        for (const auto& [addr, name] : resolved)
        {
            if (!filter.empty())
            {
                std::string lowerName = name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                if (lowerName.find(filter) == std::string::npos) continue;
            }

            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::Text("0x%016llX", static_cast<unsigned long long>(addr));

            ImGui::TableNextColumn();
            ImGui::Text("%s", name.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("Signature");

            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(addr));
            if (ImGui::SmallButton("Hook"))
            {
                CreateSafeLoggingHook(addr, name, "SigBrowser");
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Analyze"))
            {
                ValidateAndDebugAddress(addr, name);
            }
            ImGui::PopID();
        }

        ImGui::EndTable();
    }
}

void FunctionCallMonitor::RenderCombinedDatabaseView()
{
    static char searchBuffer[256] = "";
    static bool showFunctionDb = true;
    static bool showSignatureDb = true;
    static bool showOnlyMatching = false;
    
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "Combined Database View");
    ImGui::Separator();
    
    if (m_functionDatabaseLoaded && m_signatureDatabaseLoaded) {
        auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
        
        ImGui::Text("Function DB: %zu functions | Signature DB: %zu resolved", 
                   m_functionDB.GetFunctionCount(), resolvedSigs.size());
    } else {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), 
                          "One or both databases not loaded");
        return;
    }
    
    ImGui::PushItemWidth(200);
    ImGui::InputTextWithHint("##search", "Search all functions...", searchBuffer, sizeof(searchBuffer));
    ImGui::PopItemWidth();
    
    ImGui::SameLine();
    ImGui::Checkbox("Function DB", &showFunctionDb);
    ImGui::SameLine();
    ImGui::Checkbox("Signature DB", &showSignatureDb);
    ImGui::SameLine();
    ImGui::Checkbox("Only matching", &showOnlyMatching);
    
    ImGui::Separator();
    
    if (ImGui::BeginTable("CombinedDatabaseTable", 5, 
                         ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders)) {
        
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableHeadersRow();
        
        std::string searchStr = std::string(searchBuffer);
        std::transform(searchStr.begin(), searchStr.end(), searchStr.begin(), ::tolower);
        
        if (showSignatureDb) {
            auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
            
            for (const auto& [address, name] : resolvedSigs) {
                if (!searchStr.empty()) {
                    std::string lowerName = name;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                    if (lowerName.find(searchStr) == std::string::npos) continue;
                }
                
                ImGui::TableNextRow();
                
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(0.8f, 0.0f, 1.0f, 1.0f), "SIG");
                
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", address);
                
                ImGui::TableNextColumn();
                ImGui::Text("%s", name.c_str());
                
                ImGui::TableNextColumn();
                ImGui::Text("Signature");
                
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(address));
                if (ImGui::SmallButton("Hook")) {
                    CreateSafeLoggingHook(address, name, "CombinedView");
                }
                if (ImGui::SmallButton("Analyze")) {
                    ValidateAndDebugAddress(address, name);
                }
                ImGui::PopID();
            }
        }
        
        if (showFunctionDb && !showOnlyMatching) {
            auto categories = m_functionDB.GetCategories();
            for (const auto& [catName, catDesc] : categories) {
                auto funcsInCat = m_functionDB.GetFunctionsByCategory(catName);
                
                for (const auto& funcName : funcsInCat) {
                    if (!searchStr.empty()) {
                        std::string lowerName = funcName;
                        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                        if (lowerName.find(searchStr) == std::string::npos) continue;
                    }
                    
                    ImGui::TableNextRow();
                    
                    ImGui::TableNextColumn();
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.8f, 1.0f), "FUNC");
                    
                    ImGui::TableNextColumn();
                    ImGui::Text("Unknown");
                    
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", funcName.c_str());
                    
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", catName.c_str());
                    
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("No Address");
                }
            }
        }
        
        ImGui::EndTable();
    }
}

void FunctionCallMonitor::RenderEnhancedFunctionSearch()
{
    static char searchTerms[1024] = "";
    static bool searchInMemory = true;
    static bool searchInDatabase = true;
    static bool searchInSignatures = true;
    static bool includePartialMatches = true;
    static int maxResults = 100;
    static std::vector<uintptr_t> searchResults;
    static bool isSearching = false;
    static int lastNameScanCount = 0;
    static std::future<std::vector<uintptr_t>> scanFuture;
    static std::string scanStatus = "";

    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Enhanced Function Search");
    ImGui::Separator();
    
    ImGui::Text("Search Options:");
    ImGui::Checkbox("Search in memory", &searchInMemory);
    ImGui::SameLine();
    ImGui::Checkbox("Search in database", &searchInDatabase);
    ImGui::SameLine();
    ImGui::Checkbox("Search in signatures", &searchInSignatures);
    
    ImGui::Checkbox("Include partial matches", &includePartialMatches);
    ImGui::SameLine();
    ImGui::PushItemWidth(100);
    ImGui::InputInt("Max results", &maxResults);
    ImGui::PopItemWidth();
    
    ImGui::PushItemWidth(-80);
    ImGui::InputTextWithHint("##searchterms", "Enter search terms (blank = scan all strings in memory)...", 
                            searchTerms, sizeof(searchTerms));
    ImGui::PopItemWidth();
    
    // Check async scan status
    if (isSearching && scanFuture.valid()) {
        if (scanFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            try {
                auto asyncResults = scanFuture.get();
                searchResults.insert(searchResults.end(), asyncResults.begin(), asyncResults.end());
                
                // Remove duplicates
                std::sort(searchResults.begin(), searchResults.end());
                searchResults.erase(std::unique(searchResults.begin(), searchResults.end()), searchResults.end());
                
                // Apply max results limit
                if (searchResults.size() > static_cast<size_t>(maxResults)) {
                    searchResults.resize(maxResults);
                }
                
                scanStatus = "Scan complete: " + std::to_string(searchResults.size()) + " functions found";
                LogInfo(scanStatus);
            } catch (const std::exception& e) {
                scanStatus = std::string("Scan error: ") + e.what();
                LogError(scanStatus);
            }
            isSearching = false;
        } else {
            scanStatus = "Scanning memory for all strings...";
        }
    }
     
    ImGui::SameLine();
    if (ImGui::Button("Search") && !isSearching) {
        isSearching = true;
        searchResults.clear();
        bool searchErrored = false;
        scanStatus = "";
          
         std::vector<std::string> terms;
         std::string termsStr = searchTerms;
        
        // Only parse terms if search box is not empty
        if (!termsStr.empty() && termsStr.find_first_not_of(" \t\n\r") != std::string::npos) {
            std::stringstream ss(termsStr);
            std::string term;
            while (std::getline(ss, term, ',')) {
                term.erase(0, term.find_first_not_of(" \t"));
                term.erase(term.find_last_not_of(" \t") + 1);
                if (!term.empty()) {
                    terms.push_back(term);
                }
             }
         }
         
         // If search terms is empty, do comprehensive memory scan asynchronously
         if (terms.empty() && searchInMemory) {
            LogInfo("Starting comprehensive memory scan for ALL strings in memory (async)...");
            isSearching = true;
            scanStatus = "Scanning for ALL strings in memory...";
            
            // Launch async scan to find ALL strings in memory
            scanFuture = std::async(std::launch::async, [this]() {
                std::vector<uintptr_t> results;
                try {
                    LogInfo("Scanning memory sections for any readable strings...");
                    
                    // First, scan for ALL strings in memory sections (.rdata, .data)
                    std::vector<std::string> discoveredStrings;
                    uintptr_t base = 0, size = 0;
                    if (GetMainModuleInfo(base, size)) {
                        // Scan .rdata and .data sections for any strings
                        auto scanStringSection = [&](const char* sectionName) {
                            uintptr_t sectionBase = 0;
                            size_t sectionSize = 0;
                            
                            // This is a simplified approach - you'd need proper PE parsing
                            // For now, let's scan readable memory regions
                            MEMORY_BASIC_INFORMATION mbi{};
                            uintptr_t current = base;
                            
                            while (current < base + size) {
                                if (VirtualQuery(reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi))) {
                                    // Check if this region is readable and not executable (likely data)
                                    const DWORD readable = PAGE_READONLY | PAGE_READWRITE;
                                    if ((mbi.State == MEM_COMMIT) && 
                                        ((mbi.Protect & readable) != 0) &&
                                        ((mbi.Protect & PAGE_EXECUTE) == 0)) {
                                        
                                        // Scan this region for strings
                                        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(current);
                                        size_t regionSize = mbi.RegionSize;
                                        
                                        for (size_t i = 0; i < regionSize - 4; ++i) {
                                            // Look for potential ASCII strings
                                            if (ptr[i] >= 0x20 && ptr[i] <= 0x7E) {
                                                size_t strLen = 0;
                                                while (i + strLen < regionSize && 
                                                       ptr[i + strLen] >= 0x20 && 
                                                       ptr[i + strLen] <= 0x7E &&
                                                       strLen < 256) {
                                                    strLen++;
                                                }
                                                
                                                // Found a string of reasonable length
                                                if (strLen >= 4 && strLen <= 128) {
                                                    std::string found(reinterpret_cast<const char*>(ptr + i), strLen);
                                                    
                                                    // Basic filtering: must contain at least one letter
                                                    bool hasLetter = false;
                                                    for (char c : found) {
                                                        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                                                            hasLetter = true;
                                                            break;
                                                        }
                                                    }
                                                    
                                                    if (hasLetter && discoveredStrings.size() < 5000) {
                                                        discoveredStrings.push_back(found);
                                                    }
                                                    
                                                    i += strLen; // Skip past this string
                                                }
                                            }
                                        }
                                    }
                                    current += mbi.RegionSize;
                                } else {
                                    current += 0x1000; // Move to next page
                                }
                                
                                // Stop if we have enough strings
                                if (discoveredStrings.size() >= 5000) break;
                            }
                        };
                        
                        scanStringSection(".rdata");
                        
                        // Remove duplicates
                        std::sort(discoveredStrings.begin(), discoveredStrings.end());
                        discoveredStrings.erase(std::unique(discoveredStrings.begin(), discoveredStrings.end()), 
                                               discoveredStrings.end());
                        
                        LogInfo("Found " + std::to_string(discoveredStrings.size()) + " unique strings in memory");
                        
                        // Now use these discovered strings to find functions
                        if (!discoveredStrings.empty()) {
                            // Limit to first 500 most interesting strings to avoid timeout
                            if (discoveredStrings.size() > 500) {
                                discoveredStrings.resize(500);
                            }
                            
                            auto scanResults = m_functionScanner->ScanForFunctionsByStrings(discoveredStrings);
                            results.insert(results.end(), scanResults.begin(), scanResults.end());
                        }
                    }
                     
                    // Also do a prologue scan to find even more functions
                     SapphireHook::FunctionScanner::ScanConfig cfg{};
                     cfg.maxResults = 20000; // Higher limit for comprehensive scan
                     auto prologueResults = m_functionScanner->ScanForAllInterestingFunctions(cfg, nullptr);
                     results.insert(results.end(), prologueResults.begin(), prologueResults.end());
                     
                     LogInfo("Total functions found: " + std::to_string(results.size()));
                     
                 } catch (const std::exception& e) {
                     LogError("Async scan exception: " + std::string(e.what()));
                 } catch (...) {
                     LogError("Async scan unknown exception");
                 }
                 return results;
             });
             
         } else if (!terms.empty()) {
             // Normal search with specific terms
             LogInfo("Starting enhanced search with " + std::to_string(terms.size()) + " terms");
             isSearching = true;
             
             if (searchInMemory) {
                 // Launch async for memory search with specific terms
                 scanFuture = std::async(std::launch::async, [this, terms]() {
                     std::vector<uintptr_t> results;
                     try {
                         results = m_functionScanner->ScanForFunctionsByStrings(terms);
                     } catch (const std::exception& e) {
                         LogError("Memory search exception: " + std::string(e.what()));
                     }
                     return results;
                 });
             }
             
             // Database searches can be done synchronously as they're fast
             if (searchInDatabase && m_functionDatabaseLoaded) {
                 auto allFunctions = m_functionDB.GetAllFunctions();
                 for (const auto& [addr, funcInfo] : allFunctions) {
                     for (const auto& searchTerm : terms) {
                         std::string lowerName = funcInfo.name;
                         std::string lowerTerm = searchTerm;
                         std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                         std::transform(lowerTerm.begin(), lowerTerm.end(), lowerTerm.begin(), ::tolower);
                         
                         bool matches = includePartialMatches ? 
                                       (lowerName.find(lowerTerm) != std::string::npos) :
                                       (lowerName == lowerTerm);
                         
                         if (matches) {
                             searchResults.push_back(addr);
                             break;
                         }
                     }
                 }
             }
             
             if (searchInSignatures && m_signatureDatabaseLoaded) {
                 auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
                 for (const auto& [addr, name] : resolvedSigs) {
                     for (const auto& searchTerm : terms) {
                         std::string lowerName = name;
                         std::string lowerTerm = searchTerm;
                         std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                         std::transform(lowerTerm.begin(), lowerTerm.end(), lowerTerm.begin(), ::tolower);
                         
                         bool matches = includePartialMatches ? 
                                       (lowerName.find(lowerTerm) != std::string::npos) :
                                       (lowerName == lowerTerm);
                         
                         if (matches) {
                             searchResults.push_back(addr);
                             break;
                         }
                     }
                 }
             }

            // Synchronous deduplication & limiting (requested re-add).
            // We will dedup again after async memory future completes, so this is cheap now.
            if (!searchResults.empty()) {
                std::sort(searchResults.begin(), searchResults.end());
                searchResults.erase(std::unique(searchResults.begin(), searchResults.end()), searchResults.end());
                if (searchResults.size() > static_cast<size_t>(maxResults)) {
                    searchResults.resize(maxResults);
                }
            }
         } else {
             // No terms and memory search disabled
             LogInfo("No search terms provided and memory search disabled");
         }
         
         if (searchErrored) {
             ImGui::OpenPopup("SearchErrorPopup");
         }
     }
     
     // Display scan status
     if (!scanStatus.empty()) {
         ImGui::SameLine();
         if (isSearching) {
             ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s", scanStatus.c_str());
         } else {
             ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", scanStatus.c_str());
         }
     }
     
     if (ImGui::BeginPopupModal("SearchErrorPopup", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("An exception occurred during memory scanning. "
                           "The scan logic was halted to prevent a crash.\n\n"
                           "Consider narrowing your search terms.");
        if (ImGui::Button("OK")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void FunctionCallMonitor::RenderManualHookSection()
{
    static char addressInput[32] = "";
    static char nameInput[128] = "";
    static bool useRealHooks = false;
    
    ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Manual Hook Creation");
    ImGui::Separator();
    
    ImGui::Text("Create hooks manually by address:");
    
    ImGui::PushItemWidth(150);
    ImGui::InputTextWithHint("##address", "0x7FF123456789", addressInput, sizeof(addressInput));
    ImGui::SameLine();
    ImGui::Text("Address");
    
    ImGui::InputTextWithHint("##name", "Function name (optional)", nameInput, sizeof(nameInput));
    ImGui::SameLine();
    ImGui::Text("Name");
    ImGui::PopItemWidth();
    
    ImGui::Checkbox("Use real hooks (dangerous!)", &useRealHooks);
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Real hooks can crash the game if used incorrectly!");
    }
    
    if (ImGui::Button("Create Hook")) {
        uintptr_t address = 0;
        
        if (ParseAddressInput(std::string(addressInput), address)) {
            std::string hookName = std::string(nameInput);
            if (hookName.empty()) {
                hookName = "ManualHook_" + std::string(addressInput);
            }
            
            bool success = false;
            if (useRealHooks) {
                success = CreateRealLoggingHook(address, hookName, "Manual");
            } else {
                success = CreateSafeLoggingHook(address, hookName, "Manual");
            }
            
            if (success) {
                LogInfo("Created manual hook: " + hookName + " at 0x" + std::to_string(address));
                addressInput[0] = '\0';
                nameInput[0] = '\0';
            }
        } else {
            LogError("Invalid address format: " + std::string(addressInput));
        }
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Validate Address")) {
        uintptr_t address = 0;
        if (ParseAddressInput(std::string(addressInput), address)) {
            std::string name = std::string(nameInput);
            if (name.empty()) name = "ValidationTarget";
            ValidateAndDebugAddress(address, name);
        }
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Analyze Memory")) {
        uintptr_t address = 0;
        if (ParseAddressInput(std::string(addressInput), address)) {
            std::string nearbyStrings = ScanForNearbyStrings(address, 1024);
            LogInfo("Nearby strings for 0x" + std::string(addressInput) + ": " + nearbyStrings);
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Quick Actions:");
    
    if (ImGui::Button("Hook All Database Functions")) {
        if (m_functionDatabaseLoaded) {
            auto allFunctions = m_functionDB.GetAllFunctions();
            int hookedCount = 0;
            for (const auto& [addr, funcInfo] : allFunctions) {
                if (CreateSafeLoggingHook(addr, funcInfo.name, "BulkHook")) {
                    hookedCount++;
                }
                if (hookedCount >= 50) break;     
            }
            LogInfo("Bulk hooked " + std::to_string(hookedCount) + " functions from database");
        }
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Hook All Resolved Signatures")) {
        if (m_signatureDatabaseLoaded) {
            auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
            int hookedCount = 0;
            for (const auto& [addr, name] : resolvedSigs) {
                if (CreateSafeLoggingHook(addr, name, "BulkSignatureHook")) {
                    hookedCount++;
                }
                if (hookedCount >= 50) break;     
            }
            LogInfo("Bulk hooked " + std::to_string(hookedCount) + " functions from signatures");
        }
    }
    
    if (ImGui::Button("Clear All Hooks")) {
        UnhookAllFunctions();
        ClearCalls();
        LogInfo("Cleared all hooks and function calls");
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Scan & Hook Random")) {
        HookRandomFunctions(10);
    }
}

void FunctionCallMonitor::RenderSignatureSection() {
    ImGui::Text("Signature Analysis Section");
    ImGui::Separator();
    
    if (ImGui::Button("Initialize Signatures")) {
        InitializeWithSignatures();
    }
    ImGui::SameLine();
    if (ImGui::Button("Resolve Signatures")) {
        StartAsyncSignatureResolution();
    }
    ImGui::SameLine();
    if (ImGui::Button("Integrate with Database")) {
        IntegrateSignaturesWithDatabase();
    }
    
    if (ImGui::Button("Discover from Signatures")) {
        DiscoverFunctionsFromSignatures();
    }
    ImGui::SameLine();
    if (ImGui::Button("Enhanced Resolution")) {
        EnhancedSignatureResolution();
    }
    ImGui::SameLine();
    if (ImGui::Button("Debug Scanning")) {
        DebugSignatureScanning();
    }
}

void FunctionCallMonitor::RenderTypeAwareFunctionSearch() {
    static char classNameInput[128] = "";
    
    ImGui::Text("Type-Aware Function Search");
    ImGui::Separator();
    
    ImGui::PushItemWidth(200);
    ImGui::InputTextWithHint("##classname", "Enter class name...", classNameInput, sizeof(classNameInput));
    ImGui::PopItemWidth();
    
    ImGui::SameLine();
    if (ImGui::Button("Discover Functions")) {
        if (strlen(classNameInput) > 0) {
            DiscoverFunctionsByType(std::string(classNameInput));
        }
    }
    
    if (ImGui::Button("Initialize Type Info")) {
        InitializeWithTypeInformation();
    }
    ImGui::SameLine();
    if (ImGui::Button("Analyze VTables")) {
        AnalyzeVirtualFunctionTables();
    }
    ImGui::SameLine();
    if (ImGui::Button("Generate Type Hooks")) {
        GenerateTypeBasedHooks();
    }
}

void FunctionCallMonitor::RenderClassHierarchyView() {
    ImGui::Text("Class Hierarchy View - Coming Soon");
    ImGui::Text("This will show object-oriented class structures");
}

void FunctionCallMonitor::RenderVirtualFunctionTable() {
    ImGui::Text("Virtual Function Table Viewer - Coming Soon");
    ImGui::Text("This will show VTable layouts and virtual function addresses");
}

void FunctionCallMonitor::Initialize()
{
    LogInfo("FunctionCallMonitor initialized");
    s_instance = this;
    
    if (!GetMainModuleInfo(g_moduleBase, g_moduleSize))
    {
        LogError("Failed to get main module information");
    }
    else
    {
        LogInfo("Module base: 0x" + std::to_string(g_moduleBase) + ", size: 0x" + std::to_string(g_moduleSize));
    }
    
    LoadDatabasesWithErrorHandling();
    
    if (m_functionScanner && m_functionAnalyzer && m_hookManager) {
        auto funcDb = std::make_shared<SapphireHook::FunctionDatabase>();
        auto sigDb = std::make_shared<SapphireHook::SignatureDatabase>();
        
        m_functionScanner->SetFunctionDatabase(funcDb);
        m_functionAnalyzer->SetFunctionDatabase(funcDb);
        
        m_functionScanner->SetSignatureDatabase(sigDb);
        m_functionAnalyzer->SetSignatureDatabase(sigDb);
        
        m_hookManager->SetupFunctionHooks();
    }
}

void FunctionCallMonitor::LoadDatabasesWithErrorHandling()
{
    try
    {
        if (!m_functionDB.Load("data.json")) {
            m_functionDatabaseLoaded = m_functionDB.Load("data\\data.json");
        } else {
            m_functionDatabaseLoaded = true;
        }
         if (m_functionDatabaseLoaded)
         {
             LogInfo("Function database loaded successfully");
         }
         else
         {
             LogWarning("Function database failed to load");
         }
     }
     catch (const std::exception& e)
     {
         LogError("Exception loading function database: " + std::string(e.what()));
         m_functionDatabaseLoaded = false;
     }
    
    try
    {
        static const char* sigCandidates[] = {
            "data-sig.json",
            "data\\data-sig.json",
            "signatures.json",
            "data\\signatures.json"
        };
        m_signatureDatabaseLoaded = false;
        for (auto cand : sigCandidates) {
            if (m_signatureDB.Load(cand)) {
                LogInfo(std::string("Signature database loaded from: ") + cand);
                m_signatureDatabaseLoaded = true;
                break;
            }
        }
         if (m_signatureDatabaseLoaded)
         {
            LogInfo("Signature database loaded successfully");
         }
         else
         {
            LogWarning("Signature database failed to load - expected a file like data-sig.json or data\\data-sig.json");
         }
     }
     catch (const std::exception& e)
     {
         LogError("Exception loading signature database: " + std::string(e.what()));
         m_signatureDatabaseLoaded = false;
     }
}

void FunctionCallMonitor::ReloadDatabase()
{
    LogInfo("Reloading function database...");
    m_functionDatabaseLoaded = m_functionDB.Load("data.json");
    if (m_functionDatabaseLoaded)
    {
        LogInfo("Function database reloaded successfully");
    }
    else
    {
        LogError("Failed to reload function database");
    }
}

void FunctionCallMonitor::ReloadSignatureDatabase()
{
    LogInfo("Reloading signature database...");
    static const char* sigCandidates[] = {
        "data-sig.json",
        "data\\data-sig.json",
        "signatures.json",
        "data\\signatures.json"
    };
    m_signatureDatabaseLoaded = false;
    for (auto cand : sigCandidates) {
        if (m_signatureDB.Load(cand)) {
            LogInfo(std::string("Signature database reloaded from: ") + cand);
            m_signatureDatabaseLoaded = true;
            break;
        }
    }
     if (m_signatureDatabaseLoaded)
     {
         LogInfo("Signature database reloaded successfully");
     }
     else
     {
        LogError("Failed to reload signature database - put your signatures file next to the executable, e.g. data\\data-sig.json");
     }
}

void FunctionCallMonitor::AddFunctionCall(const std::string& name, uintptr_t address, const std::string& context)
{
    std::lock_guard<std::mutex> lock(m_callsMutex);

    FunctionCall call;

    if (m_useFunctionDatabase && m_functionDatabaseLoaded && m_functionDB.HasFunction(address))
    {
        call.functionName = m_functionDB.GetFunctionName(address);
        LogDebug("Using database name: " + call.functionName + " for address 0x" + std::to_string(address));
    }
    else if (!name.empty() && name.find("sub_") != 0)
    {
        call.functionName = name;
    }
    else
    {
        call.functionName = ResolveFunctionName(address);
    }

    call.address = address;
    call.timestamp = std::chrono::steady_clock::now();
    call.context = context;

    m_functionCalls.push_back(call);

    if (m_functionCalls.size() > static_cast<size_t>(m_maxEntries))
    {
        m_functionCalls.erase(m_functionCalls.begin());
    }

    LogDebug(call.functionName + " called at 0x" + std::to_string(address) + " (" + context + ") [DB: " +
        (m_useFunctionDatabase ? "enabled" : "disabled") + ", Total: " + std::to_string(m_functionCalls.size()) + "]");
}

void FunctionCallMonitor::SetDiscoveredFunctions(const std::vector<uintptr_t>& functions)
{
    m_discoveredFunctions = functions;

    if (m_useFunctionDatabase && m_functionDatabaseLoaded && m_functionDB.GetFunctionCount() > 0)
    {
        int namedFunctions = 0;

        for (uintptr_t addr : functions)
        {
            if (m_functionDB.HasFunction(addr))
            {
                namedFunctions++;

                std::string dbName = m_functionDB.GetFunctionName(addr);
                if (!dbName.empty() && dbName.find("sub_") != 0)
                {
                    m_detectedFunctionNames[addr] = dbName;
                }

                if (namedFunctions <= 10)
                {
                    LogInfo("Database function: " + dbName + " at 0x" + std::to_string(addr));
                }
            }
        }

        LogInfo("Database integration results:");
        LogInfo("* Total discovered functions: " + std::to_string(functions.size()));
        LogInfo("* Functions with database names: " + std::to_string(namedFunctions));
        LogInfo("* Database coverage: " + std::to_string(namedFunctions) + "/" + std::to_string(m_functionDB.GetFunctionCount()) + " database functions found");

        if (namedFunctions > 0)
        {
            float coverage = (float)namedFunctions / m_functionDB.GetFunctionCount() * 100.0f;
            LogInfo("* Database coverage percentage: " + std::to_string(coverage) + "%");
        }
    }
    else
    {
        LogWarning("Function database not available - functions will show as hex addresses");
    }
}

void FunctionCallMonitor::ClearCalls()
{
    std::lock_guard<std::mutex> lock(m_callsMutex);
    m_functionCalls.clear();
    LogInfo("Cleared all function calls");
}

std::string FunctionCallMonitor::ResolveFunctionName(uintptr_t address) const
{
    if (m_useFunctionDatabase && m_functionDatabaseLoaded && m_functionDB.HasFunction(address))
    {
        std::string dbName = m_functionDB.GetFunctionName(address);
        if (!dbName.empty() && dbName.find("sub_") != 0)
        {
            LogDebug("Database resolved 0x" + std::to_string(address) + " to: " + dbName);
            return dbName;
        }
    }

    auto tempIt = m_detectedFunctionNames.find(address);
    if (tempIt != m_detectedFunctionNames.end() && !tempIt->second.empty())
    {
        LogDebug("Memory scan resolved 0x" + std::to_string(address) + " to: " + tempIt->second);
        return tempIt->second;
    }

    if (m_useSignatureDatabase && m_signatureDatabaseLoaded)
    {
        auto resolvedFunctions = m_signatureDB.GetResolvedFunctions();
        auto sigIt = std::find_if(resolvedFunctions.begin(), resolvedFunctions.end(),
            [address](const std::pair<uintptr_t, std::string>& pair)
            {
                return pair.first == address;
            });
        if (sigIt != resolvedFunctions.end() && !sigIt->second.empty())
        {
            LogDebug("Signature resolved 0x" + std::to_string(address) + " to: " + sigIt->second);
            return sigIt->second;
        }
    }

    std::stringstream ss;
    ss << "sub_" << std::hex << std::uppercase << address;

    if (g_moduleBase != 0 && address >= g_moduleBase && address < g_moduleBase + g_moduleSize)
    {
        uintptr_t offset = address - g_moduleBase;
        ss << "_+" << std::hex << offset;
    }

    return ss.str();
}

bool FunctionCallMonitor::CreateFunctionHook(uintptr_t address, const std::string& name, const std::string& context)
{
    if (m_enableRealHooking)
    {
        return CreateRealLoggingHook(address, name, context);
    }
    else
    {
        return CreateSafeLoggingHook(address, name, context);
    }
}

bool FunctionCallMonitor::CreateSafeLoggingHook(uintptr_t address, const std::string& name, const std::string& context)
{
    const uintptr_t target = RelocateIfIDA(address);
    std::stringstream ss; ss << std::hex << std::uppercase << target;
    LogInfo("Creating SAFE logging hook for " + name + " at 0x" + ss.str());

    if (g_attemptedHooks.find(target) != g_attemptedHooks.end())
    {
        LogWarning("Address already hooked, skipping");
        return false;
    }

    g_attemptedHooks.insert(target);

    if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), target) == m_discoveredFunctions.end())
    {
        m_discoveredFunctions.push_back(target);
    }

    AddFunctionCall(name + "_DISCOVERED", target, "SafeDiscovery");

    LogInfo("Safely 'hooked' " + name + " (no actual hook placed)");
    return true;
}

bool FunctionCallMonitor::CreateRealLoggingHook(uintptr_t address, const std::string& name, const std::string& context)
{
    const uintptr_t target = RelocateIfIDA(address);
    std::stringstream ss; ss << std::hex << std::uppercase << target;
    LogInfo("Creating REAL logging hook for " + name + " at 0x" + ss.str());

    if (g_attemptedHooks.find(target) != g_attemptedHooks.end())
    {
        LogWarning("Address already hooked, skipping");
        return false;
    }

    if (!IsSafeAddress(target))
    {
        LogError("Address failed safety checks, aborting real hook");
        return false;
    }

    bool looksLikeFunction = false;
    if (!AnalyzeFunctionCode(target, &looksLikeFunction))
    {
        LogError("Exception while analyzing function");
        return false;
    }

    if (!looksLikeFunction)
    {
        LogWarning("Address 0x" + std::to_string(address) + " doesn't look like a function start - this might hook mid-instruction!");
        uintptr_t actualFunctionStart = FindFunctionStart(target);
        if (actualFunctionStart != target)
        {
            LogInfo("Found potential function start at 0x" + std::to_string(actualFunctionStart) + " instead of 0x" + std::to_string(target));
        }
    }

    g_attemptedHooks.insert(target);

    LogInfo("Successfully 'hooked' " + name + " (placeholder implementation)");
    
    if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), target) == m_discoveredFunctions.end())
    {
        m_discoveredFunctions.push_back(target);
    }

    return true;
}

void FunctionCallMonitor::RenderFunctionListWithPagination()
{
    std::lock_guard<std::mutex> lock(m_callsMutex);
    
    ImGui::Text("Function Calls: %zu", m_functionCalls.size());
    
    if (ImGui::Button("Clear Calls"))
    {
        ClearCalls();
    }
    
    if (ImGui::BeginTable("FunctionCallsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
    {
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Function");
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Context");
        ImGui::TableHeadersRow();
        
        for (const auto& call : m_functionCalls)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("Recent");
            ImGui::TableNextColumn();
            ImGui::Text("%s", call.functionName.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", call.address);
            ImGui::TableNextColumn();
            ImGui::Text("%s", call.context.c_str());
        }
        
        ImGui::EndTable();
    }
}

void FunctionCallMonitor::RenderPaginationControls()
{
    if (ImGui::Button("Previous"))
    {
        if (m_displayStartIndex > 0)
        {
            m_displayStartIndex = std::max(0, m_displayStartIndex - m_displayPageSize);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Next"))
    {
        m_displayStartIndex += m_displayPageSize;
    }
}

bool FunctionCallMonitor::ValidateAndDebugAddress(uintptr_t address, const std::string& name) { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot validate address");
        return false;
    }
    
    if (address == 0) {
        LogWarning("Null address provided for validation: " + name);
        return false;
    }
    
    LogInfo("FunctionCallMonitor: Validating address 0x" + std::to_string(address) + 
           " (" + name + ")");
    
    bool result = m_functionAnalyzer->ValidateAndDebugAddress(address, name);
    
    if (result) {
        LogInfo("Address validation successful for " + name);
    } else {
        LogWarning("Address validation failed for " + name);
    }
    
    return result;
}

std::string FunctionCallMonitor::ScanForNearbyStrings(uintptr_t address, size_t searchRadius) const { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot scan for nearby strings");
        return "SCANNER_NOT_AVAILABLE";
    }
    
    if (address == 0) {
        LogWarning("Null address provided to ScanForNearbyStrings");
        return "NULL_ADDRESS";
    }
    
    if (searchRadius == 0) {
        searchRadius = 1024;   
        LogDebug("Using default search radius: " + std::to_string(searchRadius));
    } else if (searchRadius > 65536) {
        LogWarning("Large search radius (" + std::to_string(searchRadius) + 
                  ") may impact performance");
    }
    
    LogDebug("Scanning for strings near 0x" + std::to_string(address) + 
            " with radius " + std::to_string(searchRadius));
    
    return m_functionScanner->ScanForNearbyStrings(address, searchRadius);
}

void FunctionCallMonitor::InitializeWithSignatures() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot initialize with signatures");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Initializing with signatures...");
    
    if (!m_signatureDatabaseLoaded) {
        LogWarning("Local signature database not loaded - attempting to reload...");
        ReloadSignatureDatabase();
    }
    
    m_functionAnalyzer->InitializeWithSignatures();
    LogInfo("Signature initialization completed");
}

void FunctionCallMonitor::StartAsyncSignatureResolution() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot start signature resolution");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Starting async signature resolution...");
    
    if (!m_signatureDatabaseLoaded) {
        LogWarning("Local signature database not loaded - resolution may be limited");
    }
    
    m_functionAnalyzer->StartAsyncSignatureResolution();
}

void FunctionCallMonitor::IntegrateSignaturesWithDatabase() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot integrate signatures");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Integrating signatures with database...");
    
    if (!m_functionDatabaseLoaded || !m_signatureDatabaseLoaded) {
        LogWarning("One or both databases not loaded - integration may be incomplete");
    }
    
    m_functionAnalyzer->IntegrateSignaturesWithDatabase();
    
    if (m_signatureDatabaseLoaded) {
        auto resolvedFunctions = m_signatureDB.GetResolvedFunctions();
        for (const auto& [addr, name] : resolvedFunctions) {
            if (m_detectedFunctionNames.find(addr) == m_detectedFunctionNames.end()) {
                m_detectedFunctionNames[addr] = name;
            }
        }
        
        LogInfo("Updated local function names with " + std::to_string(resolvedFunctions.size()) + 
               " signature-resolved functions");
    }
}

void FunctionCallMonitor::DiscoverFunctionsFromSignatures() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot discover functions from signatures");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Discovering functions from signatures...");
    
    size_t previousCount = m_discoveredFunctions.size();
    
    m_functionAnalyzer->DiscoverFunctionsFromSignatures();
    
    if (m_signatureDatabaseLoaded) {
        auto resolvedFunctions = m_signatureDB.GetResolvedFunctions();
        for (const auto& [addr, name] : resolvedFunctions) {
            if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), addr) == 
                m_discoveredFunctions.end()) {
                m_discoveredFunctions.push_back(addr);
                m_detectedFunctionNames[addr] = name;
            }
        }
        
        size_t newCount = m_discoveredFunctions.size();
        if (newCount > previousCount) {
            LogInfo("Discovered " + std::to_string(newCount - previousCount) + 
                   " new functions from signatures");
        }
    }
}

void FunctionCallMonitor::InitializeWithTypeInformation() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot initialize with type information");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Initializing with type information...");
    m_functionAnalyzer->InitializeWithTypeInformation();
}

void FunctionCallMonitor::DiscoverFunctionsByType(const std::string& className) { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot discover functions by type");
        return;
    }
    
    if (className.empty()) {
        LogWarning("Empty class name provided to DiscoverFunctionsByType");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Discovering functions for class: " + className);
    m_functionAnalyzer->DiscoverFunctionsByType(className);
}

void FunctionCallMonitor::AnalyzeVirtualFunctionTables() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot analyze VTables");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Analyzing virtual function tables...");
    m_functionAnalyzer->AnalyzeVirtualFunctionTables();
}

void FunctionCallMonitor::GenerateTypeBasedHooks() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot generate type-based hooks");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Generating type-based hooks...");
    m_functionAnalyzer->GenerateTypeBasedHooks();
}

void FunctionCallMonitor::DiagnoseSignatureIssues() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot diagnose signature issues");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Diagnosing signature issues...");
    m_functionAnalyzer->DiagnoseSignatureIssues();
    
    if (m_signatureDatabaseLoaded) {
        auto resolvedFunctions = m_signatureDB.GetResolvedFunctions();
        size_t totalSigs = m_signatureDB.GetTotalSignatures();
        
        LogInfo("Local signature database statistics:");
        LogInfo("  Total signatures: " + std::to_string(totalSigs));
        LogInfo("  Resolved signatures: " + std::to_string(resolvedFunctions.size()));
        
        if (totalSigs > 0) {
            float resolutionRate = (float)resolvedFunctions.size() / totalSigs * 100.0f;
            LogInfo("  Resolution rate: " + std::to_string(resolutionRate) + "%");
        }
    } else {
        LogWarning("Local signature database not loaded - cannot provide local diagnostics");
    }
}

void FunctionCallMonitor::EnhancedSignatureResolution() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot perform enhanced resolution");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Starting enhanced signature resolution...");
    
    size_t resolvedBefore = 0;
    if (m_signatureDatabaseLoaded) {
        resolvedBefore = m_signatureDB.GetResolvedFunctions().size();
    }
    
    m_functionAnalyzer->EnhancedSignatureResolution();
    
    if (m_signatureDatabaseLoaded) {
        size_t resolvedAfter = m_signatureDB.GetResolvedFunctions().size();
        if (resolvedAfter > resolvedBefore) {
            LogInfo("Enhanced resolution found " + std::to_string(resolvedAfter - resolvedBefore) + 
                   " additional signatures");
        } else {
            LogInfo("Enhanced resolution completed - no additional signatures found");
        }
    }
}

void FunctionCallMonitor::DebugSignatureScanning() { 
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot debug signature scanning");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Starting signature scanning debug...");
    m_functionAnalyzer->DebugSignatureScanning();
    
    LogInfo("=== FunctionCallMonitor Debug State ===");
    LogInfo("Function database loaded: " + std::string(m_functionDatabaseLoaded ? "YES" : "NO"));
    LogInfo("Signature database loaded: " + std::string(m_signatureDatabaseLoaded ? "YES" : "NO"));
    LogInfo("Discovered functions count: " + std::to_string(m_discoveredFunctions.size()));
    LogInfo("Detected function names count: " + std::to_string(m_detectedFunctionNames.size()));
    LogInfo("Function calls recorded: " + std::to_string(m_functionCalls.size()));
    
    if (m_functionScanner) {
        LogInfo("FunctionScanner: AVAILABLE");
        LogInfo("Scan in progress: " + std::string(m_functionScanner->IsScanInProgress() ? "YES" : "NO"));
    } else {
        LogInfo("FunctionScanner: NOT AVAILABLE");
    }
    
    if (m_hookManager) {
        LogInfo("HookManager: AVAILABLE");
    } else {
        LogInfo("HookManager: NOT AVAILABLE");
    }
}

void FunctionCallMonitor::HookRandomFunctions(int count) {
    if (!m_functionScanner) {
        LogWarning("Scanner unavailable; cannot hook random functions");
        return;
    }

    SapphireHook::FunctionScanner::ScanConfig cfg{};
    cfg.maxResults = 5000;

    auto all = m_functionScanner->ScanForAllInterestingFunctions(cfg, nullptr);
    if (all.empty()) {
        LogWarning("No functions discovered to hook");
        return;
    }

    std::mt19937_64 rng{ 0xC0FFEEULL };
    std::shuffle(all.begin(), all.end(), rng);

    int hooked = 0;
    for (uintptr_t addr : all) {
        if (hooked >= std::max(1, count)) break;

        if (!m_hookManager->IsSafeAddress(addr)) continue;

        std::string name = ResolveFunctionName(addr);
        if (CreateSafeLoggingHook(addr, name, "RandomHook")) {
            ++hooked;
        }
    }

    LogInfo("Random hook complete: " + std::to_string(hooked) + " functions hooked");
}

void FunctionCallMonitor::UnhookAllFunctions() {
    if (m_hookManager) {
        m_hookManager->UnhookAllFunctions();
    }
}

void FunctionCallMonitor::ScanAllFunctions() {
    auto results = ScanForAllFunctions();
    SetDiscoveredFunctions(results);
}

void FunctionCallMonitor::ScanExportedFunctions(std::vector<uintptr_t>& functions) {
    m_functionScanner->ScanExportedFunctions(functions);
}

void FunctionCallMonitor::ScanCallTargets(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions) {
    m_functionScanner->ScanCallTargets(moduleBase, moduleSize, functions);
}

void FunctionCallMonitor::ScanSafeRegion(uintptr_t baseAddr, size_t size, std::vector<uintptr_t>& functions) {
    m_functionScanner->ScanSafeRegion(baseAddr, size, functions);
}

void FunctionCallMonitor::ScanForFunctionPrologues(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions) {
    m_functionScanner->ScanForFunctionPrologues(moduleBase, moduleSize, functions);
}

void FunctionCallMonitor::ScanForUIFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions) {
    m_functionScanner->ScanForUIFunctions(memory, size, namedFunctions);
}

void FunctionCallMonitor::ScanForNetworkFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions) {
    m_functionScanner->ScanForNetworkFunctions(memory, size, namedFunctions);
}

void FunctionCallMonitor::ScanForGameplayFunctions(const uint8_t* memory, size_t size, std::map<uintptr_t, std::string>& namedFunctions) {
    m_functionScanner->ScanForGameplayFunctions(memory, size, namedFunctions);
}

void FunctionCallMonitor::UpdateTemporaryFunctionDatabase(const std::map<uintptr_t, std::string>& detectedFunctions) {
    m_functionScanner->UpdateTemporaryFunctionDatabase(detectedFunctions);
}

bool FunctionCallMonitor::IsLikelyFunctionStart(uintptr_t address) const
{
    if (!m_functionScanner) return false;
    return m_functionScanner->IsLikelyFunctionStart(address);
}

bool FunctionCallMonitor::IsLikelyFunctionStart(const uint8_t* code, size_t maxSize) const
{
    if (!m_functionScanner) return false;
    return m_functionScanner->IsLikelyFunctionStart(code, maxSize);
}

std::string FunctionCallMonitor::ExtractFunctionNameFromMemory(uintptr_t address) { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot extract function name");
        return "SCANNER_NOT_AVAILABLE";
    }
    
    if (address == 0) {
        LogWarning("Null address provided to ExtractFunctionNameFromMemory");
        return "NULL_ADDRESS";
    }
    
    if (m_functionDatabaseLoaded && m_functionDB.HasFunction(address)) {
        std::string dbName = m_functionDB.GetFunctionName(address);
        LogDebug("Function name found in database: " + dbName);
        return dbName;
    }
    
    if (m_signatureDatabaseLoaded) {
        auto resolvedFunctions = m_signatureDB.GetResolvedFunctions();
        auto it = std::find_if(resolvedFunctions.begin(), resolvedFunctions.end(),
            [address](const auto& pair) { return pair.first == address; });
        
        if (it != resolvedFunctions.end()) {
            LogDebug("Function name found in signature database: " + it->second);
            return it->second;
        }
    }
    
    std::string extractedName = m_functionScanner->ExtractFunctionNameFromMemory(address);
    
    if (!extractedName.empty() && extractedName != "UNKNOWN") {
        LogDebug("Function name extracted from memory: " + extractedName + " at 0x" + 
                std::to_string(address));
    }
    
    return extractedName;
}

bool FunctionCallMonitor::IsValidString(const char* str, size_t maxLen) const { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot validate string");
        return false;
    }
    
    if (!str) {
        LogDebug("Null string pointer provided to IsValidString");
        return false;
    }
    
    if (maxLen == 0) {
        LogDebug("Zero max length provided to IsValidString");
        return false;
    }
    
    return m_functionScanner->IsValidString(str, maxLen);
}

bool FunctionCallMonitor::IsCommittedMemory(uintptr_t address, size_t size) const { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot check memory commitment");
        return false;
    }
    
    if (address == 0) {
        LogDebug("Null address provided to IsCommittedMemory");
        return false;
    }
    
    if (size == 0) {
        LogDebug("Zero size provided to IsCommittedMemory");
        return false;
    }
    
    return m_functionScanner->IsCommittedMemory(address, size);
}

bool FunctionCallMonitor::IsExecutableMemory(uintptr_t address) const { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot check memory execution");
        return false;
    }
    
    if (address == 0) {
        LogDebug("Null address provided to IsExecutableMemory");
        return false;
    }
    
    return m_functionScanner->IsExecutableMemory(address);
}

std::future<std::vector<uintptr_t>> FunctionCallMonitor::StartAsyncScan() { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot start async scan");
        std::promise<std::vector<uintptr_t>> promise;
        promise.set_value(std::vector<uintptr_t>{});
        return promise.get_future();
    }
    
    LogInfo("FunctionCallMonitor: Starting async function scan...");
    
    auto progressCallback = [this](size_t processed, size_t total, const std::string& phase) {
        if (processed % 100 == 0 || processed == total) {
            LogInfo("Scan progress: " + std::to_string(processed) + "/" + std::to_string(total) + 
                   " (" + phase + ")");
        }
    };
    
    return m_functionScanner->StartAsyncScan(SapphireHook::FunctionScanner::ScanConfig{}, progressCallback);
}

std::future<std::vector<uintptr_t>> FunctionCallMonitor::StartAsyncScanWithStrings(const std::vector<std::string>& targetStrings) { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot start string-based async scan");
        std::promise<std::vector<uintptr_t>> promise;
        promise.set_value(std::vector<uintptr_t>{});
        return promise.get_future();
    }
    
    if (targetStrings.empty()) {
        LogWarning("No target strings provided for scan");
    } else {
        LogInfo("FunctionCallMonitor: Starting async string-based scan with " + 
               std::to_string(targetStrings.size()) + " target strings");
        
        for (size_t i = 0; i < std::min(targetStrings.size(), size_t(3)); ++i) {
            LogInfo("  Target string " + std::to_string(i + 1) + ": \"" + targetStrings[i] + "\"");
        }
    }
    
    auto progressCallback = [this](size_t processed, size_t total, const std::string& phase) {
        if (processed % 50 == 0 || processed == total) {
            LogInfo("String scan progress: " + std::to_string(processed) + "/" + std::to_string(total) + 
                   " (" + phase + ")");
        }
    };
    
    return m_functionScanner->StartAsyncScanWithStrings(targetStrings, SapphireHook::FunctionScanner::ScanConfig{}, progressCallback);
}

void FunctionCallMonitor::StopScan() { 
    if (!m_functionScanner) {
        LogWarning("FunctionScanner not initialized - cannot stop scan");
        return;
    }
    
    LogInfo("FunctionCallMonitor: Stopping active scans...");
    m_functionScanner->StopScan();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    if (!m_functionScanner->IsScanInProgress()) {
        LogInfo("Scan stopped successfully");
    } else {
        LogWarning("Scan may still be in progress");
    }
}

// ===================== Missing wrapper / utility implementations (added) =====================

void FunctionCallMonitor::VerifyDatabaseLoading() {
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot verify database loading");
        return;
    }
    m_functionAnalyzer->VerifyDatabaseLoading();
}

void FunctionCallMonitor::TestAndDebugEmbeddedData() {
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot test embedded data");
        return;
    }
    m_functionAnalyzer->TestAndDebugEmbeddedData();
}

void FunctionCallMonitor::DebugAddressSource(uintptr_t address, const std::string& name) {
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot debug address source");
        return;
    }
    m_functionAnalyzer->DebugAddressSource(address, name);
}

void FunctionCallMonitor::DebugIdaAddress(const std::string& address) {
    if (!m_functionAnalyzer) {
        LogError("FunctionAnalyzer not initialized - cannot debug IDA address");
        return;
    }
    m_functionAnalyzer->DebugIdaAddress(address);
}

void FunctionCallMonitor::ValidateDatabase() {
    LogInfo("Validating function & signature database state...");
    if (m_functionDatabaseLoaded)
        LogInfo(" Function DB: loaded (" + std::to_string(m_functionDB.GetFunctionCount()) + " entries)");
    else
        LogWarning(" Function DB: NOT loaded");

    if (m_signatureDatabaseLoaded)
        LogInfo(" Signature DB: loaded (" + std::to_string(m_signatureDB.GetResolvedFunctions().size()) + " resolved)");
    else
        LogWarning(" Signature DB: NOT loaded");
}

void FunctionCallMonitor::SetupFunctionHooks() {
    if (!m_hookManager) {
        LogError("AdvancedHookManager not initialized - cannot setup hooks");
        return;
    }
    m_hookManager->SetupFunctionHooks();
}

void FunctionCallMonitor::HookCommonAPIs() {
    if (!m_hookManager) {
        LogError("AdvancedHookManager not initialized - cannot hook common APIs");
        return;
    }
    m_hookManager->HookCommonAPIs();
}

void FunctionCallMonitor::HookFunctionByAddress(uintptr_t address, const std::string& name) {
    if (!m_hookManager) {
        LogError("AdvancedHookManager not initialized - cannot hook function");
        return;
    }
    AdvancedHookManager::HookConfig cfg{ "ManualHook" };
    m_hookManager->HookFunctionByAddress(address, name, cfg);
}

bool FunctionCallMonitor::IsValidMemoryAddress(uintptr_t address, size_t size) {
    if (address == 0 || size == 0) return false;
    return IsCommittedMemory(address, size) && IsExecutableMemory(address);
}

void FunctionCallMonitor::RenderEnhancedDatabaseSearch() {
    // Backward compatibility stub: call existing enhanced search UI.
    RenderEnhancedFunctionSearch();
}

__declspec(noinline) void __stdcall FunctionCallMonitor::FunctionHookCallback(uintptr_t returnAddress,
                                                                             uintptr_t functionAddress) {
     LogDebug("FunctionHookCallback: ret=0x" + std::to_string(returnAddress) +
              " addr=0x" + std::to_string(functionAddress));
     if (s_instance) {
         std::string name = s_instance->ResolveFunctionName(functionAddress);
         s_instance->AddFunctionCall(name, functionAddress, "HookCallback");
     }
 }

// ======================= Enhanced Memory Scan (NEW) =========================

void FunctionCallMonitor::StartMemoryScan(const std::vector<std::string>& targetStrings,
                                          bool scanPrologues,
                                          bool scanStrings)
{
    if (!m_functionScanner) {
        LogError("Memory scan: FunctionScanner not available");
        return;
    }
    if (m_memScan.running) {
        LogWarning("Memory scan already running");
        return;
    }

    m_memScan = MemoryScanState{};
    m_memScan.running = true;
    m_memScan.scanPrologues = scanPrologues;
    m_memScan.scanStrings = scanStrings;
    m_memScan.startTime = std::chrono::steady_clock::now();
    m_memScan.status = "Queued";
    m_memScan.stringHits.clear();
    m_memScan.prologueFunctions.clear();
    m_memScanTags.clear();
    m_memScanMerged.clear();
    m_memScanDirty = true;

    // Launch async tasks
    if (scanPrologues) {
        FunctionScanner::ScanConfig cfg{};
        cfg.maxResults = 25000;
        m_memScan.prologueFuture = std::async(std::launch::async, [this, cfg]() {
            LogInfo("MemoryScan: starting prologue scan");
            return m_functionScanner->ScanForAllInterestingFunctions(cfg, nullptr);
        });
    }
    if (scanStrings) {
        // If no user strings supplied, supply a small default anchor set
        std::vector<std::string> anchors = targetStrings;
        if (anchors.empty()) {
            anchors = {
                "Action","Inventory","Quest","Battle","Actor","UI","Addon",
                "Agent","Network","Packet","Ability","Status","Render","Socket"
            };
        }
        m_memScan.stringFuture = std::async(std::launch::async, [this, anchors]() {
            LogInfo("MemoryScan: starting string/anchor scan (anchors=" + std::to_string(anchors.size()) + ")");
            return m_functionScanner->ScanMemoryForFunctionStrings(anchors, nullptr);
        });
    }
    LogInfo("Memory scan started");
}

void FunctionCallMonitor::UpdateMemoryScanAsync()
{
    if (!m_memScan.running) return;

    bool prologueDone = !m_memScan.scanPrologues;
    bool stringDone = !m_memScan.scanStrings;

    if (m_memScan.scanPrologues && m_memScan.prologueFuture.valid()) {
        if (m_memScan.prologueFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            m_memScan.prologueFunctions = m_memScan.prologueFuture.get();
            LogInfo("MemoryScan: prologue scan completed with " + std::to_string(m_memScan.prologueFunctions.size()) + " candidates");
            prologueDone = true;
            m_memScanDirty = true;
        }
    }

    if (m_memScan.scanStrings && m_memScan.stringFuture.valid()) {
        if (m_memScan.stringFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            m_memScan.stringHits = m_memScan.stringFuture.get();
            LogInfo("MemoryScan: string scan produced " + std::to_string(m_memScan.stringHits.size()) + " string hits");
            // Build tag map
            for (const auto& h : m_memScan.stringHits) {
                if (!h.nearbyFunctionAddress) continue;
                auto& vec = m_memScanTags[h.nearbyFunctionAddress];
                if (std::find(vec.begin(), vec.end(), h.foundString) == vec.end())
                    vec.push_back(h.foundString);
            }
            stringDone = true;
            m_memScanDirty = true;
        }
    }

    // Merge results if dirty
    if (m_memScanDirty) {
        std::unordered_set<uintptr_t> all;
        all.reserve(m_memScan.prologueFunctions.size() + m_memScanTags.size());
        for (auto a : m_memScan.prologueFunctions) all.insert(a);
        for (const auto& kv : m_memScanTags) all.insert(kv.first);
        m_memScanMerged.assign(all.begin(), all.end());
        std::sort(m_memScanMerged.begin(), m_memScanMerged.end());
        m_memScanDirty = false;
    }

    // Status & completion
    size_t phases = (m_memScan.scanPrologues ? 1 : 0) + (m_memScan.scanStrings ? 1 : 0);
    size_t done = (prologueDone ? 1 : 0) + (stringDone ? 1 : 0);
    if (phases == 0) phases = 1; // avoid div0
    float pct = 100.f * float(done) / float(phases);
    std::ostringstream oss;
    oss << "Progress: " << done << "/" << phases << " (" << std::fixed << std::setprecision(1) << pct << "%)";
    m_memScan.status = oss.str();

    if (prologueDone && stringDone) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - m_memScan.startTime).count();
        LogInfo("Memory scan complete in " + std::to_string(elapsed) + " ms; merged functions=" +
                std::to_string(m_memScanMerged.size()));
        m_memScan.running = false;
        m_memScan.status += " (Done)";
    }
}

void FunctionCallMonitor::RenderMemoryScanTab()
{
    // Poll async futures
    UpdateMemoryScanAsync();

    static bool optPrologues = true;
    static bool optStrings = true;
    static char userAnchors[512] = "";
    static int  maxDisplay = 5000;
    static char addrFilter[32] = "";
    static char nameFilter[64] = "";
    static bool showOnlyTagged = false;

    ImGui::SeparatorText("Configuration");
    ImGui::Checkbox("Scan Prologues (.text)", &optPrologues); ImGui::SameLine();
    ImGui::Checkbox("Scan String Anchors (.rdata/.data)", &optStrings);
    ImGui::InputInt("Max display", &maxDisplay);
    ImGui::InputTextWithHint("##anchors", "Custom anchors (comma separated, blank = defaults)", userAnchors, sizeof(userAnchors));
    ImGui::Checkbox("Only tagged (has strings)", &showOnlyTagged);
    ImGui::InputTextWithHint("##addrflt", "Address hex filter (prefix)", addrFilter, sizeof(addrFilter));
    ImGui::InputTextWithHint("##nameflt", "Name substring filter", nameFilter, sizeof(nameFilter));

    if (!m_memScan.running) {
        if (ImGui::Button("Start Scan")) {
            // Parse anchors
            std::vector<std::string> anchors;
            std::string raw = userAnchors;
            std::stringstream ss(raw);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                auto trim = [](std::string& s) {
                    while (!s.empty() && (s.front()==' '||s.front()=='\t')) s.erase(s.begin());
                    while (!s.empty() && (s.back()==' '||s.back()=='\t')) s.pop_back();
                };
                trim(tok);
                if (!tok.empty()) anchors.push_back(tok);
            }
            StartMemoryScan(anchors, optPrologues, optStrings);
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear Results")) {
            m_memScanMerged.clear();
            m_memScanTags.clear();
        }
    } else {
        ImGui::TextColored(ImVec4(0.9f, 0.8f, 0.1f, 1.f), "%s", m_memScan.status.c_str());
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            m_memScan.cancelled = true;
            m_memScan.running = false;
            m_memScan.status += " (Cancelled)";
        }
    }

    ImGui::SeparatorText("Results");
    ImGui::Text("Functions: %zu (tagged: %zu)", m_memScanMerged.size(), m_memScanTags.size());

    if (ImGui::BeginTable("mem_scan_tbl", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Sources", ImGuiTableColumnFlags_WidthFixed, 110.f);
        ImGui::TableSetupColumn("Tags", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 110.f);
        ImGui::TableHeadersRow();

        size_t shown = 0;
        std::string nameFilterLower = nameFilter;
        std::transform(nameFilterLower.begin(), nameFilterLower.end(), nameFilterLower.begin(), ::tolower);

        for (auto addr : m_memScanMerged) {
            if (shown >= static_cast<size_t>(maxDisplay)) break;
            bool tagged = m_memScanTags.find(addr) != m_memScanTags.end();
            if (showOnlyTagged && !tagged) continue;

            // Address filter (prefix hex)
            if (addrFilter[0]) {
                std::stringstream hs;
                hs << std::hex << std::uppercase << addr;
                if (hs.str().rfind(addrFilter, 0) != 0) continue;
            }

            std::string resolved = ResolveFunctionName(addr);
            if (!nameFilterLower.empty()) {
                std::string rl = resolved;
                std::transform(rl.begin(), rl.end(), rl.begin(), ::tolower);
                if (rl.find(nameFilterLower) == std::string::npos)
                    continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("0x%016llX", static_cast<unsigned long long>(addr));

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(resolved.c_str());

            ImGui::TableNextColumn();
            std::string src;
            if (optPrologues && std::binary_search(m_memScan.prologueFunctions.begin(),
                                                   m_memScan.prologueFunctions.end(), addr))
                src += "PRO;";
            if (tagged) src += "STR;";
            if (src.empty()) src = "-";
            ImGui::TextUnformatted(src.c_str());

            ImGui::TableNextColumn();
            if (tagged) {
                const auto& tags = m_memScanTags[addr];
                std::string joined;
                for (size_t i = 0; i < tags.size(); ++i) {
                    if (i) joined += ", ";
                    if (joined.size() > 120) { joined += "..."; break; }
                    joined += tags[i];
                }
                ImGui::TextWrapped("%s", joined.c_str());
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(addr));
            if (ImGui::SmallButton("Hook")) {
                CreateSafeLoggingHook(addr, resolved, "MemScan");
            }
            if (ImGui::SmallButton("Analyze")) {
                ValidateAndDebugAddress(addr, resolved);
            }
            ImGui::PopID();

            ++shown;
        }

        ImGui::EndTable();
    }
}
