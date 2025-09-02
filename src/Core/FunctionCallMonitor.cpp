#include "../Core/FunctionCallMonitor.h"
#include "../Core/patternscanner.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include "../Core/ResourceLoader.h"
#include "FunctionScanner.h"
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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <Psapi.h>

// IMPORTANT: Include WindowsAPIWrapper.h AFTER windows.h to avoid conflicts
#include "../Core/WindowsAPIWrapper.h"

#ifdef _MSC_VER
#pragma intrinsic(_ReturnAddress)
#endif

using namespace SapphireHook;

// Forward declaration - function is implemented in hook_manager.cpp
extern bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize);

// AdvancedHookManager stub class until proper implementation
namespace SapphireHook {
    class AdvancedHookManager {
    public:
        struct HookConfig {
            std::string context;
        };

        // Validate that address is inside committed, executable memory of the main module
        bool IsSafeAddress(uintptr_t address)
        {
            if (address == 0) return false;

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
                return false;

            const bool committed = (mbi.State == MEM_COMMIT);
            const bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

            // Ensure it's inside the main module bounds
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
        
        static void FunctionHookCallback(uintptr_t /*returnAddress*/, uintptr_t /*functionAddress*/) {
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

// IDA absolute base used by many dumps (0x140000000)
static inline uintptr_t RelocateIfIDA(uintptr_t addr)
{
    constexpr uintptr_t IDA_BASE = 0x0000000140000000ULL;
    if (addr >= IDA_BASE && addr < (IDA_BASE + 0x10000000ULL)) // sane window
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
    // Initialize specialized helper classes
    m_functionScanner = std::make_shared<SapphireHook::FunctionScanner>();
    m_functionAnalyzer = std::make_shared<SapphireHook::FunctionAnalyzer>();
    m_hookManager = std::make_shared<SapphireHook::AdvancedHookManager>();
}

// Delegate most scanning methods to FunctionScanner
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

// Render methods - simplified implementations
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
            // Main function monitor tab
            if (ImGui::BeginTabItem("Function Monitor"))
            {
                RenderFunctionListWithPagination();
                ImGui::EndTabItem();
            }
            
            // Data browser tab
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

        // NEW: expose the enhanced search/scanning UI
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

    // Database status
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

    // Controls
    ImGui::PushItemWidth(200);
    ImGui::InputTextWithHint("##search", "Search functions...", searchBuffer, sizeof(searchBuffer));
    ImGui::SameLine();
    ImGui::Checkbox("Show only valid", &showOnlyValid);
    ImGui::PopItemWidth();

    // Category filter (optional; your JSON currently has none)
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

    // Function list table
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
            // Category filter
            if (selectedCategory != "All" && funcInfo.category != selectedCategory)
            {
                continue;
            }

            // "Show only valid": keep those inside main module when we know its bounds
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

            // Search filter
            if (!searchStr.empty())
            {
                std::string lowerName = funcInfo.name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                if (lowerName.find(searchStr) == std::string::npos) continue;
            }

            ImGui::TableNextRow();

            // Address column
            ImGui::TableNextColumn();
            ImGui::Text("0x%016llX", static_cast<unsigned long long>(relocated));

            // Name column
            ImGui::TableNextColumn();
            ImGui::Text("%s", funcInfo.name.c_str());

            // Category column
            ImGui::TableNextColumn();
            ImGui::Text("%s", funcInfo.category.empty() ? "Unknown" : funcInfo.category.c_str());

            // Actions column
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

    // Status
    const size_t totalSigs = m_signatureDB.GetTotalSignatures();
    const size_t resolvedSigs = m_signatureDB.GetResolvedSignatures();
    ImGui::Text("Resolved: %zu / %zu (%.1f%%)", resolvedSigs, totalSigs, totalSigs ? (100.0f * resolvedSigs / totalSigs) : 0.0f);

    ImGui::SameLine();
    if (ImGui::Button("Resolve All"))
    {
        // synchronous resolve to keep UI simple
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

    // Resolved entries table
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
    
    // Status overview
    if (m_functionDatabaseLoaded && m_signatureDatabaseLoaded) {
        auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
        
        ImGui::Text("Function DB: %zu functions | Signature DB: %zu resolved", 
                   m_functionDB.GetFunctionCount(), resolvedSigs.size());
    } else {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), 
                          "One or both databases not loaded");
        return;
    }
    
    // Controls
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
    
    // Combined view table
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
        
        // Show signature database entries (since they have addresses)
        if (showSignatureDb) {
            auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
            
            for (const auto& [address, name] : resolvedSigs) {
                // Apply search filter
                if (!searchStr.empty()) {
                    std::string lowerName = name;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                    if (lowerName.find(searchStr) == std::string::npos) continue;
                }
                
                ImGui::TableNextRow();
                
                // Source column
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(0.8f, 0.0f, 1.0f, 1.0f), "SIG");
                
                // Address column
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", address);
                
                // Name column
                ImGui::TableNextColumn();
                ImGui::Text("%s", name.c_str());
                
                // Category column
                ImGui::TableNextColumn();
                ImGui::Text("Signature");
                
                // Actions column
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
        
        // Show function database entries (without addresses for now)
        if (showFunctionDb && !showOnlyMatching) {
            auto categories = m_functionDB.GetCategories();
            for (const auto& [catName, catDesc] : categories) {
                auto funcsInCat = m_functionDB.GetFunctionsByCategory(catName);
                
                for (const auto& funcName : funcsInCat) {
                    // Apply search filter
                    if (!searchStr.empty()) {
                        std::string lowerName = funcName;
                        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                        if (lowerName.find(searchStr) == std::string::npos) continue;
                    }
                    
                    ImGui::TableNextRow();
                    
                    // Source column
                    ImGui::TableNextColumn();
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.8f, 1.0f), "FUNC");
                    
                    // Address column
                    ImGui::TableNextColumn();
                    ImGui::Text("Unknown");
                    
                    // Name column
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", funcName.c_str());
                    
                    // Category column
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", catName.c_str());
                    
                    // Actions column
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

    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Enhanced Function Search");
    ImGui::Separator();
    
    // Search options
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
    
    // Search input
    ImGui::PushItemWidth(-80);
    ImGui::InputTextWithHint("##searchterms", "Enter search terms (comma-separated)...", 
                            searchTerms, sizeof(searchTerms));
    ImGui::PopItemWidth();
    
    ImGui::SameLine();
    if (ImGui::Button("Search") && !isSearching) {
        isSearching = true;
        searchResults.clear();
        
        // Parse search terms
        std::vector<std::string> terms;
        std::string termsStr = searchTerms;
        std::stringstream ss(termsStr);
        std::string term;
        while (std::getline(ss, term, ',')) {
            term.erase(0, term.find_first_not_of(" \t"));
            term.erase(term.find_last_not_of(" \t") + 1);
            if (!term.empty()) {
                terms.push_back(term);
            }
        }
        
        if (!terms.empty()) {
            LogInfo("Starting enhanced search with " + std::to_string(terms.size()) + " terms");
            
            // Search in memory
            if (searchInMemory) {
                auto memoryResults = ScanForFunctionsByStrings(terms);
                searchResults.insert(searchResults.end(), memoryResults.begin(), memoryResults.end());
            }
            
            // Search in database
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
            
            // Search in signatures
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
            
            // Remove duplicates and limit results
            std::sort(searchResults.begin(), searchResults.end());
            searchResults.erase(std::unique(searchResults.begin(), searchResults.end()), searchResults.end());
            
            if (searchResults.size() > static_cast<size_t>(maxResults)) {
                searchResults.resize(maxResults);
            }
        }
        
        isSearching = false;
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Scan DB Names")) {
        if (m_functionScanner) {
            auto nameHits = m_functionScanner->AutoScanFunctionsFromDatabase(nullptr);
            lastNameScanCount = static_cast<int>(nameHits.size());
            // Merge discovered addresses into searchResults
            for (const auto& r : nameHits) {
                if (r.functionAddress) searchResults.push_back(r.functionAddress);
                // Track detected names locally for better display
                if (!r.matchedName.empty()) {
                    m_detectedFunctionNames[r.functionAddress] = r.matchedName;
                }
            }
            std::sort(searchResults.begin(), searchResults.end());
            searchResults.erase(std::unique(searchResults.begin(), searchResults.end()), searchResults.end());
            LogInfo("Name-driven scan discovered " + std::to_string(lastNameScanCount) + " candidates");
        } else {
            LogWarning("FunctionScanner not available for name-driven scan");
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Search Results: %zu functions found", searchResults.size());
    if (lastNameScanCount > 0) {
        ImGui::SameLine();
        ImGui::TextDisabled("(Name scan last found %d)", lastNameScanCount);
    }
    
    if (!searchResults.empty()) {
        if (ImGui::Button("Hook All Results")) {
            for (uintptr_t addr : searchResults) {
                std::string name = ResolveFunctionName(addr);
                CreateSafeLoggingHook(addr, name, "EnhancedSearch");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear Results")) {
            searchResults.clear();
        }
        
        // Results table
        if (ImGui::BeginTable("SearchResultsTable", 4, 
                             ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders)) {
            
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableHeadersRow();
            
            for (uintptr_t addr : searchResults) {
                ImGui::TableNextRow();
                
                // Address column
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", addr);
                
                // Name column
                ImGui::TableNextColumn();
                std::string resolvedName = ResolveFunctionName(addr);
                ImGui::Text("%s", resolvedName.c_str());
                
                // Source column
                ImGui::TableNextColumn();
                std::string source = "Unknown";
                if (m_functionDatabaseLoaded && m_functionDB.HasFunction(addr)) {
                    source = "Database";
                } else if (m_signatureDatabaseLoaded) {
                    auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
                    auto it = std::find_if(resolvedSigs.begin(), resolvedSigs.end(),
                        [addr](const auto& pair) { return pair.first == addr; });
                    if (it != resolvedSigs.end()) {
                        source = "Signature";
                    } else {
                        source = "Memory";
                    }
                }
                ImGui::Text("%s", source.c_str());
                
                // Actions column
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(addr));
                if (ImGui::SmallButton("Hook")) {
                    CreateSafeLoggingHook(addr, resolvedName, "SearchResult");
                }
                if (ImGui::SmallButton("Analyze")) {
                    ValidateAndDebugAddress(addr, resolvedName);
                }
                ImGui::PopID();
            }
            
            ImGui::EndTable();
        }
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
    
    // Input fields
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
    
    // Hook creation buttons
    if (ImGui::Button("Create Hook")) {
        uintptr_t address = 0;
        
        // Parse address
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
                // Clear inputs on success
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
    
    // Quick actions
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
                if (hookedCount >= 50) break; // Limit to prevent spam
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
                if (hookedCount >= 50) break; // Limit to prevent spam
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

// Placeholder implementations for the remaining methods
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
    
    // Initialize module information using the function from hook_manager.cpp
    if (!GetMainModuleInfo(g_moduleBase, g_moduleSize))
    {
        LogError("Failed to get main module information");
    }
    else
    {
        LogInfo("Module base: 0x" + std::to_string(g_moduleBase) + ", size: 0x" + std::to_string(g_moduleSize));
    }
    
    // Load databases
    LoadDatabasesWithErrorHandling();
    
    // Set up integration between classes
    if (m_functionScanner && m_functionAnalyzer && m_hookManager) {
        // Create new shared pointers that point to copies of the databases
        auto funcDb = std::make_shared<SapphireHook::FunctionDatabase>();
        auto sigDb = std::make_shared<SapphireHook::SignatureDatabase>();
        
        // Note: We can't copy SignatureDatabase because it contains atomic members
        // Instead, share the same database instance via a new shared_ptr
        m_functionScanner->SetFunctionDatabase(funcDb);
        m_functionAnalyzer->SetFunctionDatabase(funcDb);
        
        m_functionScanner->SetSignatureDatabase(sigDb);
        m_functionAnalyzer->SetSignatureDatabase(sigDb);
        
        // Initialize MinHook through HookManager
        m_hookManager->SetupFunctionHooks();
    }
}

void FunctionCallMonitor::LoadDatabasesWithErrorHandling()
{
    // Try to load function database
    try
    {
        // Prefer local data folder if present
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
    
    // Try to load signature database (probe common locations)
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

    // Simplified hook creation without MinHook for now
    LogInfo("Successfully 'hooked' " + name + " (placeholder implementation)");
    
    if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), target) == m_discoveredFunctions.end())
    {
        m_discoveredFunctions.push_back(target);
    }

    return true;
}

void FunctionCallMonitor::RenderFunctionListWithPagination()
{
    // Display function calls with pagination
    std::lock_guard<std::mutex> lock(m_callsMutex);
    
    ImGui::Text("Function Calls: %zu", m_functionCalls.size());
    
    if (ImGui::Button("Clear Calls"))
    {
        ClearCalls();
    }
    
    // Simple table display of function calls
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
    // Basic pagination controls
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

// Delegate all these methods to the analyzers/scanners
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
    
    // Validate search radius
    if (searchRadius == 0) {
        searchRadius = 1024; // Default value
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
    
    // Ensure our signature database is loaded
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
    
    // Update our local state after integration
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
    
    // Integrate newly discovered functions
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
    
    // Add our own diagnostics
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
    
    // Record state before enhancement
    size_t resolvedBefore = 0;
    if (m_signatureDatabaseLoaded) {
        resolvedBefore = m_signatureDB.GetResolvedFunctions().size();
    }
    
    m_functionAnalyzer->EnhancedSignatureResolution();
    
    // Report results
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
    
    // Add our own debug information
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
    // Perform a quick scan and randomly pick a few function starts to hook safely
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

    // Shuffle deterministically
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

// Specialized scanning methods delegated to FunctionScanner
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

// Add missing delegating implementations for IsLikelyFunctionStart overloads
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

// Missing method implementation for ExtractFunctionNameFromMemory
std::string FunctionCallMonitor::ExtractFunctionNameFromMemory(uintptr_t address) { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot extract function name");
        return "SCANNER_NOT_AVAILABLE";
    }
    
    if (address == 0) {
        LogWarning("Null address provided to ExtractFunctionNameFromMemory");
        return "NULL_ADDRESS";
    }
    
    // First check our own databases
    if (m_functionDatabaseLoaded && m_functionDB.HasFunction(address)) {
        std::string dbName = m_functionDB.GetFunctionName(address);
        LogDebug("Function name found in database: " + dbName);
        return dbName;
    }
    
    // Check signature database
    if (m_signatureDatabaseLoaded) {
        auto resolvedFunctions = m_signatureDB.GetResolvedFunctions();
        auto it = std::find_if(resolvedFunctions.begin(), resolvedFunctions.end(),
            [address](const auto& pair) { return pair.first == address; });
        
        if (it != resolvedFunctions.end()) {
            LogDebug("Function name found in signature database: " + it->second);
            return it->second;
        }
    }
    
    // Fall back to memory extraction via FunctionScanner
    std::string extractedName = m_functionScanner->ExtractFunctionNameFromMemory(address);
    
    if (!extractedName.empty() && extractedName != "UNKNOWN") {
        LogDebug("Function name extracted from memory: " + extractedName + " at 0x" + 
                std::to_string(address));
    }
    
    return extractedName;
}

// Memory analysis helpers
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

// Add implementations for the async operations
std::future<std::vector<uintptr_t>> FunctionCallMonitor::StartAsyncScan() { 
    if (!m_functionScanner) {
        LogError("FunctionScanner not initialized - cannot start async scan");
        std::promise<std::vector<uintptr_t>> promise;
        promise.set_value(std::vector<uintptr_t>{});
        return promise.get_future();
    }
    
    LogInfo("FunctionCallMonitor: Starting async function scan...");
    
    // Set up progress callback
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
        
        // Log first few strings for debugging
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
    
    // Wait a moment for scan to stop
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    if (!m_functionScanner->IsScanInProgress()) {
        LogInfo("Scan stopped successfully");
    } else {
        LogWarning("Scan may still be in progress");
    }
}
