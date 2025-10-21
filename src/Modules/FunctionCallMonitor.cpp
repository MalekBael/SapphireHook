#include "../Analysis/FunctionScanner.h"
#include "../Analysis/PatternScanner.h"
#include "../Core/ResourceLoader.h"
#include "../Helper/CapstoneWrapper.h"
#include "../Logger/Logger.h"
#include "../Modules/FunctionCallMonitor.h"
//#include "../vendor/imgui/imgui.h"
#include "FunctionAnalyzer.h"
#include <filesystem>
#include <fstream>

#include <imgui.h>
#include <MinHook.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <future>
#include <iomanip>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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

        AdvancedHookManager() = default;
        ~AdvancedHookManager() {
            UnhookAllFunctions();
        }

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

        void SetupFunctionHooks()
        {
            std::scoped_lock lk(m_mutex);
            if (m_vehHandle == nullptr) {
                m_vehHandle = AddVectoredExceptionHandler(1, &AdvancedHookManager::VehHandler);
                if (m_vehHandle)
                    LogInfo("AdvancedHookManager: VEH installed");
                else
                    LogError("AdvancedHookManager: VEH install failed");
            }
        }

        void HookCommonAPIs() { LogInfo("AdvancedHookManager: HookCommonAPIs called"); }

        bool HookFunctionByAddress(uintptr_t address, const std::string& name, const HookConfig& config)
        {
            const uintptr_t target = address;
            if (!IsSafeAddress(target)) {
                LogError("AdvancedHookManager: unsafe address for hook");
                return false;
            }

            std::scoped_lock lk(m_mutex);
            if (m_hooks.count(target)) {
                LogWarning("AdvancedHookManager: address already hooked");
                return false;
            }

            BYTE original = 0;
            if (!PatchByte(target, 0xCC, &original)) {
                LogError("AdvancedHookManager: failed to patch INT3");
                return false;
            }

            HookRec rec{};
            rec.name = name;
            rec.context = config.context;
            rec.addr = target;
            rec.originalByte = original;
            rec.enabled = true;
            m_hooks.emplace(target, std::move(rec));

            LogInfo("AdvancedHookManager: INT3 hook placed at 0x" + std::to_string(target) + " for " + name + " [" + config.context + "]");
            return true;
        }

        void HookRandomFunctions(int count) { LogInfo("AdvancedHookManager: HookRandomFunctions called count=" + std::to_string(count)); }

        void UnhookAllFunctions()
        {
            std::scoped_lock lk(m_mutex);
            size_t restored = 0;
            for (auto& [addr, rec] : m_hooks) {
                if (rec.enabled) {
                    PatchByte(addr, rec.originalByte, nullptr);
                    rec.enabled = false;
                    ++restored;
                }
            }
            m_hooks.clear();

            if (m_vehHandle) {
                RemoveVectoredExceptionHandler(m_vehHandle);
                m_vehHandle = nullptr;
            }

            LogInfo("AdvancedHookManager: Unhooked " + std::to_string(restored) + " functions and removed VEH");
        }

        // Called by VEH to notify a hit
        static void OnBreakpointHit(uintptr_t functionAddr, uintptr_t returnAddr)
        {
            // Bridge to the monitor's callback (logs and records)
            ::FunctionCallMonitor::FunctionHookCallback(returnAddr, functionAddr);
        }

    private:
        struct HookRec {
            std::string name;
            std::string context;
            uintptr_t addr = 0;
            BYTE originalByte = 0;
            bool enabled = false;
        };

        static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* info)
        {
            if (!info || !info->ExceptionRecord || !info->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;

            auto code = info->ExceptionRecord->ExceptionCode;
            auto ctx = info->ContextRecord;

#ifdef _M_X64
            const auto ip = static_cast<uintptr_t>(ctx->Rip);
            auto& rip = ctx->Rip;
            auto& rsp = ctx->Rsp;
#else
            const auto ip = static_cast<uintptr_t>(ctx->Eip);
            auto& rip = ctx->Eip;
            auto& rsp = ctx->Esp;
#endif

            if (code == EXCEPTION_BREAKPOINT) {
                const uintptr_t bpAt = ip;
                // Correct IP back to the INT3 location (byte before current IP)
                const uintptr_t hookSite = bpAt - 1;

                AdvancedHookManager* self = GetInstance();
                if (!self) return EXCEPTION_CONTINUE_SEARCH;

                HookRec rec{};
                {
                    std::scoped_lock lk(self->m_mutex);
                    auto it = self->m_hooks.find(hookSite);
                    if (it == self->m_hooks.end() || !it->second.enabled) {
                        return EXCEPTION_CONTINUE_SEARCH;
                    }
                    rec = it->second;
                }

                // Attempt to read return address (top of stack at function entry)
                uintptr_t returnAddr = 0;
                if (IsBadReadPtr(reinterpret_cast<const void*>(rsp), sizeof(uintptr_t)) == 0) {
                    returnAddr = *reinterpret_cast<uintptr_t const*>(rsp);
                }

                // Notify higher level
                OnBreakpointHit(rec.addr, returnAddr);

                // Temporarily restore original byte and single-step
                if (!PatchByteStatic(hookSite, rec.originalByte)) {
                    // If we cannot restore, let the exception bubble
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                // Re-execute the original first byte at hookSite
                rip = hookSite;
                // Enable single-step
#ifdef _M_X64
                ctx->EFlags |= 0x100;
#else
                ctx->EFlags |= 0x100;
#endif
                // Remember where to re-arm the breakpoint (thread-local)
                s_pendingRepatch = hookSite;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if (code == EXCEPTION_SINGLE_STEP) {
                // After executing one instruction, re-arm breakpoint if needed
                if (s_pendingRepatch) {
                    const uintptr_t site = s_pendingRepatch;
                    s_pendingRepatch = 0;
                    // Re-arm INT3
                    PatchByteStatic(site, 0xCC);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        static AdvancedHookManager* GetInstance()
        {
            return s_globalInstance;
        }

        static bool PatchByteStatic(uintptr_t address, BYTE value)
        {
            DWORD oldProtect = 0;
            if (!VirtualProtect(reinterpret_cast<LPVOID>(address), 1, PAGE_EXECUTE_READWRITE, &oldProtect))
                return false;
            *reinterpret_cast<volatile BYTE*>(address) = value;
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), 1);
            DWORD dummy = 0;
            VirtualProtect(reinterpret_cast<LPVOID>(address), 1, oldProtect, &dummy);
            return true;
        }

        bool PatchByte(uintptr_t address, BYTE newByte, BYTE* oldOut)
        {
            BYTE cur = 0;
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), &cur, 1, &got) || got != 1) {
                return false;
            }
            if (oldOut) *oldOut = cur;
            return PatchByteStatic(address, newByte);
        }

    private:
        std::mutex m_mutex;
        std::unordered_map<uintptr_t, HookRec> m_hooks;
        PVOID m_vehHandle = nullptr;

        // Per-thread pending site to re-arm after single-step
        static thread_local uintptr_t s_pendingRepatch;

        // Provide a global pointer for VEH to find our live instance
        static inline AdvancedHookManager* s_globalInstance = nullptr;

        friend class ::FunctionCallMonitor;
    };

    // Define thread_local outside the class
    thread_local uintptr_t AdvancedHookManager::s_pendingRepatch = 0;
} // namespace SapphireHook

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

// Add this helper near GetExecutableDirectory()
static std::string GetThisModuleDirectory()
{
    HMODULE hMod = nullptr;
    // Use this function's address to resolve our own module handle
    if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(&GetThisModuleDirectory),
                              &hMod)) {
        // Fallback to process exe directory if resolution fails
        return GetExecutableDirectory();
    }

    wchar_t wpath[MAX_PATH] = {0};
    DWORD len = ::GetModuleFileNameW(hMod, wpath, MAX_PATH);
    if (len == 0) return GetExecutableDirectory();

    std::wstring wstr(wpath);
    size_t pos = wstr.find_last_of(L"\\/");
    std::wstring wdir = (pos == std::wstring::npos) ? wstr : wstr.substr(0, pos);
    if (wdir.empty()) return GetExecutableDirectory();

    int needed = WideCharToMultiByte(CP_UTF8, 0, wdir.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return GetExecutableDirectory();

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

    // Register the live instance for VEH to use
    SapphireHook::AdvancedHookManager::s_globalInstance = m_hookManager.get();
}

FunctionCallMonitor::~FunctionCallMonitor()
{
    // Clean up any resources if needed
    StopScan();
    StopLiveCapture();
    
    // Wait for any running threads
    if (m_samplingThread.joinable()) {
        m_samplingActive.store(false);
        m_samplingThread.join();
    }
    
    // Clear instance pointer if this was the singleton
    if (s_instance == this) {
        s_instance = nullptr;
    }
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

            if (ImGui::BeginTabItem("Memory Scan"))
            {
                RenderMemoryScanTab();
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
    }
    else {
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
                ImGui::SameLine();
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

    if (isSearching && scanFuture.valid()) {
        if (scanFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            try {
                auto asyncResults = scanFuture.get();
                searchResults.insert(searchResults.end(), asyncResults.begin(), asyncResults.end());

                std::sort(searchResults.begin(), searchResults.end());
                searchResults.erase(std::unique(searchResults.begin(), searchResults.end()), searchResults.end());

                if (searchResults.size() > static_cast<size_t>(maxResults)) {
                    searchResults.resize(maxResults);
                }

                scanStatus = "Scan complete: " + std::to_string(searchResults.size()) + " functions found";
                LogInfo(scanStatus);
            }
            catch (const std::exception& e) {
                scanStatus = std::string("Scan error: ") + e.what();
                LogError(scanStatus);
            }
            isSearching = false;
        }
        else {
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

        if (terms.empty() && searchInMemory) {
            LogInfo("Scanning memory sections for any readable strings...");

            // Memory scan for all strings
            isSearching = true;
            scanStatus = "Scanning for ALL strings in memory...";

            scanFuture = std::async(std::launch::async, [this]() {
                std::vector<uintptr_t> results;
                try {
                    SapphireHook::FunctionScanner::ScanConfig cfg{};
                    cfg.maxResults = 5000;

                    // Prologue scan
                    auto prologueResults = m_functionScanner->ScanForAllInterestingFunctions(cfg, nullptr);
                    results.insert(results.end(), prologueResults.begin(), prologueResults.end());

                    LogInfo("Prologue scan complete: " + std::to_string(prologueResults.size()) + " functions found");

                    // String scan
                    m_memScanTags.clear();
                    auto stringHits = m_functionScanner->ScanMemoryForFunctionStrings({
                        "Action","Inventory","Quest","Battle","Actor","UI","Addon",
                        "Agent","Network","Packet","Ability","Status","Render","Socket"
                        });

                    // Transfer tags for hits that already include a nearby function
                    for (const auto& h : stringHits)
                    {
                        if (!h.nearbyFunctionAddress) continue;
                        auto& vec = m_memScanTags[h.nearbyFunctionAddress];
                        if (std::find(vec.begin(), vec.end(), h.foundString) == vec.end())
                            vec.push_back(h.foundString);
                    }

                    LogInfo("String scan complete: " + std::to_string(stringHits.size()) + " raw hits");

                    // Merge results
                    std::unordered_set<uintptr_t> all;
                    all.reserve(results.size() + m_memScanTags.size());
                    for (auto a : results)
                        all.insert(a);
                    for (const auto& kv : m_memScanTags)
                        all.insert(kv.first);

                    results.assign(all.begin(), all.end());
                    std::sort(results.begin(), results.end());

                    LogInfo("Memory scan finished; merged functions=" + std::to_string(results.size()));
                }
                catch (const std::exception& e) {
                    LogError("Async scan exception: " + std::string(e.what()));
                }
                catch (...) {
                    LogError("Async scan unknown exception");
                }
                return results;
                });
        }
        else if (!terms.empty()) {
            LogInfo("Starting enhanced search with " + std::to_string(terms.size()) + " terms");
            isSearching = true;

            if (searchInMemory) {
                scanFuture = std::async(std::launch::async, [this, terms]() {
                    std::vector<uintptr_t> results;
                    try {
                        results = m_functionScanner->ScanForFunctionsByStrings(terms);
                    }
                    catch (const std::exception& e) {
                        LogError("Memory search exception: " + std::string(e.what()));
                    }
                    return results;
                    });
            }

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

            if (!searchResults.empty()) {
                std::sort(searchResults.begin(), searchResults.end());
                searchResults.erase(std::unique(searchResults.begin(), searchResults.end()), searchResults.end());
                if (searchResults.size() > static_cast<size_t>(maxResults)) {
                    searchResults.resize(maxResults);
                }
            }
        }
        else {
            LogInfo("No search terms provided and memory search disabled");
        }

        if (searchErrored) {
            ImGui::OpenPopup("SearchErrorPopup");
        }
    }

    if (!scanStatus.empty()) {
        ImGui::SameLine();
        if (isSearching) {
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s", scanStatus.c_str());
        }
        else {
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
            }
            else {
                success = CreateSafeLoggingHook(address, hookName, "Manual");
            }

            if (success) {
                LogInfo("Created manual hook: " + hookName + " at 0x" + std::to_string(address));
                addressInput[0] = '\0';
                nameInput[0] = '\0';
            }
        }
        else {
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
    // Always prefer the DLL directory (i.e., injector’s folder if DLL sits next to injector.exe)
    const std::string dllDir = GetThisModuleDirectory();

    // Optional override via env var (only if you explicitly set it inside the target process)
    std::string dbDir = dllDir;
    if (const char* injectorPath = std::getenv("SAPPHIRE_INJECTOR_PATH")) {
        dbDir = injectorPath;
        LogInfo("Using SAPPHIRE_INJECTOR_PATH: " + dbDir);
    }
    else {
        LogInfo("Using DLL directory for databases: " + dbDir);
    }

    try {
        // Function DB
        m_functionDatabaseLoaded = false;
        const std::string funcCandidates[] = {
            dbDir + "\\data.json",
            dbDir + "\\data\\data.json"
        };

        for (const auto& path : funcCandidates) {
            LogInfo("Attempting to load function database from: " + path);
            if (m_functionDB.Load(path)) {
                m_functionDatabaseLoaded = true;
                LogInfo("Function database loaded successfully with " +
                    std::to_string(m_functionDB.GetFunctionCount()) + " functions");
                break;
            }
        }
        if (!m_functionDatabaseLoaded) {
            LogWarning("Function database failed to load. Expected files next to DLL: "
                + funcCandidates[0] + " or " + funcCandidates[1]);
        }
    }
    catch (const std::exception& e) {
        LogError("Exception loading function database: " + std::string(e.what()));
        m_functionDatabaseLoaded = false;
    }

    try {
        // Signature DB
        m_signatureDatabaseLoaded = false;
        const std::string sigCandidates[] = {
            dbDir + "\\data-sig.json",
            dbDir + "\\data\\data-sig.json",
            dbDir + "\\signatures.json",
            dbDir + "\\data\\signatures.json"
        };

        for (const auto& cand : sigCandidates) {
            LogInfo("Attempting to load signature database from: " + cand);
            if (m_signatureDB.Load(cand)) {
                m_signatureDatabaseLoaded = true;
                LogInfo("Signature database loaded from: " + cand);
                break;
            }
        }
        if (!m_signatureDatabaseLoaded) {
            LogWarning("Signature database failed to load. Expected files next to DLL, e.g.: "
                + sigCandidates[0] + " or " + sigCandidates[1]);
        }
    }
    catch (const std::exception& e) {
        LogError("Exception loading signature database: " + std::string(e.what()));
        m_signatureDatabaseLoaded = false;
    }
}

void FunctionCallMonitor::ReloadDatabase()
{
    const std::string dbDir = GetThisModuleDirectory();
    LogInfo("Reloading function database from DLL directory: " + dbDir);

    bool loaded = false;
    const std::string funcCandidates[] = {
        dbDir + "\\data.json",
        dbDir + "\\data\\data.json"
    };
    for (const auto& path : funcCandidates) {
        if (m_functionDB.Load(path)) { loaded = true; break; }
    }

    m_functionDatabaseLoaded = loaded;
    if (m_functionDatabaseLoaded) LogInfo("Function database reloaded successfully");
    else LogError("Failed to reload function database");
}

void FunctionCallMonitor::ReloadSignatureDatabase()
{
    const std::string dbDir = GetThisModuleDirectory();
    LogInfo("Reloading signature database from DLL directory: " + dbDir);

    m_signatureDatabaseLoaded = false;
    const std::string sigCandidates[] = {
        dbDir + "\\data-sig.json",
        dbDir + "\\data\\data-sig.json",
        dbDir + "\\signatures.json",
        dbDir + "\\data\\signatures.json"
    };

    for (const auto& cand : sigCandidates) {
        if (m_signatureDB.Load(cand)) {
            LogInfo("Signature database reloaded from: " + cand);
            m_signatureDatabaseLoaded = true;
            break;
        }
    }
    if (m_signatureDatabaseLoaded) LogInfo("Signature database reloaded successfully");
    else LogError("Failed to reload signature database - place it next to the DLL, e.g. data-sig.json");
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
        LogWarning("Address 0x" + std::to_string(address) + " may not be a function start");
    }

    g_attemptedHooks.insert(target);

    if (!m_hookManager) {
        LogError("Hook manager unavailable");
        return false;
    }

    // Use the bool return value
    SapphireHook::AdvancedHookManager::HookConfig cfg{ context };
    bool ok = m_hookManager->HookFunctionByAddress(target, name, cfg);
    if (!ok) {
        LogError("Failed to install real hook at 0x" + std::to_string(target));
        return false;
    }

    if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), target) == m_discoveredFunctions.end())
        m_discoveredFunctions.push_back(target);

    LogInfo("Real hook armed (INT3) for " + name);
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
    }
    else {
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
    }
    else if (searchRadius > 65536) {
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
    }
    else {
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
        }
        else {
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
    }
    else {
        LogInfo("FunctionScanner: NOT AVAILABLE");
    }

    if (m_hookManager) {
        LogInfo("HookManager: AVAILABLE");
    }
    else {
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
            [address](const auto& p) { return p.first == address; });

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
    }
    else {
        LogInfo("FunctionCallMonitor: Starting async string-based scan with " +
            std::to_string(targetStrings.size()) + " target strings");

        for (size_t i = 0; i < std::min(targetStrings.size(), size_t(3)); ++i)
        {
            LogInfo("  Target string " + std::to_string(i + 1) + ": \"" + targetStrings[i] + "\"");
        }
    }

    auto progressCallback = [this](size_t processed, size_t total, const std::string& phase) {
        m_memScan.stringProcessed.store(processed, std::memory_order_relaxed);
        m_memScan.stringTotal.store(total, std::memory_order_relaxed);
        if ((processed & 0x3F) == 0 || processed == total) {
            std::scoped_lock lk(m_memScan.phaseMutex);
            m_memScan.lastStringPhase = phase;
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
    }
    else {
        LogWarning("Scan may still be in progress");
    }
}

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
    SapphireHook::AdvancedHookManager::HookConfig cfg{ "ManualHook" };
    bool ok = m_hookManager->HookFunctionByAddress(address, name, cfg);
    if (ok) {
        if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), address) == m_discoveredFunctions.end())
            m_discoveredFunctions.push_back(address);
    }
}

bool FunctionCallMonitor::IsValidMemoryAddress(uintptr_t address, size_t size) {
    if (address == 0 || size == 0) return false;
    return IsCommittedMemory(address, size) && IsExecutableMemory(address);
}

void FunctionCallMonitor::RenderEnhancedDatabaseSearch() {
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

// Helper: read up to maxLen bytes and format as hex
std::string FunctionCallMonitor::GetPrologueBytes(uintptr_t address, size_t maxLen)
{
    if (!address || maxLen == 0) return "";
    std::vector<uint8_t> buf(maxLen);
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address),
        buf.data(), buf.size(), &got) || got == 0)
        return "(unreadable)";
    std::ostringstream oss;
    for (size_t i = 0; i < got; ++i) {
        if (i) oss << ' ';
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(buf[i]);
    }
    return oss.str();
}

bool FunctionCallMonitor::DisassembleSnippet(uintptr_t address, std::string& out,
    int maxInstr, size_t maxBytes)
{
    out.clear();
    if (!address || maxInstr <= 0 || maxBytes == 0) return false;

    std::vector<uint8_t> buf(maxBytes);
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address),
        buf.data(), buf.size(), &got) || got == 0) {
        out = "// disassembly read failed";
        return false;
    }

    SapphireHook::CapstoneWrapper wrapper;
    if (!wrapper.valid()) {
        out = "// capstone unavailable";
        return false;
    }

    auto res = wrapper.DisassembleBuffer(buf.data(), got, address, 0);
    if (!res.ok()) {
        out = "// disassembly error";
        return false;
    }

    const auto& inst = res.value();
    std::ostringstream oss;
    int count = 0;
    for (const auto& di : inst) {
        if (count >= maxInstr) break;
        oss << "0x" << std::hex << di.address << ": ";
        for (uint8_t i = 0; i < di.size; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(di.bytes[i]);
        }
        oss << "  " << di.mnemonic;
        if (!di.operands.empty()) oss << " " << di.operands;
        oss << "\n";
        ++count;
    }
    out = oss.str();
    if (out.empty()) out = "// no instructions decoded";
    return true;
}

std::string FunctionCallMonitor::GenerateFunctionAnalysis(uintptr_t address,
    const std::vector<std::string>* tags)
{
    if (!address) return "No function selected.";
    std::ostringstream oss;
    oss << "Function Analysis\n=================\n";
    oss << "Address: 0x" << std::hex << std::uppercase << address << std::dec << "\n";
    std::string resolved = ResolveFunctionName(address);
    oss << "Resolved Name: " << resolved << "\n";

    if (m_functionDatabaseLoaded && m_functionDB.HasFunction(address)) {
        oss << "Database: YES\n";
        oss << "  DB Name: " << m_functionDB.GetFunctionName(address) << "\n";
        oss << "  Category: " << m_functionDB.GetFunctionCategory(address) << "\n";
        oss << "  Description: " << m_functionDB.GetFunctionDescription(address) << "\n";
    }
    else {
        oss << "Database: NO\n";
    }

    bool sigFound = false;
    if (m_signatureDatabaseLoaded) {
        auto resolvedSigs = m_signatureDB.GetResolvedFunctions();
        auto it = std::find_if(resolvedSigs.begin(), resolvedSigs.end(),
            [address](const auto& p) { return p.first == address; });

        sigFound = (it != resolvedSigs.end());
        if (sigFound) {
            oss << "Signature: YES (" << it->second << ")\n";
        }
    }
    if (!sigFound) oss << "Signature: NO\n";

    uintptr_t startHeur = FindFunctionStart(address);
    if (startHeur != address) {
        oss << "Heuristic Start: 0x" << std::hex << startHeur << std::dec
            << " (offset -" << (address - startHeur) << " bytes)\n";
    }
    else {
        oss << "Heuristic Start: matches address\n";
    }

    bool exec = IsExecutableMemory(address);
    bool commit = IsCommittedMemory(address, 16);
    oss << "Memory State: " << (commit ? "Committed" : "NotCommitted")
        << ", " << (exec ? "Executable" : "NotExecutable") << "\n";

    bool looksStart = IsLikelyFunctionStart(address);
    oss << "Prologue Pattern: " << (looksStart ? "Likely" : "Unknown") << "\n";
    oss << "Raw Prologue Bytes: " << GetPrologueBytes(address, 16) << "\n";

    std::string nearby = ScanForNearbyStrings(address, 512);
    if (!nearby.empty() && nearby != "NULL_ADDRESS" && nearby != "SCANNER_NOT_AVAILABLE") {
        oss << "Nearby Strings (trunc): " + nearby.substr(0, (std::min<size_t>)(nearby.size(), 200)) + "\n";
    }

    if (tags && !tags->empty()) {
        oss << "Scan Tags (" << tags->size() << "): ";
        size_t shown = 0;
        for (const auto& t : *tags) {
            if (shown) oss << ", ";
            oss << t;
            if (++shown >= 15) { oss << "..."; break; }
        }
        oss << "\n";
    }
    else {
        oss << "Scan Tags: none\n";
    }

    oss << "\nHeuristics:\n";
    if (looksStart && exec)
        oss << " - Executable entry with plausible prologue.\n";
    if (!exec)
        oss << " - WARNING: Memory not executable.\n";
    if (startHeur != address)
        oss << " - Potential earlier start at 0x" << std::hex << startHeur << std::dec << ".\n";
    if (!sigFound && !(m_functionDatabaseLoaded && m_functionDB.HasFunction(address)))
        oss << " - Not named in DB/signatures; candidate for manual naming.\n";

    if (m_showDisassembly) {
        std::string snippet;
        if (DisassembleSnippet(address, snippet))
            oss << "\nDisassembly (first bytes):\n" << snippet;
        else
            oss << "\nDisassembly: (failed)\n";
    }

    oss << "\nActions:\n";
    oss << " - Hook / Analyze for deeper diagnostics.\n";
    oss << " - Include in multi-select to diff with others.\n";
    return oss.str();
}

void FunctionCallMonitor::SelectFunctionForAnalysis(uintptr_t address)
{
    m_selectedFunctionAddress = address;
    const std::vector<std::string>* tagPtr = nullptr;
    auto it = m_memScanTags.find(address);
    if (it != m_memScanTags.end()) tagPtr = &it->second;
    m_selectedFunctionAnalysis = GenerateFunctionAnalysis(address, tagPtr);
}

std::string FunctionCallMonitor::BuildMultiDiffText(const std::vector<uintptr_t>& addrs)
{
    if (addrs.size() < 2) return "";
    struct Row {
        uintptr_t addr;
        std::string name;
        bool inDB;
        bool inSig;
        bool exec;
        bool prologueLikely;
        uintptr_t heurStart;
        std::string prologueBytes;
        size_t tagCount;
    };
    std::vector<Row> rows;
    rows.reserve(addrs.size());
    auto signatureMap = m_signatureDatabaseLoaded ? m_signatureDB.GetResolvedFunctions()
        : std::vector<std::pair<uintptr_t, std::string>>{};

    for (auto a : addrs) {
        Row r{};
        r.addr = a;
        r.name = ResolveFunctionName(a);
        r.inDB = (m_functionDatabaseLoaded && m_functionDB.HasFunction(a));
        r.inSig = std::find_if(signatureMap.begin(), signatureMap.end(),
            [a](const auto& p) { return p.first == a; }) != signatureMap.end();
        r.exec = IsExecutableMemory(a);
        r.prologueLikely = IsLikelyFunctionStart(a);
        r.heurStart = FindFunctionStart(a);
        r.prologueBytes = GetPrologueBytes(a, 12);
        auto tagIt = m_memScanTags.find(a);
        r.tagCount = (tagIt != m_memScanTags.end()) ? tagIt->second.size() : 0;
        rows.push_back(std::move(r));
    }

    auto diffFlag = [&](auto accessor)->bool {
        if (rows.empty()) return false;
        auto first = accessor(rows[0]);
        for (size_t i = 1; i < rows.size(); ++i)
            if (accessor(rows[i]) != first) return true;
        return false;
        };

    bool diffDB = diffFlag([](const Row& r) {return r.inDB; });
    bool diffSig = diffFlag([](const Row& r) {return r.inSig; });
    bool diffExec = diffFlag([](const Row& r) {return r.exec; });
    bool diffProl = diffFlag([](const Row& r) {return r.prologueLikely; });
    bool diffHeur = diffFlag([](const Row& r) {return r.heurStart; });
    bool diffPrologueBytes = diffFlag([](const Row& r) {return r.prologueBytes; });
    bool diffTags = diffFlag([](const Row& r) {return r.tagCount; });

    std::ostringstream oss;
    oss << "Multi-Function Diff (" << rows.size() << " functions)\n";
    oss << "========================================\n";
    for (auto& r : rows) {
        oss << "0x" << std::hex << std::uppercase << r.addr << std::dec
            << "  " << r.name << "\n";
    }
    oss << "\nFields ( * indicates differing values ):\n";

    auto line = [&](const char* label, bool diff, auto accessor) {
        oss << (diff ? "* " : "  ") << label << ": ";
        bool first = true;
        for (auto& r : rows) {
            if (!first) oss << " | ";
            first = false;
            oss << accessor(r);
        }
        oss << "\n";
        };

    line("InDatabase", diffDB, [](const Row& r) { return r.inDB ? "Y" : "N"; });
    line("Signature", diffSig, [](const Row& r) { return r.inSig ? "Y" : "N"; });
    line("Executable", diffExec, [](const Row& r) { return r.exec ? "Y" : "N"; });
    line("PrologueLikely", diffProl, [](const Row& r) { return r.prologueLikely ? "Y" : "N"; });
    line("HeuristicStart", diffHeur, [](const Row& r) {
        std::ostringstream s; s << "0x" << std::hex << r.heurStart; return s.str(); });
    line("PrologueBytes", diffPrologueBytes, [](const Row& r) { return r.prologueBytes; });
    line("TagCount", diffTags, [](const Row& r) {
        std::ostringstream s; s << r.tagCount; return s.str(); });

    oss << "\nNotes:\n";
    if (diffPrologueBytes) oss << " - Prologue bytes differ (different families / compiler variants).\n";
    if (diffHeur)          oss << " - Heuristic starts differ (some addresses may be interior).\n";
    if (diffTags)          oss << " - Tag counts vary (different referenced string density).\n";
    return oss.str();
}

void FunctionCallMonitor::BuildMultiDiff()
{
    m_multiDiffText = BuildMultiDiffText(m_multiSelected);
    m_showMultiDiff = !m_multiDiffText.empty();
}

std::string FunctionCallMonitor::BuildSingleExport(uintptr_t address)
{
    std::ostringstream oss;
    const std::vector<std::string>* tagPtr = nullptr;
    auto it = m_memScanTags.find(address);
    if (it != m_memScanTags.end()) tagPtr = &it->second;
    oss << GenerateFunctionAnalysis(address, tagPtr);
    return oss.str();
}

std::string FunctionCallMonitor::BuildDiffExport()
{
    return m_multiDiffText;
}

void FunctionCallMonitor::RebuildAnchorStringMatches()
{
    if (!m_functionScanner) {
        LogWarning("RebuildAnchorStringMatches: function scanner unavailable");
        return;
    }
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) {
        LogError("RebuildAnchorStringMatches: main module handle not found");
        return;
    }

    size_t newlyAssociated = 0;
    size_t totalHits = m_memScan.stringHits.size();

    for (auto& hit : m_memScan.stringHits)
    {
        // Already has a function address: ensure tag recorded
        if (hit.nearbyFunctionAddress) {
            auto& tags = m_memScanTags[hit.nearbyFunctionAddress];
            if (std::find(tags.begin(), tags.end(), hit.foundString) == tags.end())
            {
                tags.push_back(hit.foundString);
                m_memScanDirty = true;
            }
            continue;
        }

        if (!hit.stringAddress)
            continue;

        // Find RIP‑relative references to the string in executable code
        auto refs = SapphireHook::PatternScanner::FindRipReferencesTo(hMod, hit.stringAddress);
        if (refs.empty())
            continue;

        // Heuristic: first reference → function start
        uintptr_t ref = refs.front();
        uintptr_t funcStart = FindFunctionStart(ref);
        if (!funcStart)
            continue;

        hit.nearbyFunctionAddress = funcStart;

        auto& tags = m_memScanTags[funcStart];
        if (std::find(tags.begin(), tags.end(), hit.foundString) == tags.end()) {
            tags.push_back(hit.foundString);
        }
        newlyAssociated++;
        m_memScanDirty = true;
    }

    if (newlyAssociated) {
        LogInfo("RebuildAnchorStringMatches: associated " + std::to_string(newlyAssociated) +
            " / " + std::to_string(totalHits) + " string hits with functions");
    }
    else {
        LogInfo("RebuildAnchorStringMatches: no new associations (string scan may not have produced raw hits or references not found)");
    }
}

// Secure export helper
namespace {
    static std::filesystem::path GetExportBaseDir()
    {
        std::filesystem::path base;
        // Reuse already defined GetExecutableDirectory()
        std::string exeDir = GetExecutableDirectory();
        if (!exeDir.empty())
            base = std::filesystem::path(exeDir) / "analysis_exports";
        else
            base = std::filesystem::current_path() / "analysis_exports";
        std::error_code ec;
        std::filesystem::create_directories(base, ec);
        return base;
    }

    static bool SanitizeExportFilename(const std::string& raw, std::string& outSafe, std::string& error)
    {
        if (raw.empty()) {
            error = "Empty filename";
            return false;
        }

        // Extract only last component (prevent supplying directories)
        std::filesystem::path p(raw);
        std::string fname = p.filename().string();

        // Strip trailing spaces
        while (!fname.empty() && (fname.back() == ' ' || fname.back() == '.'))
            fname.pop_back();

        // Allowed chars: alnum, '_', '-', '.', plus single dot groups
        std::string cleaned;
        cleaned.reserve(fname.size());
        for (char c : fname) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (std::isalnum(uc) || c == '_' || c == '-' || c == '.') {
                cleaned.push_back(c);
            }
            else {
                // skip anything else silently
            }
        }

        // Remove consecutive dots & leading dot
        std::string compact;
        compact.reserve(cleaned.size());
        bool lastDot = false;
        for (char c : cleaned) {
            if (c == '.') {
                if (lastDot) continue;
                lastDot = true;
                compact.push_back(c);
            }
            else {
                lastDot = false;
                compact.push_back(c);
            }
        }
        while (!compact.empty() && compact.front() == '.') compact.erase(compact.begin());
        if (compact.empty()) {
            error = "Filename reduced to empty after sanitization";
            return false;
        }

        // Enforce maximum length (64 chars before extension)
        std::string baseName = compact;
        std::string ext;

        auto pos = compact.rfind('.');
        if (pos != std::string::npos && pos != 0 && pos != compact.size() - 1) {
            baseName = compact.substr(0, pos);
            ext = compact.substr(pos); // keep including dot
        }

        if (baseName.size() > 64)
            baseName = baseName.substr(0, 64);

        // Enforce .txt extension (override anything else)
        outSafe = baseName + ".txt";
        return true;
    }

    static bool IsPathInside(const std::filesystem::path& base, const std::filesystem::path& candidate)
    {
        std::error_code ec;
        auto canonBase = std::filesystem::weakly_canonical(base, ec);
        if (ec) return false;
        auto canonCand = std::filesystem::weakly_canonical(candidate, ec);
        if (ec) return false;

        auto baseIt = canonBase.begin();
        auto candIt = canonCand.begin();
        for (; baseIt != canonBase.end() && candIt != canonCand.end(); ++baseIt, ++candIt) {
            if (*baseIt != *candIt) return false;
        }
        return std::distance(canonBase.begin(), canonBase.end()) <=
            std::distance(canonCand.begin(), canonCand.end());
    }
} // anonymous namespace

bool FunctionCallMonitor::WriteTextFileUTF8(const std::string& userPathOrFilename,
    const std::string& content,
    bool overwrite,
    std::string& err)
{
    try {
        std::string safeName;
        if (!SanitizeExportFilename(userPathOrFilename, safeName, err))
            return false;

        auto baseDir = GetExportBaseDir();
        std::filesystem::path outPath = baseDir / safeName;

        if (!IsPathInside(baseDir, outPath)) {
            err = "Resolved path escaped base directory";
            return false;
        }

        if (std::filesystem::exists(outPath) && !overwrite) {
            err = "File exists";
            return false;
        }

        // Open & write
        std::ofstream ofs(outPath, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            err = "Open failed";
            return false;
        }
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!ofs) {
            err = "Write failed";
            return false;
        }

        LogInfo("Exported analysis to: " + outPath.string());
        return true;
    }
    catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

void FunctionCallMonitor::RenderMemoryScanTab()
{
    UpdateMemoryScanAsync();

    ImGui::TextColored(ImVec4(0.0f, 1.0f, 1.0f, 1.0f), "Memory Function Scanner");
    ImGui::Separator();

    // Configuration / controls
    static bool scanPrologues = true;
    static bool scanStrings = true;
    static char stringTargets[512] = "";
    ImGui::Checkbox("Scan for function prologues", &scanPrologues); ImGui::SameLine();
    ImGui::Checkbox("Scan for string references", &scanStrings);

    ImGui::PushItemWidth(400);
    ImGui::InputTextWithHint("##targets", "Target strings (comma-separated, empty=defaults)", stringTargets, sizeof(stringTargets));
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (ImGui::Button("Start Scan") && !m_memScan.running) {
        std::vector<std::string> targets;
        if (stringTargets[0]) {
            std::stringstream ss(stringTargets);
            std::string item;
            while (std::getline(ss, item, ',')) {
                item.erase(0, item.find_first_not_of(" \t"));
                item.erase(item.find_last_not_of(" \t") + 1);
                if (!item.empty()) targets.push_back(item);
            }
        }
        StartMemoryScan(targets, scanPrologues, scanStrings);
    }
    ImGui::SameLine();
    if (ImGui::Button("Stop") && m_memScan.running) {
        StopScan();
        m_memScan.cancelled = true;
        m_memScan.running = false;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Analysis Panel", &m_showAnalysisPanel);
    ImGui::SameLine();
    ImGui::Checkbox("Multi Diff", &m_showMultiDiff);

    if (!m_memScan.status.empty()) {
        ImGui::TextUnformatted(m_memScan.status.c_str());
    }

    ImGui::Separator();

    // Filter box & freeze toggle
    ImGui::Checkbox("Freeze UI", &m_memScan.uiFreeze);
    ImGui::SameLine();
    static char filterBuf[128] = "";
    ImGui::PushItemWidth(200);
    if (ImGui::InputTextWithHint("##filterFunc", "Filter (substring)...", filterBuf, sizeof(filterBuf))) {
        m_memScan.filterText = filterBuf;
    }
    ImGui::PopItemWidth();
    ImGui::SameLine();
    ImGui::Text("Results: %zu unique functions", m_memScanMerged.size());

    // ----------- Horizontal split (Left: table, Right: analysis) -------------
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float rightFrac = 0.37f;
    float rightWidth = m_showAnalysisPanel ? (avail.x * rightFrac) : 0.0f;
    float spacingX = ImGui::GetStyle().ItemSpacing.x;
    float leftWidth = m_showAnalysisPanel ? (avail.x - rightWidth - spacingX) : avail.x;

    // LEFT: results table with virtualized rendering
    ImGui::BeginChild("memscan_left", ImVec2(leftWidth, 0), true, ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_HorizontalScrollbar);
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("Selection")) {
            if (ImGui::MenuItem("Clear Selection", nullptr, false, !m_multiSelected.empty())) {
                m_multiSelected.clear();
            }
            if (ImGui::MenuItem("Compare Selected", nullptr, false, m_multiSelected.size() >= 2)) {
                BuildMultiDiff();
                m_showMultiDiff = true;
            }
            if (ImGui::MenuItem("Hook All Selected", nullptr, false, !m_multiSelected.empty())) {
                for (auto a : m_multiSelected) {
                    CreateSafeLoggingHook(a, ResolveFunctionName(a), "MultiSelect");
                }
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    // Stats: show only count matching filter
    size_t displayedCount = 0;

    // Use virtualized rendering with clipper
    if (ImGui::BeginTable("MemoryScanResults", 5,
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
    {
        ImGui::TableSetupColumn("Sel", ImGuiTableColumnFlags_WidthFixed, 36.f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Tags", ImGuiTableColumnFlags_WidthFixed, 160.f);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 120.f);
        ImGui::TableHeadersRow();

        // Build an index of visible rows (filtered) once per frame
        static std::vector<int> visibleIdx;
        visibleIdx.clear();
        visibleIdx.reserve(m_memScan.rowCache.size());
        if (m_memScan.filterText.empty()) {
            for (int i = 0; i < (int)m_memScan.rowCache.size(); ++i)
                visibleIdx.push_back(i);
        }
        else {
            std::string f = m_memScan.filterText;
            std::transform(f.begin(), f.end(), f.begin(), ::tolower);
            for (int i = 0; i < (int)m_memScan.rowCache.size(); ++i) {
                const auto& rc = m_memScan.rowCache[i];
                std::string lower = rc.name;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.find(f) != std::string::npos)
                    visibleIdx.push_back(i);
            }
        }
        displayedCount = visibleIdx.size();

        ImGuiListClipper clipper;
        clipper.Begin((int)displayedCount);
        while (clipper.Step()) {
            for (int listIdx = clipper.DisplayStart; listIdx < clipper.DisplayEnd; ++listIdx) {
                const auto& rc = m_memScan.rowCache[visibleIdx[listIdx]];
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::PushID((int)rc.addr);
                bool selected = std::find(m_multiSelected.begin(), m_multiSelected.end(), rc.addr) != m_multiSelected.end();
                if (ImGui::Checkbox("##s", &selected)) {
                    if (selected) {
                        if (std::find(m_multiSelected.begin(), m_multiSelected.end(), rc.addr) == m_multiSelected.end())
                            m_multiSelected.push_back(rc.addr);
                    }
                    else {
                        m_multiSelected.erase(std::remove(m_multiSelected.begin(), m_multiSelected.end(), rc.addr), m_multiSelected.end());
                    }
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                bool single = (rc.addr == m_selectedFunctionAddress);
                if (ImGui::Selectable(rc.addrText.c_str(), single,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    SelectFunctionForAnalysis(rc.addr);
                }

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(rc.name.c_str());

                ImGui::TableNextColumn();
                if (!rc.tagsShort.empty())
                    ImGui::TextWrapped("%s", rc.tagsShort.c_str());
                else
                    ImGui::TextDisabled("None");

                ImGui::TableNextColumn();
                ImGui::PushID((int)rc.addr + 0x200000);
                if (ImGui::SmallButton("Hook"))
                    CreateSafeLoggingHook(rc.addr, rc.name, "MemoryScan");
                ImGui::SameLine();
                if (ImGui::SmallButton("Analyze"))
                    SelectFunctionForAnalysis(rc.addr);
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    ImGui::TextDisabled("Showing %zu of %zu (filtered)", displayedCount, m_memScan.rowCache.size());
    ImGui::EndChild();

    // RIGHT: analysis / diff panel
    if (m_showAnalysisPanel) {
        ImGui::SameLine();
        ImGui::BeginChild("analysis_right", ImVec2(0, 0), true);

        // Header
        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.2f, 1.0f), "Function Analysis");
        ImGui::Separator();

        // Selected info summary
        ImGui::TextDisabled("Selected: %s",
            m_selectedFunctionAddress ? ResolveFunctionName(m_selectedFunctionAddress).c_str() : "(none)");
        if (m_selectedFunctionAddress) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Refresh")) {
                SelectFunctionForAnalysis(m_selectedFunctionAddress);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy")) {
                ImGui::SetClipboardText(m_selectedFunctionAnalysis.c_str());
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Export")) {
                std::string content = BuildSingleExport(m_selectedFunctionAddress);
                std::string err;
                char fname[128];
                std::snprintf(fname, sizeof(fname), "func_analysis_%llX.txt",
                    static_cast<unsigned long long>(m_selectedFunctionAddress));
                if (WriteTextFileUTF8(fname, content, false, err))
                    m_lastAnalysisExportStatus = "Exported.";
                else
                    m_lastAnalysisExportStatus = "Export failed: " + err;
            }
        }

        ImGui::Checkbox("Show Disassembly", &m_showDisassembly);
        if (!m_lastAnalysisExportStatus.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", m_lastAnalysisExportStatus.c_str());
        }

        // Multi diff tools
        if (m_showMultiDiff) {
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.2f, 1.f), "Multi-Function Diff");
            ImGui::TextDisabled("Selection: %zu", m_multiSelected.size());
            ImGui::SameLine();
            if (ImGui::SmallButton("Rebuild") && m_multiSelected.size() >= 2) {
                BuildMultiDiff();
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Export Diff") && !m_multiDiffText.empty()) {
                std::string err;
                if (WriteTextFileUTF8("function_diff.txt", m_multiDiffText, false, err))
                    m_lastAnalysisExportStatus = "Diff exported.";
                else
                    m_lastAnalysisExportStatus = "Diff export failed: " + err;
            }
            if (!m_multiDiffText.empty()) {
                ImGui::BeginChild("diff_scroll", ImVec2(0, avail.y * 0.30f), true, ImGuiWindowFlags_HorizontalScrollbar);
                ImGui::TextUnformatted(m_multiDiffText.c_str());
                ImGui::EndChild();
            }
            else if (m_multiSelected.size() >= 2) {
                ImGui::TextDisabled("Build diff to view comparative analysis.");
            }
            else {
                ImGui::TextDisabled("Select at least 2 functions for diff.");
            }
        }

        // Single analysis
        if (m_selectedFunctionAddress) {
            ImGui::Separator();
            ImGui::BeginChild("single_analysis_scroll", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::TextUnformatted(m_selectedFunctionAnalysis.c_str());
            ImGui::EndChild();
        }
        else {
            ImGui::Separator();
            ImGui::TextDisabled("No function selected. Click a function (Analyze) to view details.");
        }

        ImGui::EndChild();
    }
}

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
    m_memScan.anchorsRebuilt = false;
    m_memScan.running = true;
    m_memScan.scanPrologues = scanPrologues;
    m_memScan.scanStrings = scanStrings;
    m_memScan.startTime = std::chrono::steady_clock::now();
    
    m_samplingActive.store(true, std::memory_order_relaxed);
    try {
        m_samplingThread = std::thread([this]() { SampleActiveModuleFunctions(); });
    }
    catch (...) {
        m_samplingActive.store(false, std::memory_order_relaxed);
        m_liveTrace.capturing = false;
    }

    m_memScan.status = "Initializing...";
    m_memScan.stringHits.clear();
    m_memScan.prologueFunctions.clear();
    m_memScanTags.clear();
    m_memScanMerged.clear();
    m_memScanDirty = true;

    m_memScan.prologueCompleted = !scanPrologues;
    m_memScan.stringCompleted = !scanStrings;
    m_memScan.lastStatusBuildTick = 0;
    m_memScan.rowCache.clear();
    m_memScan.rowsCacheDirty = true;
    m_memScan.filterText.clear();

    m_memScan.prologueProcessed.store(0);
    m_memScan.prologueTotal.store(0);
    m_memScan.stringProcessed.store(0);
    m_memScan.stringTotal.store(0);

    if (scanPrologues) {
        FunctionScanner::ScanConfig cfg{};
        cfg.maxResults = 25000;

        m_memScan.prologueFuture = std::async(std::launch::async, [this, cfg]() {
            return m_functionScanner->ScanForAllInterestingFunctions(
                cfg,
                [this](size_t processed, size_t total, const std::string& phase) {
                    m_memScan.prologueProcessed.store(processed, std::memory_order_relaxed);
                    m_memScan.prologueTotal.store(total, std::memory_order_relaxed);
                    if ((processed & 0x3FF) == 0 || processed == total) {
                        std::scoped_lock lk(m_memScan.phaseMutex);
                        m_memScan.lastProloguePhase = phase;
                    }
                }
            );
            });
    }

    if (scanStrings) {
        std::vector<std::string> anchors = targetStrings;
        if (anchors.empty()) {
            anchors = {
                "Action","Inventory","Quest","Battle","Actor","UI","Addon",
                "Agent","Network","Packet","Ability","Status","Render","Socket"
            };
        }
        m_memScan.stringTotal.store(anchors.size(), std::memory_order_relaxed);

        m_memScan.stringFuture = std::async(std::launch::async, [this, anchors]() {
            return m_functionScanner->ScanMemoryForFunctionStrings(
                anchors,
                [this](size_t processed, size_t total, const std::string& phase) {
                    m_memScan.stringProcessed.store(processed, std::memory_order_relaxed);
                    m_memScan.stringTotal.store(total, std::memory_order_relaxed);
                    if ((processed & 0x3F) == 0 || processed == total) {
                        std::scoped_lock lk(m_memScan.phaseMutex);
                        m_memScan.lastStringPhase = phase;
                    }
                }
            );
            });
    }

    LogInfo("Memory scan started (prologues=" + std::string(scanPrologues ? "Y" : "N") +
        ", strings=" + std::string(scanStrings ? "Y" : "N") + ")");
}

void FunctionCallMonitor::UpdateMemoryScanAsync()
{
    // If no active scan just return
    if (!m_memScan.running)
        return;

    bool anyStateChanged = false;

    // --- Prologue phase ---
    if (m_memScan.scanPrologues && !m_memScan.prologueCompleted && m_memScan.prologueFuture.valid())
    {
        if (m_memScan.prologueFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
        {
            // Retrieve results
            m_memScan.prologueFunctions = m_memScan.prologueFuture.get();
            m_memScan.prologueCompleted = true;

            // Normalize counters
            m_memScan.prologueTotal.store(
                std::max(m_memScan.prologueTotal.load(std::memory_order_relaxed),
                    m_memScan.prologueProcessed.load(std::memory_order_relaxed)),
                std::memory_order_relaxed);
            m_memScan.prologueProcessed.store(
                m_memScan.prologueTotal.load(std::memory_order_relaxed),
                std::memory_order_relaxed);

            m_memScanDirty = true;
            m_memScan.rowsCacheDirty = true;
            anyStateChanged = true;

            LogInfo("MemoryScan: prologue phase completed; candidates=" +
                std::to_string(m_memScan.prologueFunctions.size()));
        }
        else
        {
            // Heuristic completion if counters already hit total
            size_t tot = m_memScan.prologueTotal.load(std::memory_order_relaxed);
            if (tot && m_memScan.prologueProcessed.load(std::memory_order_relaxed) >= tot)
            {
                m_memScan.prologueCompleted = true;
                anyStateChanged = true;
            }
        }
    }

    // --- String phase ---
    if (m_memScan.scanStrings && !m_memScan.stringCompleted && m_memScan.stringFuture.valid())
    {
        if (m_memScan.stringFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
        {
            m_memScan.stringHits = m_memScan.stringFuture.get();

            // Transfer tags for hits that already include a nearby function
            for (const auto& h : m_memScan.stringHits)
            {
                if (!h.nearbyFunctionAddress) continue;
                auto& vec = m_memScanTags[h.nearbyFunctionAddress];
                if (std::find(vec.begin(), vec.end(), h.foundString) == vec.end())
                    vec.push_back(h.foundString);
            }

            m_memScan.stringCompleted = true;
            m_memScan.stringTotal.store(
                std::max(m_memScan.stringTotal.load(std::memory_order_relaxed),
                    m_memScan.stringProcessed.load(std::memory_order_relaxed)),
                std::memory_order_relaxed);
            m_memScan.stringProcessed.store(
                m_memScan.stringTotal.load(std::memory_order_relaxed),
                std::memory_order_relaxed);

            m_memScanDirty = true;
            m_memScan.rowsCacheDirty = true;
            anyStateChanged = true;

            // Auto anchor rebuild once
            if (!m_memScan.anchorsRebuilt)
            {
                RebuildAnchorStringMatches();
                m_memScan.anchorsRebuilt = true;
            }

            LogInfo("MemoryScan: string phase completed; raw hits=" +
                std::to_string(m_memScan.stringHits.size()));
        }
        else
        {
            size_t tot = m_memScan.stringTotal.load(std::memory_order_relaxed);
            if (tot && m_memScan.stringProcessed.load(std::memory_order_relaxed) >= tot)
            {
                m_memScan.stringCompleted = true;
                anyStateChanged = true;
            }
        }
    }

    // --- Merge results if something changed ---
    if (m_memScanDirty)
    {
        std::unordered_set<uintptr_t> all;
        all.reserve(m_memScan.prologueFunctions.size() + m_memScanTags.size());

        for (auto a : m_memScan.prologueFunctions)
            all.insert(a);
        for (const auto& kv : m_memScanTags)
            all.insert(kv.first);

        m_memScanMerged.assign(all.begin(), all.end());
        std::sort(m_memScanMerged.begin(), m_memScanMerged.end());

        m_memScanDirty = false;
        m_memScan.rowsCacheDirty = true;
    }

    // --- Rebuild row cache if required and UI not frozen ---
    if (m_memScan.rowsCacheDirty && !m_memScan.uiFreeze)
    {
        m_memScan.rowCache.clear();
        m_memScan.rowCache.reserve(m_memScanMerged.size());

        for (auto addr : m_memScanMerged)
        {
            MemoryScanState::RowCache rc{};
            rc.addr = addr;

            // Pre-format address
            {
                char buf[24];
                std::snprintf(buf, sizeof(buf), "0x%016llX",
                    static_cast<unsigned long long>(addr));
                rc.addrText = buf;
            }

            rc.name = ResolveFunctionName(addr);

            // Build truncated tags once
            auto itTags = m_memScanTags.find(addr);
            if (itTags != m_memScanTags.end() && !itTags->second.empty())
            {
                const auto& list = itTags->second;
                std::string joined;
                joined.reserve(96);
                size_t cap = 90;
                for (size_t i = 0; i < list.size(); ++i)
                {
                    if (i) joined.append(", ");
                    joined.append(list[i]);
                    if (joined.size() > cap) { joined.append("..."); break; }
                }
                rc.tagsShort = std::move(joined);
            }

            m_memScan.rowCache.push_back(std::move(rc));
        }

        m_memScan.rowsCacheDirty = false;
    }

    // --- Throttled status string (every ~250ms) ---
    const uint64_t nowMs =
        (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

    if (nowMs - m_memScan.lastStatusBuildTick >= 250 || anyStateChanged)
    {
        m_memScan.lastStatusBuildTick = nowMs;

        int phases = 0;
        double accum = 0.0;

        if (m_memScan.scanPrologues)
        {
            double frac = 0.0;
            size_t tot = m_memScan.prologueTotal.load(std::memory_order_relaxed);
            size_t cur = m_memScan.prologueProcessed.load(std::memory_order_relaxed);
            if (tot)
                frac = std::min(1.0, (double)cur / (double)tot);
            if (m_memScan.prologueCompleted) frac = 1.0;
            accum += frac;
            ++phases;
        }

        if (m_memScan.scanStrings)
        {
            double frac = 0.0;
            size_t tot = m_memScan.stringTotal.load(std::memory_order_relaxed);
            size_t cur = m_memScan.stringProcessed.load(std::memory_order_relaxed);
            if (tot)
                frac = std::min(1.0, (double)cur / (double)tot);
            if (m_memScan.stringCompleted) frac = 1.0;
            accum += frac;
            ++phases;
        }

        if (phases == 0) phases = 1; // avoid div by zero
        double overall = (accum / phases) * 100.0;

        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - m_memScan.startTime).count();

        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "Progress: %.1f%% | Prologues: %s | Strings: %s | Elapsed: %llums%s",
            overall,
            (m_memScan.scanPrologues
                ? (m_memScan.prologueCompleted ? "Done" : "Running")
                : "Skipped"),
            (m_memScan.scanStrings
                ? (m_memScan.stringCompleted ? "Done" : "Running")
                : "Skipped"),
            (unsigned long long)elapsedMs,
            (m_memScan.prologueCompleted && m_memScan.stringCompleted) ? " (Done)" : "");

        m_memScan.status = buf;
    }

    // --- Finalize scan ---
    if (m_memScan.prologueCompleted && m_memScan.stringCompleted && m_memScan.running)
    {
        m_memScan.running = false;
        LogInfo("Memory scan finished; merged functions=" +
            std::to_string(m_memScanMerged.size()));
    }
}


void FunctionCallMonitor::SampleActiveModuleFunctions()
{
    LogDebug("SampleActiveModuleFunctions: sampler thread started");
    size_t lastTotal = 0;

    while (m_samplingActive.load(std::memory_order_relaxed)) {
        if (m_liveTrace.capturing) {
            std::lock_guard<std::mutex> guard(m_liveTrace.mutex);

            const auto now = std::chrono::steady_clock::now();
            const float dt = std::chrono::duration<float>(now - m_liveTrace.lastUpdateTime).count();
            if (dt >= 0.10f) {
                const size_t curTotal = m_liveTrace.totalCalls;
                const size_t delta = (curTotal >= lastTotal) ? (curTotal - lastTotal) : 0;
                m_liveTrace.callsPerSecond = (dt > 0.0f) ? (static_cast<float>(delta) / dt) : 0.0f;
                m_liveTrace.lastUpdateTime = now;
                lastTotal = curTotal;

                // Keep the entries buffer from growing unbounded
                constexpr size_t kMaxEntries = 5000;
                if (m_liveTrace.entries.size() > kMaxEntries) {
                    const auto removeCount = m_liveTrace.entries.size() - kMaxEntries;
                    m_liveTrace.entries.erase(m_liveTrace.entries.begin(),
                        m_liveTrace.entries.begin() + static_cast<std::ptrdiff_t>(removeCount));
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    LogDebug("SampleActiveModuleFunctions: sampler thread stopping");
}


void FunctionCallMonitor::StartLiveCapture()
{
    if (m_liveTrace.capturing) return;

    ClearLiveTrace();
    m_liveTrace.capturing = true;
    m_liveTrace.startTime = std::chrono::steady_clock::now();
    m_liveTrace.lastUpdateTime = m_liveTrace.startTime;

    m_samplingActive.store(true, std::memory_order_relaxed);
    try {
        m_samplingThread = std::thread([this]() { SampleActiveModuleFunctions(); });
    }
    catch (...) {
        m_samplingActive.store(false, std::memory_order_relaxed);
        m_liveTrace.capturing = false;
    }
}

void FunctionCallMonitor::StopLiveCapture()
{
    m_liveTrace.capturing = false;
    m_samplingActive.store(false, std::memory_order_relaxed);
    if (m_samplingThread.joinable()) {
        try { m_samplingThread.join(); }
        catch (...) {}
    }
}

void FunctionCallMonitor::ClearLiveTrace()
{
    std::lock_guard<std::mutex> lock(m_liveTrace.mutex);
    m_liveTrace.entries.clear();
    m_liveTrace.uniqueFunctions.clear();
    m_liveTrace.totalCalls = 0;
    m_liveTrace.callsPerSecond = 0.0f;
    m_liveTrace.startTime = std::chrono::steady_clock::now();
    m_liveTrace.lastUpdateTime = m_liveTrace.startTime;
}

void FunctionCallMonitor::RenderLiveCallTrace()
{
    ImGui::Separator();
    ImGui::TextDisabled("[Live Trace]");

    if (!m_liveTrace.capturing) {
        if (ImGui::SmallButton("Start Capture")) StartLiveCapture();
    }
    else {
        if (ImGui::SmallButton("Stop Capture")) StopLiveCapture();
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear")) ClearLiveTrace();
    }

    // Snapshot state without holding the lock during ImGui rendering
    std::vector<LiveTraceEntry> entriesSnapshot;
    size_t totalCallsSnapshot = 0;
    size_t uniqueSnapshot = 0;
    float cpsSnapshot = 0.0f;

    {
        std::lock_guard<std::mutex> guard(m_liveTrace.mutex);
        totalCallsSnapshot = m_liveTrace.totalCalls;
        uniqueSnapshot = m_liveTrace.uniqueFunctions.size();
        cpsSnapshot = m_liveTrace.callsPerSecond;

        // Copy only the most recent N entries to avoid heavy copies
        const size_t maxCopy = std::min<size_t>(m_liveTrace.entries.size(), 200);
        entriesSnapshot.assign(
            m_liveTrace.entries.end() - maxCopy,
            m_liveTrace.entries.end());
    }

    ImGui::Text("Total Calls: %zu | Unique: %zu | CPS: %.2f",
        totalCallsSnapshot, uniqueSnapshot, cpsSnapshot);

    ImGui::BeginChild("live_trace_table", ImVec2(0, 180), true,
                      ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_HorizontalScrollbar);
    if (ImGui::BeginTable("LiveTraceTable", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Caller");
        ImGui::TableSetupColumn("Name");
        ImGui::TableHeadersRow();

        size_t shown = 0;
        // Render from snapshot (no lock held)
        for (auto it = entriesSnapshot.rbegin();
             it != entriesSnapshot.rend() && shown < 50; ++it, ++shown) {
            const auto& e = *it;
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("recent");
            ImGui::TableNextColumn(); ImGui::Text("0x%llX", static_cast<unsigned long long>(e.address));
            ImGui::TableNextColumn(); ImGui::Text("0x%llX", static_cast<unsigned long long>(e.callerAddress));
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.functionName.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}