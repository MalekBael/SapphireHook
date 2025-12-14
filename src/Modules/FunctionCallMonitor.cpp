#include "../Analysis/FunctionScanner.h"
#include "../Logger/Logger.h"
#include "../Modules/FunctionCallMonitor.h"
//#include "../vendor/imgui/imgui.h"
#include "FunctionAnalyzer.h"
#include <filesystem>
#include <fstream>
#include "../Core/RttiVTableFinder.h"
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
#include <unordered_set>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <Psapi.h>
#undef min
#undef max

#include "../Helper/WindowsAPIWrapper.h"
#include "../Tools/LiveTraceMonitor.h"
#include "../Hooking/hook_manager.h"

#ifdef _MSC_VER
#pragma intrinsic(_ReturnAddress)
#endif

using namespace SapphireHook;

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

			LogInfo("AdvancedHookManager: INT3 hook placed at " + Logger::HexFormat(target) + " for " + name + " [" + config.context + "]");
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

static std::mutex g_minHookMutex;
static bool g_minHookInitialized = false;

template<typename... Args>
static void GenericHookTrampoline(Args... /*args*/) {
	void* returnAddr = _ReturnAddress();
	uintptr_t calledFrom = reinterpret_cast<uintptr_t>(returnAddr);

	// Get the current hook address from thread-local storage
	static thread_local uintptr_t s_currentHookAddr = 0;

	if (FunctionCallMonitor::GetInstance()) {
		std::string name = FunctionCallMonitor::GetInstance()->ResolveFunctionName(s_currentHookAddr);
		FunctionCallMonitor::GetInstance()->AddFunctionCall(name, s_currentHookAddr, "MinHook");

		LogDebug("MinHook intercepted: " + name +
			" at " + Logger::HexFormat(s_currentHookAddr) +
			" called from " + Logger::HexFormat(calledFrom));
	}
}

// Unified directory resolution: pass nullptr for process exe, or a function address for DLL directory
static std::string GetModuleDirectory(HMODULE hMod = nullptr)
{
	// If no module specified, try to get our DLL's module first
	if (!hMod) {
		HMODULE selfMod = nullptr;
		if (::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(&GetModuleDirectory), &selfMod) && selfMod) {
			hMod = selfMod;
		}
	}

	wchar_t wpath[MAX_PATH] = { 0 };
	DWORD len = ::GetModuleFileNameW(hMod, wpath, MAX_PATH);
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

	std::string exeDir = GetModuleDirectory();
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

struct LocalHookInfo {
	std::string name;
	std::string context;
	void* originalFunction;
	uintptr_t address;

	LocalHookInfo() : name(""), context(""), originalFunction(nullptr), address(0) {}
	LocalHookInfo(const std::string& n, const std::string& c, void* orig, uintptr_t addr)
		: name(n), context(c), originalFunction(orig), address(addr)
	{
	}
};

static std::map<uintptr_t, LocalHookInfo> g_hookMap;
static std::set<uintptr_t> g_attemptedHooks;
static uintptr_t g_moduleBase = 0;
static size_t g_moduleSize = 0;
static std::map<uintptr_t, void*> g_originalFunctions;

// --- MinHook per-hook detour infrastructure (x64 generic) ---

#include <bitset>

static constexpr int kMaxMHDetours = 64;

struct MHCtx {
	uintptr_t    target{};
	std::string  name;
	std::string  context;
	void* original{}; // trampoline to call original

	// Replay support
	void* lastRCX{ nullptr };
	void* lastRDX{ nullptr };
	void* lastR8{ nullptr };
	void* lastR9{ nullptr };
	std::atomic<bool> hasLastArgs{ false };

	// Diagnostics
	DWORD lastThreadId{ 0 };
	uintptr_t lastRet{ 0 };

	// Metrics
	std::atomic<uint64_t> hits{ 0 };
};

static MHCtx g_mhCtx[kMaxMHDetours];
static std::bitset<kMaxMHDetours> g_mhUsed;
static std::unordered_map<uintptr_t, int> g_addr2idx; // target address -> slot index

static void ResetMHCtx(int i)
{
	g_mhCtx[i].target = 0;
	g_mhCtx[i].name.clear();
	g_mhCtx[i].context.clear();
	g_mhCtx[i].original = nullptr;

	g_mhCtx[i].lastRCX = nullptr;
	g_mhCtx[i].lastRDX = nullptr;
	g_mhCtx[i].lastR8 = nullptr;
	g_mhCtx[i].lastR9 = nullptr;

	g_mhCtx[i].hasLastArgs.store(false, std::memory_order_relaxed);
	g_mhCtx[i].hits.store(0, std::memory_order_relaxed);
	g_mhCtx[i].lastThreadId = 0;
	g_mhCtx[i].lastRet = 0;
}

// Generic x64 detour type. Returns uintptr_t for compatibility with most integer/pointer returns.
// Note: floating-point/struct returns won’t be represented correctly by this logger stub.
using DetourFn = uintptr_t(__fastcall*)(void*, void*, void*, void*);

template<int Idx>
static uintptr_t __fastcall MH_Detour(void* rcx, void* rdx, void* r8, void* r9)
{
	auto& ctx = g_mhCtx[Idx];

	// Capture last observed register arguments for replay
	ctx.lastRCX = rcx;
	ctx.lastRDX = rdx;
	ctx.lastR8 = r8;
	ctx.lastR9 = r9;
	ctx.hasLastArgs.store(true, std::memory_order_relaxed);
	ctx.hits.fetch_add(1, std::memory_order_relaxed);
	ctx.lastThreadId = ::GetCurrentThreadId();

	if (FunctionCallMonitor::s_instance) {
		FunctionCallMonitor::s_instance->AddFunctionCall(ctx.name, ctx.target, "MinHook");
	}

	using OrigFn = uintptr_t(__fastcall*)(void*, void*, void*, void*);
	auto orig = reinterpret_cast<OrigFn>(ctx.original);
	if (orig) {
		const auto ret = orig(rcx, rdx, r8, r9);
		ctx.lastRet = ret;
		return ret;
	}
	return 0;
}

#define MH_DETOUR(N) &MH_Detour<N>
static DetourFn g_mhDetourTable[kMaxMHDetours] = {
	MH_DETOUR(0),  MH_DETOUR(1),  MH_DETOUR(2),  MH_DETOUR(3),
	MH_DETOUR(4),  MH_DETOUR(5),  MH_DETOUR(6),  MH_DETOUR(7),
	MH_DETOUR(8),  MH_DETOUR(9),  MH_DETOUR(10), MH_DETOUR(11),
	MH_DETOUR(12), MH_DETOUR(13), MH_DETOUR(14), MH_DETOUR(15),
	MH_DETOUR(16), MH_DETOUR(17), MH_DETOUR(18), MH_DETOUR(19),
	MH_DETOUR(20), MH_DETOUR(21), MH_DETOUR(22), MH_DETOUR(23),
	MH_DETOUR(24), MH_DETOUR(25), MH_DETOUR(26), MH_DETOUR(27),
	MH_DETOUR(28), MH_DETOUR(29), MH_DETOUR(30), MH_DETOUR(31),
	MH_DETOUR(32), MH_DETOUR(33), MH_DETOUR(34), MH_DETOUR(35),
	MH_DETOUR(36), MH_DETOUR(37), MH_DETOUR(38), MH_DETOUR(39),
	MH_DETOUR(40), MH_DETOUR(41), MH_DETOUR(42), MH_DETOUR(43),
	MH_DETOUR(44), MH_DETOUR(45), MH_DETOUR(46), MH_DETOUR(47),
	MH_DETOUR(48), MH_DETOUR(49), MH_DETOUR(50), MH_DETOUR(51),
	MH_DETOUR(52), MH_DETOUR(53), MH_DETOUR(54), MH_DETOUR(55),
	MH_DETOUR(56), MH_DETOUR(57), MH_DETOUR(58), MH_DETOUR(59),
	MH_DETOUR(60), MH_DETOUR(61), MH_DETOUR(62), MH_DETOUR(63),
};

extern "C" __declspec(noinline) uintptr_t __stdcall SH_SafeCall_Fastcall4(
	void* fn, void* rcx, void* rdx, void* r8, void* r9)
{
	__try {
		using OrigFn = uintptr_t(__fastcall*)(void*, void*, void*, void*);
		return reinterpret_cast<OrigFn>(fn)(rcx, rdx, r8, r9);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

// Helper for consistent 64-bit hex formatting
static inline std::string Hex64(uintptr_t v) {
	char buf[24];
	std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(v));
	return std::string(buf);
}

static int ReserveMHSlot(uintptr_t target, const std::string& name, const std::string& ctx)
{
	for (int i = 0; i < kMaxMHDetours; ++i) {
		if (!g_mhUsed.test(i)) {
			g_mhUsed.set(i);
			g_mhCtx[i].target = target;
			g_mhCtx[i].name = name;
			g_mhCtx[i].context = ctx;
			g_mhCtx[i].original = nullptr;

			// init replay state
			g_mhCtx[i].lastRCX = nullptr;
			g_mhCtx[i].lastRDX = nullptr;
			g_mhCtx[i].lastR8 = nullptr;
			g_mhCtx[i].lastR9 = nullptr;
			g_mhCtx[i].hasLastArgs.store(false, std::memory_order_relaxed);
			g_mhCtx[i].hits.store(0, std::memory_order_relaxed);

			g_addr2idx[target] = i;
			return i;
		}
	}
	return -1;
}

static void ReleaseMHSlot(uintptr_t target)
{
	auto it = g_addr2idx.find(target);
	if (it != g_addr2idx.end()) {
		const int i = it->second;
		g_mhUsed.reset(i);
		ResetMHCtx(i);
		g_addr2idx.erase(it);
	}
}

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

bool FunctionCallMonitor::HasReplayForAddress(uintptr_t address) const
{
	const uintptr_t target = RelocateIfIDA(address);
	auto it = g_addr2idx.find(target);
	if (it == g_addr2idx.end()) return false;
	const auto& ctx = g_mhCtx[it->second];
	return ctx.original != nullptr && ctx.hasLastArgs.load(std::memory_order_relaxed);
}

bool FunctionCallMonitor::TriggerMinHookedFunction(uintptr_t address)
{
	const uintptr_t target = RelocateIfIDA(address);
	auto it = g_addr2idx.find(target);
	if (it == g_addr2idx.end()) {
		LogWarning(std::string("Trigger requested for ") + Hex64(target) + " but no MinHook slot exists");
		return false;
	}

	auto& ctx = g_mhCtx[it->second];
	if (!ctx.original) {
		LogWarning("Trigger requested but original trampoline is null");
		return false;
	}
	if (!ctx.hasLastArgs.load(std::memory_order_relaxed)) {
		LogWarning("Trigger requested but no captured arguments are available yet");
		return false;
	}

	const DWORD curTid = ::GetCurrentThreadId();
	if (ctx.lastThreadId != 0 && ctx.lastThreadId != curTid) {
		LogWarning("Trigger rejected: different thread. captured tid=" + std::to_string(ctx.lastThreadId) +
			" current tid=" + std::to_string(curTid));
		LogWarning("Many UI/Agent functions require being called on the original thread.");
		return false;
	}

	AddFunctionCall(ctx.name, ctx.target, "Trigger");
	LogDebug(std::string("Triggering original at ") + Hex64(ctx.target) +
		" rcx=" + Hex64(reinterpret_cast<uintptr_t>(ctx.lastRCX)) +
		" rdx=" + Hex64(reinterpret_cast<uintptr_t>(ctx.lastRDX)) +
		" r8=" + Hex64(reinterpret_cast<uintptr_t>(ctx.lastR8)) +
		" r9=" + Hex64(reinterpret_cast<uintptr_t>(ctx.lastR9)));

	const auto result = SH_SafeCall_Fastcall4(ctx.original, ctx.lastRCX, ctx.lastRDX, ctx.lastR8, ctx.lastR9);
	if (result == 0) {
		LogError("Trigger MinHook call raised an exception or returned 0");
		return false;
	}
	LogDebug(std::string("Trigger result: ") + Hex64(result));
	return true;
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

			// NEW: RTTI/VTables tab
			if (ImGui::BeginTabItem("RTTI/VTables"))
			{
				static char typeName[256] = "Client::UI::UIModule";
				static std::vector<rtti::VTableInfo> results;
				static std::string lastInfo;

				ImGui::InputTextWithHint("Type name", "Namespace::Type", typeName, sizeof(typeName));
				ImGui::SameLine();
				if (ImGui::Button("Find VTables"))
				{
					results.clear();
					lastInfo.clear();
					HMODULE mod = GetModuleHandleW(nullptr);
					if (mod && typeName[0] != '\0')
					{
						results = rtti::FindVTablesForType(mod, typeName);
						if (results.empty())
							lastInfo = "No vtables found.";
						else
							lastInfo = "Found " + std::to_string(results.size()) + " vtable(s).";
					}
				}
				if (!lastInfo.empty())
					ImGui::TextUnformatted(lastInfo.c_str());

				if (!results.empty() && ImGui::BeginTable("rtti_vts", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp))
				{
					ImGui::TableSetupColumn("Index");
					ImGui::TableSetupColumn("VTable");
					ImGui::TableSetupColumn("Methods");
					ImGui::TableHeadersRow();

					for (size_t i = 0; i < results.size(); ++i)
					{
						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0); ImGui::Text("%zu", i);
						ImGui::TableSetColumnIndex(1); ImGui::Text("0x%p", (void*)results[i].vtable);
						ImGui::TableSetColumnIndex(2); ImGui::Text("%zu", results[i].methods);
					}
					ImGui::EndTable();
				}

				// Import helper: add vfNs to Function DB from first vtable
				if (!results.empty())
				{
					if (ImGui::Button("Import first vtable into DB"))
					{
						const auto& vt = results.front();
						const uintptr_t vtable = vt.vtable;
						const size_t methods = vt.methods;

						// Resolve module range to sanity-check addresses
						HMODULE mod = GetModuleHandleW(nullptr);
						MODULEINFO mi{};
						uintptr_t base = 0; size_t imageSize = 0;
						if (mod && GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
						{
							base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
							imageSize = static_cast<size_t>(mi.SizeOfImage);
						}

						size_t imported = 0;
						for (size_t i = 0; i < methods; ++i)
						{
							uintptr_t fn = *reinterpret_cast<const uintptr_t*>(vtable + i * sizeof(uintptr_t));
							// Basic safety checks
							if (fn < base || fn >= base + imageSize) continue;
							MEMORY_BASIC_INFORMATION mbi{};
							if (VirtualQuery(reinterpret_cast<LPCVOID>(fn), &mbi, sizeof(mbi)) == 0) continue;
							const DWORD exeFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
							if ((mbi.State != MEM_COMMIT) || ((mbi.Protect & exeFlags) == 0)) continue;

							// Add to DB as Type::vfN
							std::string name = std::string(typeName) + "::vf" + std::to_string(i);
							m_functionDB.AddFunction(fn, name, "RTTI import", "RTTI");
							++imported;
						}

						m_functionDatabaseLoaded = true; // reflect in UI if needed
						lastInfo = "Imported " + std::to_string(imported) + " functions.";
					}

					ImGui::SameLine();
					static int slotIndex = 0;
					ImGui::SetNextItemWidth(100);
					ImGui::InputInt("Hook slot", &slotIndex);
					if (ImGui::Button("Hook selected slot (INT3)"))
					{
						if (!results.empty() && slotIndex >= 0)
						{
							const auto& vt = results.front();
							const uintptr_t vtable = vt.vtable;
							const size_t methods = vt.methods;
							if ((size_t)slotIndex < methods)
							{
								uintptr_t fn = *reinterpret_cast<const uintptr_t*>(vtable + (size_t)slotIndex * sizeof(uintptr_t));
								std::string name = std::string(typeName) + "::vf" + std::to_string(slotIndex);
								CreateSafeLoggingHook(fn, name, "RTTI");
							}
						}
					}
				}

				ImGui::EndTabItem();
			}

			ImGui::EndTabBar();
		}
	}
	ImGui::End();
}

void FunctionCallMonitor::RenderFunctionDatabaseBrowser()
{
	static char searchBuffer[256] = "";
	static bool showOnlyValid = true;
	static std::string selectedCategory = "All";

	ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.8f, 1.0f), "Function Database Browser");
	ImGui::Separator();

	// Use the instance field directly (avoid static init with member)
	bool useRealHooks = m_enableRealHooking;
	if (ImGui::Checkbox("Use Real Hooks (MinHook)", &useRealHooks)) {
		SetRealHookingEnabled(useRealHooks);
	}
	ImGui::SameLine();
	ImGui::TextColored(useRealHooks ? ImVec4(1.0f, 0.0f, 0.0f, 1.0f) : ImVec4(0.0f, 1.0f, 0.0f, 1.0f),
		useRealHooks ? "[REAL HOOKS ACTIVE]" : "[SAFE MODE]");

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
				if (useRealHooks) {
					CreateRealLoggingHook(relocated, funcInfo.name, "DatabaseBrowser");
				}
				else {
					CreateSafeLoggingHook(relocated, funcInfo.name, "DatabaseBrowser");
				}
			}
			ImGui::SameLine();
			if (ImGui::SmallButton("Debug"))
			{
				ValidateAndDebugAddress(relocated, funcInfo.name);
			}
			ImGui::SameLine();
			bool canReplay = HasReplayForAddress(relocated);
			if (!canReplay) ImGui::BeginDisabled();
			if (ImGui::SmallButton("Trigger")) {
				(void)TriggerMinHookedFunction(relocated);
			}
			if (!canReplay) ImGui::EndDisabled();
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
		LogInfo("Module base: " + Logger::HexFormat(g_moduleBase) + ", size: " + Logger::HexFormat(g_moduleSize));
	}

	LoadDatabasesWithErrorHandling();

	// Initialize MinHook
	{
		std::lock_guard<std::mutex> lock(g_minHookMutex);
		if (!g_minHookInitialized) {
			MH_STATUS status = MH_Initialize();
			if (status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED) {
				g_minHookInitialized = true;
				LogInfo("MinHook initialized during startup");
			}
			else {
				LogError("Failed to initialize MinHook: " + std::to_string(status));
			}
		}
	}

	if (m_functionScanner && m_functionAnalyzer && m_hookManager) {
		auto funcDb = std::make_shared<SapphireHook::FunctionDatabase>();
		auto sigDb = std::make_shared<SapphireHook::SignatureDatabase>();

		m_functionScanner->SetFunctionDatabase(funcDb);
		m_functionAnalyzer->SetFunctionDatabase(funcDb);

		m_functionScanner->SetSignatureDatabase(sigDb);
		m_functionAnalyzer->SetSignatureDatabase(sigDb);

		m_hookManager->SetupFunctionHooks();
	}

	// Enable real hooking by default for actual interception
	m_enableRealHooking = true;
}

void FunctionCallMonitor::LoadDatabasesWithErrorHandling()
{
	// Always prefer the DLL directory (i.e., injector’s folder if DLL sits next to injector.exe)
	const std::string dllDir = GetModuleDirectory();

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
	const std::string dbDir = GetModuleDirectory();
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
	const std::string dbDir = GetModuleDirectory();
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
		LogDebug("Using database name: " + call.functionName + " for address " + Logger::HexFormat(address));
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

	LogDebug(call.functionName + " called at " + Hex64(address) + " (" + context + ") [DB: " +
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
					LogInfo("Database function: " + dbName + " at " + Logger::HexFormat(addr));
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
			LogDebug("Database resolved " + Logger::HexFormat(address) + " to: " + dbName);
			return dbName;
		}
	}

	auto tempIt = m_detectedFunctionNames.find(address);
	if (tempIt != m_detectedFunctionNames.end() && !tempIt->second.empty())
	{
		LogDebug("Memory scan resolved " + Logger::HexFormat(address) + " to: " + tempIt->second);
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
			LogDebug("Signature resolved " + Logger::HexFormat(address) + " to: " + sigIt->second);
			return sigIt->second;
		}
	}

	// Generate sub_ADDR format using efficient formatting
	char buf[64];
	if (g_moduleBase != 0 && address >= g_moduleBase && address < g_moduleBase + g_moduleSize) {
		uintptr_t offset = address - g_moduleBase;
		std::snprintf(buf, sizeof(buf), "sub_%llX_+%llX",
			static_cast<unsigned long long>(address),
			static_cast<unsigned long long>(offset));
	} else {
		std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(address));
	}
	return std::string(buf);
}

bool FunctionCallMonitor::CreateFunctionHook(uintptr_t address, const std::string& name, const std::string& context)
{
	return m_enableRealHooking 
		? CreateRealLoggingHook(address, name, context)
		: CreateSafeLoggingHook(address, name, context);
}

bool FunctionCallMonitor::CreateSafeLoggingHook(uintptr_t address, const std::string& name, const std::string& context)
{
	const uintptr_t target = RelocateIfIDA(address);
	LogInfo("Creating SAFE logging hook for " + name + " at " + Hex64(target));

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
	LogInfo("Creating REAL MinHook for " + name + " at " + Hex64(target));

	if (g_attemptedHooks.find(target) != g_attemptedHooks.end()) {
		LogWarning("Address already hooked, skipping");
		return false;
	}

	if (!IsSafeAddress(target)) {
		LogError("Address failed safety checks, aborting real hook");
		return false;
	}

	bool looksLikeFunction = false;
	if (!AnalyzeFunctionCode(target, &looksLikeFunction)) {
		LogError("Exception while analyzing function");
		return false;
	}
	if (!looksLikeFunction) {
		LogWarning("Address " + Logger::HexFormat(address) + " may not be a function start");
	}

	// Ensure MinHook is initialized once
	{
		std::lock_guard<std::mutex> lock(g_minHookMutex);
		if (!g_minHookInitialized) {
			MH_STATUS init = MH_Initialize();
			if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED) {
				LogError("Failed to initialize MinHook: " + std::to_string(init));
				return false;
			}
			g_minHookInitialized = true;
		}
	}

	// Reserve a unique detour slot for this hook
	const int slot = ReserveMHSlot(target, name, context);
	if (slot < 0) {
		LogError("No free MinHook detour slots available");
		return false;
	}

	void* pOriginal = nullptr;
	MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(target),
		reinterpret_cast<LPVOID>(g_mhDetourTable[slot]),
		&pOriginal);
	if (status != MH_OK) {
		LogError("Failed to create MinHook at " + Logger::HexFormat(target) + ": " + std::to_string(static_cast<int>(status)));
		ReleaseMHSlot(target);
		return false;
	}

	status = MH_EnableHook(reinterpret_cast<LPVOID>(target));
	if (status != MH_OK) {
		LogError("Failed to enable MinHook at " + Logger::HexFormat(target) + ": " + std::to_string(static_cast<int>(status)));
		MH_RemoveHook(reinterpret_cast<LPVOID>(target));
		ReleaseMHSlot(target);
		return false;
	}

	// Store hook bookkeeping
	g_attemptedHooks.insert(target);
	g_hookMap[target] = LocalHookInfo(name, context, pOriginal, target);
	g_originalFunctions[target] = pOriginal;
	g_mhCtx[slot].original = pOriginal;

	if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), target) == m_discoveredFunctions.end())
		m_discoveredFunctions.push_back(target);

	LogInfo("MinHook successfully installed for " + name + " at " + Hex64(target));
	AddFunctionCall(name, target, "MinHookCreated"); // clear label; this is a created event
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


bool FunctionCallMonitor::ValidateAndDebugAddress(uintptr_t address, const std::string& name) {
	if (!m_functionAnalyzer) {
		LogError("FunctionAnalyzer not initialized - cannot validate address");
		return false;
	}

	if (address == 0) {
		LogWarning("Null address provided for validation: " + name);
		return false;
	}

	LogInfo("FunctionCallMonitor: Validating address " + Hex64(address) + " (" + name + ")");

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

	LogDebug("Scanning for strings near " + Logger::HexFormat(address) +
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

	// Add this log line to diagnose if DiscoverFunctionsFromSignatures is called
	LogInfo("DiscoverFunctionsFromSignatures: Start");

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
		else {
			LogInfo("No new functions discovered from signatures");
		}
	}

	// Add this log line to indicate completion
	LogInfo("DiscoverFunctionsFromSignatures: Complete");
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
	// First unhook MinHook hooks
	{
		std::lock_guard<std::mutex> lock(g_minHookMutex);

		for (const auto& [addr, hookInfo] : g_hookMap) {
			MH_STATUS status = MH_DisableHook(reinterpret_cast<LPVOID>(addr));
			if (status == MH_OK) {
				MH_RemoveHook(reinterpret_cast<LPVOID>(addr));
				LogInfo("Removed MinHook at " + Logger::HexFormat(addr));
			}
			ReleaseMHSlot(addr);
		}

		g_hookMap.clear();
		g_originalFunctions.clear();
		g_attemptedHooks.clear();

		// NEW: fully uninitialize MinHook when no hooks remain
		if (g_minHookInitialized) {
			const MH_STATUS st = MH_Uninitialize();
			if (st == MH_OK || st == MH_ERROR_NOT_INITIALIZED) {
				g_minHookInitialized = false;
				LogInfo("MinHook uninitialized");
			}
			else {
				LogWarning("MinHook uninitialize returned: " + std::to_string(st));
			}
		}
	}

	// Then unhook VEH/INT3 hooks if any
	if (m_hookManager) {
		m_hookManager->UnhookAllFunctions();
	}

	LogInfo("All hooks cleared");
}

// Add a function to toggle between safe and real hooks
void FunctionCallMonitor::SetRealHookingEnabled(bool enabled) {
	m_enableRealHooking = enabled;
	LogInfo("Real hooking " + std::string(enabled ? "ENABLED" : "DISABLED"));
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

		if (it != resolvedFunctions.end() && !it->second.empty()) {
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
		if ((processed & 0x3F) == 0 || processed == total) {
			LogInfo("StringScan progress: " + std::to_string(processed) + "/" + std::to_string(total) +
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

// Static callback invoked by VEH/breakpoint manager on function hit
void FunctionCallMonitor::FunctionHookCallback(unsigned __int64 returnAddr, unsigned __int64 functionAddr)
{
	SapphireHook::LiveTraceMonitor* trace = SapphireHook::LiveTraceMonitor::GetInstance();
	if (!trace) {
		SapphireHook::LogWarning("FunctionHookCallback: LiveTraceMonitor not available");
		return;
	}

	char nameBuf[64];
	std::snprintf(nameBuf, sizeof(nameBuf), "fn_0x%llX", static_cast<unsigned long long>(functionAddr));

	trace->AddTraceEntry(static_cast<uintptr_t>(functionAddr),
		static_cast<uintptr_t>(returnAddr),
		std::string(nameBuf));
}