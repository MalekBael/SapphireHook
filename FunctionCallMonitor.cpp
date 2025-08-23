// Disable IntelliSense parsing for problematic headers
#ifdef __INTELLISENSE__
#define _INC_WINDOWS
#define _WINDOWS_
#endif

#include "FunctionCallMonitor.h"
#include "patternscanner.h"
#include "resource.h"

// Standard C++ headers only
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

// Remove yaml-cpp include for now since it's not available
// #include "yaml-cpp/yaml.h"

// Windows API wrapper declarations - NO WINDOWS HEADERS AT ALL
extern "C" {
	// Module functions
	void* GetGameModuleHandle();
	bool GetGameModuleInfo(void* hModule, void* moduleInfo, unsigned long size);
	void* GetCurrentProcessHandle();

	// Stack walking
	unsigned short CaptureStack(unsigned long framesToSkip, unsigned long framesToCapture, void** backTrace);

	// Clipboard functions
	bool OpenClipboardWrapper(void* hwnd);
	bool EmptyClipboardWrapper();
	void* GlobalAllocWrapper(unsigned int flags, size_t size);
	void* GlobalLockWrapper(void* hMem);
	bool GlobalUnlockWrapper(void* hMem);
	void* SetClipboardDataWrapper(unsigned int format, void* hMem);
	bool CloseClipboardWrapper();

	// MinHook functions
	int MH_InitializeWrapper();
	int MH_CreateHookWrapper(void* pTarget, void* pDetour, void** ppOriginal);
	int MH_EnableHookWrapper(void* pTarget);
	int MH_DisableHookWrapper(void* pTarget);
	int MH_RemoveHookWrapper(void* pTarget);

	// Memory query functions
	bool VirtualQueryWrapper(const void* address, void* buffer, size_t length);
	bool IsBadReadPtrWrapper(const void* address, size_t size);

	// Intrinsic function
	void* _ReturnAddress();

	// Thread functions
	void* GetCurrentThreadWrapper();
	bool SetThreadPriorityWrapper(void* hThread, int priority);

	// Windows resource API wrappers
	void* FindResourceAWrapper(void* hModule, const char* lpName, const char* lpType);
	void* LoadResourceWrapper(void* hModule, void* hResInfo);
	unsigned long SizeofResourceWrapper(void* hModule, void* hResInfo);
	void* LockResourceWrapper(void* hResData);
	void* GetModuleHandleWrapper(const char* lpModuleName);
	void* MakeIntResourceWrapper(int id);
	bool GetModuleHandleExAWrapper(unsigned long dwFlags, const char* lpModuleName, void** phModule);
}

// Add these constants for GetModuleHandleExA since we can't include Windows headers
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 0x00000004
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x00000002

// Add this helper function near the top of your file
std::string LoadResourceData(const std::string& resourceName)
{
	int resourceId = 0;
	if (resourceName == "data.yml") resourceId = DATA_YML;
	else if (resourceName == "data-sig.yml") resourceId = DATA_SIG_YML;
	else return "";

	// Get the DLL's module handle instead of the current process
	// We need to get the module that contains this function
	void* hModule = nullptr;
	
	const unsigned long GET_MODULE_HANDLE_EX_FLAGS = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
	
	if (!GetModuleHandleExAWrapper(GET_MODULE_HANDLE_EX_FLAGS, 
		reinterpret_cast<const char*>(&LoadResourceData), &hModule))
	{
		printf("[FunctionMonitor] Failed to get DLL module handle\n");
		// Fallback to nullptr (current process)
		hModule = GetModuleHandleWrapper(nullptr);
	}

	printf("[FunctionMonitor] Using module handle: 0x%p\n", hModule);

	void* hResource = FindResourceAWrapper(hModule, 
		static_cast<const char*>(MakeIntResourceWrapper(resourceId)), 
		"RCDATA");

	if (!hResource)
	{
		printf("[FunctionMonitor] Resource '%s' (ID: %d) not found in module 0x%p\n", 
			resourceName.c_str(), resourceId, hModule);
		
		// Debug: Try to enumerate resources or get different handle
		printf("[FunctionMonitor] Trying to find resource with current process handle...\n");
		void* mainModule = GetModuleHandleWrapper(nullptr);
		hResource = FindResourceAWrapper(mainModule, 
			static_cast<const char*>(MakeIntResourceWrapper(resourceId)), 
			"RCDATA");
		
		if (!hResource) {
			printf("[FunctionMonitor] Resource still not found in main module 0x%p\n", mainModule);
			return "";
		}
		hModule = mainModule;
	}

	void* hMemory = LoadResourceWrapper(hModule, hResource);
	if (!hMemory) return "";

	unsigned long size = SizeofResourceWrapper(hModule, hResource);
	void* data = LockResourceWrapper(hMemory);

	if (!data || size == 0) return "";

	printf("[FunctionMonitor] Loaded resource '%s' (%lu bytes) from module 0x%p\n", 
		resourceName.c_str(), size, hModule);
	return std::string(static_cast<const char*>(data), size);
}

// Our own simple structure for module info
struct ModuleInfoSimple {
	void* lpBaseOfDll;
	unsigned long SizeOfImage;
	void* EntryPoint;
};

// Constants we need
#define GMEM_DDESHARE 0x2000
#define CF_TEXT 1
#define EXCEPTION_EXECUTE_HANDLER 1
#define THREAD_PRIORITY_BELOW_NORMAL -1

// MinHook status codes
#define MH_OK 0
#define MH_ERROR_ALREADY_INITIALIZED 1

FunctionCallMonitor* FunctionCallMonitor::s_instance = nullptr;

// Hook callback structure
struct HookInfo {
	std::string name;
	std::string context;
	void* originalFunction;
	uintptr_t address;
};

static std::map<uintptr_t, HookInfo> g_hookMap;
static std::set<uintptr_t> g_attemptedHooks;
static uintptr_t g_moduleBase = 0;
static size_t g_moduleSize = 0;

// For detours: store the original function pointers
static std::map<uintptr_t, void*> g_originalFunctions;

// Forward declare the detour function
void __stdcall AdvancedDetourFunction();

// Improved memory safety check that's more accurate for executable memory
bool IsSafeMemoryAddress(const void* address, size_t size = 1)
{
	if (!address) return false;

	// First, use VirtualQuery to check if the memory region is valid and accessible
	struct MemoryBasicInfo {
		void* BaseAddress;
		void* AllocationBase;
		unsigned long AllocationProtect;
		size_t RegionSize;
		unsigned long State;
		unsigned long Protect;
		unsigned long Type;
	};

	MemoryBasicInfo mbi = {};
	if (!VirtualQueryWrapper(address, &mbi, sizeof(mbi)))
	{
		return false;
	}

	// Check if memory is committed and accessible
	const unsigned long MEM_COMMIT = 0x1000;
	const unsigned long PAGE_NOACCESS = 0x01;
	const unsigned long PAGE_GUARD = 0x100;

	if (!(mbi.State & MEM_COMMIT) ||
		(mbi.Protect & PAGE_NOACCESS) ||
		(mbi.Protect & PAGE_GUARD))
	{
		return false;
	}

	// For executable memory, we want to allow:
	// PAGE_EXECUTE (0x10), PAGE_EXECUTE_READ (0x20), PAGE_EXECUTE_READWRITE (0x40)
	const unsigned long PAGE_EXECUTE = 0x10;
	const unsigned long PAGE_EXECUTE_READ = 0x20;
	const unsigned long PAGE_EXECUTE_READWRITE = 0x40;
	const unsigned long PAGE_READONLY = 0x02;
	const unsigned long PAGE_READWRITE = 0x04;

	bool isExecutable = (mbi.Protect & PAGE_EXECUTE) ||
		(mbi.Protect & PAGE_EXECUTE_READ) ||
		(mbi.Protect & PAGE_EXECUTE_READWRITE);

	bool isReadable = (mbi.Protect & PAGE_READONLY) ||
		(mbi.Protect & PAGE_READWRITE) ||
		(mbi.Protect & PAGE_EXECUTE_READ) ||
		(mbi.Protect & PAGE_EXECUTE_READWRITE);

	// For hooking, we primarily care about executable memory
	if (!isExecutable && !isReadable)
	{
		return false;
	}

	// Additional safety check: try to read a small amount safely
	__try
	{
		volatile unsigned char test = *static_cast<const unsigned char*>(address);
		if (size > 1)
		{
			// Check the last byte too
			test = static_cast<const unsigned char*>(address)[size - 1];
		}
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

// Enhanced address validation specifically for function hooking
bool FunctionCallMonitor::IsSafeAddress(uintptr_t address)
{
	// Check if address is within a reasonable range
	if (address < 0x10000 || address > 0x7FFFFFFFFFFF)
	{
		printf("[FunctionMonitor] Address 0x%llx is outside valid range\n", address);
		return false;
	}

	// Check if address is within our module bounds (more lenient check)
	if (g_moduleBase != 0 && g_moduleSize != 0)
	{
		if (address >= g_moduleBase && address <= (g_moduleBase + g_moduleSize))
		{
			// Address is within our module - apply more lenient checking
			return IsSafeMemoryAddress(reinterpret_cast<const void*>(address), 16);
		}
	}

	// For addresses outside our module, be more strict
	bool isSafe = IsSafeMemoryAddress(reinterpret_cast<const void*>(address), 4);
	if (!isSafe)
	{
		printf("[FunctionMonitor] Address 0x%llx failed memory safety check\n", address);
	}
	return isSafe;
}

FunctionCallMonitor::FunctionCallMonitor()
	: m_useFunctionDatabase(true), m_maxEntries(500), m_autoScroll(true), m_showAddresses(true), m_showTimestamps(true), m_windowOpen(false), m_enableRealHooking(false)
{
}

// Add a safer hook approach
bool FunctionCallMonitor::CreateSafeLoggingHook(uintptr_t address, const std::string& name, const std::string& context)
{
	printf("[FunctionMonitor] Creating SAFE logging hook for %s at 0x%llx\n", name.c_str(), address);

	if (g_attemptedHooks.find(address) != g_attemptedHooks.end())
	{
		printf("[FunctionMonitor] Address 0x%llx already hooked, skipping\n", address);
		return false;
	}

	g_attemptedHooks.insert(address);

	// For now, just add to discovered functions without actually hooking
	// This prevents crashes while still allowing the UI to work
	if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), address) == m_discoveredFunctions.end())
	{
		m_discoveredFunctions.push_back(address);
	}

	// Add a fake call to test the UI
	AddFunctionCall(name + "_DISCOVERED", address, "SafeDiscovery");

	printf("[FunctionMonitor] Safely 'hooked' %s at 0x%llx (no actual hook placed)\n", name.c_str(), address);
	return true;
}

// Add this new method after CreateSafeLoggingHook
bool FunctionCallMonitor::CreateRealLoggingHook(uintptr_t address, const std::string& name, const std::string& context)
{
	printf("[FunctionMonitor] Creating REAL logging hook for %s at 0x%llx\n", name.c_str(), address);

	if (g_attemptedHooks.find(address) != g_attemptedHooks.end())
	{
		printf("[FunctionMonitor] Address 0x%llx already hooked, skipping\n", address);
		return false;
	}

	// Safety checks for real hooking
	if (!IsSafeAddress(address))
	{
		printf("[FunctionMonitor] Address 0x%llx failed safety checks, aborting real hook\n", address);
		return false;
	}

	g_attemptedHooks.insert(address);

	// Create the actual hook using MinHook
	void* originalFunction = nullptr;
	int result = MH_CreateHookWrapper(
		reinterpret_cast<void*>(address),
		reinterpret_cast<void*>(&AdvancedDetourFunction),
		&originalFunction
	);

	if (result == MH_OK)
	{
		// Store the hook info
		HookInfo hookInfo;
		hookInfo.name = name;
		hookInfo.context = context;
		hookInfo.originalFunction = originalFunction;
		hookInfo.address = address;
		g_hookMap[address] = hookInfo;

		// Enable the hook
		int enableResult = MH_EnableHookWrapper(reinterpret_cast<void*>(address));
		if (enableResult == MH_OK)
		{
			m_hookedFunctions.push_back(address);
			printf("[FunctionMonitor] Successfully hooked %s at 0x%llx\n", name.c_str(), address);

			// Add to discovered functions list
			if (std::find(m_discoveredFunctions.begin(), m_discoveredFunctions.end(), address) == m_discoveredFunctions.end())
			{
				m_discoveredFunctions.push_back(address);
			}

			return true;
		}
		else
		{
			printf("[FunctionMonitor] Failed to enable hook for %s at 0x%llx (error: %d)\n", name.c_str(), address, enableResult);
			MH_RemoveHookWrapper(reinterpret_cast<void*>(address));
		}
	}
	else
	{
		printf("[FunctionMonitor] Failed to create hook for %s at 0x%llx (error: %d)\n", name.c_str(), address, result);
	}

	return false;
}

// Setup game hooks function
void SetupGameHooks()
{
	printf("[FunctionMonitor] Setting up game module info...\n");

	void* gameModule = GetGameModuleHandle();
	if (gameModule)
	{
		ModuleInfoSimple modInfo = { 0 };
		if (GetGameModuleInfo(gameModule, &modInfo, sizeof(modInfo)))
		{
			g_moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
			g_moduleSize = modInfo.SizeOfImage;

			printf("[FunctionMonitor] Game module: 0x%llx - 0x%llx (size: 0x%llx)\n",
				g_moduleBase, g_moduleBase + g_moduleSize, g_moduleSize);

			// Don't scan here - just setup the module info
			printf("[FunctionMonitor] Module info ready. Use 'Refresh Scan' to start async scanning.\n");
		}
	}
}

void FunctionCallMonitor::Initialize()
{
	s_instance = this;
	printf("[FunctionMonitor] Initializing Function Call Monitor (Async Mode)...\n");

	// Enable function database by default
	m_useFunctionDatabase = true;

	// Try to load from embedded resource first
	std::string resourceData = LoadResourceData("data.yml");
	if (!resourceData.empty())
	{
		// Parse YAML data from memory instead of using LoadFromString
		// Since LoadFromString doesn't exist, we'll save to temp file and load normally
		std::ofstream tempFile("temp_data.yml");
		if (tempFile.is_open())
		{
			tempFile << resourceData;
			tempFile.close();

			if (m_functionDB.Load("temp_data.yml"))
			{
				printf("[FunctionMonitor] Loaded function database from embedded resource with %zu functions\n",
					m_functionDB.GetFunctionCount());

				// Clean up temp file
				std::remove("temp_data.yml");
			}
		}
	}
	else
	{
		// Fallback to external file
		if (m_functionDB.Load("data.yml"))
		{
			printf("[FunctionMonitor] Loaded function database from external file with %zu functions\n",
				m_functionDB.GetFunctionCount());
		}
		else
		{
			printf("[FunctionMonitor] Failed to load function database from both resource and file\n");
		}
	}

	int status = MH_InitializeWrapper();
	if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED)
	{
		printf("[FunctionMonitor] Failed to initialize MinHook: %d\n", status);
	}
	else
	{
		printf("[FunctionMonitor] MinHook initialized successfully\n");
	}

	m_functionCalls.clear();

	// Just setup module info, don't scan
	SetupGameHooks();

	printf("[FunctionMonitor] Function Call Monitor initialized (async scanning available)\n");
}

void FunctionCallMonitor::ScanAllFunctions()
{
	printf("[FunctionMonitor] Starting asynchronous function scan...\n");
	StartAsyncScan();
}

void FunctionCallMonitor::StartAsyncScan()
{
	if (m_scanInProgress.load())
	{
		printf("[FunctionMonitor] Scan already in progress, please wait...\n");
		return;
	}

	m_stopScan = false;
	m_scanInProgress = true;

	// Launch scan on a background thread
	m_scanThread = std::thread([this]()
		{
			printf("[FunctionMonitor] Starting background function scan...\n");

			// Set thread priority to below normal using wrapper
			void* currentThread = GetCurrentThreadWrapper();
			if (currentThread)
			{
				SetThreadPriorityWrapper(currentThread, THREAD_PRIORITY_BELOW_NORMAL);
			}

			std::vector<uintptr_t> candidates;
			const uint8_t* memory = reinterpret_cast<const uint8_t*>(g_moduleBase);

			const size_t CHUNK_SIZE = 0x1000; // Process 4KB at a time
			size_t totalScanned = 0;

			for (size_t offset = 0; offset < g_moduleSize - 16 && !m_stopScan.load(); offset += 4)
			{
				// Yield periodically to avoid hogging CPU
				if ((offset % CHUNK_SIZE) == 0)
				{
					std::this_thread::sleep_for(std::chrono::microseconds(100));

					// Update progress periodically
					if ((offset % (CHUNK_SIZE * 100)) == 0)
					{
						float progress = (float)offset / (float)g_moduleSize * 100.0f;
						printf("[FunctionMonitor] Scan progress: %.1f%% (%zu candidates found)\n",
							progress, candidates.size());
					}
				}

				// Quick safety check - avoid expensive VirtualQuery calls when possible
				uintptr_t addr = g_moduleBase + offset;
				if (addr < g_moduleBase || addr >= (g_moduleBase + g_moduleSize))
					continue;

				// Use simpler pattern matching first
				if (memory[offset] == 0x48 && memory[offset + 1] == 0x89 && memory[offset + 2] == 0x5c)
				{
					// push rbx pattern
					candidates.push_back(g_moduleBase + offset);
				}
				else if (memory[offset] == 0x48 && memory[offset + 1] == 0x89 && memory[offset + 2] == 0x6c)
				{
					// push rbp pattern
					candidates.push_back(g_moduleBase + offset);
				}
				else if (memory[offset] == 0x48 && memory[offset + 1] == 0x83 && memory[offset + 2] == 0xec)
				{
					// sub rsp pattern
					candidates.push_back(g_moduleBase + offset);
				}
				else if (memory[offset] == 0x40 && (memory[offset + 1] >= 0x53 && memory[offset + 1] <= 0x57))
				{
					// push r8-r15 pattern
					candidates.push_back(g_moduleBase + offset);
				}

				// Stop at a reasonable number
				if (candidates.size() >= 5000)
				{
					printf("[FunctionMonitor] Reached candidate limit, stopping scan\n");
					break;
				}
			}

			if (!m_stopScan.load())
			{
				printf("[FunctionMonitor] Background scan complete - found %zu potential functions\n", candidates.size());

				// Update the discovered functions on the main thread data
				std::lock_guard<std::mutex> lock(m_callsMutex);
				SetDiscoveredFunctions(candidates);
			}
			else
			{
				printf("[FunctionMonitor] Scan cancelled by user\n");
			}

			m_scanInProgress = false;
		});

	// Detach the thread so it runs independently
	m_scanThread.detach();
}

void FunctionCallMonitor::StopScan()
{
	if (m_scanInProgress.load())
	{
		printf("[FunctionMonitor] Stopping scan...\n");
		m_stopScan = true;
	}
}

void FunctionCallMonitor::Shutdown()
{
	printf("[FunctionMonitor] Shutting down real-time monitoring...\n");

	// Stop any running scan
	StopScan();

	// Wait a bit for scan to stop
	int waitCount = 0;
	while (m_scanInProgress.load() && waitCount < 50)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		waitCount++;
	}

	for (size_t i = 0; i < m_hookedFunctions.size(); ++i)
	{
		uintptr_t addr = m_hookedFunctions[i];
		int disableResult = MH_DisableHookWrapper(reinterpret_cast<void*>(addr));
		int removeResult = MH_RemoveHookWrapper(reinterpret_cast<void*>(addr));

		if (disableResult != MH_OK || removeResult != MH_OK)
		{
			printf("[FunctionMonitor] Failed to unhook 0x%llx (disable: %d, remove: %d)\n",
				addr, disableResult, removeResult);
		}
	}

	m_hookedFunctions.clear();
	g_hookMap.clear();
	g_attemptedHooks.clear();
	g_originalFunctions.clear();
	s_instance = nullptr;
}

void FunctionCallMonitor::AddFunctionCall(const std::string& name, uintptr_t address, const std::string& context)
{
	std::lock_guard<std::mutex> lock(m_callsMutex);

	FunctionCall call;

	// Use database name if available and enabled
	if (m_useFunctionDatabase && m_functionDB.HasFunction(address))
	{
		call.functionName = m_functionDB.GetFunctionName(address);
		printf("[FunctionMonitor] Using database name: %s for address 0x%llx\n", call.functionName.c_str(), address);
	}
	else if (!name.empty() && name.find("sub_") != 0)
	{
		// Use provided name if it's not a hex fallback
		call.functionName = name;
	}
	else
	{
		// Generate hex fallback name
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

	// Log function calls for debugging
	printf("[FunctionMonitor] %s called at 0x%llx (%s) [DB: %s, Total: %zu]\n",
		call.functionName.c_str(), address, context.c_str(),
		m_useFunctionDatabase ? "enabled" : "disabled", m_functionCalls.size());
}

std::string FunctionCallMonitor::ResolveFunctionName(uintptr_t address) const
{
	if (m_useFunctionDatabase && m_functionDB.HasFunction(address))
	{
		std::string dbName = m_functionDB.GetFunctionName(address);
		printf("[FunctionMonitor] Database resolved 0x%llx to: %s\n", address, dbName.c_str());
		return dbName;
	}

	// Fallback to hex address
	std::stringstream ss;
	ss << "sub_" << std::hex << std::uppercase << address;
	return ss.str();
}

void FunctionCallMonitor::RenderManualHookSection()
{
	ImGui::PushID("FunctionCallMonitor_ManualHook");

	if (ImGui::CollapsingHeader("Real-Time Function Monitoring"))
	{
		ImGui::Text("Discovered Functions: %zu", m_discoveredFunctions.size());
		ImGui::Text("Active Hooks: %zu", m_hookedFunctions.size());

		// Show scan status
		if (m_scanInProgress.load())
		{
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Background scan in progress...");
			ImGui::SameLine();
			if (ImGui::Button("Stop Scan##StopScanBtn"))
			{
				StopScan();
			}
		}
		else
		{
			ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Ready to scan");
		}

		// Add the real hooking toggle with warnings
		ImGui::Separator();
		ImGui::Text("Hooking Mode:");

		if (ImGui::Checkbox("Enable Real Hooking##EnableRealHooking", &m_enableRealHooking))
		{
			if (m_enableRealHooking)
			{
				printf("[FunctionMonitor] Real hooking ENABLED - use with caution!\n");
			}
			else
			{
				printf("[FunctionMonitor] Real hooking DISABLED - safe mode active\n");
			}
		}

		if (m_enableRealHooking)
		{
			ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "DANGER: Real hooking enabled! May cause crashes!");
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Only hook functions you're confident about");
		}
		else
		{
			ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "SAFE MODE: Function discovery without crashing");
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Enable 'Real Hooking' checkbox above to actually hook functions");
		}

		static char addressStr[32] = "";
		static char nameStr[128] = "";

		ImGui::Text(m_enableRealHooking ? "Hook Function (REAL MODE):" : "Discover Function (Safe Mode):");
		ImGui::InputTextWithHint("##Address", "0x140ABCDEF0", addressStr, sizeof(addressStr));
		ImGui::SameLine();
		ImGui::InputTextWithHint("##Name", "Function name (optional)", nameStr, sizeof(nameStr));

		const char* buttonText = m_enableRealHooking ? "Hook Function (DANGER!)##HookBtn" : "Discover Function##DiscoverBtn";
		if (ImGui::Button(buttonText))
		{
			uintptr_t addr = 0;
			if (sscanf_s(addressStr, "0x%llx", &addr) == 1 || sscanf_s(addressStr, "%llx", &addr) == 1)
			{
				std::string funcName = nameStr[0] ? nameStr : "";
				if (funcName.empty())
				{
					std::stringstream ss;
					ss << "sub_" << std::hex << std::uppercase << addr;
					funcName = ss.str();
				}

				if (m_enableRealHooking)
				{
					// Show confirmation dialog for real hooking
					ImGui::OpenPopup("Confirm Real Hook##ConfirmHook");
				}
				else
				{
					CreateSafeLoggingHook(addr, funcName, "Manual");
				}
			}
		}

		// Confirmation popup for real hooking
		if (ImGui::BeginPopupModal("Confirm Real Hook##ConfirmHook", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::Text("Are you sure you want to place a REAL hook?");
			ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "This may cause the game to crash!");
			ImGui::Separator();

			if (ImGui::Button("Yes, Hook It##ConfirmYes"))
			{
				uintptr_t addr = 0;
				if (sscanf_s(addressStr, "0x%llx", &addr) == 1 || sscanf_s(addressStr, "%llx", &addr) == 1)
				{
					std::string funcName = nameStr[0] ? nameStr : "";
					if (funcName.empty())
					{
						std::stringstream ss;
						ss << "sub_" << std::hex << std::uppercase << addr;
						funcName = ss.str();
					}
					CreateRealLoggingHook(addr, funcName, "Manual");
				}
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel##ConfirmCancel"))
			{
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}

		ImGui::SameLine();
		if (ImGui::Button("Start Async Scan##RescanBtn"))
		{
			if (!m_scanInProgress.load())
			{
				ScanAllFunctions();
			}
			else
			{
				ImGui::SetTooltip("Scan already in progress");
			}
		}

		ImGui::SameLine();
		if (ImGui::Button("Test Calls##TestCallsBtn"))
		{
			for (int i = 0; i < 5; i++)
			{
				std::stringstream ss;
				ss << "TestFunction_" << i;
				AddFunctionCall(ss.str(), 0x140000000 + i * 0x1000, "Test");
			}
		}

		// Add unhook all button when real hooking is enabled
		if (m_enableRealHooking && !m_hookedFunctions.empty())
		{
			ImGui::SameLine();
			if (ImGui::Button("Unhook All##UnhookAllBtn"))
			{
				ImGui::OpenPopup("Confirm Unhook All##ConfirmUnhookAll");
			}

			if (ImGui::BeginPopupModal("Confirm Unhook All##ConfirmUnhookAll", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
			{
				ImGui::Text("Remove all %zu active hooks?", m_hookedFunctions.size());

				if (ImGui::Button("Yes##UnhookAllYes"))
				{
					UnhookAllFunctions();
					ImGui::CloseCurrentPopup();
				}
				ImGui::SameLine();
				if (ImGui::Button("Cancel##UnhookAllCancel"))
				{
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
		}

		// Add Database Function Search Section
		if (ImGui::CollapsingHeader("Database Function Search##DBSearch"))
		{
			static char searchFilter[256] = "";
			ImGui::Text("Search database functions:");
			ImGui::InputTextWithHint("##DatabaseSearch", "Search (e.g., getBGM, ExdData, etc.)", searchFilter, sizeof(searchFilter));

			if (ImGui::BeginChild("DatabaseSearchResults", ImVec2(0, 200), true))
			{
				std::string filter = searchFilter;
				std::transform(filter.begin(), filter.end(), filter.begin(), [](unsigned char c) { return std::tolower(c); });

				if (!filter.empty())
				{
					int resultCount = 0;
					for (const auto& [address, info] : m_functionDB.GetAllFunctions())
					{
						std::string funcName = info.name;
						std::transform(funcName.begin(), funcName.end(), funcName.begin(), [](unsigned char c) { return std::tolower(c); });

						if (funcName.find(filter) != std::string::npos)
						{
							char itemId[64];
							snprintf(itemId, sizeof(itemId), "dbfunc_%zu", address);
							ImGui::PushID(itemId);

							if (ImGui::Selectable(info.name.c_str(), false))
							{
								snprintf(addressStr, sizeof(addressStr), "0x%llx", address);
								snprintf(nameStr, sizeof(nameStr), "%s", info.name.c_str());
							}
							ImGui::SameLine();
							ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), " 0x%llx", address);

							// Show if already hooked
							if (std::find(m_hookedFunctions.begin(), m_hookedFunctions.end(), address) != m_hookedFunctions.end())
							{
								ImGui::SameLine();
								ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "[HOOKED]");
							}

							ImGui::PopID();
							resultCount++;

							if (resultCount >= 50) // Limit results
							{
								ImGui::Text("... (showing first 50 results)");
								break;
							}
						}
					}

					if (resultCount == 0)
					{
						ImGui::Text("No functions found matching '%s'", searchFilter);
					}
				}
				else
				{
					ImGui::Text("Enter search terms to find functions in the database");
				}
			}
			ImGui::EndChild();
		}
	}

	ImGui::PopID();
}

// Add this new method to unhook all functions
void FunctionCallMonitor::UnhookAllFunctions()
{
	printf("[FunctionMonitor] Unhooking all %zu functions...\n", m_hookedFunctions.size());

	for (uintptr_t addr : m_hookedFunctions)
	{
		int disableResult = MH_DisableHookWrapper(reinterpret_cast<void*>(addr));
		int removeResult = MH_RemoveHookWrapper(reinterpret_cast<void*>(addr));

		if (disableResult != MH_OK || removeResult != MH_OK)
		{
			printf("[FunctionMonitor] Failed to unhook 0x%llx (disable: %d, remove: %d)\n",
				addr, disableResult, removeResult);
		}
		else
		{
			printf("[FunctionMonitor] Successfully unhooked 0x%llx\n", addr);
		}
	}

	m_hookedFunctions.clear();
	g_hookMap.clear();
	g_attemptedHooks.clear();
	g_originalFunctions.clear();
}

// Add this method after the UnhookAllFunctions method
void FunctionCallMonitor::SetDiscoveredFunctions(const std::vector<uintptr_t>& functions)
{
	m_discoveredFunctions = functions;

	// If we have a database loaded, log which functions have names
	if (m_useFunctionDatabase && m_functionDB.GetFunctionCount() > 0)
	{
		int namedFunctions = 0;
		for (uintptr_t addr : functions)
		{
			if (m_functionDB.HasFunction(addr))
			{
				namedFunctions++;
				// Optionally log the first few named functions for verification
				if (namedFunctions <= 5)
				{
					printf("[FunctionMonitor] Found named function: %s at 0x%llx\n",
						m_functionDB.GetFunctionName(addr).c_str(), addr);
				}
			}
		}
		printf("[FunctionMonitor] %d of %zu discovered functions have database names\n",
			namedFunctions, functions.size());
	}
}

// Also add the missing methods that should be at the end of the file
void FunctionCallMonitor::FunctionHookCallback(uintptr_t returnAddress, uintptr_t functionAddress)
{
	if (s_instance)
	{
		std::stringstream ss;
		ss << "sub_" << std::hex << functionAddress;
		s_instance->AddFunctionCall(ss.str(), functionAddress, "Hook");
	}
}

void FunctionCallMonitor::RenderMenu()
{
	ImGui::MenuItem(GetDisplayName(), nullptr, &m_windowOpen);
}

void FunctionCallMonitor::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGuiIO& io = ImGui::GetIO();

	ImGui::SetNextWindowSize(ImVec2(800, 600), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Function Call Monitor (Real-Time)##FunctionMonitor", &m_windowOpen))
	{
		// Enhanced mouse capture detection for software mouse compatibility
		bool windowHovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows |
			ImGuiHoveredFlags_AllowWhenBlockedByActiveItem |
			ImGuiHoveredFlags_AllowWhenBlockedByPopup);
		bool windowFocused = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows);
		bool anyItemActive = ImGui::IsAnyItemActive();
		bool anyItemHovered = ImGui::IsAnyItemHovered();
		bool anyPopupOpen = ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopup);

		// More aggressive mouse capture for software mouse compatibility
		if (windowHovered || windowFocused || anyItemActive || anyItemHovered || anyPopupOpen)
		{
			io.WantCaptureMouse = true;
			io.WantCaptureKeyboard = true;

			// Additional enforcement for software mouse - force immediate capture
			if (windowHovered || anyItemHovered)
			{
				// Ensure mouse capture is maintained during hover
				io.MouseDrawCursor = false; // Let game draw cursor but capture input
			}
		}

		// Status messages with database info
		if (m_enableRealHooking)
		{
			ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "REAL HOOKING MODE: Function hooking enabled");
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Use with extreme caution - may cause crashes!");
		}
		else
		{
			ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "SAFE MODE: Function discovery without crashing");
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Enable 'Real Hooking' to actually hook functions");
		}

		// Database status
		if (m_functionDB.GetFunctionCount() > 0)
		{
			ImGui::TextColored(ImVec4(0.0f, 1.0f, 1.0f, 1.0f), "Function Database: %zu functions loaded from data.yml", m_functionDB.GetFunctionCount());
		}
		else
		{
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Function Database: Not loaded");
		}

		// Enhanced mouse capture status with software mouse detection
		if (io.WantCaptureMouse)
		{
			ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Mouse captured (software mouse compatible)");
		}
		else
		{
			ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Mouse NOT captured");
		}

		ImGui::Separator();

		// Controls section
		if (ImGui::Button("Clear##ClearBtn"))
		{
			ClearCalls();
		}

		ImGui::SameLine();
		ImGui::Checkbox("Auto Scroll##AutoScrollChk", &m_autoScroll);

		ImGui::SameLine();
		ImGui::Checkbox("Show Addresses##ShowAddrChk", &m_showAddresses);

		ImGui::SameLine();
		ImGui::Checkbox("Show Timestamps##ShowTimeChk", &m_showTimestamps);

		ImGui::SameLine();
		ImGui::Checkbox("Use Function DB##UseFunctionDBChk", &m_useFunctionDatabase);

		ImGui::SameLine();
		ImGui::SetNextItemWidth(100);
		ImGui::InputInt("Max Entries##MaxEntriesInput", &m_maxEntries, 100, 1000);

		ImGui::SetNextItemWidth(300);
		ImGui::InputTextWithHint("##Filter", "Filter functions...", m_filterText, sizeof(m_filterText));

		// Add database management section
		if (ImGui::CollapsingHeader("Function Database##FunctionDB"))
		{
			ImGui::Text("Database: %zu functions, %zu categories",
				m_functionDB.GetFunctionCount(), m_functionDB.GetCategoryCount());

			if (ImGui::Button("Reload Database##ReloadDB"))
			{
				if (m_functionDB.Load("data.yml"))
				{
					printf("[FunctionMonitor] Reloaded function database with %zu functions\n", m_functionDB.GetFunctionCount());
				}
			}

			ImGui::SameLine();
			if (ImGui::Button("Save Database##SaveDB"))
			{
				if (m_functionDB.Save())
				{
					printf("[FunctionMonitor] Saved function database\n");
				}
			}

			// Show category breakdown
			if (ImGui::CollapsingHeader("Categories##CategoriesHeader"))
			{
				for (const auto& [category, description] : m_functionDB.GetCategories())
				{
					auto functions = m_functionDB.GetFunctionsByCategory(category);
					ImGui::Text("%s: %zu functions", category.c_str(), functions.size());
					ImGui::SameLine();
					ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "(%s)", description.c_str());
				}
			}
		}

		RenderManualHookSection();

		ImGui::Separator();

		// Function calls table
		std::lock_guard<std::mutex> lock(m_callsMutex);

		ImGui::Text("Total Calls: %zu", m_functionCalls.size());

		if (ImGui::BeginTable("##FunctionCallsTable", m_showTimestamps ? 4 : 3,
			ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders |
			ImGuiTableFlags_RowBg | ImGuiTableFlags_Hideable))
		{
			ImGui::TableSetupColumn("Function");
			if (m_showAddresses)
				ImGui::TableSetupColumn("Address");
			ImGui::TableSetupColumn("Context");
			if (m_showTimestamps)
				ImGui::TableSetupColumn("Time");

			ImGui::TableHeadersRow();

			// Filter and display calls
			std::string filter = m_filterText;
			std::transform(filter.begin(), filter.end(), filter.begin(), [](unsigned char c) { return std::tolower(c); });

			int rowIndex = 0;
			for (const auto& call : m_functionCalls)
			{
				if (!filter.empty())
				{
					std::string funcName = call.functionName;
					std::transform(funcName.begin(), funcName.end(), funcName.begin(), [](unsigned char c) { return std::tolower(c); });

					if (funcName.find(filter) == std::string::npos &&
						call.context.find(filter) == std::string::npos)
					{
						continue;
					}
				}

				ImGui::TableNextRow();

				char rowId[32];
				snprintf(rowId, sizeof(rowId), "row_%d", rowIndex++);
				ImGui::PushID(rowId);

				// Column 0: Function name
				ImGui::TableSetColumnIndex(0);
				if (m_functionDB.HasFunction(call.address))
				{
					std::string category = m_functionDB.GetFunctionCategory(call.address);
					if (category == "ExdData")
					{
						ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", call.functionName.c_str());
					}
					else if (category == "Concurrency")
					{
						ImGui::TextColored(ImVec4(0.0f, 0.8f, 1.0f, 1.0f), "%s", call.functionName.c_str());
					}
					else if (category == "Client")
					{
						ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "%s", call.functionName.c_str());
					}
					else
					{
						ImGui::TextColored(ImVec4(0.8f, 1.0f, 0.8f, 1.0f), "%s", call.functionName.c_str());
					}
				}
				else if (call.context == "SafeDiscovery" || call.context == "Manual" || call.context == "Test")
				{
					ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", call.functionName.c_str());
				}
				else
				{
					ImGui::Text("%s", call.functionName.c_str());
				}

				if (m_showAddresses)
				{
					ImGui::TableSetColumnIndex(1);
					ImGui::Text("0x%llx", call.address);

					if (ImGui::BeginPopupContextItem("##AddressContextMenu"))
					{
						io.WantCaptureMouse = true;

						if (ImGui::MenuItem("Copy Address"))
						{
							std::stringstream ss;
							ss << "0x" << std::hex << call.address;
							std::string addrStr = ss.str();

							if (OpenClipboardWrapper(nullptr))
							{
								EmptyClipboardWrapper();
								void* hClipboardData = GlobalAllocWrapper(GMEM_DDESHARE, addrStr.length() + 1);
								if (hClipboardData)
								{
									char* pchData = reinterpret_cast<char*>(GlobalLockWrapper(hClipboardData));
									strcpy_s(pchData, addrStr.length() + 1, addrStr.c_str());
									GlobalUnlockWrapper(hClipboardData);
									SetClipboardDataWrapper(CF_TEXT, hClipboardData);
								}
								CloseClipboardWrapper();
							}
						}

						ImGui::EndPopup();
					}
				}

				ImGui::TableSetColumnIndex(m_showAddresses ? 2 : 1);
				ImGui::Text("%s", call.context.c_str());

				if (m_showTimestamps)
				{
					ImGui::TableSetColumnIndex(m_showAddresses ? 3 : 2);
					auto now = std::chrono::steady_clock::now();
					auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - call.timestamp);
					ImGui::Text("-%lldms", diff.count());
				}

				ImGui::PopID();
			}

			if (m_autoScroll)
			{
				float scrollY = ImGui::GetScrollY();
				float scrollMaxY = ImGui::GetScrollMaxY();
				if (scrollMaxY > 0.0f && scrollY >= scrollY - 1.0f)
				{
					ImGui::SetScrollHereY(1.0f);
				}
			}

			ImGui::EndTable();
		}

		ImGui::Separator();
		if (ImGui::CollapsingHeader("Statistics##StatsHeader"))
		{
			std::map<std::string, int> contextCounts;
			for (const auto& call : m_functionCalls)
			{
				contextCounts[call.context]++;
			}

			for (const auto& pair : contextCounts)
			{
				ImGui::Text("%s: %d calls", pair.first.c_str(), pair.second);
			}
		}
	}
	ImGui::End();
}

void FunctionCallMonitor::SetupFunctionHooks()
{
	printf("[FunctionMonitor] SetupFunctionHooks called - using %s mode\n",
		m_enableRealHooking ? "REAL HOOKING" : "safe discovery");
}

void FunctionCallMonitor::HookCommonAPIs()
{
	printf("[FunctionMonitor] HookCommonAPIs called - %s mode\n",
		m_enableRealHooking ? "REAL HOOKING enabled" : "safe mode enabled");
}

FunctionCallMonitor::FunctionPattern FunctionCallMonitor::s_patterns[] = {
	{nullptr, nullptr, nullptr}
};

// Modify the HookFunctionByAddress method to use the toggle
void FunctionCallMonitor::HookFunctionByAddress(uintptr_t address, const std::string& name)
{
	std::string funcName = name;
	if (funcName.empty() || funcName == "ManualHook")
	{
		std::stringstream ss;
		ss << "sub_" << std::hex << std::uppercase << address;
		funcName = ss.str();
	}

	if (m_enableRealHooking)
	{
		printf("[FunctionMonitor] Creating real hook for %s at 0x%llx\n", funcName.c_str(), address);
		CreateRealLoggingHook(address, funcName, "Manual");
	}
	else
	{
		printf("[FunctionMonitor] Creating safe discovery for %s at 0x%llx\n", funcName.c_str(), address);
		CreateSafeLoggingHook(address, funcName, "Manual");
	}
}

void __stdcall AdvancedDetourFunction()
{
	// Safe placeholder - won't be called in safe mode
	if (FunctionCallMonitor::s_instance)
	{
		uintptr_t returnAddress = reinterpret_cast<uintptr_t>(_ReturnAddress());
		FunctionCallMonitor::s_instance->AddFunctionCall("SafeDetour", returnAddress, "SafeMode");
	}
}

void FunctionCallMonitor::ClearCalls()
{
	std::lock_guard<std::mutex> lock(m_callsMutex);
	m_functionCalls.clear();
	printf("[FunctionMonitor] Cleared all function calls\n");
}

// Stub implementations for the type-aware functions to prevent compilation errors
void FunctionCallMonitor::RenderTypeAwareFunctionSearch()
{
	if (ImGui::CollapsingHeader("Type-Aware Function Search##TypeAwareSearch"))
	{
		ImGui::Text("Type-aware search not implemented yet");
		ImGui::Text("This will search functions by return type, parameters, and class hierarchy");
	}
}

void FunctionCallMonitor::RenderClassHierarchyView()
{
	if (ImGui::CollapsingHeader("Class Hierarchy Explorer##ClassHierarchy"))
	{
		ImGui::Text("Class hierarchy view not implemented yet");
		ImGui::Text("This will show FFXIV class inheritance and virtual functions");
	}
}

void FunctionCallMonitor::InitializeWithTypeInformation()
{
	printf("[FunctionMonitor] Type information initialization not implemented yet\n");
}