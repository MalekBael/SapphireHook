#include "hook_manager.h"
#include "MinHook.h"
#include "patternscanner.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <Psapi.h>

// Known FFXIV opcodes from the IPC definition files
namespace FFXIVOpcodes {
	// Client opcodes we want to monitor
	constexpr uint16_t PcPartyKick = 0xDE;
	constexpr uint16_t ChatHandler = 0x67;
	constexpr uint16_t ActionRequest = 0x196;
	constexpr uint16_t Move = 0x19A;
	constexpr uint16_t Command = 0x191;
	constexpr uint16_t GMCommand = 0x197;
	constexpr uint16_t TradeCommand = 0x1B3;
}

// Helper function to get the main module info
bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize)
{
	HMODULE hMainModule = GetModuleHandleW(NULL);
	if (!hMainModule)
	{
		std::cout << "Failed to get main module handle" << std::endl;
		return false;
	}

	MODULEINFO modInfo = { 0 };
	if (!GetModuleInformation(GetCurrentProcess(), hMainModule, &modInfo, sizeof(modInfo)))
	{
		std::cout << "Failed to get module information" << std::endl;
		return false;
	}

	baseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
	moduleSize = modInfo.SizeOfImage;

	// Log the actual module name for debugging
	wchar_t moduleName[MAX_PATH];
	if (GetModuleFileNameW(hMainModule, moduleName, MAX_PATH))
	{
		wchar_t* fileName = wcsrchr(moduleName, L'\\');
		if (fileName) fileName++;
		else fileName = moduleName;

		std::wcout << L"Hooking main module: " << fileName << std::endl;
	}

	std::cout << "Module base: 0x" << std::hex << baseAddress << ", size: 0x" << moduleSize << std::endl;
	return true;
}

// IPC Hook - dynamically find address
uintptr_t ipcHandlerAddr = 0;
typedef void(__fastcall* HandleIPC_t)(void* thisPtr, uint16_t opcode, void* data);
HandleIPC_t originalHandleIPC = nullptr;

void __fastcall HookedHandleIPC(void* thisPtr, uint16_t opcode, void* data)
{
	void* retAddr = _ReturnAddress();
	std::ofstream log("hooked_output.txt", std::ios::app);

	// Enhanced logging with known opcode names
	const char* opcodeName = "Unknown";
	switch (opcode)
	{
	case FFXIVOpcodes::PcPartyKick:    opcodeName = "PcPartyKick"; break;
	case FFXIVOpcodes::ChatHandler:    opcodeName = "ChatHandler"; break;
	case FFXIVOpcodes::ActionRequest:  opcodeName = "ActionRequest"; break;
	case FFXIVOpcodes::Move:           opcodeName = "Move"; break;
	case FFXIVOpcodes::Command:        opcodeName = "Command"; break;
	case FFXIVOpcodes::GMCommand:      opcodeName = "GMCommand"; break;
	case FFXIVOpcodes::TradeCommand:   opcodeName = "TradeCommand"; break;
	}

	log << "0x" << std::hex << reinterpret_cast<uintptr_t>(retAddr)
		<< " - " << opcodeName << " - 0x" << std::setw(4) << std::setfill('0') << opcode << std::endl;
	log.close();

	// Special handling for specific opcodes
	if (opcode == FFXIVOpcodes::PcPartyKick)
	{
		OutputDebugStringA("[+] PcPartyKick (0xDE) intercepted!\n");
		// You could block this by returning early without calling original
		// return; // Uncomment to block party kicks
	}

	if (opcode == FFXIVOpcodes::GMCommand)
	{
		OutputDebugStringA("[+] GM Command detected!\n");
	}

	originalHandleIPC(thisPtr, opcode, data);
}

bool FindAndHookIPC()
{
	uintptr_t moduleBase;
	size_t moduleSize;

	if (!GetMainModuleInfo(moduleBase, moduleSize))
	{
		std::cout << "Failed to get main module information" << std::endl;
		return false;
	}

	std::cout << "Scanning for IPC handler..." << std::endl;

	// More targeted IPC handler patterns based on network packet processing
	const char* ipcPatterns[] = {
		// These patterns focus on functions that handle 16-bit opcodes
		"40 53 48 83 EC ? 0F B7 DA 48 8B F9 66 85 D2",                    // Common IPC entry point
		"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B7 FA 48 8B F1",   // Packet handler with opcode
		"40 53 48 83 EC ? 48 8B D9 0F B7 D2 66 85 D2",                    // Network message handler
		"48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 0F B7 DA 66 85 DB",        // IPC processor
		"40 53 48 83 EC ? 0F B7 DA 66 85 DB 74 ? 48 8B CB",              // Opcode switch handler
		"48 83 EC ? 0F B7 C2 66 3D ? ? 0F 87",                            // Large opcode switch
		"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B7 EA 48 8B F9", // Extended handler

		// Zone-specific handlers (looking for patterns that might handle zone opcodes)
		"48 83 EC ? 66 81 FA ? ? 0F 87",                                   // Zone opcode range check
		"0F B7 C2 83 F8 ? 0F 87 ? ? ? ? 48 8D 15",                       // Jump table for opcodes
	};

	for (int i = 0; i < sizeof(ipcPatterns) / sizeof(ipcPatterns[0]); i++)
	{
		ipcHandlerAddr = patternscan(moduleBase, moduleSize, ipcPatterns[i]);
		if (ipcHandlerAddr)
		{
			std::cout << "Found potential IPC handler using pattern " << (i + 1) << " at: 0x" << std::hex << ipcHandlerAddr << std::endl;

			// Enhanced verification - look for opcode-related operations
			bool looksLikeIPC = false;
			uint8_t* code = (uint8_t*)ipcHandlerAddr;

			// Look for movzx (0F B7) instructions that load 16-bit opcodes
			for (int j = 0; j < 50; j++)
			{
				if (code[j] == 0x0F && code[j + 1] == 0xB7)  // movzx instruction
				{
					looksLikeIPC = true;
					std::cout << "Found movzx instruction at offset +" << j << " (likely opcode loading)" << std::endl;
					break;
				}
				// Also look for 16-bit comparisons
				if (code[j] == 0x66 && (code[j + 1] == 0x81 || code[j + 1] == 0x83)) // 16-bit cmp
				{
					looksLikeIPC = true;
					std::cout << "Found 16-bit comparison at offset +" << j << " (likely opcode check)" << std::endl;
					break;
				}
			}

			if (looksLikeIPC)
			{
				std::cout << "Pattern verification passed - installing hook" << std::endl;
				break;
			}
			else
			{
				std::cout << "Pattern verification failed - trying next pattern" << std::endl;
				ipcHandlerAddr = 0;
			}
		}
	}

	if (!ipcHandlerAddr)
	{
		std::cout << "Failed to find IPC handler address using patterns" << std::endl;
		std::cout << "Trying alternative approach - looking for known opcode references..." << std::endl;

		// Alternative: Look for functions that reference known opcodes
		const uint16_t knownOpcodes[] = { 0xDE, 0x196, 0x19A, 0x67, 0x191 };
		for (uint16_t opcode : knownOpcodes)
		{
			// Search for the opcode value in the code section
			for (uintptr_t addr = moduleBase; addr < moduleBase + moduleSize - 4; addr += 4)
			{
				if (*(uint16_t*)addr == opcode)
				{
					// Found opcode, now look backwards for function start
					for (uintptr_t funcStart = addr - 100; funcStart < addr; funcStart++)
					{
						uint8_t* code = (uint8_t*)funcStart;
						// Look for function prologue patterns
						if ((code[0] == 0x48 && code[1] == 0x89) || // mov [rsp+?], ?
							(code[0] == 0x40 && code[1] == 0x53) ||  // push rbx (with REX)
							(code[0] == 0x48 && code[1] == 0x83))    // sub rsp, ?
						{
							ipcHandlerAddr = funcStart;
							std::cout << "Found potential IPC handler by opcode reference 0x" << std::hex << opcode
								<< " at: 0x" << funcStart << std::endl;
							goto found_by_opcode;
						}
					}
				}
			}
		}
	found_by_opcode:

		if (!ipcHandlerAddr)
		{
			std::cout << "Failed to find IPC handler by any method" << std::endl;
			return false;
		}
	}

	// Create and enable hook
	if (MH_CreateHook(reinterpret_cast<void*>(ipcHandlerAddr), &HookedHandleIPC, reinterpret_cast<void**>(&originalHandleIPC)) != MH_OK)
	{
		std::cout << "Failed to create IPC hook" << std::endl;
		return false;
	}

	if (MH_EnableHook(reinterpret_cast<void*>(ipcHandlerAddr)) != MH_OK)
	{
		std::cout << "Failed to enable IPC hook" << std::endl;
		return false;
	}

	std::cout << "IPC hook installed successfully!" << std::endl;
	std::cout << "Monitoring opcodes: PcPartyKick(0xDE), ChatHandler(0x67), ActionRequest(0x196), Move(0x19A)" << std::endl;
	return true;
}

// Dispatcher Hook - also use pattern scanning
uintptr_t dispatcherAddr = 0;
typedef char(__fastcall* DispatcherFn)(void* rcx);
DispatcherFn originalDispatcher = nullptr;

char __fastcall HookedDispatcher(void* rcx)
{
	uint8_t* packet = reinterpret_cast<uint8_t*>(rcx);
	uint8_t opcode = packet[2];  // Adjust offset as needed

	std::ofstream log("dispatcher_output.txt", std::ios::app);
	log << "[Dispatcher] Opcode: 0x" << std::hex << std::setw(2) << std::setfill('0') << (int)opcode << std::endl;
	log.close();

	if (opcode == 0xDE)
	{
		OutputDebugStringA("[+] PcPartyKick (0xDE) triggered\n");
	}

	return originalDispatcher(rcx);
}

bool FindAndHookDispatcher()
{
	uintptr_t moduleBase;
	size_t moduleSize;

	if (!GetMainModuleInfo(moduleBase, moduleSize))
	{
		return false;
	}

	std::cout << "Scanning for dispatcher..." << std::endl;

	const char* dispatcherPatterns[] = {
		"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 45 33 FF",
		"40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 84 C0 74 ? 48 8B CB",
		"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA",
		"40 53 48 83 EC ? 48 8B D9 48 8B 0D ? ? ? ? 48 85 C9"
	};

	for (int i = 0; i < sizeof(dispatcherPatterns) / sizeof(dispatcherPatterns[0]); i++)
	{
		dispatcherAddr = patternscan(moduleBase, moduleSize, dispatcherPatterns[i]);
		if (dispatcherAddr)
		{
			std::cout << "Found dispatcher using pattern " << (i + 1) << " at: 0x" << std::hex << dispatcherAddr << std::endl;
			break;
		}
	}

	if (!dispatcherAddr)
	{
		std::cout << "Failed to find dispatcher address" << std::endl;
		return false;
	}

	if (MH_CreateHook(reinterpret_cast<void*>(dispatcherAddr), &HookedDispatcher, reinterpret_cast<void**>(&originalDispatcher)) != MH_OK)
		return false;

	return MH_EnableHook(reinterpret_cast<void*>(dispatcherAddr)) == MH_OK;
}

typedef void(__fastcall* SetMovementSpeed_t)(void* pThis, float speed);
SetMovementSpeed_t oSetMovementSpeed = nullptr;
float g_SpeedMultiplier = 1.0f;

void __fastcall hkSetMovementSpeed(void* pThis, float speed)
{
	oSetMovementSpeed(pThis, speed * g_SpeedMultiplier);
}

void HookManager::Initialize()
{
	std::cout << "Initializing hooks..." << std::endl;

	if (MH_Initialize() != MH_OK)
	{
		std::cout << "Failed to initialize MinHook!" << std::endl;
		return;
	}

	FindAndHookIPC();
	FindAndHookDispatcher();
}

void HookManager::SetSpeedMultiplier(float multiplier)
{
	g_SpeedMultiplier = multiplier;
}

void HookManager::Shutdown()
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}

void InitHooks()
{
	HookManager::Initialize();
}