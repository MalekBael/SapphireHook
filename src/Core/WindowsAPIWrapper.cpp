// This file will compile with Windows headers, but won't be parsed by IntelliSense for main files
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// Prevent winsock.h from being pulled by Windows.h in this TU
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <Windows.h>
#include <Psapi.h>
#include "../../vendor/minhook/include/MinHook.h"
#include "WindowsAPIWrapper.h"

#pragma comment(lib, "psapi.lib")

#ifdef _MSC_VER
#pragma intrinsic(_ReturnAddress)
#endif

extern "C" {
	// Module functions
	void* GetGameModuleHandle()
	{
		return GetModuleHandleW(NULL);
	}

	void* GetCurrentThreadWrapper()
	{
		return GetCurrentThread();
	}

	bool SetThreadPriorityWrapper(void* hThread, int priority)
	{
		return SetThreadPriority(static_cast<HANDLE>(hThread), priority) != 0;
	}

	bool GetGameModuleInfo(void* hModule, void* moduleInfo, unsigned long size)
	{
		return GetModuleInformation(GetCurrentProcess(), (HMODULE)hModule, (LPMODULEINFO)moduleInfo, size);
	}

	void* GetCurrentProcessHandle()
	{
		return GetCurrentProcess();
	}

	void* GetGameModuleBaseAddress()
	{
		HMODULE hModule = nullptr;
		
		// Use _ReturnAddress() to get an address within the current module
		// Then use GetModuleHandleExA to get the module base from that address
		if (GetModuleHandleExA(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(_ReturnAddress()),
			&hModule))
		{
			return hModule;
		}
		
		// Fallback: try to get the main module handle
		return GetModuleHandleW(NULL);
	}

	// Stack walking
	unsigned short CaptureStack(unsigned long framesToSkip, unsigned long framesToCapture, void** backTrace)
	{
		return CaptureStackBackTrace(framesToSkip, framesToCapture, backTrace, NULL);
	}

	// Clipboard functions
	bool OpenClipboardWrapper(void* hwnd)
	{
		return OpenClipboard((HWND)hwnd);
	}

	bool EmptyClipboardWrapper()
	{
		return EmptyClipboard();
	}

	void* GlobalAllocWrapper(unsigned int flags, size_t size)
	{
		return GlobalAlloc(flags, size);
	}

	void* GlobalLockWrapper(void* hMem)
	{
		return GlobalLock((HGLOBAL)hMem);
	}

	bool GlobalUnlockWrapper(void* hMem)
	{
		return GlobalUnlock((HGLOBAL)hMem);
	}

	void* SetClipboardDataWrapper(unsigned int format, void* hMem)
	{
		return SetClipboardData(format, (HANDLE)hMem);
	}

	bool CloseClipboardWrapper()
	{
		return CloseClipboard();
	}

	// MinHook functions
	int MH_InitializeWrapper()
	{
		return (int)MH_Initialize();
	}

	int MH_CreateHookWrapper(void* pTarget, void* pDetour, void** ppOriginal)
	{
		return (int)MH_CreateHook(pTarget, pDetour, ppOriginal);
	}

	int MH_EnableHookWrapper(void* pTarget)
	{
		return (int)MH_EnableHook(pTarget);
	}

	int MH_DisableHookWrapper(void* pTarget)
	{
		return (int)MH_DisableHook(pTarget);
	}

	int MH_RemoveHookWrapper(void* pTarget)
	{
		return (int)MH_RemoveHook(pTarget);
	}

	// Memory query functions
	bool VirtualQueryWrapper(const void* address, void* buffer, size_t length)
	{
		SIZE_T result = VirtualQuery(address, (PMEMORY_BASIC_INFORMATION)buffer, length);
		return result != 0;
	}

	bool IsBadReadPtrWrapper(const void* address, size_t size)
	{
		return IsBadReadPtr(address, size) != 0;
	}

	// Windows resource API wrappers
	void* FindResourceAWrapper(void* hModule, const char* lpName, const char* lpType)
	{
		return FindResourceA(static_cast<HMODULE>(hModule), lpName, lpType);
	}

	void* LoadResourceWrapper(void* hModule, void* hResInfo)
	{
		return LoadResource(static_cast<HMODULE>(hModule), static_cast<HRSRC>(hResInfo));
	}

	unsigned long SizeofResourceWrapper(void* hModule, void* hResInfo)
	{
		return SizeofResource(static_cast<HMODULE>(hModule), static_cast<HRSRC>(hResInfo));
	}

	void* LockResourceWrapper(void* hResData)
	{
		return LockResource(static_cast<HGLOBAL>(hResData));
	}

	void* GetModuleHandleWrapper(const char* lpModuleName)
	{
		return GetModuleHandleA(lpModuleName);
	}

	void* MakeIntResourceWrapper(int id)
	{
		return MAKEINTRESOURCEA(id);
	}

	// Add the new GetModuleHandleExA wrapper
	bool GetModuleHandleExAWrapper(unsigned long dwFlags, const char* lpModuleName, void** phModule)
	{
		return GetModuleHandleExA(dwFlags, lpModuleName, reinterpret_cast<HMODULE*>(phModule)) != 0;
	}

	// Add _ReturnAddress implementation if needed (though it's an intrinsic)
	#ifdef _MSC_VER
	// _ReturnAddress is already provided by the compiler as an intrinsic
	// No implementation needed
	#else
	void* _ReturnAddress()
	{
		// For non-MSVC compilers, provide a fallback
		return __builtin_return_address(0);
	}
	#endif

	size_t GetModuleFileNameAWrapper(void* hModule, char* buffer, size_t size)
	{
		if (!buffer || size == 0) return 0;
		DWORD r = GetModuleFileNameA(static_cast<HMODULE>(hModule), buffer, static_cast<DWORD>(size));
		return static_cast<size_t>(r);
	}
}