// This file will compile with Windows headers, but won't be parsed by IntelliSense for main files
#include <Windows.h>
#include <Psapi.h>
#include "MinHook.h"

#pragma comment(lib, "psapi.lib")

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
}