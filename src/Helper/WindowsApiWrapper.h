#pragma once

#include <cstddef>
#include <cstdint>

#ifndef WINDOWS_API_WRAPPER_H
#define WINDOWS_API_WRAPPER_H

extern "C" {

	void* GetGameModuleHandle();

	bool GetGameModuleInfo(void* hModule, void* moduleInfo, unsigned long size);

	void* GetCurrentProcessHandle();

	void* GetGameModuleBaseAddress();

	size_t GetModuleFileNameAWrapper(void* hModule, char* buffer, size_t size);

	void* GetCurrentThreadWrapper();

	bool SetThreadPriorityWrapper(void* hThread, int priority);

	unsigned short CaptureStack(unsigned long framesToSkip, unsigned long framesToCapture, void** backTrace);

	bool OpenClipboardWrapper(void* hwnd);

	bool EmptyClipboardWrapper();

	void* GlobalAllocWrapper(unsigned int flags, size_t size);

	void* GlobalLockWrapper(void* hMem);

	bool GlobalUnlockWrapper(void* hMem);

	void* SetClipboardDataWrapper(unsigned int format, void* hMem);

	bool CloseClipboardWrapper();

	int MH_InitializeWrapper();

	int MH_CreateHookWrapper(void* pTarget, void* pDetour, void** ppOriginal);

	int MH_EnableHookWrapper(void* pTarget);

	int MH_DisableHookWrapper(void* pTarget);

	int MH_RemoveHookWrapper(void* pTarget);

	bool VirtualQueryWrapper(const void* address, void* buffer, size_t length);

	bool IsBadReadPtrWrapper(const void* address, size_t size);

	void* FindResourceAWrapper(void* hModule, const char* lpName, const char* lpType);

	void* LoadResourceWrapper(void* hModule, void* hResInfo);

	unsigned long SizeofResourceWrapper(void* hModule, void* hResInfo);

	void* LockResourceWrapper(void* hResData);

	void* GetModuleHandleWrapper(const char* lpModuleName);

	void* MakeIntResourceWrapper(int id);

	bool GetModuleHandleExAWrapper(unsigned long dwFlags, const char* lpModuleName, void** phModule);
}   

#ifdef _MSC_VER
extern "C" void* _ReturnAddress();
#pragma intrinsic(_ReturnAddress)
#endif

#ifndef GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 0x00000004
#endif

#ifndef GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT  
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x00000002
#endif

#ifndef GMEM_DDESHARE
#define GMEM_DDESHARE 0x2000
#endif

#ifndef CF_TEXT
#define CF_TEXT 1
#endif

#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER 1
#endif

#ifndef THREAD_PRIORITY_BELOW_NORMAL
#define THREAD_PRIORITY_BELOW_NORMAL -1
#endif

#ifndef MH_OK
#define MH_OK 0
#endif

#ifndef MH_ERROR_ALREADY_INITIALIZED
#define MH_ERROR_ALREADY_INITIALIZED 1
#endif

#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif

#ifndef PAGE_NOACCESS
#define PAGE_NOACCESS 0x01
#endif

#ifndef PAGE_GUARD
#define PAGE_GUARD 0x100
#endif

#ifndef PAGE_EXECUTE
#define PAGE_EXECUTE 0x10
#endif

#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ 0x20
#endif

#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif

#ifndef PAGE_READONLY
#define PAGE_READONLY 0x02
#endif

#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif

#endif 