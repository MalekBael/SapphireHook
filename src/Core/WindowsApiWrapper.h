#pragma once

// WindowsAPIWrapper.h - Header for Windows API wrapper functions
// This provides C-style function declarations for Windows APIs without including Windows headers
// in the main codebase, avoiding IntelliSense parsing issues.

#include <cstddef>
#include <cstdint>

#ifndef WINDOWS_API_WRAPPER_H
#define WINDOWS_API_WRAPPER_H

extern "C" {

	// ===== MODULE FUNCTIONS =====

	/// <summary>
	/// Gets a handle to the current game module (main executable)
	/// </summary>
	/// <returns>Handle to the current module, or nullptr on failure</returns>
	void* GetGameModuleHandle();

	/// <summary>
	/// Retrieves information about a specified module
	/// </summary>
	/// <param name="hModule">Handle to the module</param>
	/// <param name="moduleInfo">Pointer to structure to receive module information</param>
	/// <param name="size">Size of the moduleInfo structure</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GetGameModuleInfo(void* hModule, void* moduleInfo, unsigned long size);

	/// <summary>
	/// Gets a handle to the current process
	/// </summary>
	/// <returns>Handle to the current process</returns>
	void* GetCurrentProcessHandle();

	/// <summary>
	/// Gets the base address of the current game module
	/// </summary>
	/// <returns>Base address of the module, or nullptr on failure</returns>
	void* GetGameModuleBaseAddress();

	/// <summary>
	/// Retrieves the fully qualified path for the specified module (nullptr = main EXE)
	/// Returns number of chars written (excluding null) or 0 on failure
	/// </summary>
	/// <param name="hModule">Handle to the module</param>
	/// <param name="buffer">Destination buffer for the path</param>
	/// <param name="size">Size of buffer in bytes</param>
	/// <returns>Number of chars written (excluding null) or 0 on failure</returns>
	size_t GetModuleFileNameAWrapper(void* hModule, char* buffer, size_t size);

	// ===== THREAD FUNCTIONS =====

	/// <summary>
	/// Gets a handle to the current thread
	/// </summary>
	/// <returns>Handle to the current thread</returns>
	void* GetCurrentThreadWrapper();

	/// <summary>
	/// Sets the priority of a thread
	/// </summary>
	/// <param name="hThread">Handle to the thread</param>
	/// <param name="priority">Thread priority value</param>
	/// <returns>true if successful, false otherwise</returns>
	bool SetThreadPriorityWrapper(void* hThread, int priority);

	// ===== STACK WALKING =====

	/// <summary>
	/// Captures a stack back trace
	/// </summary>
	/// <param name="framesToSkip">Number of frames to skip from the top of the stack</param>
	/// <param name="framesToCapture">Number of frames to capture</param>
	/// <param name="backTrace">Array to receive the captured stack frames</param>
	/// <returns>Number of frames actually captured</returns>
	unsigned short CaptureStack(unsigned long framesToSkip, unsigned long framesToCapture, void** backTrace);

	// ===== CLIPBOARD FUNCTIONS =====

	/// <summary>
	/// Opens the clipboard for examination and prevents other applications from modifying the clipboard content
	/// </summary>
	/// <param name="hwnd">Handle to the window to be associated with the open clipboard</param>
	/// <returns>true if successful, false otherwise</returns>
	bool OpenClipboardWrapper(void* hwnd);

	/// <summary>
	/// Empties the clipboard and frees handles to data in the clipboard
	/// </summary>
	/// <returns>true if successful, false otherwise</returns>
	bool EmptyClipboardWrapper();

	/// <summary>
	/// Allocates the specified number of bytes from the heap
	/// </summary>
	/// <param name="flags">Memory allocation attributes</param>
	/// <param name="size">Number of bytes to allocate</param>
	/// <returns>Handle to the allocated memory object, or nullptr on failure</returns>
	void* GlobalAllocWrapper(unsigned int flags, size_t size);

	/// <summary>
	/// Locks a global memory object and returns a pointer to the first byte of the object's memory block
	/// </summary>
	/// <param name="hMem">Handle to the global memory object</param>
	/// <returns>Pointer to the first byte of the memory block, or nullptr on failure</returns>
	void* GlobalLockWrapper(void* hMem);

	/// <summary>
	/// Decrements the lock count associated with a memory object
	/// </summary>
	/// <param name="hMem">Handle to the global memory object</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GlobalUnlockWrapper(void* hMem);

	/// <summary>
	/// Places data on the clipboard in a specified clipboard format
	/// </summary>
	/// <param name="format">Clipboard format</param>
	/// <param name="hMem">Handle to the data</param>
	/// <returns>Handle to the data on success, nullptr on failure</returns>
	void* SetClipboardDataWrapper(unsigned int format, void* hMem);

	/// <summary>
	/// Closes the clipboard
	/// </summary>
	/// <returns>true if successful, false otherwise</returns>
	bool CloseClipboardWrapper();

	// ===== MINHOOK FUNCTIONS =====

	/// <summary>
	/// Initializes the MinHook library
	/// </summary>
	/// <returns>Status code (0 = success)</returns>
	int MH_InitializeWrapper();

	/// <summary>
	/// Creates a hook for the specified target function
	/// </summary>
	/// <param name="pTarget">Pointer to the target function</param>
	/// <param name="pDetour">Pointer to the detour function</param>
	/// <param name="ppOriginal">Pointer to receive the trampoline function</param>
	/// <returns>Status code (0 = success)</returns>
	int MH_CreateHookWrapper(void* pTarget, void* pDetour, void** ppOriginal);

	/// <summary>
	/// Enables an already created hook
	/// </summary>
	/// <param name="pTarget">Pointer to the target function</param>
	/// <returns>Status code (0 = success)</returns>
	int MH_EnableHookWrapper(void* pTarget);

	/// <summary>
	/// Disables an already created hook
	/// </summary>
	/// <param name="pTarget">Pointer to the target function</param>
	/// <returns>Status code (0 = success)</returns>
	int MH_DisableHookWrapper(void* pTarget);

	/// <summary>
	/// Removes an already created hook
	/// </summary>
	/// <param name="pTarget">Pointer to the target function</param>
	/// <returns>Status code (0 = success)</returns>
	int MH_RemoveHookWrapper(void* pTarget);

	// ===== MEMORY QUERY FUNCTIONS =====

	/// <summary>
	/// Provides information about a range of pages in the virtual address space
	/// </summary>
	/// <param name="address">Pointer to the base address of the region</param>
	/// <param name="buffer">Pointer to a structure to receive information</param>
	/// <param name="length">Size of the buffer</param>
	/// <returns>true if successful, false otherwise</returns>
	bool VirtualQueryWrapper(const void* address, void* buffer, size_t length);

	/// <summary>
	/// Verifies that the calling process has read access to the specified range of memory
	/// </summary>
	/// <param name="address">Pointer to the first byte of the memory block</param>
	/// <param name="size">Size of the memory block</param>
	/// <returns>true if the calling process cannot read from the specified memory, false if it can</returns>
	bool IsBadReadPtrWrapper(const void* address, size_t size);

	// ===== WINDOWS RESOURCE API WRAPPERS =====

	/// <summary>
	/// Determines the location of a resource with the specified type and name in the specified module
	/// </summary>
	/// <param name="hModule">Handle to the module containing the resource</param>
	/// <param name="lpName">Name of the resource</param>
	/// <param name="lpType">Resource type</param>
	/// <returns>Handle to the specified resource's information block, or nullptr on failure</returns>
	void* FindResourceAWrapper(void* hModule, const char* lpName, const char* lpType);

	/// <summary>
	/// Retrieves a handle that can be used to obtain a pointer to the first byte of the specified resource in memory
	/// </summary>
	/// <param name="hModule">Handle to the module containing the resource</param>
	/// <param name="hResInfo">Handle to the resource</param>
	/// <returns>Handle to the data associated with the resource, or nullptr on failure</returns>
	void* LoadResourceWrapper(void* hModule, void* hResInfo);

	/// <summary>
	/// Returns the size, in bytes, of the specified resource
	/// </summary>
	/// <param name="hModule">Handle to the module containing the resource</param>
	/// <param name="hResInfo">Handle to the resource</param>
	/// <returns>Size of the resource in bytes, or 0 on failure</returns>
	unsigned long SizeofResourceWrapper(void* hModule, void* hResInfo);

	/// <summary>
	/// Retrieves a pointer to the specified resource in memory
	/// </summary>
	/// <param name="hResData">Handle to the resource to lock</param>
	/// <returns>Pointer to the first byte of the resource, or nullptr on failure</returns>
	void* LockResourceWrapper(void* hResData);

	/// <summary>
	/// Retrieves a module handle for the specified module
	/// </summary>
	/// <param name="lpModuleName">Name of the loaded module, or nullptr for the main executable</param>
	/// <returns>Handle to the specified module, or nullptr on failure</returns>
	void* GetModuleHandleWrapper(const char* lpModuleName);

	/// <summary>
	/// Converts an integer value to a resource type compatible with resource functions
	/// </summary>
	/// <param name="id">Integer identifier to convert</param>
	/// <returns>Pointer that can be used as a resource type/name</returns>
	void* MakeIntResourceWrapper(int id);

	/// <summary>
	/// Retrieves a module handle for the specified module and increments the module's reference count
	/// </summary>
	/// <param name="dwFlags">Flags that specify how the module handle is to be obtained</param>
	/// <param name="lpModuleName">Name of the loaded module or an address in the module</param>
	/// <param name="phModule">Handle to the specified module</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GetModuleHandleExAWrapper(unsigned long dwFlags, const char* lpModuleName, void** phModule);
} // extern "C"

// ===== MICROSOFT COMPILER INTRINSIC =====
// Move this OUTSIDE the extern "C" block since it's a C++ intrinsic

/// <summary>
/// Returns the address of the function that called the current function
/// Available only on Microsoft compilers with intrinsic support
/// </summary>
/// <returns>Return address of the calling function</returns>
#ifdef _MSC_VER
// Declare as intrinsic - no implementation needed, compiler provides it
extern "C" void* _ReturnAddress();
#pragma intrinsic(_ReturnAddress)
#endif

// ===== CONSTANTS =====
// These constants are defined here since we can't include Windows headers

// GetModuleHandleExA flags
#ifndef GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 0x00000004
#endif

#ifndef GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT  
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x00000002
#endif

// Global memory allocation flags
#ifndef GMEM_DDESHARE
#define GMEM_DDESHARE 0x2000
#endif

// Clipboard formats
#ifndef CF_TEXT
#define CF_TEXT 1
#endif

// Exception handling
#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER 1
#endif

// Thread priorities
#ifndef THREAD_PRIORITY_BELOW_NORMAL
#define THREAD_PRIORITY_BELOW_NORMAL -1
#endif

// MinHook status codes
#ifndef MH_OK
#define MH_OK 0
#endif

#ifndef MH_ERROR_ALREADY_INITIALIZED
#define MH_ERROR_ALREADY_INITIALIZED 1
#endif

// Memory states and protection constants
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

#endif // WINDOWS_API_WRAPPER_H