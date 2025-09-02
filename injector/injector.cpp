#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;

void LogProcesses()
{
	std::cout << "\n=== Current Running Processes ===" << std::endl;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W processEntry;
		processEntry.dwSize = sizeof(processEntry);
		if (Process32FirstW(snapshot, &processEntry))
		{
			do
			{
				std::wstring procName = processEntry.szExeFile;
				std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);

				if (procName.find(L"ffxiv") != std::wstring::npos ||
					procName.find(L"ff14") != std::wstring::npos)
				{
					std::wcout << L"  " << processEntry.szExeFile
						<< L" (PID: " << processEntry.th32ProcessID
						<< L", Parent PID: " << processEntry.th32ParentProcessID << L")" << std::endl;
				}
			} while (Process32NextW(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}
	std::cout << "================================\n" << std::endl;
}

DWORD GetProcessId(const std::wstring& processName)
{
	DWORD processId = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W processEntry;
		processEntry.dwSize = sizeof(processEntry);
		if (Process32FirstW(snapshot, &processEntry))
		{
			do
			{
				if (processName == processEntry.szExeFile)
				{
					processId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32NextW(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}
	return processId;
}

bool IsProcessRunning(DWORD processId)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess)
	{
		DWORD exitCode;
		GetExitCodeProcess(hProcess, &exitCode);
		CloseHandle(hProcess);
		return exitCode == STILL_ACTIVE;
	}
	return false;
}

bool InjectDLL(DWORD processId, const std::wstring& dllPath)
{
	std::cout << "\n[INJECT] Starting injection process..." << std::endl;
	std::cout << "[INJECT] Target PID: " << processId << std::endl;

	// Verify process is still running
	if (!IsProcessRunning(processId))
	{
		std::cout << "[INJECT] ERROR: Process " << processId << " is not running!" << std::endl;
		return false;
	}

	std::cout << "[INJECT] Opening process..." << std::endl;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess)
	{
		std::cout << "[INJECT] Failed to open process. Error: " << GetLastError() << std::endl;
		return false;
	}

	std::cout << "[INJECT] Allocating memory in target process..." << std::endl;
	size_t dllPathSize = (dllPath.size() + 1) * sizeof(wchar_t);
	LPVOID pRemoteMemory = VirtualAllocEx(hProcess, nullptr, dllPathSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteMemory)
	{
		std::cout << "[INJECT] Failed to allocate memory. Error: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return false;
	}

	std::cout << "[INJECT] Writing DLL path to target process..." << std::endl;
	if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPathSize, nullptr))
	{
		std::cout << "[INJECT] Failed to write DLL path. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

	std::cout << "[INJECT] Creating remote thread to load DLL..." << std::endl;
	std::cout << "[INJECT] LoadLibraryW address: 0x" << std::hex << pLoadLibraryW << std::dec << std::endl;

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryW, pRemoteMemory, 0, nullptr);
	if (!hThread)
	{
		std::cout << "[INJECT] Failed to create remote thread. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	std::cout << "[INJECT] Waiting for DLL to load..." << std::endl;
	DWORD waitResult = WaitForSingleObject(hThread, 5000);

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	std::cout << "[INJECT] Thread exit code: 0x" << std::hex << exitCode << std::dec << std::endl;

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	// Wait a moment and check if process is still running
	std::this_thread::sleep_for(std::chrono::milliseconds(500));
	if (!IsProcessRunning(processId))
	{
		std::cout << "[INJECT] WARNING: Target process is no longer running after injection!" << std::endl;
		return false;
	}

	std::cout << "[INJECT] Injection completed successfully." << std::endl;
	return true;
}

int main()
{
	SetConsoleTitleW(L"SapphireHook Injector - Diagnostic Mode");
	std::cout << "==================================" << std::endl;
	std::cout << "  SapphireHook Injector (DEBUG)" << std::endl;
	std::cout << "==================================" << std::endl;
	std::cout << std::endl;

	// Log initial state
	std::cout << "Checking for FFXIV processes BEFORE injection..." << std::endl;
	LogProcesses();

	fs::path currentPath = fs::current_path();
	fs::path fullDllPath = currentPath / "SapphireHookDLL.dll";

	if (!fs::exists(fullDllPath))
	{
		std::cout << "Error: SapphireHookDLL.dll not found!" << std::endl;
		std::cout << "Current directory: " << currentPath << std::endl;
		std::cout << "Press any key to exit..." << std::endl;
		std::cin.get();
		return 1;
	}

	std::cout << "DLL found: " << fullDllPath << std::endl;

	// Find FFXIV process
	DWORD processId = GetProcessId(L"ffxiv_dx11.exe");
	if (processId == 0)
	{
		std::cout << "Error: ffxiv_dx11.exe not found!" << std::endl;
		std::cout << "Make sure the game is running." << std::endl;
		std::cout << "Press any key to exit..." << std::endl;
		std::cin.get();
		return 1;
	}

	std::cout << "\nFound ffxiv_dx11.exe with PID: " << processId << std::endl;
	std::cout << "\nPress ENTER to inject (or close this window to cancel)..." << std::endl;
	std::cin.get();

	// Inject
	std::wstring dllPathStr = fullDllPath.wstring();
	bool success = InjectDLL(processId, dllPathStr);

	// Check what happened after injection
	std::cout << "\nChecking for FFXIV processes AFTER injection..." << std::endl;
	LogProcesses();

	if (success)
	{
		std::cout << "\nInjection reported success." << std::endl;
		std::cout << "If the game closed/restarted, it might be due to:" << std::endl;
		std::cout << "1. Anti-cheat detection" << std::endl;
		std::cout << "2. DLL initialization crash" << std::endl;
		std::cout << "3. Hook installation failure" << std::endl;
	}
	else
	{
		std::cout << "\nInjection failed!" << std::endl;
	}

	std::cout << "\nPress any key to exit..." << std::endl;
	std::cin.get();
	return 0;
}