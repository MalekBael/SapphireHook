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
	std::cout << "[INJECT] Target PID: " << processId << std::endl;

	// Verify process is still running
	if (!IsProcessRunning(processId))
	{
		std::cout << "[INJECT] ERROR: Process " << processId << " is not running!" << std::endl;
		return false;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess)
	{
		std::cout << "[INJECT] Failed to open process. Error: " << GetLastError() << std::endl;
		return false;
	}

	size_t dllPathSize = (dllPath.size() + 1) * sizeof(wchar_t);
	LPVOID pRemoteMemory = VirtualAllocEx(hProcess, nullptr, dllPathSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteMemory)
	{
		std::cout << "[INJECT] Failed to allocate memory. Error: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPathSize, nullptr))
	{
		std::cout << "[INJECT] Failed to write DLL path. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryW, pRemoteMemory, 0, nullptr);
	if (!hThread)
	{
		std::cout << "[INJECT] Failed to create remote thread. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	DWORD waitResult = WaitForSingleObject(hThread, 5000);
	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	std::cout << "[INJECT] LoadLibraryW returned: 0x" << std::hex << exitCode << std::dec << std::endl;

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	// Give the process a moment and validate it's still alive
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	if (!IsProcessRunning(processId))
	{
		std::cout << "[INJECT] WARNING: Target process is no longer running after injection!" << std::endl;
		return false;
	}

	return exitCode != 0;
}

int main()
{
	SetConsoleTitleW(L"SapphireHook Injector");

	fs::path currentPath = fs::current_path();
	fs::path fullDllPath = currentPath / "SapphireHookDLL.dll";
	if (!fs::exists(fullDllPath))
	{
		std::cout << "Error: SapphireHookDLL.dll not found in: " << currentPath << std::endl;
		return 1;
	}

	std::wstring dllPathStr = fullDllPath.wstring();
	const std::wstring targetExe = L"ffxiv_dx11.exe";

	std::cout << "Waiting for process 'ffxiv_dx11.exe' (up to 30s)..." << std::endl;
	DWORD processId = 0;
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
	while (std::chrono::steady_clock::now() < deadline)
	{
		processId = GetProcessId(targetExe);
		if (processId != 0) break;
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	if (processId == 0)
	{
		std::cout << "Process not found. Exiting." << std::endl;
		return 2;
	}

	std::cout << "Found PID: " << processId << ". Injecting..." << std::endl;
	bool success = InjectDLL(processId, dllPathStr);
	std::cout << (success ? "Injection succeeded." : "Injection failed.") << std::endl;
	return success ? 0 : 1;
}