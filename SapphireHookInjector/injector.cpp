#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <atomic>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <chrono>
#include <thread>
#include <algorithm>
#include <optional>
#include <cstdint>
#include <csignal>
#include <iomanip>
#include <sstream>
#include <array>
#include <fstream>
#include <bcrypt.h>
#include <ShlObj.h>
#include <KnownFolders.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

namespace fs = std::filesystem;

static std::atomic<bool> g_cancel{ false };

enum class LogLevel { Info, Warn, Error };

static void Log(LogLevel lvl, const std::string& msg) {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    const char* tag =
        (lvl == LogLevel::Info) ? "INFO" :
        (lvl == LogLevel::Warn) ? "WARN" : "ERR ";
    std::cout << std::setfill('0')
        << "[" << tag << " "
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond << "."
        << std::setw(3) << st.wMilliseconds
        << "] " << msg << std::endl;
}

static void EnableCancelHandler() {
    std::signal(SIGINT, [](int) {
        g_cancel = true;
        Log(LogLevel::Warn, "Cancellation requested (Ctrl-C)");
        });
}

static bool EnableSeDebugPrivilege() {
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    if (ok) Log(LogLevel::Info, "SeDebugPrivilege enabled");
    return ok;
}

struct ProcInfo {
    DWORD pid{};
    std::wstring exe;
};

static std::vector<ProcInfo> FindProcessesByPattern(const std::vector<std::wstring>& patterns) {
    std::vector<ProcInfo> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            std::wstring name = pe.szExeFile;
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            for (auto& p : patterns) {
                if (lower.find(p) != std::wstring::npos) {
                    result.push_back({ pe.th32ProcessID, name });
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return result;
}

static bool IsProcessRunning(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD code = 0;
    bool ok = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return ok && code == STILL_ACTIVE;
}

static bool IsDllAlreadyLoaded(DWORD pid, const std::wstring& dllNameCaseInsensitive) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{ sizeof(me) };
    bool found = false;
    if (Module32FirstW(snapshot, &me)) {
        do {
            std::wstring mod = me.szModule;
            std::wstring lowerMod = mod;
            std::transform(lowerMod.begin(), lowerMod.end(), lowerMod.begin(), ::towlower);
            std::wstring lowerTarget = dllNameCaseInsensitive;
            std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);
            if (lowerMod == lowerTarget) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &me));
    }
    CloseHandle(snapshot);
    return found;
}

static std::string HashFileSHA256(const fs::path& p) {
    if (!fs::exists(p)) return {};
    HANDLE hFile = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};
    BCRYPT_ALG_HANDLE hAlg{};
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) { CloseHandle(hFile); return {}; }
    DWORD objectLen = 0, cb = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLen), sizeof(objectLen), &cb, 0);
    if (status < 0 || objectLen == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return {};
    }
    std::vector<BYTE> hashObject(objectLen);
    BCRYPT_HASH_HANDLE hHash{};
    status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), static_cast<ULONG>(hashObject.size()), nullptr, 0, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return {};
    }
    std::array<char, 4096> buffer{};
    DWORD bytesRead = 0;
    while (ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) && bytesRead) {
        status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buffer.data()), bytesRead, 0);
        if (status < 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return {};
        }
    }
    BYTE hash[32]{};
    status = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    if (status < 0) return {};
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (BYTE b : hash) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

struct Args {
    std::wstring processName{ L"ffxiv_dx11.exe" };
    fs::path dllPath{ L"SapphireHookDLL.dll" };
    int waitSeconds{ 30 };
    bool pickProcess{ true };
    bool watch{ false };
    int retry{ 0 };
    std::optional<DWORD> directPid{};
    std::vector<std::wstring> extraPatterns{};
};

// Simple UTF-8 -> UTF-16 helper (naive, ok for ASCII process names)
static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(len ? len - 1 : 0, L'\0');
    if (len > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    return w;
}

static void LoadConfig(Args& a) {
    // Acquire %APPDATA% path via Shell API first, then fallback to environment.
    fs::path base;
    wchar_t* appData = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appData))) {
        base = fs::path(appData);
        CoTaskMemFree(appData);
    }
    else {
        wchar_t* envVal = nullptr;
        size_t sz = 0;
        if (_wdupenv_s(&envVal, &sz, L"APPDATA") == 0 && envVal) {
            base = fs::path(envVal);
            free(envVal);
        }
    }

    if (base.empty()) {
        Log(LogLevel::Warn, "Could not resolve APPDATA; skipping config load");
        return;
    }

    fs::path cfg = base / L"SapphireHook" / L"injector.toml";
    std::error_code ec;
    if (!fs::exists(cfg, ec)) return;
    std::ifstream ifs(cfg);
    if (!ifs.is_open()) {
        Log(LogLevel::Warn, "Config found but could not open: " + cfg.string());
        return;
    }
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        auto trim = [](std::string& s2) {
            auto notsp = [](int c) { return !std::isspace(c); };
            s2.erase(s2.begin(), std::find_if(s2.begin(), s2.end(), notsp));
            s2.erase(std::find_if(s2.rbegin(), s2.rend(), notsp).base(), s2.end());
            };
        trim(key); trim(val);
        if (key == "dll") a.dllPath = fs::path(val);
        else if (key == "process") a.processName = ToWide(val);
        else if (key == "wait") a.waitSeconds = std::stoi(val);
        else if (key == "watch") a.watch = (val == "1" || val == "true" || val == "yes");
        else if (key == "retry") a.retry = std::stoi(val);
        else if (key == "pid") a.directPid = static_cast<DWORD>(std::stoul(val));
        else if (key == "pattern") a.extraPatterns.push_back(ToWide(val));
    }
    Log(LogLevel::Info, "Loaded config: " + cfg.string());
}

static Args ParseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string v = argv[i];
        if (v == "--dll" && i + 1 < argc) a.dllPath = fs::path(argv[++i]);
        else if (v == "--proc" && i + 1 < argc) a.processName = ToWide(argv[++i]);
        else if (v == "--pid" && i + 1 < argc) a.directPid = static_cast<DWORD>(std::stoul(argv[++i]));
        else if (v == "--wait" && i + 1 < argc) a.waitSeconds = std::stoi(argv[++i]);
        else if (v == "--no-pick") a.pickProcess = false;
        else if (v == "--watch") a.watch = true;
        else if (v == "--retry" && i + 1 < argc) a.retry = std::stoi(argv[++i]);
        else if (v == "--pattern" && i + 1 < argc) a.extraPatterns.push_back(ToWide(argv[++i]));
    }
    return a;
}

static bool InjectDLL(DWORD pid, const std::wstring& fullDllPath) {
    if (!IsProcessRunning(pid)) {
        Log(LogLevel::Error, "Process not running at inject start");
        return false;
    }
    if (IsDllAlreadyLoaded(pid, fs::path(fullDllPath).filename().wstring())) {
        Log(LogLevel::Warn, "DLL already loaded; skipping");
        return true;
    }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        Log(LogLevel::Error, "OpenProcess failed: " + std::to_string(GetLastError()));
        return false;
    }

    size_t bytes = (fullDllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        Log(LogLevel::Error, "VirtualAllocEx failed: " + std::to_string(GetLastError()));
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteMem, fullDllPath.c_str(), bytes, nullptr)) {
        Log(LogLevel::Error, "WriteProcessMemory failed: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) {
        Log(LogLevel::Error, "GetModuleHandleW(kernel32.dll) failed");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    auto pLoadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW"));
    if (!pLoadLibraryW) {
        Log(LogLevel::Error, "GetProcAddress(LoadLibraryW) failed");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLibraryW, remoteMem, 0, nullptr);
    if (!hThread) {
        Log(LogLevel::Error, "CreateRemoteThread failed: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    DWORD wait = WaitForSingleObject(hThread, 8000);
    DWORD loadResult = 0;
    GetExitCodeThread(hThread, &loadResult);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);

    if (wait == WAIT_TIMEOUT) {
        Log(LogLevel::Warn, "Remote thread wait timed out; continuing");
    }
    if (loadResult == 0) {
        Log(LogLevel::Warn, "LoadLibraryW returned NULL (module load may have failed)");
    }

    bool loaded = IsDllAlreadyLoaded(pid, fs::path(fullDllPath).filename().wstring());
    Log(LogLevel::Info, std::string("Post-check: DLL ") + (loaded ? "present" : "NOT present"));

    CloseHandle(hProc);
    return loaded;
}

#ifndef SH_DISABLE_INJECTOR_MAIN
int main(int argc, char** argv) {
    SetConsoleTitleW(L"SapphireHook Injector");
    EnableCancelHandler();
    bool dbg = EnableSeDebugPrivilege();
    if (!dbg) Log(LogLevel::Warn, "SeDebugPrivilege not granted (continuing)");

    Args args = ParseArgs(argc, argv);
    LoadConfig(args);

    fs::path dllPath = fs::absolute(args.dllPath);
    std::error_code ec;
    dllPath = fs::weakly_canonical(dllPath, ec);
    if (ec || !fs::exists(dllPath)) {
        Log(LogLevel::Error, "DLL not found: " + dllPath.string());
        return 1;
    }

    auto hash = HashFileSHA256(dllPath);
    if (!hash.empty())
        Log(LogLevel::Info, "DLL SHA256: " + hash);

    std::vector<std::wstring> patterns = { args.processName, L"ffxiv_dx11.exe", L"ffxiv.exe" };
    for (auto& p : args.extraPatterns) patterns.push_back(p);

    auto waitForProcess = [&](int waitSeconds) -> DWORD {
        if (args.directPid) {
            if (IsProcessRunning(*args.directPid)) {
                Log(LogLevel::Info, "Using direct PID: " + std::to_string(*args.directPid));
                return *args.directPid;
            }
            Log(LogLevel::Error, "Direct PID not running");
            return 0;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(waitSeconds);
        while (std::chrono::steady_clock::now() < deadline && !g_cancel) {
            auto procs = FindProcessesByPattern(patterns);
            if (!procs.empty()) {
                if (procs.size() == 1 || !args.pickProcess)
                    return procs.front().pid;
                Log(LogLevel::Info, "Multiple candidates found:");
                for (size_t i = 0; i < procs.size(); ++i)
                    std::wcout << L" [" << i << L"] " << procs[i].exe << L" (PID " << procs[i].pid << L")\n";
                std::cout << "Enter index: ";
                size_t idx = 0;
                if (std::cin >> idx && idx < procs.size())
                    return procs[idx].pid;
                Log(LogLevel::Warn, "Invalid selection. Retrying...");
                std::cin.clear();
                std::cin.ignore(1024, '\n');
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        return 0;
    };

    DWORD selectedPid = waitForProcess(args.waitSeconds);
    if (selectedPid == 0) {
        Log(LogLevel::Error, "No target process found within timeout");
        return 2;
    }

    auto injectWithRetries = [&](DWORD pid) -> bool {
        const int maxAttempts = (std::max)(1, args.retry + 1);
        for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
            if (g_cancel) return false;
            Log(LogLevel::Info, "Injection attempt " + std::to_string(attempt));
            if (InjectDLL(pid, dllPath.wstring())) return true;
            Log(LogLevel::Error, "Attempt failed");
            if (attempt < maxAttempts)
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        return false;
    };

    if (!args.watch) {
        return injectWithRetries(selectedPid) ? 0 : 4;
    }

    Log(LogLevel::Info, "Watch mode enabled");
    while (!g_cancel) {
        if (!injectWithRetries(selectedPid)) {
            Log(LogLevel::Error, "Failed to inject into current instance");
        } else {
            Log(LogLevel::Info, "Monitoring process (PID " + std::to_string(selectedPid) + ")");
            while (!g_cancel && IsProcessRunning(selectedPid))
                std::this_thread::sleep_for(std::chrono::seconds(2));
            if (g_cancel) break;
            Log(LogLevel::Warn, "Process exited; awaiting restart");
        }
        selectedPid = waitForProcess(args.waitSeconds);
        if (selectedPid == 0) {
            Log(LogLevel::Error, "No new process found; ending watch");
            break;
        }
    }
    return 0;
}
#endif // SH_DISABLE_INJECTOR_MAIN


//TESTTESTTEST
