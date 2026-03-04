# SapphireHook

A C++20 native hook DLL for FFXIV. Provides network packet monitoring/decoding, memory analysis tools, and an ImGui overlay.

## Requirements

- **Visual Studio 2022** (v143 toolset) or **VS Build Tools 2022** with the *Desktop development with C++* workload
- **Windows 10/11 SDK** (10.0.26100.0 or later)
- Git (to clone the repo)

> All third-party dependencies (`vendor/`, `vcpkg/`) are bundled — no separate installs needed.

## Clone

```bat
git clone https://github.com/MalekBael/SapphireHook.git
cd SapphireHook
```

No submodules to initialise; everything is included in the repository.

## Build

Open a **Developer Command Prompt for VS 2022** (or any shell where `MSBuild.exe` is on `PATH`) and run:

```bat
MSBuild.exe SapphireHookDLL.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /m
```

| Flag | Purpose |
|---|---|
| `/t:Rebuild` | Clean + full rebuild (no stale objects) |
| `/p:Configuration=Debug` | Debug build (change to `Release` for release) |
| `/p:Platform=x64` | 64-bit target |
| `/m` | Parallel compilation |

Output: `x64\Debug\SapphireHookDLL.dll`

To also build the injector:

```bat
MSBuild.exe SapphireHookInjector\SapphireHookInjector.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /m
```

## Inject

```bat
SapphireHookInjector.exe <ffxiv_pid>
```

Find the FFXIV process ID in Task Manager or via `Get-Process ffxiv_dx11 | Select-Object Id`.


## Logs

Written to `%TEMP%\SapphireHook\` by default.

