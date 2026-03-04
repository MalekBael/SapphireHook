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

### CMake (recommended)

> **Important:** For the Ninja generator, CMake must be run from a **VS 2022 Developer Command Prompt (x64)** (or equivalent shell where `vcvarsall.bat x64` has been sourced). This ensures `cl.exe`, the Windows SDK headers, and `kernel32.lib` / other SDK libs are all on the correct environment paths. Without this, the linker will fail with `LNK1104: cannot open file 'kernel32.lib'`.
>
> In VS Code, open the Command Palette (`Ctrl+Shift+P`) → **CMake: Select a Kit** → choose **Visual Studio Build Tools 2022 Release - amd64** (or the equivalent VS 2022 Professional x64 kit). The CMake extension will initialise the environment for you automatically.

- Quick (single-line, recommended): Configure and build everything (DLL + Injector) in one command using Ninja.

```bash
cmake --preset default && cmake --build --preset default --parallel
```

- Visual Studio (multi-config generators): Configure, then build the whole project (all targets) with a single `cmake --build` call. No Developer Command Prompt needed — the VS generator handles environment setup automatically.

```powershell
cmake --preset vs2022
cmake --build build_vs --config Debug --parallel
```

- Using the named presets directly:

```bash
# Debug (Ninja — requires Developer Command Prompt or VS Code kit)
cmake --preset default
cmake --build --preset default --parallel

# Release (Ninja)
cmake --preset release
cmake --build --preset release --parallel
```

- Common extras:
	- Build a specific target: `cmake --build build --target <target-name> --config Debug`
	- Clean: `cmake --build build --target clean`
	- Switch configuration: replace `Debug` with `Release`

- Note: `cmake --build` builds the full CMake project and its targets (including the DLL and Injector) — you do not need to build them separately. Output layout depends on the generator (multi-config generators place outputs in config subfolders; Ninja places outputs directly under `build/`).

### MSBuild (alternative)

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

To also build the injector with MSBuild:

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

