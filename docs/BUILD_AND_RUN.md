# Build, Run, Inject

This document describes the typical developer workflow for building and using SapphireHook.

## Build (VS Code / MSBuild)

Recommended default:

- Use the VS Code task: **Build All (MSBuild)** (Debug/x64).

Outputs:

- `x64/Debug/SapphireHookDLL.dll` (injection target)
- `SapphireHookInjector/x64/Debug/SapphireHookInjector.exe`

Notes:

- The build copies `data/` into the output folder so runtime lookups work.
- Dependencies are a mix of vendored libraries and vcpkg packages.

## Run / Inject

Typical usage:

1. Start the game.
2. Use the injector to load `SapphireHookDLL.dll` into the target process.
3. Toggle the UI overlay in-game.

If you prefer another injector, that’s fine; SapphireHook is a standard native DLL.

## Hotkeys

- `INSERT`: toggle overlay visibility
- `END`: unload (if supported by current build/config)

If hotkeys are ignored, check focus rules (some modules disable hotkeys when game is unfocused).

## Logs

Logs are written under the temp folder by default:

- `%TEMP%\SapphireHook\`

When debugging a crash or failed initialization, grab the latest log from that folder first.

## Data Files

SapphireHook uses JSON/YAML data under `data/` (actions, items, territories, etc.).

- These files are copied to the output directory during build.
- If a lookup is missing or incorrect, update the corresponding data file.

## Common Dev Workflow

- Build (Debug/x64)
- Inject
- Reproduce / test
- Inspect logs
- Iterate

For deeper troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
