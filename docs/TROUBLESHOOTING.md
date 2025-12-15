# Troubleshooting

## Overlay Doesn’t Show

- Confirm injection succeeded (check logs in `%TEMP%\SapphireHook\`).
- Press `INSERT` to toggle overlay.
- Ensure the game window is focused.

## Injection Issues

- Run the injector as the same user integrity level as the game.
- Verify you’re injecting the matching architecture (x64 DLL into x64 process).
- Check AV/EDR interference if injection intermittently fails.

## Missing Data / Lookup Failures

- Confirm `data/` exists beside the built DLL output.
- Check logs for missing JSON keys or parse errors.

## Build Notes (vcpkg applocal)

Some vcpkg projects run an `applocal.ps1` step that prefers PowerShell 7 (`pwsh`).

- If `pwsh` is missing, builds can still succeed, but you may see “pwsh.exe not recognized” messages.
- Installing PowerShell 7 and ensuring `pwsh` is on PATH removes this noise.

## Capturing Useful Debug Info

When reporting a bug, include:

- The latest log file from `%TEMP%\SapphireHook\`
- Configuration (Debug/Release, x64)
- What you were doing (module/window + steps to reproduce)
- If relevant: opcode/opname, packet length, and capture timestamp
