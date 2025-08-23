@echo off
setlocal

:: Check if we're already running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
    goto :run_injector
) else (
    echo Requesting administrator privileges...
    :: Re-run this script with administrator privileges
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b
)

:run_injector
echo ==========================================
echo     SapphireHook Injector Admin Runner
echo ==========================================
echo.

:: Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo Current directory: %CD%
echo.

:: Check if the injector exists
if not exist "SapphireHookInjector.exe" (
    echo Error: SapphireHookInjector.exe not found in current directory!
    echo Make sure this batch file is in the same folder as the executable.
    echo.
    pause
    exit /b 1
)

:: Check if the DLL exists
if exist "SapphireHookDLL.dll" (
    echo Found SapphireHookDLL.dll
) else (
    echo Warning: SapphireHookDLL.dll not found in current directory.
    echo The injector may fail if the DLL is not present.
)
echo.

echo Starting SapphireHookInjector.exe...
echo.
SapphireHookInjector.exe

echo.
echo Injector finished. Press any key to close this window...
pause >nul