@echo off
REM ============================================================================
REM SvmDebug v19 Pure VMEXIT - Driver Deployment Script
REM ============================================================================
REM This script loads the freshly compiled v19 drivers
REM Drivers must be compiled first (see COMPILATION_SUCCESS_REPORT_v19.md)
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo [*] SvmDebug v19 Pure VMEXIT Driver Deployment
echo [*] ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: This script requires administrator privileges
    echo [!] Please run "cmd" as administrator and try again
    pause
    exit /b 1
)

echo [+] Administrator privileges confirmed
echo.

REM ============================================================================
REM Step 1: Stop and remove old drivers
REM ============================================================================
echo [*] Step 1: Stopping and unloading old drivers...
echo.

for %%D in (SvmDebug DBKKernel) do (
    echo   - Checking %%D status...
    sc query %%D >nul 2>&1
    if !errorlevel! equ 0 (
        echo     [*] Stopping %%D...
        sc stop %%D >nul 2>&1
        timeout /t 1 /nobreak >nul
        echo     [*] Removing %%D...
        sc delete %%D >nul 2>&1
        timeout /t 1 /nobreak >nul
        echo     [+] %%D removed
    ) else (
        echo     [*] %%D not installed (skipping)
    )
)

echo.

REM ============================================================================
REM Step 2: Create new driver entries
REM ============================================================================
echo [*] Step 2: Creating new driver entries...
echo.

REM DBKKernel
echo   - Creating DBKKernel entry...
sc create DBKKernel type= kernel binPath= "D:\工具\cheat-engine-7.5\Cheat Engine\bin\DBK64.sys" >nul 2>&1
if %errorlevel% equ 0 (
    sc description DBKKernel "Cheat Engine Kernel Driver Bridge (v19 Pure VMEXIT)" >nul 2>&1
    echo     [+] DBKKernel entry created
) else (
    echo     [!] WARNING: Could not create DBKKernel entry
)

REM SvmDebug
echo   - Creating SvmDebug entry...
sc create SvmDebug type= kernel binPath= "C:\Users\yejinzhao\source\repos\SvmDebug\x64\Release\SvmDebug.sys" >nul 2>&1
if %errorlevel% equ 0 (
    sc description SvmDebug "AMD SVM Type-1 Hypervisor (v19 Pure VMEXIT)" >nul 2>&1
    echo     [+] SvmDebug entry created
) else (
    echo     [!] WARNING: Could not create SvmDebug entry
)

echo.

REM ============================================================================
REM Step 3: Start drivers
REM ============================================================================
echo [*] Step 3: Starting drivers in correct order...
echo.

echo   - Starting DBKKernel (Cheat Engine bridge)...
sc start DBKKernel
if %errorlevel% equ 0 (
    echo     [+] DBKKernel started successfully
) else (
    echo     [!] ERROR: Failed to start DBKKernel
)
timeout /t 1 /nobreak >nul

echo.
echo   - Starting SvmDebug (VMM hypervisor)...
sc start SvmDebug
if %errorlevel% equ 0 (
    echo     [+] SvmDebug started successfully
) else (
    echo     [!] ERROR: Failed to start SvmDebug
)
timeout /t 1 /nobreak >nul

echo.

REM ============================================================================
REM Step 4: Verify driver status
REM ============================================================================
echo [*] Step 4: Verifying driver status...
echo.

for %%D in (DBKKernel SvmDebug) do (
    echo   - %%D status:
    sc query %%D | findstr /C:"STATE" /C:"RUNNING" /C:"STOPPED" | findstr /V "STOPPED_PENDING"
    echo.
)

echo [*] Deployment complete!
echo.
echo [+] Next steps:
echo    1. Open DebugView (Sysinternals)
echo    2. Add filter "[SVM-CE]" to see diagnostic logs
echo    3. Start Cheat Engine 7.5 with target process
echo    4. Perform memory scan/read to verify VMEXIT logs appear
echo.
echo [+] Expected output in DebugView:
echo    [SVM-CE] VMEXIT READ OK #N: PID=... addr=... size=... data[0..7]=...
echo    [SVM-CE] WRITE VMEXIT #N: PID=... addr=... size=...
echo.
echo [!] DO NOT SEE (indicates v18 code or failure):
echo    [SVM-CE] !! FALLBACK #N: StealthDirectRead ...
echo    [SVM-CE] WRITE #N (Guest R0 StealthDirectWrite, NOT VMEXIT): ...
echo.

pause
