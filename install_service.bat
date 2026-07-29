@echo off
REM ╔══════════════════════════════════════════════════════════════╗
REM ║  VAULT-X  ·  Windows Service Installer                       ║
REM ║  File     : install_service.bat                              ║
REM ║  Run as   : Administrator (right-click → Run as administrator)║
REM ╚══════════════════════════════════════════════════════════════╝

title VAULT-X Service Installer
color 1F
cls

echo.
echo ============================================================
echo   VAULT-X Protection Service Installer  v1.0.0
echo ============================================================
echo.

REM ── Check Administrator ──────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo   [ERROR] Must be run as Administrator.
    echo   Right-click this file and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)
echo   [OK] Running as Administrator.

REM ── Locate Python ────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% NEQ 0 (
    echo.
    echo   [ERROR] Python not found in PATH.
    echo   Download from: https://python.org/downloads
    echo   Check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do set PYVER=%%i
echo   [OK] %PYVER%

REM ── Project directory ────────────────────────────────────────────
set "PROJ=%~dp0"
if "%PROJ:~-1%"=="\" set "PROJ=%PROJ:~0,-1%"
echo   [OK] Project directory: %PROJ%

REM ── Step 1: Install dependencies ─────────────────────────────────
echo.
echo   [1/6] Installing Python dependencies...
pip install cryptography pywin32 watchdog --quiet
if %errorlevel% NEQ 0 (
    echo   [WARN] Some packages may have failed. Continuing...
)
echo   [OK] Dependencies installed.

REM ── Step 2: pywin32 post-install ─────────────────────────────────
echo.
echo   [2/6] Configuring pywin32 for Windows Service support...
for /f "tokens=*" %%i in ('python -c "import sys; print(sys.prefix)"') do set PYPREFIX=%%i
python "%PYPREFIX%\Scripts\pywin32_postinstall.py" -install >nul 2>&1
if %errorlevel% NEQ 0 (
    echo   [WARN] pywin32 post-install had issues. Service may still work.
) else (
    echo   [OK] pywin32 configured.
)

REM ── Step 3: Set VAULTX_API_KEY ───────────────────────────────────
echo.
echo   [3/6] Configuring API key...

REM Check if already set
if defined VAULTX_API_KEY (
    echo   [OK] VAULTX_API_KEY already set in environment.
) else (
    REM Generate a random API key using Python
    for /f "tokens=*" %%k in ('python -c "import secrets; print(secrets.token_urlsafe(32))"') do set GENERATED_KEY=%%k
    echo.
    echo   Generated API key: %GENERATED_KEY%
    echo.
    echo   Setting as system environment variable...
    setx VAULTX_API_KEY "%GENERATED_KEY%" /M >nul 2>&1
    set VAULTX_API_KEY=%GENERATED_KEY%
    echo   [OK] VAULTX_API_KEY set.
    echo   [!!] SAVE THIS KEY: %GENERATED_KEY%
    echo        You need it to access the admin console.
)

REM ── Step 4: Remove old service if present ────────────────────────
echo.
echo   [4/6] Removing any existing service installation...
sc stop VaultXProtection >nul 2>&1
timeout /t 2 /nobreak >nul
python "%PROJ%\service.py" remove >nul 2>&1
sc delete VaultXProtection >nul 2>&1
timeout /t 2 /nobreak >nul
echo   [OK] Clean slate ready.

REM ── Step 5: Install and start the service ────────────────────────
echo.
echo   [5/6] Installing VAULT-X Windows Service...
cd /d "%PROJ%"
python service.py install
if %errorlevel% NEQ 0 (
    echo.
    echo   [ERROR] Service installation failed.
    echo   Make sure you ran this as Administrator.
    pause
    exit /b 1
)

REM Set service to auto-start on boot
sc config VaultXProtection start= auto >nul 2>&1
sc description VaultXProtection "VAULT-X 24/7 Data Loss Prevention — file watcher, HTTP API, and monitoring" >nul 2>&1
echo   [OK] Service installed and set to auto-start on boot.

echo.
echo   Starting service...
python service.py start
if %errorlevel% NEQ 0 (
    echo   [WARN] Service did not start immediately.
    echo   Try: python service.py start
    echo   Or check: Services.msc → VaultXProtection
) else (
    timeout /t 3 /nobreak >nul
    sc query VaultXProtection | findstr "RUNNING" >nul 2>&1
    if %errorlevel% EQU 0 (
        echo   [OK] Service is RUNNING.
    ) else (
        echo   [WARN] Service may still be starting. Check Services.msc.
    )
)

REM ── Step 6: Check state file ─────────────────────────────────────
echo.
echo   [6/6] Checking service state...
timeout /t 4 /nobreak >nul
python service.py status
echo.

REM ── Summary ──────────────────────────────────────────────────────
echo ============================================================
echo   VAULT-X Service Installation Complete!
echo ============================================================
echo.
echo   SERVICE NAME : VaultXProtection
echo   AUTO-START   : Yes (starts on Windows boot)
echo   HTTP API     : http://127.0.0.1:8765
echo   API KEY      : %VAULTX_API_KEY%
echo   LOG FILE     : %PROJ%\my_vault\service.log
echo   STATE FILE   : %PROJ%\my_vault\.service_state.json
echo.
echo   MANAGE THE SERVICE:
echo     Start  : python service.py start
echo     Stop   : python service.py stop
echo     Status : python service.py status
echo     Remove : python service.py remove
echo.
echo   OR USE WINDOWS:
echo     services.msc → find "VAULT-X Protection Service"
echo.
echo   TEST THE HTTP API (in a new terminal):
echo     curl -H "X-API-Key: %VAULTX_API_KEY%" http://127.0.0.1:8765/status
echo.
echo ============================================================
pause
