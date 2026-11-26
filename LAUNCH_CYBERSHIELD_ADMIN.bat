@echo off
setlocal EnableExtensions

:: Auto-elevate to Administrator so Windows Firewall (netsh) rules work live
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges for CyberShield Mesh...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo ====================================================================
echo  CyberShield Mesh - Administrator Live Launcher
echo ====================================================================

set "PY_CMD="
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python"
) else (
    where py >nul 2>&1
    if %errorlevel% equ 0 (
        set "PY_CMD=py -3"
    )
)

if "%PY_CMD%"=="" (
    echo [ERROR] Python 3 not found on PATH. Install Python 3.10+ first.
    pause
    exit /b 1
)

if not exist ".env" (
    echo [INFO] Creating .env from .env.example...
    copy /Y ".env.example" ".env" >nul
)

echo [1/2] Ensuring Python dependencies are installed...
%PY_CMD% -m pip install --quiet -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] pip install failed.
    pause
    exit /b 1
)

if not exist "electron\node_modules" (
    echo [2/2] Installing Electron dependencies...
    pushd electron
    call npm install
    popd
) else (
    echo [2/2] Electron dependencies already installed.
)

echo Launching CyberShield Mesh Desktop App...
pushd electron
call npm start
popd
endlocal
