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

if exist "%~dp0.venv\Scripts\python.exe" (
    set "CYBERSHIELD_PYTHON=%~dp0.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set "CYBERSHIELD_PYTHON=python"
    ) else (
        where py >nul 2>&1
        if %errorlevel% equ 0 (
            set "CYBERSHIELD_PYTHON=py"
        ) else (
            echo [ERROR] Python 3 not found. Please run INSTALL_WINDOWS.bat first.
            pause
            exit /b 1
        )
    )
)

if not exist ".env" (
    copy /Y ".env.example" ".env" >nul
)

if not exist "electron\node_modules" (
    echo [INFO] First-time Electron setup detected — running INSTALL_WINDOWS.bat...
    call "%~dp0INSTALL_WINDOWS.bat"
    exit /b
)

echo Using Python: %CYBERSHIELD_PYTHON%
echo Launching CyberShield Mesh Desktop Console...
pushd electron
call npm start
popd
endlocal
