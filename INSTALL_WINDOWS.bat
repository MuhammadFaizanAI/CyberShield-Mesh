@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ====================================================================
echo  CyberShield Mesh - Windows One-Click Installer
echo ====================================================================
echo.

:: 1. Detect Python 3
set "SYS_PY="
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "SYS_PY=python"
) else (
    where py >nul 2>&1
    if %errorlevel% equ 0 (
        set "SYS_PY=py -3"
    )
)

if "%SYS_PY%"=="" (
    echo [ERROR] Python 3 was not found on PATH.
    echo Download Python 3.11+ from https://www.python.org/downloads/
    echo IMPORTANT: Check "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)

:: 2. Detect Node.js / npm
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js / npm was not found on PATH.
    echo Download Node.js LTS from https://nodejs.org/ and re-run this installer.
    pause
    exit /b 1
)

echo [1/5] Creating isolated Python virtual environment (.venv)...
if not exist ".venv\Scripts\python.exe" (
    %SYS_PY% -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create Python .venv.
        pause
        exit /b 1
    )
)
set "VENV_PY=%~dp0.venv\Scripts\python.exe"

echo [2/5] Installing Python backend dependencies...
"%VENV_PY%" -m pip install --upgrade pip >nul 2>&1
"%VENV_PY%" -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Python requirements.
    pause
    exit /b 1
)

echo [3/5] Installing Electron desktop runtime...
pushd electron
call npm install
if %errorlevel% neq 0 (
    popd
    echo [ERROR] npm install failed inside electron\
    pause
    exit /b 1
)
popd

echo [4/5] Configuring .env environment file...
if not exist ".env" (
    copy /Y ".env.example" ".env" >nul
    echo Created .env from .env.example.
)

findstr /C:"GEMINI_API_KEY=your_gemini_api_key_here" ".env" >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo Paste your Google Gemini API Key (or press Enter to set it later in .env):
    set /p "USER_GEMINI_KEY=GEMINI_API_KEY: "
    if not "%USER_GEMINI_KEY%"=="" (
        powershell -NoProfile -Command "(Get-Content '.env') -replace 'GEMINI_API_KEY=your_gemini_api_key_here', ('GEMINI_API_KEY=' + $env:USER_GEMINI_KEY) | Set-Content '.env'"
        echo [OK] Saved GEMINI_API_KEY to .env.
    )
)

echo [5/5] Creating Desktop shortcut ("CyberShield Mesh")...
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\CyberShield Mesh.lnk'); $s.TargetPath = '%~dp0LAUNCH_CYBERSHIELD_ADMIN.bat'; $s.WorkingDirectory = '%~dp0'; $s.Description = 'CyberShield Mesh Autonomous Endpoint Security'; $s.Save()" >nul 2>&1

echo.
echo ====================================================================
echo  INSTALLATION COMPLETE!
echo  - Desktop shortcut created: "CyberShield Mesh"
echo  - Launch anytime with: LAUNCH_CYBERSHIELD_ADMIN.bat (Auto-Admin)
echo  - Optional standalone .exe build: BUILD_WINDOWS_EXES.bat
echo ====================================================================
echo.
set /p "LAUNCH_NOW=Launch CyberShield Mesh as Administrator now? [Y/n]: "
if /I "%LAUNCH_NOW%"=="N" goto :done
call "%~dp0LAUNCH_CYBERSHIELD_ADMIN.bat"

:done
endlocal
