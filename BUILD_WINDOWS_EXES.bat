@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ====================================================================
echo  CyberShield Mesh - Windows Standalone .EXE Builder
echo ====================================================================
echo  This script builds two standalone Windows executables in:
echo    release_windows\CyberShieldMesh-Portable.exe  (Admin Defense App)
echo    release_windows\sim_intrusion.exe             (Demo Attack Beacon)
echo ====================================================================
echo.

:: Detect Python (python or py -3)
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
    echo [ERROR] Python 3 was not found on PATH.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo and check "Add Python to PATH", then re-run this script.
    pause
    exit /b 1
)

where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js / npm was not found on PATH.
    echo Please install Node.js LTS from https://nodejs.org/ and re-run this script.
    pause
    exit /b 1
)

echo [INFO] Using Python command: %PY_CMD%
if not exist "release_windows" mkdir "release_windows"
if not exist "dist_backend" mkdir "dist_backend"

echo.
echo [1/4] Installing Python dependencies + PyInstaller...
%PY_CMD% -m pip install --upgrade pip >nul 2>&1
%PY_CMD% -m pip install -r requirements.txt pyinstaller
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Python dependencies.
    pause
    exit /b 1
)

echo.
echo [2/4] Building release_windows\sim_intrusion.exe ...
where g++ >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] MinGW g++ found - compiling native C++ WinSock2 binary...
    g++ demo_attack\sim_intrusion.cpp -o release_windows\sim_intrusion.exe -O2 -static -static-libgcc -static-libstdc++ -lws2_32
) else (
    echo [INFO] MinGW g++ not found - building standalone sim_intrusion.exe via PyInstaller...
    %PY_CMD% -m PyInstaller --noconfirm --onefile ^
        --name sim_intrusion ^
        --distpath release_windows ^
        demo_attack\sim_intrusion.py
)
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build sim_intrusion.exe
    pause
    exit /b 1
)

echo.
echo [3/4] Freezing CyberShield FastAPI + Gemini Backend (cybershield_backend.exe)...
%PY_CMD% -m PyInstaller --noconfirm --onefile ^
    --paths . ^
    --name cybershield_backend ^
    --distpath dist_backend ^
    --add-data "frontend;frontend" ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.loops ^
    --hidden-import uvicorn.loops.auto ^
    --hidden-import uvicorn.protocols ^
    --hidden-import uvicorn.protocols.http ^
    --hidden-import uvicorn.protocols.http.auto ^
    --hidden-import uvicorn.protocols.websockets ^
    --hidden-import uvicorn.protocols.websockets.auto ^
    --hidden-import uvicorn.lifespan ^
    --hidden-import uvicorn.lifespan.on ^
    --hidden-import websockets ^
    --collect-all google.genai ^
    --collect-data certifi ^
    backend\run_server.py
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build cybershield_backend.exe
    pause
    exit /b 1
)

echo.
echo [4/4] Packaging CyberShieldMesh-Portable.exe via Electron Builder...
set "CSC_IDENTITY_AUTO_DISCOVERY=false"
pushd electron
call npm install
if %errorlevel% neq 0 (
    popd
    echo [ERROR] npm install failed inside electron\
    pause
    exit /b 1
)
call npm run build:win
if %errorlevel% neq 0 (
    popd
    echo [ERROR] Electron Windows build failed.
    pause
    exit /b 1
)
popd

copy /Y "electron\dist\CyberShieldMesh-Portable.exe" "release_windows\CyberShieldMesh-Portable.exe" >nul
if exist ".env" (
    copy /Y ".env" "release_windows\.env" >nul
) else (
    copy /Y ".env.example" "release_windows\.env" >nul
)

echo.
echo ====================================================================
echo  BUILD COMPLETE!
echo  Your final Windows files are ready in:
echo    %~dp0release_windows\
echo.
echo    1) CyberShieldMesh-Portable.exe  (Double-click -> prompts Admin)
echo    2) sim_intrusion.exe             (Connects to Ubuntu 10.100.5.67:4444)
echo    3) .env                          (Keep in same folder as the app)
echo ====================================================================
echo.
explorer "%~dp0release_windows"
pause
endlocal
