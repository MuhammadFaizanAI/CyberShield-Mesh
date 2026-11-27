'use strict';

const { app, BrowserWindow, Menu, Tray, dialog, nativeImage, shell } = require('electron');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const zlib = require('zlib');

const BACKEND_HOST = '127.0.0.1';
const BACKEND_PORT = 8000;
const HEALTH_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}/health`;
const APP_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}/`;
const HEALTH_POLL_INTERVAL_MS = 250;
const HEALTH_TIMEOUT_MS = 18000;

let mainWindow = null;
let tray = null;
let backendProcess = null;
let isQuitting = false;

// ============================================================================
// WINDOWS ADMINISTRATOR PRIVILEGE DETECTION & AUTO-UAC ELEVATION
// ============================================================================
function isWindowsAdmin() {
  if (process.platform !== 'win32') return true;
  try {
    execFileSync('net', ['session'], { stdio: 'ignore', windowsHide: true });
    return true;
  } catch (_) {
    return false;
  }
}

function tryElevateOnWindows() {
  if (process.platform !== 'win32') return false;
  if (isWindowsAdmin()) return false;
  if (
    process.argv.includes('--no-elevate') ||
    process.argv.includes('--elevated') ||
    process.env.CYBERSHIELD_NO_ELEVATE === '1'
  ) {
    return false;
  }

  try {
    const projectRoot = path.resolve(__dirname, '..');
    const launcherBat = path.join(projectRoot, 'LAUNCH_CYBERSHIELD_ADMIN.bat');

    if (app.isPackaged) {
      const exe = process.execPath.replace(/'/g, "''");
      execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-WindowStyle',
          'Hidden',
          '-Command',
          `Start-Process -FilePath '${exe}' -ArgumentList '--elevated' -Verb RunAs`
        ],
        { stdio: 'ignore', windowsHide: true }
      );
      return true;
    }

    if (fs.existsSync(launcherBat)) {
      const bat = launcherBat.replace(/'/g, "''");
      const wd = projectRoot.replace(/'/g, "''");
      execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-WindowStyle',
          'Hidden',
          '-Command',
          `Start-Process -FilePath '${bat}' -WorkingDirectory '${wd}' -Verb RunAs`
        ],
        { stdio: 'ignore', windowsHide: true }
      );
      return true;
    }

    const exe = process.execPath.replace(/'/g, "''");
    const appDir = path.resolve(__dirname).replace(/'/g, "''");
    execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-WindowStyle',
        'Hidden',
        '-Command',
        `Start-Process -FilePath '${exe}' -ArgumentList '"${appDir}" --elevated' -Verb RunAs`
      ],
      { stdio: 'ignore', windowsHide: true }
    );
    return true;
  } catch (err) {
    console.warn('[electron] UAC elevation declined or unavailable; continuing in Standard User Mode:', err.message);
    return false;
  }
}

// ============================================================================
// INLINE SHIELD PNG ICON GENERATOR (ZERO EXTERNAL .ICO DEPENDENCY)
// ============================================================================
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) {
      c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function createShieldTrayDataUrl(size = 32) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  const cx = (size - 1) / 2;

  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0;

    for (let x = 0; x < size; x++) {
      const idx = rowStart + 1 + x * 4;
      const nx = Math.abs(x - cx) / (size * 0.42);
      const ny = y / (size - 1);

      const maxHalfWidth = ny < 0.55 ? 0.92 : Math.max(0, 0.92 * (1 - (ny - 0.55) / 0.42));
      const inOuter = ny >= 0.08 && ny <= 0.94 && nx <= maxHalfWidth;
      const inInner = ny >= 0.17 && ny <= 0.84 && nx <= Math.max(0, maxHalfWidth - 0.18);

      if (inInner) {
        const isCoreStripe = nx < 0.13 && ny > 0.28 && ny < 0.72;
        raw[idx] = isCoreStripe ? 16 : 16;
        raw[idx + 1] = isCoreStripe ? 185 : 20;
        raw[idx + 2] = isCoreStripe ? 129 : 28;
        raw[idx + 3] = 255;
      } else if (inOuter) {
        // Precision emerald (#10B981) shield outline
        raw[idx] = 16;
        raw[idx + 1] = 185;
        raw[idx + 2] = 129;
        raw[idx + 3] = 255;
      } else {
        raw[idx] = 0;
        raw[idx + 1] = 0;
        raw[idx + 2] = 0;
        raw[idx + 3] = 0;
      }
    }
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;

  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const png = Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0))
  ]);

  return `data:image/png;base64,${png.toString('base64')}`;
}

// ============================================================================
// PYTHON FASTAPI BACKEND LIFECYCLE
// ============================================================================
function resolvePythonExecutable(projectRoot) {
  if (process.env.CYBERSHIELD_PYTHON && fs.existsSync(process.env.CYBERSHIELD_PYTHON)) {
    return process.env.CYBERSHIELD_PYTHON;
  }
  const winVenv = path.join(projectRoot, '.venv', 'Scripts', 'python.exe');
  if (process.platform === 'win32' && fs.existsSync(winVenv)) {
    return winVenv;
  }
  const nixVenv = path.join(projectRoot, '.venv', 'bin', 'python');
  if (process.platform !== 'win32' && fs.existsSync(nixVenv)) {
    return nixVenv;
  }
  return process.platform === 'win32' ? 'python' : 'python3';
}

function fetchHealthStatus() {
  return new Promise((resolve) => {
    const req = http.get(HEALTH_URL, { timeout: 1000 }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          resolve({ ok: false, isAdmin: false });
          return;
        }
        try {
          const parsed = JSON.parse(body);
          resolve({ ok: true, isAdmin: !!parsed.is_admin });
        } catch (_) {
          resolve({ ok: true, isAdmin: false });
        }
      });
    });
    req.on('error', () => resolve({ ok: false, isAdmin: false }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, isAdmin: false });
    });
  });
}

async function waitForBackendReady(timeoutMs = HEALTH_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = await fetchHealthStatus();
    if (status.ok) return true;
    await new Promise((r) => setTimeout(r, HEALTH_POLL_INTERVAL_MS));
  }
  return false;
}

function spawnBackend() {
  const packagedBackend = path.join(
    process.resourcesPath || '',
    'backend',
    process.platform === 'win32' ? 'cybershield_backend.exe' : 'cybershield_backend'
  );

  if (app.isPackaged && fs.existsSync(packagedBackend)) {
    const exeDir = path.dirname(app.getPath('exe'));
    console.log(`[electron] Spawning bundled backend: ${packagedBackend} (cwd=${exeDir})`);
    backendProcess = spawn(packagedBackend, [], {
      cwd: exeDir,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } else {
    const projectRoot = path.resolve(__dirname, '..');
    const pythonBin = resolvePythonExecutable(projectRoot);
    const args = [
      '-m',
      'uvicorn',
      'backend.main:app',
      '--host',
      BACKEND_HOST,
      '--port',
      String(BACKEND_PORT)
    ];

    console.log(`[electron] Spawning backend: ${pythonBin} ${args.join(' ')} (cwd=${projectRoot})`);
    backendProcess = spawn(pythonBin, args, {
      cwd: projectRoot,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  }

  backendProcess.stdout.on('data', (chunk) => {
    process.stdout.write(`[backend] ${chunk}`);
  });

  backendProcess.stderr.on('data', (chunk) => {
    process.stderr.write(`[backend] ${chunk}`);
  });

  backendProcess.on('error', (err) => {
    console.error('[electron] Failed to spawn Python backend:', err);
  });

  backendProcess.on('exit', (code, signal) => {
    console.log(`[electron] Backend exited (code=${code}, signal=${signal})`);
    backendProcess = null;
  });
}

function killBackendTree() {
  if (!backendProcess || !backendProcess.pid) return;
  const pid = backendProcess.pid;
  backendProcess = null;

  try {
    if (process.platform === 'win32') {
      execFileSync('taskkill', ['/F', '/T', '/PID', String(pid)], {
        stdio: 'ignore',
        windowsHide: true
      });
    } else {
      process.kill(pid, 'SIGTERM');
      setTimeout(() => {
        try {
          process.kill(pid, 'SIGKILL');
        } catch (_) {}
      }, 1500);
    }
    console.log(`[electron] Cleaned up backend process tree (PID ${pid}).`);
  } catch (err) {
    console.warn(`[electron] Backend cleanup note for PID ${pid}:`, err.message);
  }
}

// ============================================================================
// WINDOW & SYSTEM TRAY
// ============================================================================
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1380,
    height: 840,
    minWidth: 1080,
    minHeight: 680,
    autoHideMenuBar: true,
    backgroundColor: '#0A0D12',
    title: 'CyberShield Mesh — Endpoint Detection & Response',
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadURL(APP_URL);

  // Open external URLs (such as Google OAuth 2.0 consent) in the real system browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url) && !url.startsWith(APP_URL)) {
      shell.openExternal(url);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });

  mainWindow.once('ready-to-show', () => {
    if (mainWindow) mainWindow.show();
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createSystemTray() {
  const icon = nativeImage.createFromDataURL(createShieldTrayDataUrl(32));
  tray = new Tray(icon);
  tray.setToolTip('CyberShield Mesh — EDR Sensor Active');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Open CyberShield Console',
      click: () => {
        if (!mainWindow) {
          createMainWindow();
        } else {
          mainWindow.show();
          mainWindow.focus();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Quit Sensor & Console',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);
  tray.on('click', () => {
    if (!mainWindow) {
      createMainWindow();
    } else if (mainWindow.isVisible()) {
      mainWindow.focus();
    } else {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// ============================================================================
// APP LIFECYCLE
// ============================================================================
app.whenReady().then(async () => {
  const existing = await fetchHealthStatus();

  // If on Windows and neither this Electron process nor an existing backend is elevated,
  // automatically trigger UAC elevation so Windows Defender Firewall (/32) rules enforce live.
  if (!existing.isAdmin && tryElevateOnWindows()) {
    isQuitting = true;
    app.quit();
    return;
  }

  if (!existing.ok) {
    spawnBackend();
  }

  const ready = await waitForBackendReady(HEALTH_TIMEOUT_MS);
  if (!ready) {
    dialog.showErrorBox(
      'CyberShield Mesh Sensor Failed to Start',
      `Timed out waiting for ${HEALTH_URL}.\n\nRun INSTALL_WINDOWS.bat or verify Python packages:\n  .venv\\Scripts\\python.exe -m pip install -r requirements.txt`
    );
    killBackendTree();
    app.quit();
    return;
  }

  createSystemTray();
  createMainWindow();
});

app.on('before-quit', () => {
  isQuitting = true;
  killBackendTree();
});

app.on('will-quit', () => {
  killBackendTree();
});

app.on('window-all-closed', () => {
  if (isQuitting) {
    app.quit();
  }
});

process.on('SIGINT', () => {
  isQuitting = true;
  killBackendTree();
  process.exit(0);
});

process.on('SIGTERM', () => {
  isQuitting = true;
  killBackendTree();
  process.exit(0);
});
