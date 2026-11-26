'use strict';

const { app, BrowserWindow, Menu, Tray, dialog, nativeImage } = require('electron');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const zlib = require('zlib');

const BACKEND_HOST = '127.0.0.1';
const BACKEND_PORT = 8000;
const HEALTH_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}/health`;
const APP_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}/`;
const HEALTH_POLL_INTERVAL_MS = 300;
const HEALTH_TIMEOUT_MS = 15000;

let mainWindow = null;
let tray = null;
let backendProcess = null;
let isQuitting = false;

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
    raw[rowStart] = 0; // filter type 0

    for (let x = 0; x < size; x++) {
      const idx = rowStart + 1 + x * 4;
      const nx = Math.abs(x - cx) / (size * 0.42);
      const ny = y / (size - 1);

      // Shield silhouette: wide top, tapering to point at bottom
      const maxHalfWidth = ny < 0.55 ? 0.92 : Math.max(0, 0.92 * (1 - (ny - 0.55) / 0.42));
      const inOuter = ny >= 0.08 && ny <= 0.94 && nx <= maxHalfWidth;
      const inInner = ny >= 0.17 && ny <= 0.84 && nx <= Math.max(0, maxHalfWidth - 0.18);

      if (inInner) {
        // Dark cyber navy core with subtle cyan center highlight
        const isCoreStripe = nx < 0.14 && ny > 0.28 && ny < 0.72;
        raw[idx] = isCoreStripe ? 56 : 12;
        raw[idx + 1] = isCoreStripe ? 189 : 36;
        raw[idx + 2] = isCoreStripe ? 248 : 68;
        raw[idx + 3] = 255;
      } else if (inOuter) {
        // Glowing cyan shield border (#38bdf8)
        raw[idx] = 56;
        raw[idx + 1] = 189;
        raw[idx + 2] = 248;
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
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

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
function resolvePythonExecutable() {
  if (process.env.CYBERSHIELD_PYTHON) {
    return process.env.CYBERSHIELD_PYTHON;
  }
  return process.platform === 'win32' ? 'python' : 'python3';
}

function checkHealthOnce() {
  return new Promise((resolve) => {
    const req = http.get(HEALTH_URL, { timeout: 1000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForBackendReady(timeoutMs = HEALTH_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await checkHealthOnce();
    if (ok) return true;
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
    const pythonBin = resolvePythonExecutable();
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
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 680,
    autoHideMenuBar: true,
    backgroundColor: '#050811',
    title: 'CyberShield Mesh — Autonomous Intrusion Defense',
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadURL(APP_URL);

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
  tray.setToolTip('CyberShield Mesh — Autonomous Intrusion Defense');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show CyberShield',
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
      label: 'Quit',
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
  const alreadyUp = await checkHealthOnce();
  if (!alreadyUp) {
    spawnBackend();
  }

  const ready = await waitForBackendReady(HEALTH_TIMEOUT_MS);
  if (!ready) {
    dialog.showErrorBox(
      'CyberShield Mesh Backend Failed to Start',
      `Timed out waiting for ${HEALTH_URL}.\n\nEnsure Python dependencies are installed:\n  pip install -r requirements.txt`
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
