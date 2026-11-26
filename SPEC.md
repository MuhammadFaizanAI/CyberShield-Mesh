Save this as `SPEC.md` in your project folder (alongside `cybershield_mesh_live_intrusion_defense_pitch_visual.html`), open the folder in **Antigravity IDE**, and tell it: *"Read `SPEC.md` and `cybershield_mesh_live_intrusion_defense_pitch_visual.html`, then build the complete CyberShield Mesh project step by step."*

```markdown
# MASTER ENGINEERING SPEC: CyberShield Mesh
**Role:** Act as a Principal Systems Engineer and Elite Vibe Coder. Build a production-grade, rock-solid, zero-crash live demo application for the **Google AI Agent-a-thon 2026** (GDG on Campus, FAST CFD Campus).  
**Deadline Context:** 24-hour hackathon build for a 3-minute live stage demo + 2-minute judge Q&A. Reliability, visual polish, and real autonomous tool execution are top priorities.

---

## 1. Hackathon Requirements & Core Problem Statement
We must satisfy every judging criterion:
- **AI Brain:** Google Gemini (`google-genai` SDK) making real-time security decisions—NOT hardcoded `if/else` scripts.
- **Autonomous Tool Execution:** Gemini must invoke real OS-level and API tools via Function Calling.
- **Practical Real-World Problem:** Built-in Windows Security (Defender + Windows Firewall) is strong against known malware files, but fails in three critical blind spots:
  1. **Outbound Traffic Blind Spot:** Windows Firewall allows almost all outbound connections by default. A custom script or compromised app can silently stream data to an external IP with zero warnings.
  2. **Signature-Free Attacks:** Custom scripts/binaries do not match known virus signatures, so antivirus stays completely silent.
  3. **No Remote Visibility or Autonomous Containment:** Windows does not alert your phone when you are away from your desk, nor does it autonomously sever suspicious live sockets and blacklist the remote IP in both directions.

---

## 2. Live Demo Environment (Two-PC Setup)
- **Attacker PC (Ubuntu Linux, IP `10.100.5.67`):** Runs `ncat -lvnp 4444` to receive exfiltrated data.
- **Target PC (Windows 10/11):** Runs **CyberShield Mesh** (Electron Desktop App + Python FastAPI/Gemini Backend) in an Administrator terminal.
- **Proof of Problem:** We run a harmless custom outbound TCP client (`demo_attack/sim_intrusion.py` or C++ `sim_intrusion.cpp`) on Windows connecting to `10.100.5.67:4444`. Windows Security gives **zero alarm** while data streams to Ubuntu. Then CyberShield Mesh detects it, reasons with Gemini, alerts our phone, kills the process, and blocks `10.100.5.67` in Windows Firewall—all in real time.

---

## 3. Architecture & Exact Folder Structure
Build a clean, modular repository:

```text
cybershield-mesh/
├── .env.example                 # GEMINI_API_KEY, GEMINI_MODEL, NTFY_TOPIC, WATCH_PORTS, DEMO_TARGET_IP
├── requirements.txt             # fastapi, uvicorn[standard], psutil, requests, python-dotenv, google-genai
├── README.md                    # Complete setup, Admin launch, and 3-minute demo runbook
├── backend/
│   ├── __init__.py
│   ├── config.py                # Loads .env settings safely with defaults
│   ├── state.py                 # Thread-safe incident memory store + WebSocket ConnectionManager
│   ├── tools.py                 # Real OS & API action tools (with graceful non-Admin fallback)
│   ├── agent.py                 # Google Gemini autonomous defense agent + interactive chat handler
│   ├── monitor.py               # Background psutil TCP socket monitor (1-second polling loop)
│   └── main.py                  # FastAPI app, /ws endpoint, /api/chat, /api/simulate, /api/reset, static UI
├── frontend/
│   └── index.html               # Upgraded CyberShield Mesh Live Dashboard (WebSocket-driven + AI Chat)
├── electron/
│   ├── package.json             # Electron latest, "main": "main.js", "start": "electron ."
│   └── main.js                  # Spawns FastAPI backend, waits for health check, opens dark window + Tray
└── demo_attack/
    ├── sim_intrusion.py         # Python outbound TCP exfiltration simulator (connects to Ubuntu :4444)
    └── sim_intrusion.cpp        # Optional C++ WinSock2 version (compiles with g++ -lws2_32)

```

---

## 4. Detailed Component Specifications

### A. Real Action Tools (`backend/tools.py`)

Implement clean, well-typed Python functions with clear docstrings (used directly as Gemini Function Calling tools):

1. `send_mobile_alert(ip: str, process_name: str, reason: str) -> dict`
* Sends an HTTP POST to `https://ntfy.sh/{NTFY_TOPIC}` with a 4-second timeout so it never hangs the demo if internet hiccups.
* Broadcasts **Step 3 (Mobile Alert Sent)** over WebSocket.


2. `kill_process(pid: int) -> dict`
* Terminates the target PID using `psutil.Process(pid).terminate()` (with fallback `.kill()`).
* Never allows killing system-critical PIDs (`0`, `4`, or CyberShield's own PID).
* Broadcasts **Step 4 (Connection Disconnected / Link Severed)** over WebSocket.


3. `block_ip_firewall(ip: str) -> dict`
* On Windows, executes:
* `netsh advfirewall firewall add rule name="CyberShield_Block_Out_{ip}" dir=out action=block remoteip={ip}`
* `netsh advfirewall firewall add rule name="CyberShield_Block_In_{ip}" dir=in action=block remoteip={ip}`


* Checks if running as Admin; if not Admin, logs a clear `[SIMULATED BLOCK - RUN AS ADMIN]` warning instead of crashing.
* Broadcasts **Step 5 (Incoming Source Blocked)** over WebSocket.


4. `unblock_ip_firewall(ip: str) -> dict`
* Deletes `CyberShield_Block_Out_{ip}` and `CyberShield_Block_In_{ip}` via `netsh`.
* Updates incident state and broadcasts a `PROTECTED` / unblocked status update to the dashboard.



### B. Google Gemini AI Agent (`backend/agent.py`)

* Use the official `google-genai` SDK (`from google import genai`).
* Default model: `gemini-3.5-flash-lite` (configurable via `GEMINI_MODEL` in `.env` for sub-second demo latency).
* **Autonomous Defense Function (`analyze_and_defend(event: dict)`):**
* Broadcasts **Step 2 (AI Agent Defending)** to the dashboard.
* Sends the live telemetry (`remote_ip`, `remote_port`, `pid`, `process_name`, `local_port`, `timestamp`) to Gemini with a strict system prompt:
> You are CyberShield Mesh, an autonomous endpoint defense AI. Evaluate the suspicious outbound connection. If it appears to be unauthorized data exfiltration, a reverse shell, or a suspicious non-whitelisted connection, you MUST call `send_mobile_alert`, `kill_process`, and `block_ip_firewall` in order, then return a concise 2-sentence plain-English explanation of what you stopped and why.


* Execute Gemini's tool calls (or automatic function calling) and store the incident + Gemini's reasoning in `state.py`.


* **Interactive Chat Function (`chat_with_agent(user_message: str)`):**
* Injects recent incident memory (blocked IPs, killed PIDs, process names, timestamps) into the prompt.
* Registers `unblock_ip_firewall` and `block_ip_firewall` as callable tools so the user can type:
* *"Why did you block 10.100.5.67?"* → Gemini explains the exact incident.
* *"Unblock 10.100.5.67, that's my test server."* → Gemini calls `unblock_ip_firewall("10.100.5.67")` live and confirms.





### C. Background Network Monitor (`backend/monitor.py`)

* Runs as an `asyncio` background task started on FastAPI lifespan startup.
* Polls `psutil.net_connections(kind='inet')` every 1 second.
* Filters for `status == 'ESTABLISHED'` outbound connections.
* Ignores loopback (`127.0.0.1`, `::1`), empty remote addresses, and already-processed `(pid, remote_ip)` pairs (with a cooldown so it doesn't spam Gemini).
* Flags a connection if:
* `remote_port` is in `WATCH_PORTS` (default: `4444, 1337, 9001, 5555`), OR
* Process name is a known demo/suspicious binary (`sim_intrusion.exe`, `ncat.exe`, `nc.exe`) connecting to a non-localhost IP.


* When triggered, broadcasts **Step 1 (Intrusion Detected)** with real `remote_ip`, `remote_port`, `pid`, and `process_name`, then invokes `agent.analyze_and_defend(...)`.

### D. FastAPI Server (`backend/main.py`)

* Serves `frontend/index.html` at `GET /`.
* `GET /health` → returns `{"status": "ok"}` (used by Electron to know when backend is ready).
* `WS /ws` → pushes real-time JSON events (`step`, `ip`, `port`, `pid`, `process_name`, `ai_summary`, `log_entry`) to the dashboard.
* `POST /api/chat` → accepts `{"message": "..."}` and returns Gemini's reply + any tool actions taken.
* `POST /api/simulate` → triggers a safe built-in simulated intrusion (backup button if Wi-Fi/Ubuntu has issues during judging) that still runs the real Gemini agent + mobile alert flow.
* `POST /api/reset` → deletes all `CyberShield_Block_*` Windows Firewall rules, clears handled PIDs/incidents, and resets the dashboard to `PROTECTED / MONITORING`.

### E. Frontend Dashboard (`frontend/index.html`)

* Base the UI directly on the existing `cybershield_mesh_live_intrusion_defense_pitch_visual.html` in this workspace:
* Keep the exact `#050811` dark cyber aesthetic, Space Grotesk + Inter + JetBrains Mono fonts, animated HTML5 Canvas (`ATTACKER SOURCE` → `YOUR PC + AI AGENT` → `MOBILE PHONE`), 5-step progress pills, floating Mobile Alert buzz card, and Right Live Dashboard panel.


* **Upgrade to 100% Live Mode:**
* Connect to `ws://127.0.0.1:8000/ws` with automatic reconnect.
* Start in **Idle / Monitoring (`PROTECTED`)** state rather than auto-looping a fake attack.
* Dynamically display the **real** attacker IP, port, and process name received from the WebSocket.
* Top-right header controls: Sound toggle, **"Simulate Attack"** button (`POST /api/simulate`), and **"Reset / Unblock"** button (`POST /api/reset`).
* Bottom of the right sidebar: add a compact, sleek **"Ask CyberShield AI"** chat input + response area wired to `POST /api/chat` (keep the entire layout single-screen, zero page scroll).



### F. Electron Desktop App Wrapper (`electron/`)

* **`electron/package.json`:** `electron@latest`, `"main": "main.js"`, `"scripts": { "start": "electron ." }`.
* **`electron/main.js`:**
* Spawns the Python FastAPI backend (`python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`) from the parent project root using `child_process.spawn`.
* Polls `http://127.0.0.1:8000/health` every 300ms until ready (up to 15 seconds).
* Opens a dark `BrowserWindow` (`width: 1280, height: 800, minWidth: 1024, minHeight: 680, autoHideMenuBar: true, backgroundColor: '#050811'`).
* Creates a System Tray icon using a built-in inline `nativeImage` data URL (so it never crashes due to a missing `.ico` file) with **"Show CyberShield"** and **"Quit"** menu items.
* On app quit, cleanly kills the spawned Python backend process tree (using `taskkill /F /T /PID <pid>` on Windows so no orphaned `uvicorn` processes remain).



---

## 5. Execution & Verification Checklist

After generating all files, provide a concise `README.md` with exact copy-paste commands to:

1. Install Python dependencies (`pip install -r requirements.txt`) and create `.env` from `.env.example`.
2. Install Electron (`cd electron && npm install`).
3. Launch the desktop app from an **Administrator** terminal (`cd electron && npm start`).
4. Run the live two-PC demo (`ncat -lvnp 4444` on Ubuntu `10.100.5.67`, then `python demo_attack/sim_intrusion.py` on Windows) and verify:
* Dashboard transitions live from Step 1 → Step 5 with real IP/PID.
* Phone receives the `ntfy.sh` push notification.
* `sim_intrusion.py` is killed and `10.100.5.67` is blocked in Windows Firewall.
* Typing *"Unblock 10.100.5.67"* in the dashboard AI chat removes the firewall rule live.



```

```