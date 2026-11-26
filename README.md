# CyberShield Mesh

**Autonomous AI Endpoint Intrusion Defense** built for the **Google AI Agent-a-thon 2026** (GDG on Campus, FAST CFD Campus).

CyberShield Mesh closes three real-world blind spots in built-in Windows Security:
1. **Outbound Traffic Blind Spot:** Windows Firewall permits almost all outbound connections by default.
2. **Signature-Free Attacks:** Custom scripts or compiled binaries bypass signature-based antivirus completely.
3. **No Remote Visibility or Autonomous Containment:** CyberShield Mesh uses **Google Gemini (`google-genai`)** with real Function Calling tools to alert your phone (`ntfy.sh`), terminate the offending process (`psutil`), and apply bidirectional Windows Firewall blocks (`netsh`) in seconds.

---

## Project Structure

```text
.
├── .env.example                 # Environment template
├── requirements.txt             # FastAPI, Uvicorn, psutil, requests, dotenv, google-genai
├── README.md                    # Setup & 3-minute live demo runbook
├── backend/
│   ├── __init__.py
│   ├── config.py                # Safe .env loader with defaults
│   ├── state.py                 # Thread-safe incident store + WebSocket ConnectionManager
│   ├── tools.py                 # Real OS/API tools (ntfy.sh, psutil kill, netsh block/unblock)
│   ├── agent.py                 # Google Gemini autonomous defense agent + interactive chat
│   ├── monitor.py               # 1-second background psutil TCP socket monitor
│   └── main.py                  # FastAPI server (/, /health, /ws, /api/chat, /api/simulate, /api/reset)
├── frontend/
│   └── index.html               # Single-screen live WebSocket cyber dashboard + AI chat
├── electron/
│   ├── package.json             # Electron desktop manifest
│   └── main.js                  # Spawns FastAPI, polls /health, opens dark window + System Tray
└── demo_attack/
    ├── sim_intrusion.py         # Harmless Python outbound TCP beacon (:4444)
    └── sim_intrusion.cpp        # Optional native C++ WinSock2 outbound beacon
```

---

## 1. Python Backend Setup

From the project root:

```bash
pip install -r requirements.txt
```

Create your `.env` file from `.env.example`:

- **Windows PowerShell:**
  ```powershell
  Copy-Item .env.example .env
  ```
- **Linux / macOS:**
  ```bash
  cp .env.example .env
  ```

Edit `.env` and set:
- `GEMINI_API_KEY` — your Google AI Studio API key
- `GEMINI_MODEL` — defaults to `gemini-3.5-flash-lite`
- `NTFY_TOPIC` — unique topic name (install the free **ntfy** mobile app and subscribe to this exact topic)
- `WATCH_PORTS` — defaults to `4444,1337,9001,5555`
- `DEMO_TARGET_IP` — attacker PC IP (default `10.100.5.67`)

---

## 2. Electron Desktop App Setup

```bash
cd electron
npm install
```

---

## 3. Launch CyberShield Mesh (Administrator Required for Real Firewall Rules)

On Windows 10/11, open **PowerShell or Command Prompt as Administrator**, then run:

```powershell
cd electron
npm start
```

What happens automatically:
- Electron spawns `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`.
- Polls `http://127.0.0.1:8000/health` until ready.
- Opens the dark `1280x800` CyberShield Mesh live dashboard and adds a **System Tray** shield icon (`Show CyberShield` / `Quit`).
- Quitting cleanly terminates the Python backend process tree.

> **Standalone browser mode (without Electron):**
> ```bash
> python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
> ```
> Then open `http://127.0.0.1:8000/`.
>
> *(If launched without Administrator privileges on Windows, CyberShield Mesh will never crash — it logs `[SIMULATED BLOCK - RUN AS ADMIN]` cleanly.)*

---

## 4. 3-Minute Live Two-PC Demo Runbook

### Preparation
1. **Attacker PC (Ubuntu Linux, `10.100.5.67`):** Start the TCP listener:
   ```bash
   ncat -lvnp 4444
   ```
2. **Phone:** Open the **ntfy** app subscribed to your `NTFY_TOPIC`.
3. **Target PC (Windows 10/11, Administrator terminal):** Launch CyberShield Mesh (`cd electron && npm start`). Confirm the dashboard displays **PROTECTED** and **LIVE WS**.

### Live Demo Flow
1. **Trigger Real Outbound Exfiltration** on Windows (in a separate terminal):
   ```powershell
   python demo_attack/sim_intrusion.py
   ```
   *(Optional native C++ binary version to show signature-free binary detection:)*
   ```powershell
   g++ demo_attack/sim_intrusion.cpp -o sim_intrusion.exe -lws2_32
   .\sim_intrusion.exe 10.100.5.67 4444
   ```
2. **Watch Autonomous Defense Live (Steps 1 → 5):**
   - **Step 1 (Intrusion Detected):** `monitor.py` spots the `ESTABLISHED` TCP connection to `10.100.5.67:4444` with real PID and process name.
   - **Step 2 (Gemini AI Defending):** Gemini evaluates the live telemetry and decides to invoke containment tools.
   - **Step 3 (Mobile Alert Sent):** Your phone buzzes with the `ntfy.sh` push notification; the dashboard Mobile Alert card buzzes in sync.
   - **Step 4 (Link Severed):** `kill_process` terminates `sim_intrusion.py` — the Ubuntu `ncat` stream stops immediately.
   - **Step 5 (Source Blocked):** `block_ip_firewall` adds `CyberShield_Block_Out_10.100.5.67` and `CyberShield_Block_In_10.100.5.67` in Windows Firewall.
3. **Interactive Gemini Chat Demo (Right Sidebar):**
   - Ask: `Why did you block 10.100.5.67?` → Gemini cites the exact process, PID, port, and timestamp from incident memory.
   - Command: `Unblock 10.100.5.67, that's my test server.` → Gemini calls `unblock_ip_firewall("10.100.5.67")` live, removes the Windows Firewall rules, and updates the dashboard back to **PROTECTED**.
4. **Backup / Reset Buttons (Header):**
   - **Simulate Attack:** If venue Wi-Fi or Ubuntu has issues, click **Simulate Attack** to run the real Gemini agent + `ntfy.sh` push + full Step 1 → 5 visual flow safely.
   - **Reset / Unblock:** Deletes all `CyberShield_Block_*` Windows Firewall rules and resets dashboard state between judge demos.
