# CyberShield Mesh

**Autonomous Gemini-Powered Endpoint Security Console** with **Sign in with Google**, real-time **Gmail API + ntfy intrusion alerts**, live OS socket telemetry (`psutil`), SQLite persistence, and autonomous Windows/Linux firewall containment.

---

## Key Capabilities

- **Google OAuth 2.0 Account Login:** Users sign into the desktop console with their real Google Account (`openid`, `email`, `profile`, `gmail.send`), automatically binding this PC to their inbox with refreshable local sessions in SQLite (`backend/data/cybershield.db`).
- **Real-Time Gmail + Optional ntfy Alerts:** When Gemini detects an unauthorized outbound connection, CyberShield Mesh sends a formatted HTML intrusion alert directly to the user's own Gmail inbox (triggering an instant phone notification) and optionally pushes to `ntfy.sh`.
- **Real Endpoint Security Console (Zero Fake Simulation):**
  - **Live Monitor:** Real-time `psutil` table of active `ESTABLISHED` outbound TCP connections with risk classification and manual **Kill PID** / **Block IP** controls.
  - **Threats & Incidents:** Persisted SQLite history of every intrusion, Gemini's reasoning, Gmail delivery ID, process termination, and firewall rule state.
  - **Firewall & Whitelist:** Active inbound+outbound OS firewall blocks (`netsh` on Windows Admin / `iptables` on Linux root), manual block/unblock, and a Trusted IP Whitelist.
  - **AI Security Copilot:** Conversational Gemini assistant with live tool execution (`unblock_ip_firewall`, `block_ip_firewall`, `kill_process`, `send_user_alert`).
  - **Account & Settings:** Connected Google profile, **Send Test Alert to My Gmail**, Autonomous Mode toggle, Watch Ports, and Suspicious Binaries editor.

---

## 1. Google Cloud OAuth 2.0 Setup (1 Minute)

To enable **Sign in with Google** and **Gmail API Alerts**:
1. Open [Google Cloud Console → APIs & Services → Library](https://console.cloud.google.com/apis/library) and enable **Gmail API**.
2. Open **APIs & Services → OAuth consent screen** (External, add your Gmail under **Test users**).
3. Open **APIs & Services → Credentials → Create Credentials → OAuth client ID → Web application**.
4. Under **Authorized redirect URIs**, add:
   ```text
   http://127.0.0.1:8000/auth/google/callback
   ```
5. Copy the **Client ID** and **Client Secret** — you can either paste them into `.env` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) or paste them directly inside the app's **Sign-In setup panel**.

---

## 2. Quick Start

### Python Dependencies & `.env`
```bash
pip install -r requirements.txt
cp .env.example .env   # Windows PowerShell: Copy-Item .env.example .env
```
Set `GEMINI_API_KEY` (and optionally `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`) in `.env`.

### Run on Ubuntu / Linux
- **Browser Console:**
  ```bash
  .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
  ```
  Open `http://127.0.0.1:8000/`.
- **Electron Desktop App:**
  ```bash
  cd electron && npm install
  CYBERSHIELD_PYTHON=/home/faizan/CyberFieldMesh/.venv/bin/python npx electron --no-sandbox .
  ```

### Windows 10/11 — Clone & One-Click Install (Recommended)
```powershell
git clone https://github.com/MuhammadFaizanAI/CyberShield-Mesh.git
cd CyberShield-Mesh
.\INSTALL_WINDOWS.bat
```
What `INSTALL_WINDOWS.bat` does automatically:
1. Creates an isolated `.venv` and installs all Python dependencies (`requirements.txt`).
2. Installs Electron (`electron/node_modules`).
3. Prompts for your `GEMINI_API_KEY` (saves to `.env`).
4. Creates a **CyberShield Mesh** shortcut on your Windows Desktop and launches the app as **Administrator** (UAC) so real Windows Firewall rules work immediately.
5. Sign in with your **Google Account** right on the app's welcome screen to activate real Gmail alerts.

*(Optional: run `BUILD_WINDOWS_EXES.bat` if you also want standalone portable `.exe` files in `release_windows\`.)*

---

## 3. Live Two-PC Intrusion Test
1. **Attacker PC (Ubuntu, `10.100.5.67`):** `ncat -lvnp 4444`
2. **Target PC (Windows Admin):** Launch CyberShield Mesh, sign in with Google, and verify **Send Test Alert to My Gmail** in **Account & Settings**.
3. Run `python demo_attack/sim_intrusion.py` (or `sim_intrusion.exe`) on Windows — CyberShield detects the real outbound TCP socket, emails your Google inbox immediately, terminates the process, and blocks `10.100.5.67` in Windows Firewall.
