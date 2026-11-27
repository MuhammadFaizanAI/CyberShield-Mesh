"""Google Gemini Verdict-First Autonomous Defense Engine & AI Security Copilot.

Pipeline for intercepted (frozen) outbound connections:
1. Evaluates process forensics (`process_name`, `cmdline`, `parent_name`,
   `remote_ip`, `remote_port`, `socket_state`, `cloud_provider`, `trigger_reason`)
   using Google Gemini (`google-genai`) structured JSON verdict BEFORE any alert
   or firewall modification occurs.
2. If Verdict == MALICIOUS:
   a) Terminates the frozen process (`kill_process(pid)`)
   b) Enforces a single-host `/32` firewall rule (`block_ip_firewall(remote_ip)`)
   c) Dispatches Gmail + Ntfy forensic alert (`send_user_alert`)
   d) Marks incident `"BLOCKED"` and emits the confirmed containment event.
3. If Verdict == BENIGN:
   a) Immediately resumes the suspended process (`resume_process(pid)`)
   b) Records `(process_name.lower(), remote_ip)` in `state.verified_benign_pairs`
   c) Sends ZERO Gmail/Ntfy alerts, applies ZERO firewall blocks, marks `"BENIGN_CLEARED"`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Literal, Optional

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from backend.auth import get_current_user
from backend.config import STANDARD_SAFE_PORTS, match_verified_cloud_provider, settings
from backend.db import db
from backend.state import state, ws_manager
from backend.tools import (
    block_ip_firewall,
    kill_process,
    resume_process,
    send_user_alert,
    unblock_ip_firewall,
    whitelist_ip,
)

logger = logging.getLogger("cybershield.agent")


class ThreatVerdict(BaseModel):
    verdict: Literal["MALICIOUS", "BENIGN"] = Field(
        description="MALICIOUS for unauthorized exfiltration, reverse shells, raw sockets, C2, or unapproved non-standard outbound streams; BENIGN for legitimate signed user applications or normal standard-port cloud traffic."
    )
    mitre_id: str = Field(
        default="T1048",
        description="Applicable MITRE ATT&CK technique ID (e.g. T1048, T1059.001, T1572, T1071, or NONE if BENIGN).",
    )
    summary: str = Field(
        description="Concise 2-sentence forensic explanation citing exact process, command-line behavior, and destination IP:port."
    )


DEFENSE_VERDICT_SYSTEM_PROMPT = (
    "You are CyberShield Mesh, an enterprise Endpoint Detection & Response (EDR) AI triage engine. "
    "A local process has just been frozen (`psutil.suspend()`) mid-connection (`SYN_SENT` or `ESTABLISHED`). "
    "Analyze its `process_name`, `parent_name`, full `cmdline`, `remote_ip`, `remote_port`, `socket_state`, "
    "`cloud_provider`, and `trigger_reason`, and return a strict JSON verdict (`MALICIOUS` or `BENIGN`).\n\n"
    "Rules for `MALICIOUS`:\n"
    "- Any Living-off-the-Land Binary (`curl.exe`, `powershell.exe`, `pwsh.exe`, `cmd.exe`, `certutil.exe`, "
    "`bitsadmin.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `ncat.exe`, `nc.exe`, `ssh.exe`, `scp.exe`, "
    "`sftp.exe`, `python.exe`, `python3.exe`, `sim_intrusion.exe`) uploading/exfiltrating data (`-T`, `--upload-file`, "
    "`-d`, `-F`), opening raw sockets (`TcpClient`, `ncat`, `nc`), creating SSH tunnels (`-R`, `-L`, `-D`), running "
    "encoded commands (`-enc`), or connecting to private LAN/hotspot IPs or watch ports (`4444`, `1337`, `9001`, `5555`, `7777`, `9090`).\n"
    "- Unknown binaries connecting to unverified external/LAN IPs on non-standard ports.\n\n"
    "Rules for `BENIGN`:\n"
    "- Legitimate desktop browsers, WebView2 (`msedgewebview2.exe`), WhatsApp, Teams, Discord, Slack, VS Code, or "
    "Windows core services (`svchost.exe`) communicating with verified cloud infrastructure (Meta, Microsoft, Google, "
    "Cloudflare) on standard web/messaging ports (`80`, `443`, `5222`, `5223`, `5228`, `8080`, `8443`)."
)

COPILOT_SYSTEM_PROMPT = (
    "You are CyberShield Mesh AI Security Copilot inside an enterprise EDR console. "
    "Answer concisely (2-4 sentences) with precision technical clarity using the live socket table, "
    "blocked `/32` rules, trusted whitelist, and incident forensics provided.\n"
    "Available live tools:\n"
    "- `unblock_ip_firewall(ip)` — removes `/32` firewall deny rules.\n"
    "- `block_ip_firewall(ip)` — enforces `/32` inbound+outbound firewall deny rules.\n"
    "- `whitelist_ip(ip, label)` — adds a trusted IP to the whitelist (and unblocks it if blocked).\n"
    "- `kill_process(pid)` — terminates a local PID.\n"
    "- `send_user_alert(ip, process_name, reason)` — sends a Gmail/Ntfy alert.\n"
    "When the operator commands an action (block, unblock, whitelist/trust, kill), invoke the tool immediately."
)

_client: Optional[genai.Client] = None


def _get_client() -> Optional[genai.Client]:
    global _client
    if not settings.has_valid_gemini_key:
        return None
    if _client is None:
        _client = genai.Client(api_key=settings.gemini_api_key)
    return _client


def _heuristic_offline_verdict(event: dict[str, Any]) -> ThreatVerdict:
    """Deterministic fallback verdict used ONLY if Gemini API is unreachable."""
    proc_name = str(event.get("process_name", "unknown"))
    proc_lower = proc_name.lower()
    remote_ip = str(event.get("remote_ip", ""))
    remote_port = int(event.get("remote_port", 0) or 0)
    trigger = str(event.get("trigger_reason", ""))
    cloud = match_verified_cloud_provider(remote_ip)

    # High-confidence malicious signatures
    high_conf_malicious = (
        trigger.startswith("MITRE_")
        or trigger.startswith("watch_port:")
        or proc_lower in {"ncat.exe", "ncat", "nc.exe", "nc", "sim_intrusion.exe", "sim_intrusion"}
        or (proc_lower in settings.lolbins and remote_port not in STANDARD_SAFE_PORTS)
    )
    if high_conf_malicious:
        mitre = "T1048"
        if "T1059" in trigger:
            mitre = "T1059.001"
        elif "T1572" in trigger:
            mitre = "T1572"
        return ThreatVerdict(
            verdict="MALICIOUS",
            mitre_id=mitre,
            summary=(
                f"Intercepted and terminated {proc_name} attempting unauthorized outbound stream "
                f"to {remote_ip}:{remote_port} ({mitre}). Single-host /32 firewall block enforced."
            ),
        )

    if cloud and remote_port in STANDARD_SAFE_PORTS:
        return ThreatVerdict(
            verdict="BENIGN",
            mitre_id="NONE",
            summary=f"Cleared {proc_name} communicating with verified {cloud} endpoint {remote_ip}:{remote_port}.",
        )

    return ThreatVerdict(
        verdict="MALICIOUS",
        mitre_id="T1071",
        summary=(
            f"Contained anomalous non-standard outbound connection from {proc_name} "
            f"to unverified peer {remote_ip}:{remote_port}."
        ),
    )


def _run_defense_sync(event: dict[str, Any], incident_id: int) -> dict[str, Any]:
    remote_ip = str(event.get("remote_ip", ""))
    remote_port = int(event.get("remote_port", 0) or 0)
    local_port = int(event.get("local_port", 0) or 0)
    pid = int(event.get("pid", 0) or 0)
    process_name = str(event.get("process_name", "unknown"))
    cmdline = str(event.get("cmdline", "") or process_name)
    parent_name = str(event.get("parent_name", "unknown") or "unknown")
    socket_state = str(event.get("socket_state", "ESTABLISHED"))
    timestamp = str(event.get("timestamp", ""))
    trigger_reason = str(event.get("trigger_reason", ""))
    cloud_provider = match_verified_cloud_provider(remote_ip) or "unverified/private"

    state.set_active_incident_id(incident_id)
    actions_taken: list[dict[str, Any]] = []
    used_gemini = False
    verdict_obj: Optional[ThreatVerdict] = None

    telemetry_prompt = (
        "Intercepted & suspended outbound socket telemetry:\n"
        f"- process_name: {process_name}\n"
        f"- pid: {pid}\n"
        f"- parent_name: {parent_name}\n"
        f"- cmdline: {cmdline}\n"
        f"- socket_state: {socket_state}\n"
        f"- local_port: {local_port}\n"
        f"- remote_ip: {remote_ip}\n"
        f"- remote_port: {remote_port}\n"
        f"- cloud_provider: {cloud_provider}\n"
        f"- sensor_trigger: {trigger_reason}\n"
        f"- timestamp_utc: {timestamp}\n"
    )

    client = _get_client()
    if client is not None:
        try:
            response = client.models.generate_content(
                model=settings.gemini_model,
                contents=telemetry_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=DEFENSE_VERDICT_SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=ThreatVerdict,
                    temperature=0.0,
                ),
            )
            raw_text = (response.text or "").strip()
            verdict_obj = ThreatVerdict.model_validate_json(raw_text)
            used_gemini = True
        except Exception as exc:
            logger.error("Gemini verdict evaluation error (using offline classifier): %s", exc)

    if verdict_obj is None:
        verdict_obj = _heuristic_offline_verdict(event)

    try:
        if verdict_obj.verdict == "BENIGN":
            # 1. Immediately resume the frozen process
            res_resume = resume_process(pid)
            actions_taken.append({"tool": "resume_process", "pid": pid, "result": res_resume})

            # 2. Cache (process_name, remote_ip) so it is never suspended or re-queried in this session
            state.add_verified_benign(process_name, remote_ip)

            # 3. ZERO Gmail/Ntfy alerts, ZERO firewall blocks — mark quietly as BENIGN_CLEARED
            updated = db.update_incident(
                incident_id,
                ai_summary=verdict_obj.summary,
                status="BENIGN_CLEARED",
                action=f"benign_cleared_resume({pid})",
            )
            ws_manager.emit_activity(
                "info",
                f"Cleared benign socket: {process_name} (PID {pid}) -> {remote_ip}:{remote_port} resumed.",
            )
            ws_manager.emit_incident_update(updated)
            return {
                "incident_id": incident_id,
                "verdict": "BENIGN",
                "used_gemini": used_gemini,
                "model": settings.gemini_model,
                "ai_summary": verdict_obj.summary,
                "actions": actions_taken,
            }

        # =====================================================================
        # MALICIOUS VERDICT -> STRICT CONTAINMENT PIPELINE
        # =====================================================================
        # 1. Kill frozen process immediately before a single byte can resume
        kill_res = kill_process(pid)
        actions_taken.append({"tool": "kill_process", "pid": pid, "result": kill_res})

        # 2. Enforce single-host /32 bidirectional firewall rule
        block_reason = f"[{verdict_obj.mitre_id}] {process_name} -> {remote_ip}:{remote_port}"
        block_res = block_ip_firewall(
            ip=remote_ip,
            reason=block_reason,
            process_name=process_name,
        )
        actions_taken.append({"tool": "block_ip_firewall", "ip": remote_ip, "result": block_res})

        # 3. Dispatch forensic Gmail + Ntfy alert ONLY if admin firewall enforced or process killed
        alert_reason = (
            f"MITRE {verdict_obj.mitre_id} | Pre-exfiltration freeze on {socket_state} | "
            f"Parent: {parent_name} | Cmd: {cmdline} | "
            f"Containment: PID {pid} terminated, {block_res.get('remote_spec', remote_ip)} blocked."
        )
        if state.is_admin() or kill_res.get("killed"):
            alert_res = send_user_alert(
                ip=remote_ip,
                process_name=process_name,
                reason=alert_reason,
                ai_summary=verdict_obj.summary,
            )
            actions_taken.append({"tool": "send_user_alert", "ip": remote_ip, "result": alert_res})

        # 4. Finalize incident as BLOCKED and surface danger containment event
        updated = db.update_incident(
            incident_id,
            ai_summary=verdict_obj.summary,
            status="BLOCKED",
        )
        ws_manager.emit_activity(
            "danger",
            f"BLOCKED [{verdict_obj.mitre_id}]: {process_name} (PID {pid}) -> {remote_ip}:{remote_port} — {verdict_obj.summary}",
        )
        ws_manager.emit_incident_update(updated)

        return {
            "incident_id": incident_id,
            "verdict": "MALICIOUS",
            "mitre_id": verdict_obj.mitre_id,
            "used_gemini": used_gemini,
            "model": settings.gemini_model,
            "ai_summary": verdict_obj.summary,
            "actions": actions_taken,
        }
    finally:
        # Safety guarantee: never leave a PID tracked as suspended after triage completes
        if pid in state.get_suspended_pids():
            resume_process(pid)
        state.set_active_incident_id(None)
        state.set_protection_status("ARMED")


async def analyze_and_defend(event: dict[str, Any], incident_id: int) -> dict[str, Any]:
    """Run silent verdict-first Gemini triage on an intercepted/frozen socket."""
    state.set_protection_status("CONTAINING")
    ws_manager.emit_incident_update(db.get_incident_by_id(incident_id))
    return await asyncio.to_thread(_run_defense_sync, event, incident_id)


def _run_chat_sync(user_message: str) -> dict[str, Any]:
    recent_incidents = db.list_incidents(limit=15)
    blocked_ips = db.list_blocked_ips()
    whitelist_ips = db.list_whitelist_ips()
    active_conns = state.get_active_connections()[:20]
    user = get_current_user()
    actions_taken: list[dict[str, Any]] = []

    def _chat_unblock_ip(ip: str) -> dict[str, Any]:
        """Remove CyberShield single-host (/32) OS firewall block rules for an IP address."""
        res = unblock_ip_firewall(ip=ip)
        actions_taken.append({"tool": "unblock_ip_firewall", "target": ip, "result": res})
        return res

    def _chat_block_ip(ip: str) -> dict[str, Any]:
        """Block a single external IP address (/32) bidirectionally in the OS firewall."""
        res = block_ip_firewall(ip=ip, reason="Blocked via AI Security Copilot")
        actions_taken.append({"tool": "block_ip_firewall", "target": ip, "result": res})
        return res

    def _chat_whitelist_ip(ip: str, label: str = "Trusted via Copilot") -> dict[str, Any]:
        """Add an IP address to the Trusted IP Whitelist and remove any active block on it."""
        res = whitelist_ip(ip=ip, label=label)
        actions_taken.append({"tool": "whitelist_ip", "target": ip, "result": res})
        return res

    def _chat_kill_pid(pid: int) -> dict[str, Any]:
        """Terminate a local OS process by PID."""
        res = kill_process(pid=pid)
        actions_taken.append({"tool": "kill_process", "target": str(pid), "result": res})
        return res

    def _chat_send_alert(ip: str, process_name: str, reason: str) -> dict[str, Any]:
        """Send a real security alert to the signed-in Google user's Gmail and optional ntfy push."""
        res = send_user_alert(ip=ip, process_name=process_name, reason=reason)
        actions_taken.append({"tool": "send_user_alert", "target": ip, "result": res})
        return res

    _chat_unblock_ip.__name__ = "unblock_ip_firewall"
    _chat_block_ip.__name__ = "block_ip_firewall"
    _chat_whitelist_ip.__name__ = "whitelist_ip"
    _chat_kill_pid.__name__ = "kill_process"
    _chat_send_alert.__name__ = "send_user_alert"

    context_blob = json.dumps(
        {
            "signed_in_user": user["email"] if user else None,
            "is_admin_firewall": state.is_admin(),
            "blocked_ips": blocked_ips,
            "whitelist_ips": whitelist_ips,
            "active_connections_count": len(active_conns),
            "active_connections_sample": active_conns[:10],
            "recent_incidents": recent_incidents[:10],
        },
        indent=2,
    )

    prompt = (
        f"Live CyberShield Mesh Endpoint State:\n{context_blob}\n\n"
        f"Operator question/command: {user_message}"
    )

    client = _get_client()
    if client is not None:
        try:
            response = client.models.generate_content(
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=COPILOT_SYSTEM_PROMPT,
                    tools=[
                        _chat_unblock_ip,
                        _chat_block_ip,
                        _chat_whitelist_ip,
                        _chat_kill_pid,
                        _chat_send_alert,
                    ],
                    temperature=0.1,
                ),
            )
            reply = (response.text or "").strip()
            if not reply and actions_taken:
                last = actions_taken[-1]
                reply = f"Executed `{last['tool']}` on `{last['target']}`."
            elif not reply:
                reply = "Sensor active. No unresolved threats."
            return {
                "reply": reply,
                "actions": actions_taken,
                "blocked_ips": db.list_blocked_ips(),
                "used_gemini": True,
            }
        except Exception as exc:
            logger.error("Gemini chat_with_agent error: %s", exc)

    # Deterministic offline command fallback
    lowered = user_message.lower()
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_message)
    if ("whitelist" in lowered or "trust" in lowered) and ip_match:
        target_ip = ip_match.group(0)
        _chat_whitelist_ip(target_ip)
        return {
            "reply": f"Added `{target_ip}` to the Trusted IP Whitelist.",
            "actions": actions_taken,
            "blocked_ips": db.list_blocked_ips(),
            "used_gemini": False,
        }
    if "unblock" in lowered and ip_match:
        target_ip = ip_match.group(0)
        res = _chat_unblock_ip(target_ip)
        return {
            "reply": f"Unblocked `{target_ip}`: {res.get('detail', 'done')}",
            "actions": actions_taken,
            "blocked_ips": db.list_blocked_ips(),
            "used_gemini": False,
        }
    if "block" in lowered and "unblock" not in lowered and ip_match:
        target_ip = ip_match.group(0)
        res = _chat_block_ip(target_ip)
        return {
            "reply": f"Blocked `{target_ip}` (/32): {res.get('detail', 'done')}",
            "actions": actions_taken,
            "blocked_ips": db.list_blocked_ips(),
            "used_gemini": False,
        }

    if recent_incidents:
        latest = recent_incidents[0]
        reply = (
            f"Latest incident #{latest['id']}: `{latest['process_name']}` (PID {latest['pid']}) -> "
            f"`{latest['remote_ip']}:{latest['remote_port']}` [{latest['status']}]. "
            f"{latest.get('ai_summary', '')}"
        ).strip()
    else:
        reply = (
            f"80ms sensor armed: {len(active_conns)} active socket(s), "
            f"{len(blocked_ips)} blocked `/32` peer(s)."
        )

    return {
        "reply": reply,
        "actions": actions_taken,
        "blocked_ips": db.list_blocked_ips(),
        "used_gemini": False,
    }


async def chat_with_agent(user_message: str) -> dict[str, Any]:
    cleaned = (user_message or "").strip()
    if not cleaned:
        return {
            "reply": "Enter a security query or command (e.g. `Unblock 10.100.5.99`, `Whitelist 10.100.5.67`).",
            "actions": [],
            "blocked_ips": db.list_blocked_ips(),
            "used_gemini": False,
        }
    return await asyncio.to_thread(_run_chat_sync, cleaned)
