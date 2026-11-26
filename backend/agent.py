"""Google Gemini Autonomous Endpoint Defense Agent & Security Copilot.

Uses the official `google-genai` SDK (`from google import genai`) with Function
Calling wired directly to real alerting (Gmail API + optional ntfy) and OS
containment tools (`kill_process`, `block_ip_firewall`, `unblock_ip_firewall`).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

from google import genai
from google.genai import types

from backend.auth import get_current_user
from backend.config import settings
from backend.db import db
from backend.state import state, ws_manager
from backend.tools import (
    block_ip_firewall,
    kill_process,
    send_user_alert,
    unblock_ip_firewall,
)

logger = logging.getLogger("cybershield.agent")

DEFENSE_SYSTEM_PROMPT = (
    "You are CyberShield Mesh, an autonomous endpoint defense AI protecting a user's PC. "
    "Evaluate the live outbound connection telemetry carefully. If it appears to be "
    "unauthorized data exfiltration, a reverse shell, or a suspicious non-whitelisted "
    "connection, you MUST call `send_user_alert`, `kill_process`, and `block_ip_firewall` "
    "in that exact order, then return a concise 2-sentence plain-English explanation of "
    "what you stopped and why."
)

COPILOT_SYSTEM_PROMPT = (
    "You are CyberShield Mesh AI Security Copilot embedded in a live endpoint security console. "
    "Answer the operator's security questions clearly and concisely (2-4 sentences) using the "
    "live endpoint telemetry, signed-in Google account status, blocked IPs, and persisted incident "
    "history provided. "
    "You have real tools to unblock IPs (`unblock_ip_firewall`), block IPs (`block_ip_firewall`), "
    "terminate a process (`kill_process`), or send an alert (`send_user_alert`). "
    "Whenever the operator explicitly asks you to block, unblock, or kill a target, invoke the "
    "appropriate tool immediately and confirm the exact result."
)

_client: Optional[genai.Client] = None


def _get_client() -> Optional[genai.Client]:
    global _client
    if not settings.has_valid_gemini_key:
        return None
    if _client is None:
        _client = genai.Client(api_key=settings.gemini_api_key)
    return _client


def _run_defense_sync(event: dict[str, Any], incident_id: int) -> dict[str, Any]:
    remote_ip = str(event.get("remote_ip", ""))
    remote_port = int(event.get("remote_port", 0) or 0)
    local_port = int(event.get("local_port", 0) or 0)
    pid = int(event.get("pid", 0) or 0)
    process_name = str(event.get("process_name", "unknown"))
    timestamp = str(event.get("timestamp", ""))
    trigger_reason = str(event.get("trigger_reason", ""))

    state.set_active_incident_id(incident_id)
    actions_taken: list[dict[str, Any]] = []
    called_names: set[str] = set()

    def _tool_send_user_alert(ip: str, process_name: str, reason: str) -> dict[str, Any]:
        """Send an urgent security alert to the signed-in user's Google email and optional ntfy push."""
        res = send_user_alert(ip=ip, process_name=process_name, reason=reason)
        called_names.add("send_user_alert")
        actions_taken.append({"tool": "send_user_alert", "ip": ip, "result": res})
        return res

    def _tool_kill_process(pid: int) -> dict[str, Any]:
        """Terminate a suspicious local process by PID to immediately sever its live connection."""
        res = kill_process(pid=pid)
        called_names.add("kill_process")
        actions_taken.append({"tool": "kill_process", "pid": pid, "result": res})
        return res

    def _tool_block_ip_firewall(ip: str) -> dict[str, Any]:
        """Block an external IP address bidirectionally (outbound + inbound) in the OS firewall."""
        res = block_ip_firewall(
            ip=ip,
            reason=f"Autonomous Gemini defense ({process_name} -> {remote_ip}:{remote_port})",
            process_name=process_name,
        )
        called_names.add("block_ip_firewall")
        actions_taken.append({"tool": "block_ip_firewall", "ip": ip, "result": res})
        return res

    _tool_send_user_alert.__name__ = "send_user_alert"
    _tool_kill_process.__name__ = "kill_process"
    _tool_block_ip_firewall.__name__ = "block_ip_firewall"

    user = get_current_user()
    telemetry_prompt = (
        "Live outbound TCP socket alert from CyberShield endpoint sensor:\n"
        f"- remote_ip: {remote_ip}\n"
        f"- remote_port: {remote_port}\n"
        f"- local_port: {local_port}\n"
        f"- pid: {pid}\n"
        f"- process_name: {process_name}\n"
        f"- trigger_reason: {trigger_reason}\n"
        f"- timestamp: {timestamp}\n"
        f"- signed_in_owner_email: {user['email'] if user else 'not_signed_in'}\n\n"
        "Assess this live outbound connection now and execute containment tools if malicious."
    )

    ai_summary = ""
    used_gemini = False
    client = _get_client()

    if client is not None:
        try:
            response = client.models.generate_content(
                model=settings.gemini_model,
                contents=telemetry_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=DEFENSE_SYSTEM_PROMPT,
                    tools=[
                        _tool_send_user_alert,
                        _tool_kill_process,
                        _tool_block_ip_firewall,
                    ],
                    temperature=0.1,
                ),
            )
            used_gemini = True
            ai_summary = (response.text or "").strip()
        except Exception as exc:
            logger.error("Gemini analyze_and_defend error (running failsafe): %s", exc)

    if not used_gemini:
        reason = (
            f"Unauthorized outbound TCP connection from {process_name} (PID {pid}) "
            f"to non-whitelisted peer {remote_ip}:{remote_port}."
        )
        _tool_send_user_alert(remote_ip, process_name, reason)
        _tool_kill_process(pid)
        _tool_block_ip_firewall(remote_ip)
        ai_summary = (
            f"Stopped unauthorized outbound connection from {process_name} (PID {pid}) "
            f"to {remote_ip}:{remote_port}. Dispatched an alert, terminated the process, "
            f"and applied bidirectional firewall rules on {remote_ip}."
        )
    elif not ai_summary:
        ai_summary = (
            f"Intercepted suspicious outbound connection from {process_name} (PID {pid}) "
            f"to {remote_ip}:{remote_port} and executed autonomous containment."
        )

    final_status = "BLOCKED" if "block_ip_firewall" in called_names else "CONTAINED"
    updated = db.update_incident(
        incident_id,
        ai_summary=ai_summary,
        status=final_status,
    )
    state.set_active_incident_id(None)
    state.set_protection_status("ARMED")

    ws_manager.emit_activity(
        "success",
        f"Gemini AI containment finished for {remote_ip}:{remote_port} — {ai_summary[:120]}",
    )
    ws_manager.emit_incident_update(updated)

    return {
        "incident_id": incident_id,
        "used_gemini": used_gemini,
        "model": settings.gemini_model,
        "ai_summary": ai_summary,
        "actions": actions_taken,
    }


async def analyze_and_defend(event: dict[str, Any], incident_id: int) -> dict[str, Any]:
    """Run Gemini autonomous threat evaluation & containment in a background thread."""
    remote_ip = str(event.get("remote_ip", ""))
    remote_port = int(event.get("remote_port", 0) or 0)
    pid = int(event.get("pid", 0) or 0)
    process_name = str(event.get("process_name", "unknown"))

    state.set_protection_status("CONTAINING")
    updated = db.update_incident(incident_id, status="ANALYZING")
    ws_manager.emit_activity(
        "warn",
        f"Gemini ({settings.gemini_model}) analyzing {process_name} (PID {pid}) -> {remote_ip}:{remote_port}...",
    )
    ws_manager.emit_incident_update(updated)

    return await asyncio.to_thread(_run_defense_sync, event, incident_id)


def _run_chat_sync(user_message: str) -> dict[str, Any]:
    recent_incidents = db.list_incidents(limit=15)
    blocked_ips = db.list_blocked_ips()
    whitelist_ips = db.list_whitelist_ips()
    active_conns = state.get_active_connections()[:20]
    user = get_current_user()
    actions_taken: list[dict[str, Any]] = []

    def _chat_unblock_ip(ip: str) -> dict[str, Any]:
        """Remove CyberShield OS firewall block rules for a previously blocked IP address."""
        res = unblock_ip_firewall(ip=ip)
        actions_taken.append({"tool": "unblock_ip_firewall", "target": ip, "result": res})
        return res

    def _chat_block_ip(ip: str) -> dict[str, Any]:
        """Block an external IP address bidirectionally (outbound + inbound) in the OS firewall."""
        res = block_ip_firewall(ip=ip, reason="Blocked via AI Security Copilot")
        actions_taken.append({"tool": "block_ip_firewall", "target": ip, "result": res})
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
    _chat_kill_pid.__name__ = "kill_process"
    _chat_send_alert.__name__ = "send_user_alert"

    context_blob = json.dumps(
        {
            "signed_in_user": user["email"] if user else None,
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
                        _chat_kill_pid,
                        _chat_send_alert,
                    ],
                    temperature=0.2,
                ),
            )
            reply = (response.text or "").strip()
            if not reply and actions_taken:
                last = actions_taken[-1]
                reply = f"Executed `{last['tool']}` on {last['target']}."
            elif not reply:
                reply = "Endpoint sensor is active and no unresolved threats are present."
            return {
                "reply": reply,
                "actions": actions_taken,
                "blocked_ips": db.list_blocked_ips(),
                "used_gemini": True,
            }
        except Exception as exc:
            logger.error("Gemini chat_with_agent error: %s", exc)

    # Graceful offline / missing-key fallback
    lowered = user_message.lower()
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_message)
    if "unblock" in lowered and ip_match:
        target_ip = ip_match.group(0)
        res = _chat_unblock_ip(target_ip)
        return {
            "reply": f"Unblocked {target_ip}: {res.get('detail', 'done')}",
            "actions": actions_taken,
            "blocked_ips": db.list_blocked_ips(),
            "used_gemini": False,
        }
    if "block" in lowered and "unblock" not in lowered and ip_match:
        target_ip = ip_match.group(0)
        res = _chat_block_ip(target_ip)
        return {
            "reply": f"Blocked {target_ip}: {res.get('detail', 'done')}",
            "actions": actions_taken,
            "blocked_ips": db.list_blocked_ips(),
            "used_gemini": False,
        }

    if recent_incidents:
        latest = recent_incidents[0]
        reply = (
            f"Latest incident: {latest['process_name']} (PID {latest['pid']}) connected to "
            f"{latest['remote_ip']}:{latest['remote_port']} at {latest['timestamp']} "
            f"(status: {latest['status']}). {latest.get('ai_summary', '')}"
        ).strip()
    else:
        reply = (
            f"Endpoint monitor active with {len(active_conns)} live outbound connection(s) "
            f"and {len(blocked_ips)} blocked IP(s). No threats recorded yet."
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
            "reply": "Ask about any active socket, recent threat, or command me to block/unblock an IP.",
            "actions": [],
            "blocked_ips": db.list_blocked_ips(),
            "used_gemini": False,
        }
    return await asyncio.to_thread(_run_chat_sync, cleaned)
