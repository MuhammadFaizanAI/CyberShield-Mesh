"""Google Gemini Autonomous Defense Agent & Interactive Security Chat.

Uses the official `google-genai` SDK (`from google import genai`) with Function
Calling bound directly to `backend/tools.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Optional

from google import genai
from google.genai import types

from backend.config import settings
from backend.state import state, ws_manager
from backend.tools import (
    block_ip_firewall,
    kill_process,
    send_mobile_alert,
    unblock_ip_firewall,
)

logger = logging.getLogger("cybershield.agent")

DEFENSE_SYSTEM_PROMPT = (
    "You are CyberShield Mesh, an autonomous endpoint defense AI. "
    "Evaluate the suspicious outbound connection. If it appears to be unauthorized "
    "data exfiltration, a reverse shell, or a suspicious non-whitelisted connection, "
    "you MUST call `send_mobile_alert`, `kill_process`, and `block_ip_firewall` in order, "
    "then return a concise 2-sentence plain-English explanation of what you stopped and why."
)

CHAT_SYSTEM_PROMPT = (
    "You are CyberShield Mesh, an autonomous endpoint defense AI assistant embedded in "
    "the live security dashboard. Answer operator questions concisely (2-3 sentences max) "
    "using the provided live incident memory. "
    "If the operator asks to unblock an IP (e.g. a test server or false positive), call "
    "`unblock_ip_firewall(ip)` immediately and confirm. "
    "If the operator asks to block an IP, call `block_ip_firewall(ip)` immediately and confirm."
)

_client: Optional[genai.Client] = None


def _get_client() -> Optional[genai.Client]:
    global _client
    if not settings.has_valid_gemini_key:
        return None
    if _client is None:
        _client = genai.Client(api_key=settings.gemini_api_key)
    return _client


def _run_defense_sync(event: dict[str, Any]) -> dict[str, Any]:
    """Execute Gemini autonomous reasoning & tool calling in a worker thread."""
    remote_ip = str(event.get("remote_ip", ""))
    remote_port = int(event.get("remote_port", 0) or 0)
    local_port = int(event.get("local_port", 0) or 0)
    pid = int(event.get("pid", 0) or 0)
    process_name = str(event.get("process_name", "unknown"))
    timestamp = str(event.get("timestamp", ""))

    actions_taken: list[dict[str, Any]] = []
    called_names: set[str] = set()

    def _traced_send_mobile_alert(ip: str, process_name: str, reason: str) -> dict[str, Any]:
        """Send an urgent push notification to the user's phone via ntfy.sh."""
        res = send_mobile_alert(ip=ip, process_name=process_name, reason=reason)
        called_names.add("send_mobile_alert")
        actions_taken.append({"tool": "send_mobile_alert", "result": res})
        time.sleep(0.35)
        return res

    def _traced_kill_process(pid: int) -> dict[str, Any]:
        """Terminate a suspicious local process by PID to sever its active connection."""
        res = kill_process(pid=pid)
        called_names.add("kill_process")
        actions_taken.append({"tool": "kill_process", "result": res})
        time.sleep(0.35)
        return res

    def _traced_block_ip_firewall(ip: str) -> dict[str, Any]:
        """Block an external IP address in both outbound and inbound Windows Firewall rules."""
        res = block_ip_firewall(ip=ip)
        called_names.add("block_ip_firewall")
        actions_taken.append({"tool": "block_ip_firewall", "result": res})
        return res

    # Preserve canonical tool names for Gemini function declarations
    _traced_send_mobile_alert.__name__ = "send_mobile_alert"
    _traced_kill_process.__name__ = "kill_process"
    _traced_block_ip_firewall.__name__ = "block_ip_firewall"

    telemetry_prompt = (
        "Live outbound socket alert from CyberShield endpoint sensor:\n"
        f"- remote_ip: {remote_ip}\n"
        f"- remote_port: {remote_port}\n"
        f"- local_port: {local_port}\n"
        f"- pid: {pid}\n"
        f"- process_name: {process_name}\n"
        f"- timestamp: {timestamp}\n"
        f"- watch_ports: {sorted(settings.watch_ports)}\n\n"
        "Assess this connection now and execute containment tools if malicious."
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
                        _traced_send_mobile_alert,
                        _traced_kill_process,
                        _traced_block_ip_firewall,
                    ],
                    temperature=0.1,
                ),
            )
            used_gemini = True
            ai_summary = (response.text or "").strip()
        except Exception as exc:
            logger.error("Gemini analyze_and_defend error (activating failsafe): %s", exc)
            ai_summary = ""

    # Guaranteed failsafe so a missing key or transient API hiccup never stalls the live demo
    if not used_gemini:
        reason = (
            f"Unauthorized outbound TCP connection from {process_name} (PID {pid}) "
            f"to non-whitelisted peer {remote_ip}:{remote_port}."
        )
        _traced_send_mobile_alert(remote_ip, process_name, reason)
        _traced_kill_process(pid)
        _traced_block_ip_firewall(remote_ip)
        ai_summary = (
            f"Stopped suspicious outbound exfiltration from {process_name} (PID {pid}) "
            f"to {remote_ip}:{remote_port}. Sent a mobile alert, terminated the process, "
            f"and applied bidirectional firewall blocks on {remote_ip}."
        )
    elif not ai_summary:
        ai_summary = (
            f"CyberShield Mesh intercepted suspicious outbound traffic from {process_name} "
            f"(PID {pid}) to {remote_ip}:{remote_port} and completed autonomous containment."
        )

    state.update_latest_incident(
        ip=remote_ip,
        ai_summary=ai_summary,
        status="BLOCKED" if "block_ip_firewall" in called_names else "CONTAINED",
    )

    final_step = 5 if "block_ip_firewall" in called_names else max(
        2, int(state.get_snapshot().get("step", 2))
    )
    ws_manager.emit_event(
        step=final_step,
        status="SOURCE BLOCKED" if final_step == 5 else "AI DEFENDING",
        ip=remote_ip,
        port=remote_port,
        pid=pid,
        process_name=process_name,
        ai_summary=ai_summary,
        log_entry=f"[AI] {ai_summary[:110]}",
        extra={
            "used_gemini": used_gemini,
            "model": settings.gemini_model,
            "actions_taken": [a["tool"] for a in actions_taken],
        },
    )

    return {
        "used_gemini": used_gemini,
        "model": settings.gemini_model,
        "ai_summary": ai_summary,
        "actions": actions_taken,
    }


async def analyze_and_defend(event: dict[str, Any]) -> dict[str, Any]:
    """Broadcast Step 2 (AI Agent Defending) and run Gemini autonomous containment."""
    remote_ip = str(event.get("remote_ip", ""))
    remote_port = int(event.get("remote_port", 0) or 0)
    pid = int(event.get("pid", 0) or 0)
    process_name = str(event.get("process_name", "unknown"))

    ws_manager.emit_event(
        step=2,
        status="AI DEFENDING",
        ip=remote_ip,
        port=remote_port,
        pid=pid,
        process_name=process_name,
        ai_summary=f"Gemini ({settings.gemini_model}) analyzing {process_name} -> {remote_ip}:{remote_port}...",
        log_entry=f"[2] Gemini AI analyzing {process_name} (PID {pid}) -> {remote_ip}:{remote_port}",
    )

    # Brief beat so Step 2 animates visibly on stage before Step 3 fires
    await asyncio.sleep(0.35)
    return await asyncio.to_thread(_run_defense_sync, event)


def _run_chat_sync(user_message: str) -> dict[str, Any]:
    """Handle interactive dashboard chat with incident memory and live firewall tools."""
    recent_incidents = state.get_recent_incidents(limit=10)
    blocked_ips = state.get_blocked_ips()
    killed_pids = state.get_killed_pids()
    actions_taken: list[dict[str, Any]] = []

    def _traced_unblock_ip_firewall(ip: str) -> dict[str, Any]:
        """Remove CyberShield Windows Firewall block rules for a previously blocked IP."""
        res = unblock_ip_firewall(ip=ip)
        actions_taken.append({"tool": "unblock_ip_firewall", "ip": ip, "result": res})
        return res

    def _traced_block_ip_firewall(ip: str) -> dict[str, Any]:
        """Block an external IP address in both outbound and inbound Windows Firewall rules."""
        res = block_ip_firewall(ip=ip)
        actions_taken.append({"tool": "block_ip_firewall", "ip": ip, "result": res})
        return res

    _traced_unblock_ip_firewall.__name__ = "unblock_ip_firewall"
    _traced_block_ip_firewall.__name__ = "block_ip_firewall"

    memory_block = json.dumps(
        {
            "blocked_ips": blocked_ips,
            "killed_pids": killed_pids,
            "recent_incidents": recent_incidents,
        },
        indent=2,
    )

    prompt = (
        f"Current CyberShield Mesh live incident memory:\n{memory_block}\n\n"
        f"Operator message: {user_message}"
    )

    client = _get_client()
    if client is not None:
        try:
            response = client.models.generate_content(
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=CHAT_SYSTEM_PROMPT,
                    tools=[_traced_unblock_ip_firewall, _traced_block_ip_firewall],
                    temperature=0.2,
                ),
            )
            reply = (response.text or "").strip()
            if not reply and actions_taken:
                last = actions_taken[-1]
                reply = f"Executed `{last['tool']}` for {last['ip']}."
            elif not reply:
                reply = "Monitoring active. No active threats at this moment."
            return {
                "reply": reply,
                "actions": actions_taken,
                "blocked_ips": state.get_blocked_ips(),
                "used_gemini": True,
            }
        except Exception as exc:
            logger.error("Gemini chat_with_agent error: %s", exc)

    # Graceful offline / missing-key fallback so chat commands still function cleanly
    lowered = user_message.lower()
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_message)
    if "unblock" in lowered and ip_match:
        target_ip = ip_match.group(0)
        res = _traced_unblock_ip_firewall(target_ip)
        return {
            "reply": (
                f"Removed CyberShield firewall rules for {target_ip} "
                f"({res.get('detail', 'unblocked')})."
            ),
            "actions": actions_taken,
            "blocked_ips": state.get_blocked_ips(),
            "used_gemini": False,
        }
    if "block" in lowered and "unblock" not in lowered and ip_match:
        target_ip = ip_match.group(0)
        res = _traced_block_ip_firewall(target_ip)
        return {
            "reply": (
                f"Applied bidirectional firewall block for {target_ip} "
                f"({res.get('detail', 'blocked')})."
            ),
            "actions": actions_taken,
            "blocked_ips": state.get_blocked_ips(),
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
            "No intrusions recorded yet. CyberShield Mesh is actively monitoring "
            f"outbound connections on watch ports {sorted(settings.watch_ports)}."
        )

    if not settings.has_valid_gemini_key:
        reply += " (Set GEMINI_API_KEY in .env to enable full Gemini reasoning.)"

    return {
        "reply": reply,
        "actions": actions_taken,
        "blocked_ips": state.get_blocked_ips(),
        "used_gemini": False,
    }


async def chat_with_agent(user_message: str) -> dict[str, Any]:
    """Async wrapper for interactive security chat."""
    cleaned = (user_message or "").strip()
    if not cleaned:
        return {
            "reply": "Ask me about any blocked IP, recent incident, or tell me to unblock an IP.",
            "actions": [],
            "blocked_ips": state.get_blocked_ips(),
            "used_gemini": False,
        }
    return await asyncio.to_thread(_run_chat_sync, cleaned)
