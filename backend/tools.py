"""Real OS-level process control, single-host (/32) firewall actions, and post-verdict alerting."""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

import psutil

from backend.alerts import dispatch_user_alert
from backend.db import db
from backend.firewall import (
    enforce_os_block_single_host,
    flush_all_os_blocks,
    is_admin,
    is_linux,
    is_windows,
    remove_os_block_single_host,
    validate_ip,
)
from backend.state import state, ws_manager

logger = logging.getLogger("cybershield.tools")

CRITICAL_PIDS = {0, 4}


def suspend_process(pid: int) -> dict[str, Any]:
    """Freeze all threads of a suspicious process in <1ms to halt outbound exfiltration mid-handshake."""
    try:
        target_pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "suspended": False, "error": f"Invalid PID: {pid}"}

    if target_pid in CRITICAL_PIDS or target_pid == os.getpid() or target_pid <= 4:
        return {"ok": False, "suspended": False, "pid": target_pid, "error": "Protected PID"}

    try:
        proc = psutil.Process(target_pid)
        proc.suspend()
        state.mark_pid_suspended(target_pid)
        return {"ok": True, "suspended": True, "pid": target_pid}
    except psutil.NoSuchProcess:
        return {"ok": True, "suspended": False, "pid": target_pid, "detail": "already_exited"}
    except psutil.AccessDenied:
        return {"ok": False, "suspended": False, "pid": target_pid, "error": "access_denied"}
    except Exception as exc:
        return {"ok": False, "suspended": False, "pid": target_pid, "error": str(exc)}


def resume_process(pid: int) -> dict[str, Any]:
    """Resume a previously suspended process immediately after a BENIGN verdict."""
    try:
        target_pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "resumed": False, "error": f"Invalid PID: {pid}"}

    state.clear_pid_suspended(target_pid)
    try:
        proc = psutil.Process(target_pid)
        proc.resume()
        return {"ok": True, "resumed": True, "pid": target_pid}
    except psutil.NoSuchProcess:
        return {"ok": True, "resumed": False, "pid": target_pid, "detail": "already_exited"}
    except psutil.AccessDenied:
        return {"ok": False, "resumed": False, "pid": target_pid, "error": "access_denied"}
    except Exception as exc:
        return {"ok": False, "resumed": False, "pid": target_pid, "error": str(exc)}


def kill_process(pid: int) -> dict[str, Any]:
    """Terminate a local OS process by PID (including frozen/suspended processes).

    Refuses to kill system-critical PIDs (0, 4, or CyberShield Mesh's own process).
    """
    try:
        target_pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "killed": False, "error": f"Invalid PID: {pid}"}

    own_pid = os.getpid()
    if target_pid in CRITICAL_PIDS or target_pid == own_pid or target_pid <= 0:
        msg = f"Refused to terminate protected/invalid PID {target_pid}."
        logger.warning(msg)
        return {"ok": False, "killed": False, "pid": target_pid, "error": msg}

    state.clear_pid_suspended(target_pid)
    killed = False
    method = "none"
    detail = ""
    proc_name = "unknown"

    try:
        proc = psutil.Process(target_pid)
        try:
            proc_name = proc.name()
        except psutil.Error:
            pass

        # On Windows terminate() calls TerminateProcess (works on suspended threads);
        # on POSIX kill() sends SIGKILL (immediately reaps suspended processes).
        if is_windows():
            proc.terminate()
            method = "terminate"
        else:
            proc.kill()
            method = "kill"

        try:
            proc.wait(timeout=1.5)
            killed = True
            detail = f"Terminated {proc_name} (PID {target_pid})."
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1.5)
            killed = True
            method = "kill"
            detail = f"Force-killed {proc_name} (PID {target_pid})."
    except psutil.NoSuchProcess:
        killed = True
        method = "already_exited"
        detail = f"Process PID {target_pid} already exited."
    except psutil.AccessDenied:
        killed = False
        method = "access_denied"
        detail = f"[ACCESS DENIED — ELEVATE TO ADMIN] Unable to terminate PID {target_pid}."
        logger.warning(detail)
    except Exception as exc:
        killed = False
        method = "error"
        detail = f"Error terminating PID {target_pid}: {exc}"
        logger.exception(detail)

    active_id = state.get_active_incident_id()
    updated = db.update_incident(
        active_id,
        process_killed=killed,
        action=f"kill_process({target_pid})",
    )
    ws_manager.emit_activity(
        "success" if killed else "warn",
        detail,
    )
    ws_manager.emit_incident_update(updated)

    return {
        "ok": True,
        "killed": killed,
        "pid": target_pid,
        "process_name": proc_name,
        "method": method,
        "detail": detail,
    }


def block_ip_firewall(
    ip: str,
    reason: str = "Blocked by CyberShield Mesh",
    process_name: str = "",
) -> dict[str, Any]:
    """Block a single external host (/32 or /128) bidirectionally in the OS firewall."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError:
        return {"ok": False, "blocked": False, "error": f"Invalid IP address: {ip}"}

    parsed = ipaddress.ip_address(clean_ip)
    if parsed.is_loopback or parsed.is_unspecified:
        return {
            "ok": False,
            "blocked": False,
            "ip": clean_ip,
            "error": "Refusing to block loopback or unspecified address.",
        }

    if db.is_ip_whitelisted(clean_ip):
        msg = f"Skipped blocking {clean_ip}: peer is on the Trusted IP Whitelist."
        ws_manager.emit_activity("info", msg)
        return {"ok": False, "blocked": False, "ip": clean_ip, "error": msg}

    fw = enforce_os_block_single_host(clean_ip)
    simulated = bool(fw["simulated"])
    rule_out = str(fw["rule_out"])
    rule_in = str(fw["rule_in"])
    detail = str(fw["detail"])

    record = db.add_blocked_ip(
        clean_ip,
        reason=reason,
        process_name=process_name,
        rule_out=rule_out,
        rule_in=rule_in,
        simulated=simulated,
    )

    active_id = state.get_active_incident_id()
    updated = db.update_incident(
        active_id,
        ip=clean_ip,
        ip_blocked=not simulated or True,
        status="BLOCKED",
        action=f"block_ip_firewall({fw['remote_spec']})",
    )

    ws_manager.emit_activity(
        "success" if not simulated else "warn",
        f"Firewall block {fw['remote_spec']}: {'Enforced in OS Firewall' if not simulated else 'Policy Recorded (Elevate to Admin for netsh)'}",
    )
    ws_manager.emit_firewall_update()
    ws_manager.emit_incident_update(updated)

    return {
        "ok": True,
        "blocked": True,
        "ip": clean_ip,
        "remote_spec": fw["remote_spec"],
        "rules": [rule_out, rule_in],
        "simulated": simulated,
        "detail": detail,
        "record": record,
    }


# Alias matching EDR terminology
block_ip = block_ip_firewall


def unblock_ip_firewall(ip: str) -> dict[str, Any]:
    """Remove CyberShield OS firewall block rules for a previously blocked IP address."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError:
        return {"ok": False, "unblocked": False, "error": f"Invalid IP address: {ip}"}

    fw = remove_os_block_single_host(clean_ip)
    db.remove_blocked_ip(clean_ip)
    updated = db.update_incident(
        ip=clean_ip,
        ip_blocked=False,
        status="UNBLOCKED",
        action=f"unblock_ip_firewall({clean_ip})",
    )

    ws_manager.emit_activity("info", f"Unblocked {clean_ip} and removed /32 firewall rules.")
    ws_manager.emit_firewall_update()
    ws_manager.emit_incident_update(updated)

    return {
        "ok": True,
        "unblocked": True,
        "ip": clean_ip,
        "rules_removed": fw["rules_removed"],
        "simulated": fw["simulated"],
        "detail": fw["detail"],
        "remaining_blocked_ips": [r["ip"] for r in db.list_blocked_ips()],
    }


def whitelist_ip(ip: str, label: str = "Trusted via Copilot") -> dict[str, Any]:
    """Add an IP address to the Trusted IP Whitelist (and remove any active block on it)."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError:
        return {"ok": False, "whitelisted": False, "error": f"Invalid IP address: {ip}"}

    # Ensure it is also unblocked if previously blocked
    if any(r["ip"] == clean_ip for r in db.list_blocked_ips()):
        remove_os_block_single_host(clean_ip)
        db.remove_blocked_ip(clean_ip)

    rec = db.add_whitelist_ip(clean_ip, label=label)
    ws_manager.emit_activity("info", f"Whitelisted trusted peer {clean_ip} ({label}).")
    ws_manager.emit_firewall_update()
    return {
        "ok": True,
        "whitelisted": True,
        "ip": clean_ip,
        "record": rec,
        "whitelist_ips": db.list_whitelist_ips(),
    }


def send_user_alert(
    ip: str,
    process_name: str,
    reason: str,
    ai_summary: str = "",
) -> dict[str, Any]:
    """Dispatch Gmail API + optional Ntfy alert ONLY after a confirmed MALICIOUS verdict."""
    active_id = state.get_active_incident_id()
    inc = db.get_incident_by_id(active_id) if active_id else None
    port = int(inc.get("remote_port", 0)) if inc else 0
    pid = int(inc.get("pid", 0)) if inc else 0

    # Suppress noisy email spam if running un-elevated on Windows where netsh couldn't enforce?
    # No — if a real threat was killed in Standard Mode, one concise alert noting elevation status is helpful,
    # while BENIGN traffic NEVER calls send_user_alert at all!
    receipt = dispatch_user_alert(
        ip=ip,
        port=port,
        pid=pid,
        process_name=process_name,
        reason=reason,
        ai_summary=ai_summary,
    )

    gmail_res = receipt.get("gmail", {})
    ntfy_res = receipt.get("ntfy", {})

    updated = db.update_incident(
        active_id,
        ip=ip,
        gmail_sent=bool(gmail_res.get("sent")),
        gmail_message_id=str(gmail_res.get("message_id") or ""),
        ntfy_sent=bool(ntfy_res.get("sent")),
        action=f"send_user_alert({ip})",
    )

    channels: list[str] = []
    if gmail_res.get("sent"):
        channels.append(f"Gmail ({gmail_res.get('to')})")
    if ntfy_res.get("sent"):
        channels.append(f"ntfy/{ntfy_res.get('topic')}")

    if channels:
        ws_manager.emit_activity(
            "info",
            f"Dispatched post-verdict forensic alert via {', '.join(channels)} for {process_name} -> {ip}",
        )
    ws_manager.emit_incident_update(updated)
    return {
        "ok": True,
        "ip": ip,
        "process_name": process_name,
        **receipt,
    }


def reset_all_firewall_rules() -> dict[str, Any]:
    """Delete all CyberShield_Block_* firewall rules and clear blocked IP records."""
    blocked_rows = db.list_blocked_ips()
    cleared_ips = [r["ip"] for r in blocked_rows]
    flush_all_os_blocks(cleared_ips)
    db.clear_blocked_ips()
    state.clear_cooldowns()
    ws_manager.emit_activity(
        "info",
        f"Cleared all CyberShield firewall rules ({len(cleared_ips)} IP(s) unblocked).",
    )
    ws_manager.emit_firewall_update()
    return {"ok": True, "cleared_ips": cleared_ips}
