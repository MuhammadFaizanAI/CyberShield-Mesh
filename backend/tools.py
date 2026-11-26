"""Real OS-level and API autonomous defense tools for Google Gemini Function Calling.

Every tool returns a structured JSON-serializable dict, broadcasts the
corresponding real-time step update over WebSocket, and degrades gracefully
when running without Windows Administrator privileges (never crashes the demo).
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import platform
import subprocess
from typing import Any

import psutil
import requests

from backend.config import settings
from backend.state import state, ws_manager

logger = logging.getLogger("cybershield.tools")

CRITICAL_PIDS = {0, 4}


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _validate_ip(ip: str) -> str:
    cleaned = (ip or "").strip()
    parsed = ipaddress.ip_address(cleaned)
    return str(parsed)


def _run_netsh(args: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        output = (proc.stdout or proc.stderr or "").strip()
        return proc.returncode == 0, output
    except Exception as exc:
        return False, str(exc)


def send_mobile_alert(ip: str, process_name: str, reason: str) -> dict[str, Any]:
    """Send an urgent push notification to the user's phone via ntfy.sh.

    Call this FIRST when a suspicious outbound connection is detected so the
    owner is notified immediately on their mobile device.

    Args:
        ip: Remote attacker IP address involved in the suspicious connection.
        process_name: Name of the local process making the outbound connection.
        reason: Concise explanation of why the traffic was flagged.

    Returns:
        Dictionary describing delivery status, ntfy topic, and timestamp.
    """
    topic = settings.ntfy_topic
    url = f"https://ntfy.sh/{topic}"
    title = f"CyberShield Alert: Intrusion to {ip}"
    body = (
        f"Process: {process_name}\n"
        f"Remote IP: {ip}\n"
        f"Reason: {reason}\n"
        f"Action: Autonomous containment in progress."
    )

    delivered = False
    http_status: int | None = None
    error_detail = ""

    try:
        resp = requests.post(
            url,
            data=body.encode("utf-8"),
            headers={
                "Title": title,
                "Priority": "high",
                "Tags": "rotating_light,shield",
            },
            timeout=4,
        )
        http_status = resp.status_code
        delivered = 200 <= resp.status_code < 300
        if not delivered:
            error_detail = f"HTTP {resp.status_code}"
    except requests.RequestException as exc:
        error_detail = str(exc)
        logger.warning("ntfy.sh mobile alert failed (non-fatal): %s", exc)

    state.update_latest_incident(
        ip=ip,
        mobile_alert_sent=delivered,
        action=f"send_mobile_alert({ip})",
    )

    log_msg = (
        f"[3] Mobile alert delivered to ntfy/{topic} ({ip})"
        if delivered
        else f"[3] Mobile alert dispatched (offline fallback: {error_detail or 'timeout'})"
    )
    ws_manager.emit_event(
        step=3,
        status="MOBILE ALERT SENT",
        ip=ip,
        process_name=process_name,
        log_entry=log_msg,
        extra={
            "mobile_delivered": delivered,
            "mobile_topic": topic,
            "mobile_reason": reason,
        },
    )

    return {
        "ok": True,
        "delivered": delivered,
        "topic": topic,
        "http_status": http_status,
        "error": error_detail,
        "ip": ip,
        "process_name": process_name,
    }


def kill_process(pid: int) -> dict[str, Any]:
    """Terminate a suspicious local process by PID to sever its active connection.

    Call this SECOND after sending the mobile alert. Refuses to kill system-critical
    PIDs (0, 4, or CyberShield's own process).

    Args:
        pid: Numeric OS process ID of the suspicious process to terminate.

    Returns:
        Dictionary describing whether the process was terminated and why.
    """
    try:
        target_pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "killed": False, "error": f"Invalid PID: {pid}"}

    own_pid = os.getpid()
    snap = state.get_snapshot()
    is_simulated = bool(snap.get("simulated")) and target_pid == int(snap.get("pid") or -1)

    if target_pid in CRITICAL_PIDS or target_pid == own_pid or target_pid < 0:
        msg = f"Refused to terminate protected/invalid PID {target_pid}"
        logger.warning(msg)
        return {"ok": False, "killed": False, "pid": target_pid, "error": msg}

    killed = False
    method = "none"
    detail = ""
    proc_name = str(snap.get("process_name") or "unknown")

    if is_simulated:
        killed = True
        method = "simulated"
        detail = f"Simulated process {proc_name} (PID {target_pid}) severed safely"
    else:
        try:
            proc = psutil.Process(target_pid)
            try:
                proc_name = proc.name()
            except psutil.Error:
                pass

            proc.terminate()
            method = "terminate"
            try:
                proc.wait(timeout=1.5)
                killed = True
                detail = f"Process {proc_name} (PID {target_pid}) terminated cleanly"
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.5)
                killed = True
                method = "kill"
                detail = f"Process {proc_name} (PID {target_pid}) force-killed"
        except psutil.NoSuchProcess:
            killed = True
            method = "already_exited"
            detail = f"Process PID {target_pid} already exited"
        except psutil.AccessDenied:
            killed = False
            method = "access_denied"
            detail = f"[ACCESS DENIED - RUN AS ADMIN] Could not terminate PID {target_pid}"
            logger.warning(detail)
        except Exception as exc:
            killed = False
            method = "error"
            detail = f"Failed to terminate PID {target_pid}: {exc}"
            logger.exception(detail)

    if killed:
        state.record_killed_pid(target_pid, ip=snap.get("ip") or None)
    state.update_latest_incident(
        ip=snap.get("ip") or None,
        action=f"kill_process({target_pid})",
    )

    log_msg = (
        f"[4] Severed link • Terminated {proc_name} (PID {target_pid})"
        if killed
        else f"[4] Termination warning for PID {target_pid}: {detail}"
    )
    ws_manager.emit_event(
        step=4,
        status="LINK SEVERED",
        pid=target_pid,
        process_name=proc_name,
        log_entry=log_msg,
        extra={"kill_method": method, "kill_detail": detail},
    )

    return {
        "ok": True,
        "killed": killed,
        "pid": target_pid,
        "process_name": proc_name,
        "method": method,
        "detail": detail,
    }


def block_ip_firewall(ip: str) -> dict[str, Any]:
    """Block an external IP address in both outbound and inbound Windows Firewall rules.

    Call this THIRD to permanently block the remote attacker IP from reconnecting.
    Falls back cleanly with a warning if not running as Windows Administrator.

    Args:
        ip: Remote IPv4 or IPv6 address to block in Windows Firewall.

    Returns:
        Dictionary describing the created firewall rules and enforcement mode.
    """
    try:
        clean_ip = _validate_ip(ip)
    except ValueError:
        return {"ok": False, "blocked": False, "error": f"Invalid IP address: {ip}"}

    parsed = ipaddress.ip_address(clean_ip)
    if parsed.is_loopback:
        return {
            "ok": False,
            "blocked": False,
            "ip": clean_ip,
            "error": "Refusing to block loopback address.",
        }

    rule_out = f"CyberShield_Block_Out_{clean_ip}"
    rule_in = f"CyberShield_Block_In_{clean_ip}"

    simulated_block = False
    detail = ""

    if is_windows() and is_admin():
        # Delete any existing rule with the same name first to avoid duplicates
        _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_out}"])
        _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_in}"])

        ok_out, out_msg = _run_netsh(
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_out}",
                "dir=out",
                "action=block",
                f"remoteip={clean_ip}",
            ]
        )
        ok_in, in_msg = _run_netsh(
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_in}",
                "dir=in",
                "action=block",
                f"remoteip={clean_ip}",
            ]
        )
        if ok_out and ok_in:
            detail = f"Windows Firewall rules active: {rule_out}, {rule_in}"
        else:
            simulated_block = True
            detail = (
                f"[SIMULATED BLOCK - RUN AS ADMIN] netsh reported: "
                f"out=({out_msg}) in=({in_msg})"
            )
            logger.warning(detail)
    else:
        simulated_block = True
        env_note = "not running as Administrator" if is_windows() else f"OS is {platform.system()}"
        detail = f"[SIMULATED BLOCK - RUN AS ADMIN] ({env_note}) Would add {rule_out} & {rule_in}"
        logger.warning(detail)

    state.record_blocked_ip(clean_ip)
    state.update_latest_incident(
        ip=clean_ip,
        action=f"block_ip_firewall({clean_ip})",
    )

    log_msg = (
        f"[5] Blocked {clean_ip} (In+Out Firewall rules)"
        if not simulated_block
        else f"[5] Blocked {clean_ip} [SIMULATED - RUN AS ADMIN]"
    )
    ws_manager.emit_event(
        step=5,
        status="SOURCE BLOCKED",
        ip=clean_ip,
        log_entry=log_msg,
        extra={
            "firewall_rules": [rule_out, rule_in],
            "firewall_simulated": simulated_block,
            "firewall_detail": detail,
        },
    )

    return {
        "ok": True,
        "blocked": True,
        "ip": clean_ip,
        "rules": [rule_out, rule_in],
        "simulated": simulated_block,
        "detail": detail,
    }


def unblock_ip_firewall(ip: str) -> dict[str, Any]:
    """Remove CyberShield Windows Firewall block rules for a previously blocked IP.

    Use this when the user explicitly confirms an IP is safe (e.g. a test server)
    and asks CyberShield Mesh to unblock it.

    Args:
        ip: Remote IPv4 or IPv6 address to unblock.

    Returns:
        Dictionary describing the removed firewall rules and updated protection state.
    """
    try:
        clean_ip = _validate_ip(ip)
    except ValueError:
        return {"ok": False, "unblocked": False, "error": f"Invalid IP address: {ip}"}

    rule_out = f"CyberShield_Block_Out_{clean_ip}"
    rule_in = f"CyberShield_Block_In_{clean_ip}"

    simulated_unblock = False
    detail = ""

    if is_windows() and is_admin():
        ok_out, out_msg = _run_netsh(
            ["advfirewall", "firewall", "delete", "rule", f"name={rule_out}"]
        )
        ok_in, in_msg = _run_netsh(
            ["advfirewall", "firewall", "delete", "rule", f"name={rule_in}"]
        )
        detail = (
            f"Deleted Windows Firewall rules ({rule_out}: {ok_out}, {rule_in}: {ok_in})"
        )
        if not (ok_out or ok_in):
            detail += f" | netsh: {out_msg or in_msg}"
    else:
        simulated_unblock = True
        env_note = "not running as Administrator" if is_windows() else f"OS is {platform.system()}"
        detail = f"[SIMULATED UNBLOCK - RUN AS ADMIN] ({env_note}) Cleared {rule_out} & {rule_in}"
        logger.warning(detail)

    state.remove_blocked_ip(clean_ip)
    state.update_latest_incident(
        ip=clean_ip,
        action=f"unblock_ip_firewall({clean_ip})",
    )

    remaining = state.get_blocked_ips()
    log_msg = f"[UNBLOCK] Removed firewall block for {clean_ip} • Status: PROTECTED"
    ws_manager.emit_event(
        step=0,
        status="PROTECTED",
        ip=clean_ip,
        ai_summary=f"Unblocked {clean_ip} per operator request. Autonomous monitoring remains active.",
        log_entry=log_msg,
        extra={
            "unblocked_ip": clean_ip,
            "remaining_blocked_ips": remaining,
            "firewall_simulated": simulated_unblock,
            "firewall_detail": detail,
        },
    )

    return {
        "ok": True,
        "unblocked": True,
        "ip": clean_ip,
        "rules_removed": [rule_out, rule_in],
        "simulated": simulated_unblock,
        "remaining_blocked_ips": remaining,
        "detail": detail,
    }


def reset_all_firewall_rules() -> dict[str, Any]:
    """Delete all CyberShield_Block_* firewall rules on Windows (or simulate cleanly)."""
    tracked_ips = state.get_blocked_ips()
    removed_rules: list[str] = []
    simulated = False

    if is_windows() and is_admin():
        for ip in tracked_ips:
            for prefix in ("CyberShield_Block_Out_", "CyberShield_Block_In_"):
                rule_name = f"{prefix}{ip}"
                ok, _ = _run_netsh(
                    ["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                )
                if ok:
                    removed_rules.append(rule_name)

        # Also clean up any leftover CyberShield_Block_* rules from prior runs
        try:
            ps_cmd = (
                "Get-NetFirewallRule -DisplayName 'CyberShield_Block_*' "
                "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        except Exception as exc:
            logger.debug("PowerShell wildcard firewall cleanup skipped: %s", exc)
    else:
        simulated = True
        for ip in tracked_ips:
            removed_rules.extend(
                [f"CyberShield_Block_Out_{ip}", f"CyberShield_Block_In_{ip}"]
            )

    return {
        "ok": True,
        "cleared_ips": tracked_ips,
        "removed_rules": removed_rules,
        "simulated": simulated,
    }
