"""Real OS-level and Alert action tools for Google Gemini Function Calling & Operator Console.

All actions operate on real OS processes, real Windows Firewall (`netsh`) /
Linux firewall rules (with safe non-Admin fallback), and real Gmail API + ntfy
notifications delivered to the signed-in Google account.
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import platform
import shutil
import subprocess
from typing import Any

import psutil

from backend.alerts import dispatch_user_alert
from backend.db import db
from backend.state import state, ws_manager

logger = logging.getLogger("cybershield.tools")

CRITICAL_PIDS = {0, 4}


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


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


def validate_ip(ip: str) -> str:
    cleaned = (ip or "").strip()
    return str(ipaddress.ip_address(cleaned))


def _run_cmd(cmd: list[str], timeout: int = 8) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (proc.stdout or proc.stderr or "").strip()
        return proc.returncode == 0, output
    except Exception as exc:
        return False, str(exc)


def send_user_alert(ip: str, process_name: str, reason: str) -> dict[str, Any]:
    """Send an urgent real-time security alert to the signed-in user's Google account (Gmail) and optional ntfy push.

    Call this FIRST when evaluating a suspicious outbound connection so the
    device owner receives immediate notification on their phone/Gmail.

    Args:
        ip: Remote external IP address involved in the suspicious connection.
        process_name: Local process name making the suspicious outbound connection.
        reason: Concise explanation of why the connection was flagged as suspicious.

    Returns:
        Dictionary with Gmail and ntfy delivery receipts.
    """
    active_id = state.get_active_incident_id()
    inc = db.get_incident_by_id(active_id) if active_id else None
    port = int(inc.get("remote_port", 0)) if inc else 0
    pid = int(inc.get("pid", 0)) if inc else 0

    receipt = dispatch_user_alert(
        ip=ip,
        port=port,
        pid=pid,
        process_name=process_name,
        reason=reason,
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
            "warn",
            f"Security alert delivered via {', '.join(channels)} for {process_name} -> {ip}",
        )
    else:
        err = gmail_res.get("error") or ntfy_res.get("error") or "No alert channel active"
        ws_manager.emit_activity(
            "warn",
            f"Alert attempted for {ip} ({err})",
        )

    ws_manager.emit_incident_update(updated)
    return {
        "ok": True,
        "ip": ip,
        "process_name": process_name,
        **receipt,
    }


def kill_process(pid: int) -> dict[str, Any]:
    """Terminate a suspicious local OS process by PID to immediately sever its live network socket.

    Call this SECOND after alerting the user. Refuses to kill system-critical PIDs
    (0, 4, or CyberShield Mesh's own process).

    Args:
        pid: Numeric OS process ID to terminate.

    Returns:
        Dictionary describing whether the process was terminated.
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

        proc.terminate()
        method = "terminate"
        try:
            proc.wait(timeout=1.5)
            killed = True
            detail = f"Terminated {proc_name} (PID {target_pid}) cleanly."
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
        detail = f"[ACCESS DENIED - RUN AS ADMIN] Unable to terminate PID {target_pid}."
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
        "success" if killed else "error",
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
    """Block an external IP address bidirectionally (outbound + inbound) in the OS firewall.

    Call this THIRD to permanently block the attacker IP. Checks the Trusted IP
    Whitelist first and degrades safely if not running with Administrator privileges.

    Args:
        ip: Remote IPv4 or IPv6 address to block.
        reason: Short explanation of why the IP is being blocked.
        process_name: Optional offending process name associated with the block.

    Returns:
        Dictionary describing created firewall rules and enforcement status.
    """
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
        msg = f"Skipped blocking {clean_ip} because it is on the Trusted IP Whitelist."
        ws_manager.emit_activity("info", msg)
        return {"ok": False, "blocked": False, "ip": clean_ip, "error": msg}

    rule_out = f"CyberShield_Block_Out_{clean_ip}"
    rule_in = f"CyberShield_Block_In_{clean_ip}"
    simulated = False
    detail = ""

    if is_windows() and is_admin():
        remote_spec = f"{clean_ip}/32" if parsed.version == 4 else f"{clean_ip}/128"
        _run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"])
        _run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"])
        ok_out, out_msg = _run_cmd(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_out}",
                "dir=out",
                "action=block",
                f"remoteip={remote_spec}",
            ]
        )
        ok_in, in_msg = _run_cmd(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_in}",
                "dir=in",
                "action=block",
                f"remoteip={remote_spec}",
            ]
        )
        if ok_out and ok_in:
            detail = f"Windows Firewall single-host ({remote_spec}) rules active: {rule_out}, {rule_in}"
        else:
            simulated = True
            detail = f"[SIMULATED BLOCK - RUN AS ADMIN] netsh: out=({out_msg}) in=({in_msg})"
            logger.warning(detail)
    elif is_linux() and is_admin() and shutil.which("iptables") and parsed.version == 4:
        ok_out, out_msg = _run_cmd(
            ["iptables", "-I", "OUTPUT", "-d", clean_ip, "-j", "DROP"]
        )
        ok_in, in_msg = _run_cmd(
            ["iptables", "-I", "INPUT", "-s", clean_ip, "-j", "DROP"]
        )
        if ok_out and ok_in:
            detail = f"Linux iptables DROP rules active (INPUT + OUTPUT) for {clean_ip}"
        else:
            simulated = True
            detail = f"[SIMULATED BLOCK - RUN AS ROOT] iptables: {out_msg} {in_msg}".strip()
    else:
        simulated = True
        env_note = (
            "not running as Administrator"
            if is_windows()
            else f"{platform.system()} (run as root for iptables or Windows Admin for netsh)"
        )
        detail = f"[RECORDED BLOCK - RUN AS ADMIN FOR OS FIREWALL] ({env_note}) {rule_out} & {rule_in}"
        logger.warning(detail)

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
        ip_blocked=True,
        status="BLOCKED",
        action=f"block_ip_firewall({clean_ip})",
    )

    ws_manager.emit_activity(
        "success",
        f"Blocked {clean_ip} ({'OS Firewall Active' if not simulated else 'Policy Recorded — Run as Admin'})",
    )
    ws_manager.emit_firewall_update()
    ws_manager.emit_incident_update(updated)

    return {
        "ok": True,
        "blocked": True,
        "ip": clean_ip,
        "rules": [rule_out, rule_in],
        "simulated": simulated,
        "detail": detail,
        "record": record,
    }


def unblock_ip_firewall(ip: str) -> dict[str, Any]:
    """Remove CyberShield OS firewall block rules for a previously blocked IP address.

    Call this when the operator confirms an IP is trusted or asks to unblock it.

    Args:
        ip: Remote IPv4 or IPv6 address to unblock.

    Returns:
        Dictionary describing the removed firewall rules and updated blocked list.
    """
    try:
        clean_ip = validate_ip(ip)
    except ValueError:
        return {"ok": False, "unblocked": False, "error": f"Invalid IP address: {ip}"}

    parsed = ipaddress.ip_address(clean_ip)
    rule_out = f"CyberShield_Block_Out_{clean_ip}"
    rule_in = f"CyberShield_Block_In_{clean_ip}"
    simulated = False
    detail = ""

    if is_windows() and is_admin():
        ok_out, out_msg = _run_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"]
        )
        ok_in, in_msg = _run_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"]
        )
        detail = f"Removed Windows Firewall rules ({rule_out}: {ok_out}, {rule_in}: {ok_in})"
        if not (ok_out or ok_in) and (out_msg or in_msg):
            detail += f" | {out_msg or in_msg}"
    elif is_linux() and is_admin() and shutil.which("iptables") and parsed.version == 4:
        _run_cmd(["iptables", "-D", "OUTPUT", "-d", clean_ip, "-j", "DROP"])
        _run_cmd(["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"])
        detail = f"Removed Linux iptables DROP rules for {clean_ip}"
    else:
        simulated = True
        detail = f"Removed {clean_ip} from CyberShield block policy."

    db.remove_blocked_ip(clean_ip)
    updated = db.update_incident(
        ip=clean_ip,
        ip_blocked=False,
        status="UNBLOCKED",
        action=f"unblock_ip_firewall({clean_ip})",
    )

    ws_manager.emit_activity("info", f"Unblocked {clean_ip} and removed firewall rules.")
    ws_manager.emit_firewall_update()
    ws_manager.emit_incident_update(updated)

    return {
        "ok": True,
        "unblocked": True,
        "ip": clean_ip,
        "rules_removed": [rule_out, rule_in],
        "simulated": simulated,
        "detail": detail,
        "remaining_blocked_ips": [r["ip"] for r in db.list_blocked_ips()],
    }


def reset_all_firewall_rules() -> dict[str, Any]:
    """Delete all CyberShield_Block_* firewall rules and clear blocked IP records."""
    blocked_rows = db.list_blocked_ips()
    cleared_ips = [r["ip"] for r in blocked_rows]

    for ip in cleared_ips:
        if is_windows() and is_admin():
            _run_cmd(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=CyberShield_Block_Out_{ip}"]
            )
            _run_cmd(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=CyberShield_Block_In_{ip}"]
            )
        elif is_linux() and is_admin() and shutil.which("iptables"):
            try:
                if ipaddress.ip_address(ip).version == 4:
                    _run_cmd(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
                    _run_cmd(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            except ValueError:
                pass

    if is_windows() and is_admin():
        ps_cmd = (
            "Get-NetFirewallRule -DisplayName 'CyberShield_Block_*' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue"
        )
        _run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])

    db.clear_blocked_ips()
    state.clear_cooldowns()
    ws_manager.emit_activity(
        "info",
        f"Cleared all CyberShield firewall rules ({len(cleared_ips)} IP(s) unblocked).",
    )
    ws_manager.emit_firewall_update()
    return {"ok": True, "cleared_ips": cleared_ips}
