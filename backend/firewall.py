"""OS-level single-host (/32 & /128) firewall enforcement for Windows Defender Firewall & Linux iptables."""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import platform
import shutil
import subprocess
from typing import Any

logger = logging.getLogger("cybershield.firewall")


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
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0].strip()
    return str(ipaddress.ip_address(cleaned))


def run_firewall_cmd(cmd: list[str], timeout: int = 8) -> tuple[bool, str]:
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


def enforce_os_block_single_host(clean_ip: str) -> dict[str, Any]:
    """Apply bidirectional single-host (/32 or /128) OS firewall block rules."""
    parsed = ipaddress.ip_address(clean_ip)
    cidr_suffix = "/32" if parsed.version == 4 else "/128"
    remote_spec = f"{clean_ip}{cidr_suffix}"
    rule_out = f"CyberShield_Block_Out_{clean_ip}"
    rule_in = f"CyberShield_Block_In_{clean_ip}"
    simulated = False

    if is_windows() and is_admin():
        run_firewall_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"])
        run_firewall_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"])
        ok_out, out_msg = run_firewall_cmd(
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
        ok_in, in_msg = run_firewall_cmd(
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
            detail = f"Windows Defender Firewall single-host ({remote_spec}) rules active: {rule_out}, {rule_in}"
        else:
            simulated = True
            detail = f"[ELEVATE TO ADMIN] netsh failed: out=({out_msg}) in=({in_msg})"
            logger.warning(detail)
    elif is_linux() and is_admin() and shutil.which("iptables") and parsed.version == 4:
        ok_out, out_msg = run_firewall_cmd(
            ["iptables", "-I", "OUTPUT", "-d", remote_spec, "-j", "DROP"]
        )
        ok_in, in_msg = run_firewall_cmd(
            ["iptables", "-I", "INPUT", "-s", remote_spec, "-j", "DROP"]
        )
        if ok_out and ok_in:
            detail = f"Linux iptables single-host ({remote_spec}) DROP active"
        else:
            simulated = True
            detail = f"[ELEVATE TO ROOT] iptables: {out_msg} {in_msg}".strip()
    else:
        simulated = True
        env_note = (
            "Standard User Mode — elevate to Administrator to enforce Windows Firewall"
            if is_windows()
            else f"{platform.system()} non-root mode"
        )
        detail = f"[POLICY RECORDED — {env_note}] {rule_out} & {rule_in} ({remote_spec})"
        logger.warning(detail)

    return {
        "ip": clean_ip,
        "remote_spec": remote_spec,
        "rule_out": rule_out,
        "rule_in": rule_in,
        "simulated": simulated,
        "detail": detail,
    }


def remove_os_block_single_host(clean_ip: str) -> dict[str, Any]:
    """Delete CyberShield inbound+outbound single-host OS firewall rules."""
    parsed = ipaddress.ip_address(clean_ip)
    cidr_suffix = "/32" if parsed.version == 4 else "/128"
    remote_spec = f"{clean_ip}{cidr_suffix}"
    rule_out = f"CyberShield_Block_Out_{clean_ip}"
    rule_in = f"CyberShield_Block_In_{clean_ip}"
    simulated = False

    if is_windows() and is_admin():
        ok_out, out_msg = run_firewall_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"]
        )
        ok_in, in_msg = run_firewall_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"]
        )
        detail = f"Deleted Windows Firewall rules ({rule_out}: {ok_out}, {rule_in}: {ok_in})"
        if not (ok_out or ok_in) and (out_msg or in_msg):
            detail += f" | {out_msg or in_msg}"
    elif is_linux() and is_admin() and shutil.which("iptables") and parsed.version == 4:
        run_firewall_cmd(["iptables", "-D", "OUTPUT", "-d", remote_spec, "-j", "DROP"])
        run_firewall_cmd(["iptables", "-D", "INPUT", "-s", remote_spec, "-j", "DROP"])
        run_firewall_cmd(["iptables", "-D", "OUTPUT", "-d", clean_ip, "-j", "DROP"])
        run_firewall_cmd(["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"])
        detail = f"Removed Linux iptables DROP rules for {remote_spec}"
    else:
        simulated = True
        detail = f"Removed {clean_ip} from CyberShield block policy."

    return {
        "ip": clean_ip,
        "rules_removed": [rule_out, rule_in],
        "simulated": simulated,
        "detail": detail,
    }


def flush_all_os_blocks(tracked_ips: list[str]) -> None:
    """Remove all CyberShield_Block_* OS firewall rules."""
    for ip in tracked_ips:
        try:
            remove_os_block_single_host(validate_ip(ip))
        except ValueError:
            continue

    if is_windows() and is_admin():
        ps_cmd = (
            "Get-NetFirewallRule -DisplayName 'CyberShield_Block_*' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue"
        )
        run_firewall_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
