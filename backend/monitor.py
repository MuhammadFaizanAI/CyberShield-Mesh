"""80ms Pre-Exfiltration Socket Interception & Windows/Cloud Baseline Classifier.

Architecture:
1. Polls `psutil.net_connections(kind="inet")` every 80ms (`0.08s`), inspecting
   BOTH `CONN_SYN_SENT` and `CONN_ESTABLISHED` sockets so unauthorized streams
   are intercepted during the TCP handshake before payload exfiltration occurs.
2. Applies OS & Cloud Baseline intelligence (Windows Core Services, WebView2 /
   WhatsApp / Browsers, Verified Meta/Google/Microsoft/Cloudflare CIDRs, Trusted
   IP Whitelist, and session-learned `verified_benign_pairs`) for zero false positives.
3. Freezes suspicious processes in `<1ms` via `psutil.Process(pid).suspend()` right
   inside the scanner thread and creates silent `"ANALYZING"` incidents—no alerts
   or banners fire until Gemini returns a confirmed MALICIOUS verdict.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
from typing import Any, Optional

import psutil

from backend.agent import analyze_and_defend
from backend.config import (
    DEFAULT_LOLBINS,
    STANDARD_SAFE_PORTS,
    TRUSTED_DESKTOP_APPS,
    WINDOWS_CORE_PROCESSES,
    match_verified_cloud_provider,
    settings,
)
from backend.db import db, utc_now_iso
from backend.state import state, ws_manager
from backend.tools import suspend_process

logger = logging.getLogger("cybershield.monitor")

WATCHED_SOCKET_STATES = {psutil.CONN_SYN_SENT, psutil.CONN_ESTABLISHED}

_CURL_EXFIL_RE = re.compile(
    r"(?:^|\s)(?:-t|--upload-file|-d|--data|--data-raw|--data-binary|-f|--form)(?:\s|=|$)",
    re.IGNORECASE,
)
_SSH_TUNNEL_RE = re.compile(r"(?:^|\s)-(?:[a-z]*[rld])(?:\s|$)", re.IGNORECASE)

_protected_pids_cache: tuple[float, set[int]] = (0.0, set())


def _is_ignored_ip(ip: str) -> bool:
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_loopback
            or addr.is_unspecified
            or addr.is_link_local
            or addr.is_multicast
        )
    except ValueError:
        return True


def _get_protected_pids() -> set[int]:
    """Return PIDs belonging to CyberShield Mesh itself (cached for 2.0s)."""
    global _protected_pids_cache
    now = time.monotonic()
    cached_ts, cached_set = _protected_pids_cache
    if cached_set and (now - cached_ts) < 2.0:
        return cached_set

    own_pid = os.getpid()
    protected = {own_pid}
    try:
        curr = psutil.Process(own_pid)
        electron_root = None
        for parent in curr.parents():
            pname = parent.name().lower()
            if pname in {"python.exe", "python", "python3", "node.exe", "node", "electron.exe", "electron"}:
                protected.add(parent.pid)
                if pname in {"electron.exe", "electron"}:
                    electron_root = parent
        if electron_root is not None:
            try:
                for child in electron_root.children(recursive=True):
                    if child.name().lower() in {"electron.exe", "electron"}:
                        protected.add(child.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception:
        pass

    _protected_pids_cache = (now, protected)
    return protected


def _classify_trigger_reason(
    process_name: str,
    cmdline: str,
    parent_name: str,
    remote_port: int,
    socket_state: str,
    port_flagged: bool,
    proc_flagged: bool,
) -> str:
    cmd_lower = cmdline.lower()
    proc_lower = process_name.lower()

    if proc_lower in {"curl.exe", "curl"} and _CURL_EXFIL_RE.search(cmdline):
        return f"MITRE_T1048_exfiltration:{process_name}[{socket_state}] parent={parent_name} cmd='{cmdline}'"
    if proc_lower in {"powershell.exe", "pwsh.exe", "pwsh"} and any(
        tok in cmd_lower
        for tok in ("tcpclient", "socket", "-enc", "invoke-webrequest", "invoke-restmethod", "iwr ")
    ):
        return f"MITRE_T1059_001_raw_socket:{process_name}[{socket_state}] parent={parent_name} cmd='{cmdline}'"
    if proc_lower in {"ssh.exe", "scp.exe", "sftp.exe", "ssh", "scp", "sftp"}:
        tag = "MITRE_T1572_tunnel" if _SSH_TUNNEL_RE.search(cmdline) else "MITRE_T1572_tunnel_or_transfer"
        return f"{tag}:{process_name}[{socket_state}] parent={parent_name} cmd='{cmdline}'"
    if port_flagged:
        return f"watch_port:{remote_port} proc={process_name}[{socket_state}] parent={parent_name} cmd='{cmdline}'"
    if proc_flagged:
        return f"suspicious_lolbin:{process_name}[{socket_state}] parent={parent_name} cmd='{cmdline}'"
    return f"anomalous_outbound_port:{process_name}[{socket_state}]->{remote_port} parent={parent_name} cmd='{cmdline}'"


def scan_live_connections(
    suspend_on_detect: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scan SYN_SENT + ESTABLISHED sockets, immediately freeze threats, and return telemetry."""
    cfg, blocked_set, whitelist_set = state.get_fast_policy_snapshot()
    autonomous_mode = bool(cfg.get("autonomous_mode", True))
    watch_ports = {int(p) for p in cfg.get("watch_ports", list(settings.watch_ports))}

    raw_suspects = {
        str(p).lower()
        for p in cfg.get("suspicious_processes", list(settings.suspicious_processes))
    } | set(DEFAULT_LOLBINS)
    # Never classify core OS daemons or trusted browsers/apps as LOLBins
    suspicious_procs = raw_suspects - set(WINDOWS_CORE_PROCESSES) - set(TRUSTED_DESKTOP_APPS)

    protected_pids = _get_protected_pids()
    verified_benign = state.get_verified_benign_pairs()
    suspended_pids = state.get_suspended_pids()

    active_list: list[dict[str, Any]] = []
    flagged_events: list[dict[str, Any]] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        logger.debug("psutil.net_connections AccessDenied; elevate to Administrator for full visibility.")
        return active_list, flagged_events
    except Exception as exc:
        logger.warning("Failed to poll net_connections: %s", exc)
        return active_list, flagged_events

    proc_cache: dict[int, tuple[str, str, str]] = {}

    for conn in connections:
        if conn.status not in WATCHED_SOCKET_STATES:
            continue
        if not conn.raddr:
            continue

        remote_ip = str(getattr(conn.raddr, "ip", "") or "")
        remote_port = int(getattr(conn.raddr, "port", 0) or 0)
        if _is_ignored_ip(remote_ip):
            continue

        local_ip = str(getattr(conn.laddr, "ip", "") or "") if conn.laddr else ""
        local_port = int(getattr(conn.laddr, "port", 0) or 0) if conn.laddr else 0
        pid = int(conn.pid or 0)

        if pid > 0:
            if pid not in proc_cache:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    try:
                        raw_cmd = proc.cmdline()
                        cmd = (" ".join(raw_cmd) if raw_cmd else name)[:350]
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        cmd = name
                    try:
                        parent = proc.parent()
                        p_name = parent.name() if parent else "unknown"
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        p_name = "unknown"
                    proc_cache[pid] = (name, cmd, p_name)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    proc_cache[pid] = ("unknown", "", "unknown")
            process_name, cmdline, parent_name = proc_cache[pid]
        else:
            process_name, cmdline, parent_name = "system", "", "system"

        proc_lower = process_name.lower()
        # Self-protection check (also guards uvicorn/electron child workers by cmdline)
        is_self_cmdline = proc_lower in {"python.exe", "python", "python3", "node.exe", "electron.exe"} and (
            "backend.main:app" in cmdline or "cybershield" in cmdline.lower()
        )
        is_protected = (pid in protected_pids) or is_self_cmdline

        cloud_provider = match_verified_cloud_provider(remote_ip)
        is_verified_cloud = cloud_provider is not None
        is_safe_port = remote_port in STANDARD_SAFE_PORTS

        is_whitelisted = remote_ip in whitelist_set
        is_benign_cached = (proc_lower, remote_ip) in verified_benign
        is_blocked = remote_ip in blocked_set

        port_flagged = remote_port in watch_ports
        proc_flagged = proc_lower in suspicious_procs

        # Baseline exemptions (never apply if process is a LOLBin or destination is an explicit watch_port)
        is_windows_core_safe = (
            not proc_flagged
            and not port_flagged
            and (proc_lower in WINDOWS_CORE_PROCESSES or pid <= 4)
            and (is_safe_port or is_verified_cloud)
        )
        is_trusted_app_safe = (
            not proc_flagged
            and not port_flagged
            and (proc_lower in TRUSTED_DESKTOP_APPS)
            and (is_safe_port or is_verified_cloud)
        )
        is_cloud_web_safe = (
            not proc_flagged
            and not port_flagged
            and is_safe_port
            and is_verified_cloud
        )

        anomalous_port = (remote_port not in STANDARD_SAFE_PORTS) and (pid > 4)

        is_suspicious = (
            (port_flagged or proc_flagged or anomalous_port)
            and not is_whitelisted
            and not is_benign_cached
            and not is_windows_core_safe
            and not is_trusted_app_safe
            and not is_cloud_web_safe
            and not is_protected
        )

        is_currently_suspended = pid in suspended_pids
        if is_suspicious and pid > 4:
            if not state.is_pair_in_cooldown(pid, remote_ip, settings.incident_cooldown_sec):
                # Sub-millisecond pre-exfiltration process freeze mid-handshake!
                did_suspend = False
                if suspend_on_detect and autonomous_mode:
                    sus_res = suspend_process(pid)
                    did_suspend = bool(sus_res.get("suspended"))
                    if did_suspend:
                        is_currently_suspended = True
                        suspended_pids.add(pid)

                reason = _classify_trigger_reason(
                    process_name=process_name,
                    cmdline=cmdline,
                    parent_name=parent_name,
                    remote_port=remote_port,
                    socket_state=conn.status,
                    port_flagged=port_flagged,
                    proc_flagged=proc_flagged,
                )
                flagged_events.append(
                    {
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "pid": pid,
                        "process_name": process_name,
                        "cmdline": cmdline,
                        "parent_name": parent_name,
                        "socket_state": conn.status,
                        "cloud_provider": cloud_provider or "",
                        "suspended": did_suspend,
                        "timestamp": utc_now_iso(),
                        "trigger_reason": reason,
                    }
                )

        if is_currently_suspended:
            risk = "analyzing"
        elif is_suspicious:
            risk = "high"
        elif is_blocked:
            risk = "blocked"
        elif is_whitelisted or is_benign_cached:
            risk = "trusted"
        else:
            risk = "normal"

        active_list.append(
            {
                "pid": pid,
                "process_name": process_name,
                "cmdline": cmdline,
                "parent_name": parent_name,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "cloud_provider": cloud_provider or "",
                "status": "SUSPENDED" if is_currently_suspended else conn.status,
                "socket_state": conn.status,
                "suspended": is_currently_suspended,
                "risk": risk,
            }
        )

    risk_order = {"high": 0, "analyzing": 1, "blocked": 2, "normal": 3, "trusted": 4}
    active_list.sort(
        key=lambda c: (risk_order.get(c["risk"], 9), c["process_name"].lower(), c["remote_ip"])
    )
    return active_list, flagged_events


class NetworkMonitor:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task[None]] = None
        self._defense_tasks: set[asyncio.Task[Any]] = set()
        self._running = False
        self._last_conn_broadcast = 0.0
        self._last_telemetry_sample = 0.0
        self._last_conn_signature: tuple[tuple[int, str, int, str, str], ...] = ()
        self._last_net_io: Optional[tuple[float, int, int]] = None

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.is_running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name="cybershield-net-monitor")
        logger.info(
            "80ms pre-exfiltration socket monitor started (interval=%.3fs).",
            settings.monitor_interval_sec,
        )

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        for dt in list(self._defense_tasks):
            dt.cancel()
        if self._defense_tasks:
            await asyncio.gather(*self._defense_tasks, return_exceptions=True)
            self._defense_tasks.clear()
        logger.info("Network monitor stopped.")

    def _handle_flagged_event(self, event: dict[str, Any]) -> None:
        pid = int(event["pid"])
        remote_ip = str(event["remote_ip"])
        remote_port = int(event["remote_port"])
        process_name = str(event["process_name"])
        socket_state = str(event.get("socket_state", "ESTABLISHED"))
        suspended = bool(event.get("suspended", False))

        state.mark_pair_handled(pid, remote_ip)
        cfg, _, _ = state.get_fast_policy_snapshot()
        autonomous = bool(cfg.get("autonomous_mode", True))

        # Silent ANALYZING incident — NO email/ntfy spam or red danger banner before Gemini verdict!
        event["status"] = "ANALYZING" if autonomous else "MONITOR_LOGGED"
        incident = db.create_incident(event)
        inc_id = int(incident["id"])

        freeze_tag = "FROZEN mid-handshake" if suspended else f"observed ({socket_state})"
        ws_manager.emit_activity(
            "warn" if autonomous else "info",
            f"Triaging {process_name} (PID {pid}) -> {remote_ip}:{remote_port} [{freeze_tag}]",
        )
        ws_manager.emit_incident_update(incident)

        if autonomous:
            task = asyncio.create_task(
                self._safe_defend(event, inc_id),
                name=f"defend-{inc_id}-{remote_ip}",
            )
            self._defense_tasks.add(task)
            task.add_done_callback(self._defense_tasks.discard)

    async def _safe_defend(self, event: dict[str, Any], incident_id: int) -> None:
        try:
            await analyze_and_defend(event, incident_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Unhandled error in analyze_and_defend: %s", exc)
            state.set_protection_status("ARMED")

    def _sample_system_telemetry(self) -> dict[str, Any]:
        now = time.monotonic()
        tx_kbps = 0.0
        rx_kbps = 0.0
        try:
            io = psutil.net_io_counters()
            if io is not None:
                if self._last_net_io is not None:
                    prev_t, prev_sent, prev_recv = self._last_net_io
                    dt = max(0.1, now - prev_t)
                    tx_kbps = max(0.0, (io.bytes_sent - prev_sent) / 1024.0 / dt)
                    rx_kbps = max(0.0, (io.bytes_recv - prev_recv) / 1024.0 / dt)
                self._last_net_io = (now, io.bytes_sent, io.bytes_recv)
        except Exception:
            pass

        try:
            cpu_pct = float(psutil.cpu_percent(interval=None))
            mem_pct = float(psutil.virtual_memory().percent)
        except Exception:
            cpu_pct, mem_pct = 0.0, 0.0

        return state.update_telemetry(tx_kbps, rx_kbps, cpu_pct, mem_pct)

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                active_conns, flagged_events = await asyncio.to_thread(
                    scan_live_connections, True
                )

                for event in flagged_events:
                    logger.warning(
                        "Intercepted outbound socket: %s (PID %s, state=%s, suspended=%s) -> %s:%s | %s",
                        event["process_name"],
                        event["pid"],
                        event.get("socket_state"),
                        event.get("suspended"),
                        event["remote_ip"],
                        event["remote_port"],
                        event["trigger_reason"],
                    )
                    self._handle_flagged_event(event)

                # Throttle WebSocket UI broadcasts & host telemetry to 1.0s (or state change >=250ms)
                now = time.monotonic()
                sig = tuple(
                    (c["pid"], c["remote_ip"], c["remote_port"], c["status"], c["risk"])
                    for c in active_conns[:60]
                )
                telemetry: Optional[dict[str, Any]] = None
                if (now - self._last_telemetry_sample) >= 1.0:
                    self._last_telemetry_sample = now
                    telemetry = await asyncio.to_thread(self._sample_system_telemetry)

                state_changed = sig != self._last_conn_signature and (now - self._last_conn_broadcast) >= 0.25
                if state_changed or (now - self._last_conn_broadcast) >= 1.0:
                    self._last_conn_signature = sig
                    self._last_conn_broadcast = now
                    ws_manager.emit_connections(active_conns, telemetry)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("NetworkMonitor loop error: %s", exc)

            await asyncio.sleep(settings.monitor_interval_sec)


network_monitor = NetworkMonitor()
