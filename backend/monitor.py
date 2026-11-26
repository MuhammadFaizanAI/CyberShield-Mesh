"""Real-time background psutil TCP socket monitor.

Continuously inspects live ESTABLISHED non-loopback TCP sockets every second:
1. Streams real active connections to the Endpoint Security Console over /ws.
2. Evaluates connections against dynamic Watch Ports & Suspicious Binaries while
   respecting the Trusted IP Whitelist.
3. Persists incidents to SQLite and triggers Gemini autonomous containment
   (or alert-only mode when Autonomous Mode is toggled off).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from typing import Any, Optional

import psutil

from backend.agent import analyze_and_defend
from backend.alerts import dispatch_user_alert
from backend.config import settings
from backend.db import db, utc_now_iso
from backend.state import state, ws_manager

logger = logging.getLogger("cybershield.monitor")


def _is_ignored_ip(ip: str) -> bool:
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_unspecified
    except ValueError:
        return True


def scan_live_connections() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (all_active_outbound_connections, newly_flagged_suspicious_events)."""
    cfg = db.get_settings()
    watch_ports = {int(p) for p in cfg.get("watch_ports", list(settings.watch_ports))}
    suspicious_procs = {
        str(p).lower()
        for p in cfg.get("suspicious_processes", list(settings.suspicious_processes))
    }
    blocked_set = {r["ip"] for r in db.list_blocked_ips()}
    whitelist_set = {r["ip"] for r in db.list_whitelist_ips()}

    own_pid = os.getpid()
    active_list: list[dict[str, Any]] = []
    flagged_events: list[dict[str, Any]] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        logger.debug("psutil.net_connections AccessDenied; run as Administrator for full PID visibility.")
        return active_list, flagged_events
    except Exception as exc:
        logger.warning("Failed to poll net_connections: %s", exc)
        return active_list, flagged_events

    proc_cache: dict[int, str] = {}

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED:
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
                    proc_cache[pid] = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    proc_cache[pid] = "unknown"
            process_name = proc_cache[pid]
        else:
            process_name = "system"

        is_whitelisted = remote_ip in whitelist_set
        is_blocked = remote_ip in blocked_set
        port_flagged = remote_port in watch_ports
        proc_flagged = process_name.lower() in suspicious_procs
        is_suspicious = (port_flagged or proc_flagged) and not is_whitelisted and pid != own_pid

        risk = "normal"
        if is_suspicious:
            risk = "high"
        elif is_blocked:
            risk = "blocked"
        elif is_whitelisted:
            risk = "trusted"

        entry = {
            "pid": pid,
            "process_name": process_name,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": conn.status,
            "risk": risk,
        }
        active_list.append(entry)

        if is_suspicious and pid > 0:
            if not state.is_pair_in_cooldown(pid, remote_ip, settings.incident_cooldown_sec):
                flagged_events.append(
                    {
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "pid": pid,
                        "process_name": process_name,
                        "timestamp": utc_now_iso(),
                        "trigger_reason": (
                            f"watch_port:{remote_port}"
                            if port_flagged
                            else f"suspicious_binary:{process_name}"
                        ),
                    }
                )

    # Sort high-risk connections to the top of the live table
    risk_order = {"high": 0, "blocked": 1, "normal": 2, "trusted": 3}
    active_list.sort(key=lambda c: (risk_order.get(c["risk"], 9), c["process_name"].lower(), c["remote_ip"]))
    return active_list, flagged_events


class NetworkMonitor:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task[None]] = None
        self._defense_tasks: set[asyncio.Task[Any]] = set()
        self._running = False
        self._last_conn_broadcast = 0.0
        self._last_conn_signature: tuple[tuple[int, str, int, str], ...] = ()
        self._last_net_io: Optional[tuple[float, int, int]] = None

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.is_running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name="cybershield-net-monitor")
        logger.info("Real-time psutil network monitor started.")

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

        state.mark_pair_handled(pid, remote_ip)
        cfg = db.get_settings()
        autonomous = bool(cfg.get("autonomous_mode", True))

        event["status"] = "DETECTED" if autonomous else "ALERT_ONLY"
        incident = db.create_incident(event)
        inc_id = int(incident["id"])

        ws_manager.emit_activity(
            "danger",
            f"Suspicious outbound connection: {process_name} (PID {pid}) -> {remote_ip}:{remote_port}",
        )
        ws_manager.emit_incident_update(incident)

        if autonomous:
            task = asyncio.create_task(
                self._safe_defend(event, inc_id),
                name=f"defend-{inc_id}-{remote_ip}",
            )
        else:
            task = asyncio.create_task(
                self._safe_alert_only(event, inc_id),
                name=f"alert-only-{inc_id}-{remote_ip}",
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

    async def _safe_alert_only(self, event: dict[str, Any], incident_id: int) -> None:
        try:
            receipt = await asyncio.to_thread(
                dispatch_user_alert,
                ip=event["remote_ip"],
                port=int(event["remote_port"]),
                pid=int(event["pid"]),
                process_name=event["process_name"],
                reason=f"Monitor-Only detection ({event['trigger_reason']}). Manual action required.",
            )
            gmail_res = receipt.get("gmail", {})
            ntfy_res = receipt.get("ntfy", {})
            updated = db.update_incident(
                incident_id,
                gmail_sent=bool(gmail_res.get("sent")),
                gmail_message_id=str(gmail_res.get("message_id") or ""),
                ntfy_sent=bool(ntfy_res.get("sent")),
                ai_summary="Autonomous Mode is paused. Owner alerted for manual review.",
                action="alert_only_notification",
            )
            ws_manager.emit_incident_update(updated)
        except Exception as exc:
            logger.exception("Monitor-only alert dispatch failed: %s", exc)

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
                active_conns, flagged_events = await asyncio.to_thread(scan_live_connections)
                telemetry = await asyncio.to_thread(self._sample_system_telemetry)

                sig = tuple(
                    (c["pid"], c["remote_ip"], c["remote_port"], c["risk"])
                    for c in active_conns[:50]
                )
                now = time.monotonic()
                if sig != self._last_conn_signature or (now - self._last_conn_broadcast) >= 1.5:
                    self._last_conn_signature = sig
                    self._last_conn_broadcast = now
                    ws_manager.emit_connections(active_conns, telemetry)

                for event in flagged_events:
                    logger.warning(
                        "Suspicious outbound connection detected: %s (PID %s) -> %s:%s",
                        event["process_name"],
                        event["pid"],
                        event["remote_ip"],
                        event["remote_port"],
                    )
                    self._handle_flagged_event(event)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("NetworkMonitor loop error: %s", exc)

            await asyncio.sleep(settings.monitor_interval_sec)


network_monitor = NetworkMonitor()
