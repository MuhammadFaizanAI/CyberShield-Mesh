"""Background psutil TCP socket monitor (1-second polling loop).

Detects outbound ESTABLISHED connections to watch ports or initiated by known
suspicious/demo binaries, broadcasts Step 1 (Intrusion Detected), and triggers
the Gemini autonomous defense agent.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from typing import Any, Optional

import psutil

from backend.agent import analyze_and_defend
from backend.config import settings
from backend.state import state, utc_now_iso, ws_manager

logger = logging.getLogger("cybershield.monitor")


def _is_ignored_ip(ip: str) -> bool:
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_unspecified
    except ValueError:
        return True


def _scan_suspicious_connections() -> list[dict[str, Any]]:
    """Run in a worker thread to inspect live ESTABLISHED IPv4/IPv6 TCP sockets."""
    findings: list[dict[str, Any]] = []
    own_pid = os.getpid()

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        logger.debug("psutil.net_connections raised AccessDenied; retrying next tick.")
        return findings
    except Exception as exc:
        logger.warning("Failed to poll net_connections: %s", exc)
        return findings

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.raddr:
            continue

        remote_ip = getattr(conn.raddr, "ip", None)
        remote_port = getattr(conn.raddr, "port", 0)
        if not remote_ip or _is_ignored_ip(remote_ip):
            continue

        pid = conn.pid
        if not pid or pid == own_pid:
            continue

        if state.is_pair_in_cooldown(pid, remote_ip, settings.incident_cooldown_sec):
            continue

        process_name = "unknown"
        try:
            process_name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = "unknown"

        port_flagged = int(remote_port) in settings.watch_ports
        proc_flagged = process_name.lower() in settings.suspicious_processes

        if not (port_flagged or proc_flagged):
            continue

        local_port = getattr(conn.laddr, "port", 0) if conn.laddr else 0
        findings.append(
            {
                "remote_ip": str(remote_ip),
                "remote_port": int(remote_port),
                "local_port": int(local_port),
                "pid": int(pid),
                "process_name": process_name,
                "timestamp": utc_now_iso(),
                "simulated": False,
                "trigger_reason": (
                    f"watch_port:{remote_port}" if port_flagged else f"suspicious_binary:{process_name}"
                ),
            }
        )

    return findings


class NetworkMonitor:
    """Asyncio background monitor started and stopped by FastAPI lifespan."""

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task[None]] = None
        self._defense_tasks: set[asyncio.Task[Any]] = set()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.is_running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name="cybershield-net-monitor")
        logger.info(
            "Network monitor started (interval=%.1fs, watch_ports=%s)",
            settings.monitor_interval_sec,
            sorted(settings.watch_ports),
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

    def dispatch_intrusion(self, event: dict[str, Any]) -> asyncio.Task[Any]:
        """Record incident, broadcast Step 1, and launch autonomous Gemini defense."""
        pid = int(event.get("pid", 0) or 0)
        remote_ip = str(event.get("remote_ip", ""))
        remote_port = int(event.get("remote_port", 0) or 0)
        process_name = str(event.get("process_name", "unknown"))

        if not event.get("simulated"):
            state.mark_pair_handled(pid, remote_ip)

        state.start_incident(event)

        ws_manager.emit_event(
            step=1,
            status="INTRUSION DETECTED",
            ip=remote_ip,
            port=remote_port,
            pid=pid,
            process_name=process_name,
            ai_summary=f"Outbound TCP connection detected from {process_name} (PID {pid}) to {remote_ip}:{remote_port}.",
            log_entry=f"[1] Intrusion detected: {process_name} (PID {pid}) -> {remote_ip}:{remote_port}",
            extra={"simulated": bool(event.get("simulated", False))},
        )

        task = asyncio.create_task(
            self._safe_defend(event),
            name=f"defend-{remote_ip}-{pid}",
        )
        self._defense_tasks.add(task)
        task.add_done_callback(self._defense_tasks.discard)
        return task

    async def _safe_defend(self, event: dict[str, Any]) -> None:
        try:
            await analyze_and_defend(event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Unhandled error in analyze_and_defend: %s", exc)

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                findings = await asyncio.to_thread(_scan_suspicious_connections)
                for event in findings:
                    logger.warning(
                        "Suspicious outbound connection detected: %s (PID %s) -> %s:%s",
                        event["process_name"],
                        event["pid"],
                        event["remote_ip"],
                        event["remote_port"],
                    )
                    self.dispatch_intrusion(event)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("NetworkMonitor loop iteration error: %s", exc)

            await asyncio.sleep(settings.monitor_interval_sec)


network_monitor = NetworkMonitor()
