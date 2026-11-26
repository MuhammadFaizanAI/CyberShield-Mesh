"""Thread-safe incident memory store and real-time WebSocket ConnectionManager.

Bridges synchronous Gemini Function Calling tool threads back to FastAPI's
asyncio event loop so dashboard clients see every step (1 -> 5) in real time.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import WebSocket

logger = logging.getLogger("cybershield.state")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_snapshot() -> dict[str, Any]:
    return {
        "step": 0,
        "status": "PROTECTED",
        "ip": "",
        "port": 0,
        "pid": 0,
        "process_name": "",
        "local_port": 0,
        "simulated": False,
        "ai_summary": "Autonomous endpoint monitor active. Watching outbound TCP sockets.",
        "log_entry": "System ready • Monitoring outbound TCP sockets",
        "blocked_ips": [],
        "logs": ["System ready • Monitoring outbound TCP sockets"],
        "timestamp": utc_now_iso(),
    }


class IncidentStore:
    """Thread-safe in-memory incident ledger, cooldown tracker, and UI snapshot."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._incidents: list[dict[str, Any]] = []
        self._blocked_ips: set[str] = set()
        self._killed_pids: set[int] = set()
        self._handled_pairs: dict[tuple[int, str], float] = {}
        self._snapshot: dict[str, Any] = _default_snapshot()
        self._next_incident_id = 1

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop = loop

    def get_event_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        with self._lock:
            return self._loop

    def is_pair_in_cooldown(self, pid: int, remote_ip: str, cooldown_sec: float) -> bool:
        now = time.monotonic()
        with self._lock:
            last_seen = self._handled_pairs.get((pid, remote_ip))
            if last_seen is None:
                return False
            if (now - last_seen) < cooldown_sec:
                return True
            self._handled_pairs.pop((pid, remote_ip), None)
            return False

    def mark_pair_handled(self, pid: int, remote_ip: str) -> None:
        with self._lock:
            self._handled_pairs[(pid, remote_ip)] = time.monotonic()

    def start_incident(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            incident = {
                "id": self._next_incident_id,
                "timestamp": event.get("timestamp") or utc_now_iso(),
                "remote_ip": str(event.get("remote_ip", "")),
                "remote_port": int(event.get("remote_port", 0) or 0),
                "local_port": int(event.get("local_port", 0) or 0),
                "pid": int(event.get("pid", 0) or 0),
                "process_name": str(event.get("process_name", "unknown")),
                "simulated": bool(event.get("simulated", False)),
                "status": "DETECTED",
                "mobile_alert_sent": False,
                "process_killed": False,
                "ip_blocked": False,
                "ai_summary": "",
                "actions": [],
            }
            self._next_incident_id += 1
            self._incidents.insert(0, incident)
            self._incidents = self._incidents[:50]

            self._snapshot.update(
                {
                    "ip": incident["remote_ip"],
                    "port": incident["remote_port"],
                    "local_port": incident["local_port"],
                    "pid": incident["pid"],
                    "process_name": incident["process_name"],
                    "simulated": incident["simulated"],
                    "ai_summary": "",
                    "timestamp": incident["timestamp"],
                }
            )
            return copy.deepcopy(incident)

    def update_latest_incident(
        self,
        ip: Optional[str] = None,
        action: Optional[str] = None,
        **fields: Any,
    ) -> None:
        with self._lock:
            target = None
            if ip:
                for inc in self._incidents:
                    if inc.get("remote_ip") == ip:
                        target = inc
                        break
            if target is None and self._incidents:
                target = self._incidents[0]
            if target is None:
                return
            for k, v in fields.items():
                target[k] = v
            if action:
                target.setdefault("actions", []).append(action)

    def record_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.add(ip)
            self._snapshot["blocked_ips"] = sorted(self._blocked_ips)
            self.update_latest_incident(ip=ip, ip_blocked=True, status="BLOCKED")

    def remove_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.discard(ip)
            self._snapshot["blocked_ips"] = sorted(self._blocked_ips)
            self.update_latest_incident(ip=ip, ip_blocked=False, status="UNBLOCKED")

    def record_killed_pid(self, pid: int, ip: Optional[str] = None) -> None:
        with self._lock:
            if pid > 0:
                self._killed_pids.add(pid)
            self.update_latest_incident(ip=ip, process_killed=True)

    def get_blocked_ips(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_ips)

    def get_killed_pids(self) -> list[int]:
        with self._lock:
            return sorted(self._killed_pids)

    def get_recent_incidents(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._incidents[:limit])

    def update_snapshot(
        self,
        *,
        step: Optional[int] = None,
        status: Optional[str] = None,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        ai_summary: Optional[str] = None,
        log_entry: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        with self._lock:
            if step is not None:
                self._snapshot["step"] = step
            if status is not None:
                self._snapshot["status"] = status
            if ip is not None:
                self._snapshot["ip"] = ip
            if port is not None:
                self._snapshot["port"] = port
            if pid is not None:
                self._snapshot["pid"] = pid
            if process_name is not None:
                self._snapshot["process_name"] = process_name
            if ai_summary is not None:
                self._snapshot["ai_summary"] = ai_summary
            if log_entry:
                self._snapshot["log_entry"] = log_entry
                logs: list[str] = self._snapshot.setdefault("logs", [])
                if not logs or logs[0] != log_entry:
                    logs.insert(0, log_entry)
                    self._snapshot["logs"] = logs[:6]

            self._snapshot["blocked_ips"] = sorted(self._blocked_ips)
            self._snapshot["timestamp"] = utc_now_iso()

            payload = copy.deepcopy(self._snapshot)
            if extra:
                payload.update(extra)
            return payload

    def get_snapshot(self) -> dict[str, Any]:
        with self._lock:
            snap = copy.deepcopy(self._snapshot)
            snap["blocked_ips"] = sorted(self._blocked_ips)
            return snap

    def reset(self) -> dict[str, Any]:
        with self._lock:
            self._incidents.clear()
            self._blocked_ips.clear()
            self._killed_pids.clear()
            self._handled_pairs.clear()
            self._snapshot = _default_snapshot()
            self._snapshot["log_entry"] = "Defense reset • Firewall rules cleared • Monitoring active"
            self._snapshot["logs"] = [self._snapshot["log_entry"]]
            return copy.deepcopy(self._snapshot)


class ConnectionManager:
    """Manages active dashboard WebSocket connections with thread-safe broadcast."""

    def __init__(self, store: IncidentStore) -> None:
        self._store = store
        self._connections: set[WebSocket] = set()
        self._lock = threading.RLock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        with self._lock:
            self._connections.add(websocket)
        snapshot = self._store.get_snapshot()
        snapshot["type"] = "snapshot"
        try:
            await websocket.send_json(snapshot)
        except Exception as exc:
            logger.debug("Initial snapshot send failed: %s", exc)
            self.disconnect(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        with self._lock:
            self._connections.discard(websocket)

    async def broadcast_async(self, payload: dict[str, Any]) -> None:
        with self._lock:
            clients = list(self._connections)
        if not clients:
            return

        stale: list[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)

    def broadcast(self, payload: dict[str, Any]) -> None:
        """Broadcast from either the asyncio loop or a worker thread."""
        loop = self._store.get_event_loop()
        if loop is None or loop.is_closed():
            return
        try:
            running_loop = asyncio.get_running_loop()
            if running_loop is loop:
                loop.create_task(self.broadcast_async(payload))
                return
        except RuntimeError:
            pass

        try:
            asyncio.run_coroutine_threadsafe(self.broadcast_async(payload), loop)
        except Exception as exc:
            logger.debug("Thread-safe WebSocket broadcast skipped: %s", exc)

    def emit_event(
        self,
        *,
        step: Optional[int] = None,
        status: Optional[str] = None,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        ai_summary: Optional[str] = None,
        log_entry: Optional[str] = None,
        event_type: str = "event",
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        payload = self._store.update_snapshot(
            step=step,
            status=status,
            ip=ip,
            port=port,
            pid=pid,
            process_name=process_name,
            ai_summary=ai_summary,
            log_entry=log_entry,
            extra=extra,
        )
        payload["type"] = event_type
        self.broadcast(payload)
        return payload


state = IncidentStore()
ws_manager = ConnectionManager(state)
