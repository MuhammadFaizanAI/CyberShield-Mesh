"""Live runtime state, session learning cache, suspended-PID tracker, and WebSocket hub."""

from __future__ import annotations

import asyncio
import copy
import ctypes
import logging
import os
import platform
import socket
import threading
import time
from typing import Any, Optional

from fastapi import WebSocket

from backend.auth import get_current_user
from backend.config import settings
from backend.db import db, utc_now_iso

logger = logging.getLogger("cybershield.state")


def detect_is_admin() -> bool:
    if platform.system().lower() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


class RuntimeState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._protection_status: str = "ARMED"
        self._active_connections: list[dict[str, Any]] = []
        self._telemetry: dict[str, Any] = {
            "tx_kbps": 0.0,
            "rx_kbps": 0.0,
            "cpu_percent": 0.0,
            "mem_percent": 0.0,
            "history": [],
        }
        self._handled_pairs: dict[tuple[int, str], float] = {}
        self._verified_benign_pairs: set[tuple[str, str]] = set()
        self._suspended_pids: set[int] = set()
        self._activity_feed: list[dict[str, Any]] = [
            {
                "timestamp": utc_now_iso(),
                "level": "info",
                "message": "CyberShield Mesh 80ms behavioral sensor initialized.",
            }
        ]
        self._active_incident_id: Optional[int] = None

        # Short-lived in-memory policy cache so 80ms scanner avoids hitting SQLite every tick
        self._policy_cache_ts: float = 0.0
        self._policy_cache: Optional[tuple[dict[str, Any], set[str], set[str]]] = None

    def is_admin(self) -> bool:
        return detect_is_admin()

    def invalidate_policy_cache(self) -> None:
        with self._lock:
            self._policy_cache = None
            self._policy_cache_ts = 0.0

    def get_fast_policy_snapshot(self) -> tuple[dict[str, Any], set[str], set[str]]:
        """Return (settings_dict, blocked_ip_set, whitelist_ip_set) cached for 1.0s."""
        now = time.monotonic()
        with self._lock:
            if self._policy_cache is not None and (now - self._policy_cache_ts) < 1.0:
                return self._policy_cache
        cfg = db.get_settings()
        blocked_set = {r["ip"] for r in db.list_blocked_ips()}
        whitelist_set = {r["ip"] for r in db.list_whitelist_ips()}
        with self._lock:
            self._policy_cache = (cfg, blocked_set, whitelist_set)
            self._policy_cache_ts = now
            return self._policy_cache

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop = loop

    def get_event_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        with self._lock:
            return self._loop

    def set_protection_status(self, status: str) -> None:
        with self._lock:
            self._protection_status = status

    def get_protection_status(self) -> str:
        with self._lock:
            if self._protection_status == "CONTAINING" or self._suspended_pids:
                return "CONTAINING"
            cfg, _, _ = self.get_fast_policy_snapshot()
            return "ARMED" if cfg.get("autonomous_mode", True) else "MONITOR_ONLY"

    def set_active_incident_id(self, incident_id: Optional[int]) -> None:
        with self._lock:
            self._active_incident_id = incident_id

    def get_active_incident_id(self) -> Optional[int]:
        with self._lock:
            return self._active_incident_id

    def mark_pid_suspended(self, pid: int) -> None:
        with self._lock:
            if pid > 0:
                self._suspended_pids.add(int(pid))

    def clear_pid_suspended(self, pid: int) -> None:
        with self._lock:
            self._suspended_pids.discard(int(pid))

    def get_suspended_pids(self) -> set[int]:
        with self._lock:
            return set(self._suspended_pids)

    def add_verified_benign(self, process_name: str, remote_ip: str) -> None:
        with self._lock:
            self._verified_benign_pairs.add((process_name.strip().lower(), remote_ip.strip()))

    def is_verified_benign(self, process_name: str, remote_ip: str) -> bool:
        with self._lock:
            return (process_name.strip().lower(), remote_ip.strip()) in self._verified_benign_pairs

    def get_verified_benign_pairs(self) -> set[tuple[str, str]]:
        with self._lock:
            return set(self._verified_benign_pairs)

    def clear_verified_benign(self) -> None:
        with self._lock:
            self._verified_benign_pairs.clear()

    def set_active_connections(self, connections: list[dict[str, Any]]) -> None:
        with self._lock:
            self._active_connections = copy.deepcopy(connections)

    def get_active_connections(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._active_connections)

    def update_telemetry(self, tx_kbps: float, rx_kbps: float, cpu_percent: float, mem_percent: float) -> dict[str, Any]:
        point = {
            "t": utc_now_iso(),
            "tx": round(max(0.0, tx_kbps), 2),
            "rx": round(max(0.0, rx_kbps), 2),
        }
        with self._lock:
            history: list[dict[str, Any]] = self._telemetry.setdefault("history", [])
            history.append(point)
            if len(history) > 40:
                del history[:-40]
            self._telemetry["tx_kbps"] = point["tx"]
            self._telemetry["rx_kbps"] = point["rx"]
            self._telemetry["cpu_percent"] = round(cpu_percent, 1)
            self._telemetry["mem_percent"] = round(mem_percent, 1)
            return copy.deepcopy(self._telemetry)

    def get_telemetry(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._telemetry)

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

    def clear_cooldowns(self) -> None:
        with self._lock:
            self._handled_pairs.clear()

    def add_activity(self, level: str, message: str) -> dict[str, Any]:
        entry = {
            "timestamp": utc_now_iso(),
            "level": level,
            "message": message,
        }
        with self._lock:
            self._activity_feed.insert(0, entry)
            self._activity_feed = self._activity_feed[:40]
        return entry

    def count_neutralized_threats(self, incidents: Optional[list[dict[str, Any]]] = None) -> int:
        rows = incidents if incidents is not None else db.list_incidents(limit=200)
        return sum(
            1
            for inc in rows
            if inc.get("status") not in {"BENIGN_CLEARED", "ANALYZING"}
        )

    def get_full_snapshot(self) -> dict[str, Any]:
        with self._lock:
            incidents = db.list_incidents(limit=50)
            return {
                "protection_status": self.get_protection_status(),
                "user": get_current_user(),
                "oauth_configured": settings.has_google_oauth_config,
                "redirect_uri": settings.google_redirect_uri,
                "gemini_configured": settings.has_valid_gemini_key,
                "gemini_model": settings.gemini_model,
                "hostname": socket.gethostname(),
                "os_name": f"{platform.system()} {platform.release()}",
                "is_admin": detect_is_admin(),
                "active_connections": copy.deepcopy(self._active_connections),
                "suspended_pids": sorted(self._suspended_pids),
                "telemetry": copy.deepcopy(self._telemetry),
                "incidents": incidents,
                "total_incidents": self.count_neutralized_threats(incidents),
                "blocked_ips": db.list_blocked_ips(),
                "whitelist_ips": db.list_whitelist_ips(),
                "settings": db.get_settings(),
                "activity_feed": copy.deepcopy(self._activity_feed[:25]),
                "timestamp": utc_now_iso(),
            }


class ConnectionManager:
    def __init__(self, runtime: RuntimeState) -> None:
        self._runtime = runtime
        self._connections: set[WebSocket] = set()
        self._lock = threading.RLock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        with self._lock:
            self._connections.add(websocket)
        payload = self._runtime.get_full_snapshot()
        payload["type"] = "snapshot"
        try:
            await websocket.send_json(payload)
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
        loop = self._runtime.get_event_loop()
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
            logger.debug("Thread-safe WS broadcast skipped: %s", exc)

    def emit_activity(self, level: str, message: str, extra: Optional[dict[str, Any]] = None) -> None:
        entry = self._runtime.add_activity(level, message)
        payload: dict[str, Any] = {
            "type": "activity",
            "entry": entry,
            "protection_status": self._runtime.get_protection_status(),
            "suspended_pids": sorted(self._runtime.get_suspended_pids()),
            "timestamp": utc_now_iso(),
        }
        if extra:
            payload.update(extra)
        self.broadcast(payload)

    def emit_connections(self, connections: list[dict[str, Any]], telemetry: Optional[dict[str, Any]] = None) -> None:
        self._runtime.set_active_connections(connections)
        self.broadcast(
            {
                "type": "connections_update",
                "active_connections": connections,
                "suspended_pids": sorted(self._runtime.get_suspended_pids()),
                "telemetry": telemetry if telemetry is not None else self._runtime.get_telemetry(),
                "protection_status": self._runtime.get_protection_status(),
                "timestamp": utc_now_iso(),
            }
        )

    def emit_incident_update(self, incident: Optional[dict[str, Any]] = None) -> None:
        incidents = db.list_incidents(limit=50)
        self.broadcast(
            {
                "type": "incident_updated",
                "incident": incident,
                "incidents": incidents,
                "total_incidents": self._runtime.count_neutralized_threats(incidents),
                "suspended_pids": sorted(self._runtime.get_suspended_pids()),
                "protection_status": self._runtime.get_protection_status(),
                "timestamp": utc_now_iso(),
            }
        )

    def emit_firewall_update(self) -> None:
        self._runtime.invalidate_policy_cache()
        self.broadcast(
            {
                "type": "firewall_updated",
                "blocked_ips": db.list_blocked_ips(),
                "whitelist_ips": db.list_whitelist_ips(),
                "protection_status": self._runtime.get_protection_status(),
                "timestamp": utc_now_iso(),
            }
        )

    def emit_settings_update(self) -> None:
        self._runtime.invalidate_policy_cache()
        self.broadcast(
            {
                "type": "settings_updated",
                "settings": db.get_settings(),
                "protection_status": self._runtime.get_protection_status(),
                "timestamp": utc_now_iso(),
            }
        )

    def emit_auth_update(self) -> None:
        self.broadcast(
            {
                "type": "auth_updated",
                "user": get_current_user(),
                "oauth_configured": settings.has_google_oauth_config,
                "redirect_uri": settings.google_redirect_uri,
                "timestamp": utc_now_iso(),
            }
        )


state = RuntimeState()
ws_manager = ConnectionManager(state)
