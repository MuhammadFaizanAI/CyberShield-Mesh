"""Thread-safe SQLite persistence for CyberShield Mesh.

Stores:
- Active Google OAuth user profile & refreshable tokens (`auth_session`)
- Real security incidents & Gemini reasoning (`incidents`)
- Active firewall IP blocks (`blocked_ips`)
- Trusted IP whitelist (`whitelist_ips`)
- Runtime detection & alert channel preferences (`app_settings`)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.config import settings


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CyberShieldDB:
    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._lock = threading.RLock()
        data_dir = settings.data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(data_dir, 0o700)
        except OSError:
            pass

        self.db_path = db_path or (data_dir / "cybershield.db")
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_session (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    google_sub TEXT NOT NULL,
                    email TEXT NOT NULL,
                    name TEXT NOT NULL,
                    picture TEXT DEFAULT '',
                    access_token TEXT NOT NULL,
                    refresh_token TEXT DEFAULT '',
                    token_expiry REAL DEFAULT 0,
                    scopes TEXT DEFAULT '',
                    signed_in_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER DEFAULT 0,
                    local_port INTEGER DEFAULT 0,
                    pid INTEGER DEFAULT 0,
                    process_name TEXT DEFAULT 'unknown',
                    trigger_reason TEXT DEFAULT '',
                    status TEXT DEFAULT 'DETECTED',
                    gmail_sent INTEGER DEFAULT 0,
                    gmail_message_id TEXT DEFAULT '',
                    ntfy_sent INTEGER DEFAULT 0,
                    process_killed INTEGER DEFAULT 0,
                    ip_blocked INTEGER DEFAULT 0,
                    ai_summary TEXT DEFAULT '',
                    actions_json TEXT DEFAULT '[]'
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT DEFAULT '',
                    process_name TEXT DEFAULT '',
                    rule_out TEXT DEFAULT '',
                    rule_in TEXT DEFAULT '',
                    simulated INTEGER DEFAULT 0,
                    blocked_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_ips (
                    ip TEXT PRIMARY KEY,
                    label TEXT DEFAULT '',
                    added_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._seed_default_settings()

    def _seed_default_settings(self) -> None:
        defaults: dict[str, Any] = {
            "autonomous_mode": True,
            "gmail_alerts_enabled": True,
            "ntfy_alerts_enabled": True,
            "ntfy_topic": settings.ntfy_topic,
            "watch_ports": sorted(settings.watch_ports),
            "suspicious_processes": sorted(settings.suspicious_processes),
        }
        cur = self._conn.cursor()
        for k, v in defaults.items():
            cur.execute(
                "INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)",
                (k, json.dumps(v)),
            )

    # ------------------------------------------------------------------
    # Google Auth Session
    # ------------------------------------------------------------------
    def save_auth_session(
        self,
        *,
        google_sub: str,
        email: str,
        name: str,
        picture: str,
        access_token: str,
        refresh_token: str,
        token_expiry: float,
        scopes: str,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._lock:
            existing = self.get_auth_session()
            final_refresh = refresh_token or (
                existing.get("refresh_token", "") if existing else ""
            )
            self._conn.execute(
                """
                INSERT INTO auth_session (
                    id, google_sub, email, name, picture,
                    access_token, refresh_token, token_expiry, scopes, signed_in_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    google_sub=excluded.google_sub,
                    email=excluded.email,
                    name=excluded.name,
                    picture=excluded.picture,
                    access_token=excluded.access_token,
                    refresh_token=excluded.refresh_token,
                    token_expiry=excluded.token_expiry,
                    scopes=excluded.scopes,
                    signed_in_at=excluded.signed_in_at
                """,
                (
                    google_sub,
                    email,
                    name,
                    picture,
                    access_token,
                    final_refresh,
                    float(token_expiry),
                    scopes,
                    now,
                ),
            )
            return self.get_auth_session() or {}

    def update_auth_tokens(self, access_token: str, token_expiry: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE auth_session SET access_token = ?, token_expiry = ? WHERE id = 1",
                (access_token, float(token_expiry)),
            )

    def get_auth_session(self) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM auth_session WHERE id = 1"
            ).fetchone()
            return dict(row) if row else None

    def clear_auth_session(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM auth_session WHERE id = 1")

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------
    def create_incident(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO incidents (
                    timestamp, remote_ip, remote_port, local_port,
                    pid, process_name, trigger_reason, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("timestamp") or utc_now_iso(),
                    str(event.get("remote_ip", "")),
                    int(event.get("remote_port", 0) or 0),
                    int(event.get("local_port", 0) or 0),
                    int(event.get("pid", 0) or 0),
                    str(event.get("process_name", "unknown")),
                    str(event.get("trigger_reason", "")),
                    str(event.get("status", "DETECTED")),
                ),
            )
            inc_id = cur.lastrowid
            return self.get_incident_by_id(int(inc_id)) or {}

    def _hydrate_incident(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["gmail_sent"] = bool(d.get("gmail_sent"))
        d["ntfy_sent"] = bool(d.get("ntfy_sent"))
        d["process_killed"] = bool(d.get("process_killed"))
        d["ip_blocked"] = bool(d.get("ip_blocked"))
        try:
            d["actions"] = json.loads(d.pop("actions_json", "[]") or "[]")
        except json.JSONDecodeError:
            d["actions"] = []
        return d

    def get_incident_by_id(self, incident_id: int) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            return self._hydrate_incident(row) if row else None

    def update_incident(
        self,
        incident_id: Optional[int] = None,
        *,
        ip: Optional[str] = None,
        action: Optional[str] = None,
        **fields: Any,
    ) -> Optional[dict[str, Any]]:
        allowed_cols = {
            "status",
            "gmail_sent",
            "gmail_message_id",
            "ntfy_sent",
            "process_killed",
            "ip_blocked",
            "ai_summary",
        }
        with self._lock:
            target: Optional[sqlite3.Row] = None
            if incident_id is not None:
                target = self._conn.execute(
                    "SELECT * FROM incidents WHERE id = ?", (incident_id,)
                ).fetchone()
            elif ip:
                target = self._conn.execute(
                    "SELECT * FROM incidents WHERE remote_ip = ? ORDER BY id DESC LIMIT 1",
                    (ip,),
                ).fetchone()
            if target is None:
                target = self._conn.execute(
                    "SELECT * FROM incidents ORDER BY id DESC LIMIT 1"
                ).fetchone()
            if target is None:
                return None

            tid = int(target["id"])
            sets: list[str] = []
            vals: list[Any] = []
            for k, v in fields.items():
                if k in allowed_cols:
                    sets.append(f"{k} = ?")
                    vals.append(int(v) if isinstance(v, bool) else v)

            if action:
                try:
                    existing_actions = json.loads(target["actions_json"] or "[]")
                except json.JSONDecodeError:
                    existing_actions = []
                existing_actions.append(action)
                sets.append("actions_json = ?")
                vals.append(json.dumps(existing_actions))

            if sets:
                vals.append(tid)
                self._conn.execute(
                    f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?",
                    tuple(vals),
                )
            return self.get_incident_by_id(tid)

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._hydrate_incident(r) for r in rows]

    def count_incidents(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()
            return int(row["c"]) if row else 0

    def clear_incidents(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM incidents")

    # ------------------------------------------------------------------
    # Blocked IPs
    # ------------------------------------------------------------------
    def add_blocked_ip(
        self,
        ip: str,
        *,
        reason: str = "",
        process_name: str = "",
        rule_out: str = "",
        rule_in: str = "",
        simulated: bool = False,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO blocked_ips (ip, reason, process_name, rule_out, rule_in, simulated, blocked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason=excluded.reason,
                    process_name=excluded.process_name,
                    rule_out=excluded.rule_out,
                    rule_in=excluded.rule_in,
                    simulated=excluded.simulated,
                    blocked_at=excluded.blocked_at
                """,
                (ip, reason, process_name, rule_out, rule_in, int(simulated), now),
            )
            return {
                "ip": ip,
                "reason": reason,
                "process_name": process_name,
                "rule_out": rule_out,
                "rule_in": rule_in,
                "simulated": simulated,
                "blocked_at": now,
            }

    def remove_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))

    def list_blocked_ips(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
            ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                d["simulated"] = bool(d.get("simulated"))
                out.append(d)
            return out

    def clear_blocked_ips(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM blocked_ips")

    # ------------------------------------------------------------------
    # Trusted Whitelist IPs
    # ------------------------------------------------------------------
    def add_whitelist_ip(self, ip: str, label: str = "") -> dict[str, Any]:
        now = utc_now_iso()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO whitelist_ips (ip, label, added_at)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET label=excluded.label
                """,
                (ip, label, now),
            )
            return {"ip": ip, "label": label, "added_at": now}

    def remove_whitelist_ip(self, ip: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM whitelist_ips WHERE ip = ?", (ip,))

    def list_whitelist_ips(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM whitelist_ips ORDER BY added_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def is_ip_whitelisted(self, ip: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM whitelist_ips WHERE ip = ?", (ip,)
            ).fetchone()
            return row is not None

    # ------------------------------------------------------------------
    # App Settings
    # ------------------------------------------------------------------
    def get_settings(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM app_settings").fetchall()
            out: dict[str, Any] = {}
            for r in rows:
                try:
                    out[r["key"]] = json.loads(r["value"])
                except json.JSONDecodeError:
                    out[r["key"]] = r["value"]
            return out

    def update_settings(self, updates: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "autonomous_mode",
            "gmail_alerts_enabled",
            "ntfy_alerts_enabled",
            "ntfy_topic",
            "watch_ports",
            "suspicious_processes",
        }
        with self._lock:
            for k, v in updates.items():
                if k in allowed:
                    self._conn.execute(
                        """
                        INSERT INTO app_settings (key, value) VALUES (?, ?)
                        ON CONFLICT(key) DO UPDATE SET value=excluded.value
                        """,
                        (k, json.dumps(v)),
                    )
            return self.get_settings()


db = CyberShieldDB()
