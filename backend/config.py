"""Configuration loader for CyberShield Mesh.

Reads environment variables from `.env` with safe defaults across both
development mode (`python -m uvicorn`) and frozen PyInstaller `.exe` mode.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _resolve_roots() -> tuple[Path, Path]:
    """Return (project_root, frontend_index_path) for dev or frozen .exe builds."""
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        meipass = Path(getattr(sys, "_MEIPASS", exe_dir))
        candidate_env_paths = [
            Path.cwd() / ".env",
            exe_dir / ".env",
            exe_dir.parent / ".env",
            exe_dir.parent.parent / ".env",
            meipass / ".env",
        ]
        for env_file in candidate_env_paths:
            if env_file.exists():
                load_dotenv(env_file, override=False)

        for idx in (
            meipass / "frontend" / "index.html",
            exe_dir / "frontend" / "index.html",
            exe_dir.parent / "frontend" / "index.html",
        ):
            if idx.exists():
                return exe_dir, idx
        return exe_dir, meipass / "frontend" / "index.html"

    project_root = Path(__file__).resolve().parent.parent
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)
    else:
        load_dotenv(override=False)
    return project_root, project_root / "frontend" / "index.html"


PROJECT_ROOT, FRONTEND_INDEX = _resolve_roots()


def _parse_watch_ports(raw: str) -> set[int]:
    ports: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
            if 1 <= port <= 65535:
                ports.add(port)
        except ValueError:
            continue
    return ports or {4444, 1337, 9001, 5555}


def _parse_int(raw: str, default: int) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _parse_float(raw: str, default: float) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    project_root: Path = PROJECT_ROOT
    frontend_index: Path = FRONTEND_INDEX

    gemini_api_key: str = field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip()
    )
    gemini_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite").strip()
        or "gemini-3.5-flash-lite"
    )
    ntfy_topic: str = field(
        default_factory=lambda: os.getenv("NTFY_TOPIC", "cybershield-mesh-alerts-2026").strip()
        or "cybershield-mesh-alerts-2026"
    )
    watch_ports: set[int] = field(
        default_factory=lambda: _parse_watch_ports(
            os.getenv("WATCH_PORTS", "4444,1337,9001,5555")
        )
    )
    demo_target_ip: str = field(
        default_factory=lambda: os.getenv("DEMO_TARGET_IP", "10.100.5.67").strip()
        or "10.100.5.67"
    )
    host: str = field(
        default_factory=lambda: os.getenv("HOST", "127.0.0.1").strip() or "127.0.0.1"
    )
    port: int = field(
        default_factory=lambda: _parse_int(os.getenv("PORT", "8000"), 8000)
    )
    monitor_interval_sec: float = field(
        default_factory=lambda: max(
            0.5, _parse_float(os.getenv("MONITOR_INTERVAL_SEC", "1.0"), 1.0)
        )
    )
    incident_cooldown_sec: float = field(
        default_factory=lambda: max(
            5.0, _parse_float(os.getenv("INCIDENT_COOLDOWN_SEC", "30.0"), 30.0)
        )
    )
    suspicious_processes: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "sim_intrusion.exe",
                "sim_intrusion",
                "ncat.exe",
                "ncat",
                "nc.exe",
                "nc",
            }
        )
    )

    @property
    def has_valid_gemini_key(self) -> bool:
        key = self.gemini_api_key
        return bool(key) and key != "your_gemini_api_key_here"


settings = Settings()
