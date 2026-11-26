"""Configuration loader for CyberShield Mesh.

Reads environment variables from `.env` across both development mode and frozen
PyInstaller `.exe` builds, and supports saving Google OAuth credentials cleanly.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _resolve_paths() -> tuple[Path, Path, Path, Path]:
    """Return (project_root, frontend_index, data_dir, env_file_path)."""
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
        chosen_env = exe_dir / ".env"
        for env_file in candidate_env_paths:
            if env_file.exists():
                load_dotenv(env_file, override=False)
                chosen_env = env_file
                break

        frontend_idx = meipass / "frontend" / "index.html"
        for idx in (
            meipass / "frontend" / "index.html",
            exe_dir / "frontend" / "index.html",
            exe_dir.parent / "frontend" / "index.html",
        ):
            if idx.exists():
                frontend_idx = idx
                break

        data_dir = exe_dir / "data"
        return exe_dir, frontend_idx, data_dir, chosen_env

    project_root = Path(__file__).resolve().parent.parent
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)
    else:
        load_dotenv(override=False)
    return (
        project_root,
        project_root / "frontend" / "index.html",
        project_root / "backend" / "data",
        env_path,
    )


PROJECT_ROOT, FRONTEND_INDEX, DATA_DIR, ENV_FILE_PATH = _resolve_paths()


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


@dataclass
class Settings:
    project_root: Path = PROJECT_ROOT
    frontend_index: Path = FRONTEND_INDEX
    data_dir: Path = DATA_DIR
    env_file: Path = ENV_FILE_PATH

    gemini_api_key: str = field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip()
    )
    gemini_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite").strip()
        or "gemini-3.5-flash-lite"
    )
    google_client_id: str = field(
        default_factory=lambda: os.getenv("GOOGLE_CLIENT_ID", "").strip()
    )
    google_client_secret: str = field(
        default_factory=lambda: os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
    )
    google_redirect_uri: str = field(
        default_factory=lambda: os.getenv(
            "GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/auth/google/callback"
        ).strip()
        or "http://127.0.0.1:8000/auth/google/callback"
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

    @property
    def has_google_oauth_config(self) -> bool:
        cid = self.google_client_id
        csec = self.google_client_secret
        return (
            bool(cid)
            and bool(csec)
            and "your_google_client_id" not in cid.lower()
            and "your_google_client_secret" not in csec.lower()
        )

    def update_google_oauth(self, client_id: str, client_secret: str) -> None:
        """Persist Google OAuth client credentials to `.env` and update runtime settings."""
        clean_id = client_id.strip()
        clean_secret = client_secret.strip()
        self.google_client_id = clean_id
        self.google_client_secret = clean_secret
        os.environ["GOOGLE_CLIENT_ID"] = clean_id
        os.environ["GOOGLE_CLIENT_SECRET"] = clean_secret

        updates = {
            "GOOGLE_CLIENT_ID": clean_id,
            "GOOGLE_CLIENT_SECRET": clean_secret,
            "GOOGLE_REDIRECT_URI": self.google_redirect_uri,
        }
        existing_lines: list[str] = []
        if self.env_file.exists():
            existing_lines = self.env_file.read_text(encoding="utf-8").splitlines()

        seen: set[str] = set()
        new_lines: list[str] = []
        for line in existing_lines:
            stripped = line.strip()
            replaced = False
            for k, v in updates.items():
                if stripped.startswith(f"{k}="):
                    new_lines.append(f"{k}={v}")
                    seen.add(k)
                    replaced = True
                    break
            if not replaced:
                new_lines.append(line)

        for k, v in updates.items():
            if k not in seen:
                new_lines.append(f"{k}={v}")

        self.env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


settings = Settings()
