"""PyInstaller-friendly entrypoint for CyberShield Mesh backend (`cybershield_backend.exe`)."""

from __future__ import annotations

import multiprocessing
import uvicorn

from backend.config import settings
from backend.main import app


def main() -> None:
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
