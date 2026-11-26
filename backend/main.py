"""CyberShield Mesh FastAPI Backend Server.

Endpoints:
- GET  /              -> Serves the live WebSocket dashboard (`frontend/index.html`)
- GET  /health        -> Returns `{"status": "ok"}` for Electron startup polling
- GET  /api/state     -> Returns current live snapshot & recent incident memory
- WS   /ws            -> Streams real-time Step 1-5 defense JSON events
- POST /api/chat      -> Interactive Gemini security chat with live unblock/block tools
- POST /api/simulate  -> Safe simulated intrusion running the real Gemini + ntfy flow
- POST /api/reset     -> Removes all CyberShield firewall rules & resets to PROTECTED
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.agent import chat_with_agent
from backend.config import settings
from backend.monitor import network_monitor
from backend.state import state, utc_now_iso, ws_manager
from backend.tools import reset_all_firewall_rules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("cybershield.main")


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000)


class SimulateRequest(BaseModel):
    remote_ip: str | None = None
    remote_port: int | None = None
    process_name: str | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    state.set_event_loop(asyncio.get_running_loop())
    network_monitor.start()
    logger.info(
        "CyberShield Mesh backend ready on http://%s:%s (model=%s, watch_ports=%s)",
        settings.host,
        settings.port,
        settings.gemini_model,
        sorted(settings.watch_ports),
    )
    try:
        yield
    finally:
        await network_monitor.stop()
        logger.info("CyberShield Mesh backend shut down cleanly.")


app = FastAPI(
    title="CyberShield Mesh",
    description="Autonomous Gemini-Powered Endpoint Intrusion Defense",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
async def serve_dashboard() -> FileResponse:
    if not settings.frontend_index.exists():
        raise HTTPException(status_code=404, detail="frontend/index.html not found")
    return FileResponse(settings.frontend_index)


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "ok",
        "model": settings.gemini_model,
        "monitoring": network_monitor.is_running,
    }


@app.get("/api/state")
async def get_state() -> dict[str, Any]:
    return {
        "snapshot": state.get_snapshot(),
        "incidents": state.get_recent_incidents(limit=10),
        "watch_ports": sorted(settings.watch_ports),
        "model": settings.gemini_model,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and accept optional client pings
            msg = await websocket.receive_text()
            if msg.strip().lower() == "ping":
                await websocket.send_json({"type": "pong", "timestamp": utc_now_iso()})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


@app.post("/api/chat")
async def api_chat(payload: ChatRequest) -> dict[str, Any]:
    return await chat_with_agent(payload.message)


@app.post("/api/simulate")
async def api_simulate(payload: SimulateRequest | None = None) -> dict[str, Any]:
    target_ip = (payload.remote_ip if payload and payload.remote_ip else settings.demo_target_ip)
    target_port = (payload.remote_port if payload and payload.remote_port else 4444)
    proc_name = (
        payload.process_name
        if payload and payload.process_name
        else "sim_intrusion.py (SIMULATED)"
    )

    event = {
        "remote_ip": target_ip,
        "remote_port": int(target_port),
        "local_port": 54321,
        "pid": 42424,
        "process_name": proc_name,
        "timestamp": utc_now_iso(),
        "simulated": True,
        "trigger_reason": "manual_dashboard_simulation",
    }
    network_monitor.dispatch_intrusion(event)
    return {"status": "started", "event": event}


@app.post("/api/reset")
async def api_reset() -> dict[str, Any]:
    fw_result = await asyncio.to_thread(reset_all_firewall_rules)
    snapshot = state.reset()
    snapshot["type"] = "reset"
    await ws_manager.broadcast_async(snapshot)
    return {
        "status": "reset",
        "firewall": fw_result,
        "snapshot": snapshot,
    }
