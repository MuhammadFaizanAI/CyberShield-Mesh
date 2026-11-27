"""CyberShield Mesh FastAPI Server — Google OAuth 2.0, Gmail Alerts & Real Endpoint Security Console."""

from __future__ import annotations

import asyncio
import ctypes
import html
import logging
import platform
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from backend.agent import chat_with_agent
from backend.alerts import dispatch_user_alert
from backend.auth import (
    create_google_login_url,
    get_current_user,
    handle_google_callback,
    logout_google_user,
)
from backend.config import settings
from backend.db import db, utc_now_iso
from backend.monitor import network_monitor, scan_live_connections
from backend.state import state, ws_manager
from backend.tools import (
    block_ip_firewall,
    kill_process,
    reset_all_firewall_rules,
    unblock_ip_firewall,
    validate_ip,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("cybershield.main")


class GoogleOAuthConfigRequest(BaseModel):
    client_id: str = Field(..., min_length=10)
    client_secret: str = Field(..., min_length=6)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1500)


class IPActionRequest(BaseModel):
    ip: str = Field(..., min_length=3, max_length=64)
    reason: str | None = None
    label: str | None = None


class KillProcessRequest(BaseModel):
    pid: int = Field(..., gt=0)


class SettingsUpdateRequest(BaseModel):
    autonomous_mode: bool | None = None
    gmail_alerts_enabled: bool | None = None
    ntfy_alerts_enabled: bool | None = None
    ntfy_topic: str | None = None
    watch_ports: list[int] | None = None
    suspicious_processes: list[str] | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    state.set_event_loop(asyncio.get_running_loop())
    network_monitor.start()
    logger.info(
        "CyberShield Mesh ready on http://%s:%s (model=%s, oauth_configured=%s)",
        settings.host,
        settings.port,
        settings.gemini_model,
        settings.has_google_oauth_config,
    )
    try:
        yield
    finally:
        await network_monitor.stop()
        logger.info("CyberShield Mesh shut down cleanly.")


app = FastAPI(
    title="CyberShield Mesh",
    description="Autonomous Gemini Endpoint Intrusion Defense with Google OAuth & Gmail Alerts",
    version="2.0.0",
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
async def serve_console() -> FileResponse:
    if not settings.frontend_index.exists():
        raise HTTPException(status_code=404, detail="frontend/index.html not found")
    return FileResponse(settings.frontend_index)


@app.get("/health")
async def health_check() -> dict[str, Any]:
    user = get_current_user()
    return {
        "status": "ok",
        "model": settings.gemini_model,
        "monitoring": network_monitor.is_running,
        "is_admin": state.is_admin(),
        "authenticated": user is not None,
        "oauth_configured": settings.has_google_oauth_config,
    }


@app.post("/api/system/elevate")
async def api_system_elevate() -> dict[str, Any]:
    """Trigger Windows UAC Administrator relaunch when running un-elevated."""
    if state.is_admin():
        return {"ok": True, "already_admin": True, "detail": "Already running with Administrator privileges."}

    if platform.system().lower() != "windows":
        raise HTTPException(
            status_code=400,
            detail="Automatic UAC elevation is Windows-specific. On Linux, launch backend with sudo for iptables.",
        )

    launcher = settings.project_root / "LAUNCH_CYBERSHIELD_ADMIN.bat"
    target = str(launcher if launcher.exists() else settings.project_root)
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            "cmd.exe",
            f'/c "{target}"',
            str(settings.project_root),
            1,
        )
        if int(rc) <= 32:
            raise HTTPException(status_code=403, detail="UAC elevation prompt was cancelled or denied.")
        ws_manager.emit_activity("info", "Triggered UAC Administrator relaunch. Close non-admin instance once elevated window opens.")
        return {"ok": True, "elevating": True, "detail": "UAC prompt launched. Approve elevation to activate Admin Firewall Mode."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Elevation trigger failed: {exc}") from exc


# ============================================================================
# GOOGLE OAUTH 2.0 AUTHENTICATION ENDPOINTS
# ============================================================================
@app.get("/auth/me")
async def auth_me() -> dict[str, Any]:
    user = get_current_user()
    return {
        "authenticated": user is not None,
        "user": user,
        "oauth_configured": settings.has_google_oauth_config,
        "redirect_uri": settings.google_redirect_uri,
    }


@app.post("/auth/config")
async def auth_save_config(payload: GoogleOAuthConfigRequest) -> dict[str, Any]:
    settings.update_google_oauth(payload.client_id, payload.client_secret)
    ws_manager.emit_auth_update()
    ws_manager.emit_activity("info", "Saved Google OAuth 2.0 Client credentials to .env.")
    return {
        "ok": True,
        "oauth_configured": settings.has_google_oauth_config,
        "redirect_uri": settings.google_redirect_uri,
    }


@app.get("/auth/google/login")
async def auth_google_login(redirect: int = Query(default=0)):
    try:
        auth_url = create_google_login_url()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if redirect == 1:
        return RedirectResponse(url=auth_url, status_code=302)
    return {"auth_url": auth_url}


@app.get("/auth/google/callback", response_class=HTMLResponse)
async def auth_google_callback(
    code: str | None = None,
    state_param: str | None = Query(default=None, alias="state"),
    error: str | None = None,
) -> HTMLResponse:
    if error:
        safe_err = html.escape(error)
        return HTMLResponse(
            status_code=400,
            content=f"""<!DOCTYPE html>
<html><body style="background:#050811;color:#f1f5f9;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
  <div style="max-width:440px;background:#0f172a;border:1px solid #f43f5e66;border-radius:16px;padding:28px;text-align:center;">
    <h2 style="color:#fda4af;margin-top:0;">Google Sign-In Cancelled</h2>
    <p style="color:#cbd5e1;font-size:14px;">Google returned: <code>{safe_err}</code></p>
    <a href="/" style="display:inline-block;margin-top:12px;padding:10px 18px;background:#0ea5e9;color:#050811;border-radius:10px;text-decoration:none;font-weight:700;">Return to CyberShield Mesh</a>
  </div>
</body></html>""",
        )

    if not code or not state_param:
        raise HTTPException(status_code=400, detail="Missing OAuth code or state parameter.")

    try:
        user = await asyncio.to_thread(handle_google_callback, code, state_param)
    except ValueError as exc:
        safe_err = html.escape(str(exc))
        return HTMLResponse(
            status_code=400,
            content=f"""<!DOCTYPE html>
<html><body style="background:#050811;color:#f1f5f9;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
  <div style="max-width:460px;background:#0f172a;border:1px solid #f43f5e66;border-radius:16px;padding:28px;text-align:center;">
    <h2 style="color:#fda4af;margin-top:0;">Sign-In Error</h2>
    <p style="color:#cbd5e1;font-size:13px;">{safe_err}</p>
    <a href="/" style="display:inline-block;margin-top:12px;padding:10px 18px;background:#0ea5e9;color:#050811;border-radius:10px;text-decoration:none;font-weight:700;">Back to CyberShield Mesh</a>
  </div>
</body></html>""",
        )

    ws_manager.emit_auth_update()
    ws_manager.emit_activity(
        "success",
        f"Signed in with Google as {user.get('name')} ({user.get('email')}). Gmail alerts active.",
    )

    safe_name = html.escape(str(user.get("name", "User")))
    safe_email = html.escape(str(user.get("email", "")))
    return HTMLResponse(
        content=f"""<!DOCTYPE html>
<html><head><title>Signed In — CyberShield Mesh</title></head>
<body style="background:#050811;color:#f1f5f9;font-family:Inter,Segoe UI,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
  <div style="max-width:460px;background:#0b1120;border:1px solid #10b98166;border-radius:18px;padding:30px;text-align:center;">
    <div style="font-size:12px;font-weight:700;color:#34d399;letter-spacing:1.2px;text-transform:uppercase;">Google Account Connected</div>
    <h2 style="margin:10px 0 6px 0;color:#ffffff;">Welcome, {safe_name}</h2>
    <p style="margin:0 0 18px 0;color:#94a3b8;font-size:13px;">Real-time intrusion alerts will be delivered to <strong style="color:#38bdf8;">{safe_email}</strong>.</p>
    <p style="margin:0 0 20px 0;color:#64748b;font-size:12px;">Your CyberShield Mesh desktop app has unlocked automatically. You can close this browser tab or click below to open the web console.</p>
    <a href="/" style="display:inline-block;padding:10px 20px;background:#38bdf8;color:#050811;border-radius:10px;text-decoration:none;font-weight:700;font-size:13px;">Open Console in Browser</a>
  </div>
</body></html>"""
    )


@app.post("/auth/logout")
async def auth_logout() -> dict[str, Any]:
    res = await asyncio.to_thread(logout_google_user)
    ws_manager.emit_auth_update()
    ws_manager.emit_activity("info", "Signed out Google account.")
    return res


# ============================================================================
# REAL ENDPOINT SECURITY CONSOLE APIs & WEBSOCKET
# ============================================================================
@app.get("/api/state")
async def api_state() -> dict[str, Any]:
    return state.get_full_snapshot()


@app.get("/api/connections")
async def api_connections() -> dict[str, Any]:
    conns, _ = await asyncio.to_thread(scan_live_connections, False)
    state.set_active_connections(conns)
    return {"connections": conns, "count": len(conns), "timestamp": utc_now_iso()}


@app.get("/api/incidents")
async def api_incidents(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, Any]:
    return {"incidents": db.list_incidents(limit=limit), "total": db.count_incidents()}


@app.post("/api/process/kill")
async def api_kill_process(payload: KillProcessRequest) -> dict[str, Any]:
    return await asyncio.to_thread(kill_process, payload.pid)


@app.post("/api/firewall/block")
async def api_block_ip(payload: IPActionRequest) -> dict[str, Any]:
    res = await asyncio.to_thread(
        block_ip_firewall,
        payload.ip,
        payload.reason or "Manually blocked by operator",
    )
    if not res.get("ok"):
        raise HTTPException(status_code=400, detail=res.get("error", "Block failed"))
    return res


@app.post("/api/firewall/unblock")
async def api_unblock_ip(payload: IPActionRequest) -> dict[str, Any]:
    res = await asyncio.to_thread(unblock_ip_firewall, payload.ip)
    if not res.get("ok"):
        raise HTTPException(status_code=400, detail=res.get("error", "Unblock failed"))
    return res


@app.post("/api/firewall/reset")
async def api_reset_firewall() -> dict[str, Any]:
    return await asyncio.to_thread(reset_all_firewall_rules)


@app.get("/api/whitelist")
async def api_list_whitelist() -> dict[str, Any]:
    return {"whitelist_ips": db.list_whitelist_ips()}


@app.post("/api/whitelist")
async def api_add_whitelist(payload: IPActionRequest) -> dict[str, Any]:
    try:
        clean_ip = validate_ip(payload.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid IP: {payload.ip}") from exc
    rec = db.add_whitelist_ip(clean_ip, label=(payload.label or "Trusted peer").strip())
    ws_manager.emit_activity("info", f"Added {clean_ip} to Trusted IP Whitelist.")
    ws_manager.emit_firewall_update()
    return {"ok": True, "record": rec, "whitelist_ips": db.list_whitelist_ips()}


@app.delete("/api/whitelist/{ip}")
async def api_remove_whitelist(ip: str) -> dict[str, Any]:
    db.remove_whitelist_ip(ip)
    ws_manager.emit_activity("info", f"Removed {ip} from Trusted IP Whitelist.")
    ws_manager.emit_firewall_update()
    return {"ok": True, "whitelist_ips": db.list_whitelist_ips()}


@app.get("/api/settings")
async def api_get_settings() -> dict[str, Any]:
    return {"settings": db.get_settings()}


@app.put("/api/settings")
async def api_update_settings(payload: SettingsUpdateRequest) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    if payload.autonomous_mode is not None:
        updates["autonomous_mode"] = payload.autonomous_mode
    if payload.gmail_alerts_enabled is not None:
        updates["gmail_alerts_enabled"] = payload.gmail_alerts_enabled
    if payload.ntfy_alerts_enabled is not None:
        updates["ntfy_alerts_enabled"] = payload.ntfy_alerts_enabled
    if payload.ntfy_topic is not None:
        updates["ntfy_topic"] = payload.ntfy_topic.strip()
    if payload.watch_ports is not None:
        clean_ports = sorted({int(p) for p in payload.watch_ports if 1 <= int(p) <= 65535})
        if clean_ports:
            updates["watch_ports"] = clean_ports
    if payload.suspicious_processes is not None:
        clean_procs = sorted({p.strip().lower() for p in payload.suspicious_processes if p.strip()})
        updates["suspicious_processes"] = clean_procs

    updated = db.update_settings(updates)
    ws_manager.emit_activity("info", "Updated CyberShield Mesh detection & alert settings.")
    ws_manager.emit_settings_update()
    return {"ok": True, "settings": updated}


@app.post("/api/alerts/test")
async def api_test_alert() -> dict[str, Any]:
    user = get_current_user()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Sign in with your Google account first to test Gmail alert delivery.",
        )
    receipt = await asyncio.to_thread(
        dispatch_user_alert,
        ip="127.0.0.1",
        port=0,
        pid=0,
        process_name="CyberShield-SelfTest",
        reason="Operator requested a live delivery verification test from CyberShield Mesh.",
        ai_summary="All configured notification channels were exercised cleanly.",
        is_test=True,
    )
    ws_manager.emit_activity(
        "success" if receipt.get("any_delivered") else "warn",
        f"Test alert result — Gmail: {receipt['gmail'].get('sent')}, ntfy: {receipt['ntfy'].get('sent')}",
    )
    return receipt


@app.post("/api/chat")
async def api_chat(payload: ChatRequest) -> dict[str, Any]:
    return await chat_with_agent(payload.message)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            if msg.strip().lower() == "ping":
                await websocket.send_json({"type": "pong", "timestamp": utc_now_iso()})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
