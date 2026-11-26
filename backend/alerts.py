"""Real-time intrusion alert delivery via Gmail API (signed-in Google account) & optional ntfy.sh."""

from __future__ import annotations

import base64
import html
import logging
import platform
import socket
from email.message import EmailMessage
from typing import Any

import requests

from backend.auth import get_valid_access_token
from backend.db import db, utc_now_iso

logger = logging.getLogger("cybershield.alerts")

GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"


def _build_intrusion_email(
    *,
    to_email: str,
    user_name: str,
    ip: str,
    port: int,
    pid: int,
    process_name: str,
    reason: str,
    ai_summary: str,
    is_test: bool,
) -> EmailMessage:
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()}"
    timestamp = utc_now_iso()

    if is_test:
        subject = f"[CyberShield Mesh] Test Security Alert Verified ({hostname})"
        badge_text = "TEST ALERT • DELIVERY VERIFIED"
        badge_color = "#10b981"
    else:
        peer = f"{ip}:{port}" if port else ip
        subject = f"[CyberShield Mesh] URGENT Intrusion Blocked: {process_name} -> {peer}"
        badge_text = "HIGH SEVERITY • AUTONOMOUS CONTAINMENT"
        badge_color = "#f43f5e"

    text_body = (
        f"CyberShield Mesh Security Alert\n"
        f"========================================\n"
        f"Account  : {user_name} ({to_email})\n"
        f"Endpoint : {hostname} ({os_info})\n"
        f"Time UTC : {timestamp}\n"
        f"Remote   : {ip}:{port}\n"
        f"Process  : {process_name} (PID {pid})\n"
        f"Reason   : {reason}\n"
        f"{'AI Notes : ' + ai_summary if ai_summary else ''}\n"
    ).strip()

    html_body = f"""\
<!DOCTYPE html>
<html>
<body style="margin:0;padding:24px;background:#050811;font-family:Inter,Segoe UI,Arial,sans-serif;color:#e2e8f0;">
  <div style="max-width:560px;margin:0 auto;background:#0b1120;border:1px solid #1e293b;border-radius:16px;overflow:hidden;">
    <div style="padding:18px 22px;background:#0f172a;border-bottom:1px solid #1e293b;">
      <div style="font-size:11px;font-weight:700;letter-spacing:1.2px;color:{badge_color};text-transform:uppercase;">
        {html.escape(badge_text)}
      </div>
      <div style="margin-top:6px;font-size:18px;font-weight:700;color:#ffffff;">
        CyberShield Mesh Endpoint Alert
      </div>
    </div>
    <div style="padding:20px 22px;font-size:13px;line-height:1.55;">
      <p style="margin:0 0 14px 0;color:#cbd5e1;">
        Hi {html.escape(user_name)}, CyberShield Mesh flagged suspicious network activity on <strong>{html.escape(hostname)}</strong>.
      </p>
      <table style="width:100%;border-collapse:collapse;background:#050811;border:1px solid #1e293b;border-radius:10px;">
        <tr><td style="padding:9px 12px;color:#94a3b8;width:130px;">Remote Peer</td><td style="padding:9px 12px;color:#fda4af;font-family:monospace;font-weight:700;">{html.escape(f'{ip}:{port}' if port else ip)}</td></tr>
        <tr><td style="padding:9px 12px;color:#94a3b8;border-top:1px solid #1e293b;">Local Process</td><td style="padding:9px 12px;color:#38bdf8;font-family:monospace;">{html.escape(f'{process_name} (PID {pid})')}</td></tr>
        <tr><td style="padding:9px 12px;color:#94a3b8;border-top:1px solid #1e293b;">Endpoint</td><td style="padding:9px 12px;color:#e2e8f0;">{html.escape(f'{hostname} — {os_info}')}</td></tr>
        <tr><td style="padding:9px 12px;color:#94a3b8;border-top:1px solid #1e293b;">Timestamp</td><td style="padding:9px 12px;color:#e2e8f0;font-family:monospace;">{html.escape(timestamp)}</td></tr>
      </table>
      <div style="margin-top:14px;padding:12px 14px;background:#0f172a;border-left:3px solid #38bdf8;border-radius:6px;">
        <div style="font-size:11px;font-weight:700;color:#38bdf8;text-transform:uppercase;margin-bottom:4px;">Reason &amp; AI Assessment</div>
        <div style="color:#e2e8f0;">{html.escape(reason)}</div>
        {f'<div style="margin-top:6px;color:#94a3b8;">{html.escape(ai_summary)}</div>' if ai_summary else ''}
      </div>
    </div>
    <div style="padding:12px 22px;background:#070c18;border-top:1px solid #1e293b;font-size:11px;color:#64748b;">
      Sent automatically by CyberShield Mesh via your signed-in Google account ({html.escape(to_email)}).
    </div>
  </div>
</body>
</html>
"""

    msg = EmailMessage()
    msg["To"] = to_email
    msg["From"] = to_email
    msg["Subject"] = subject
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    return msg


def send_gmail_alert(
    *,
    ip: str,
    port: int,
    pid: int,
    process_name: str,
    reason: str,
    ai_summary: str = "",
    is_test: bool = False,
) -> dict[str, Any]:
    """Send an instant security email directly to the signed-in Google user via Gmail API."""
    access_token, session, err = get_valid_access_token()
    if not access_token or not session:
        return {
            "sent": False,
            "channel": "gmail",
            "to": session.get("email", "") if session else "",
            "error": err or "User not signed in with Google.",
        }

    to_email = str(session.get("email") or "")
    user_name = str(session.get("name") or to_email)

    msg = _build_intrusion_email(
        to_email=to_email,
        user_name=user_name,
        ip=ip,
        port=port,
        pid=pid,
        process_name=process_name,
        reason=reason,
        ai_summary=ai_summary,
        is_test=is_test,
    )
    raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")

    try:
        resp = requests.post(
            GMAIL_SEND_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={"raw": raw_b64},
            timeout=8,
        )
        if 200 <= resp.status_code < 300:
            data = resp.json()
            msg_id = str(data.get("id") or "")
            logger.info("Gmail alert delivered to %s (id=%s)", to_email, msg_id)
            return {
                "sent": True,
                "channel": "gmail",
                "to": to_email,
                "message_id": msg_id,
                "error": "",
            }
        err_msg = f"Gmail API HTTP {resp.status_code}: {resp.text[:200]}"
        logger.warning(err_msg)
        return {
            "sent": False,
            "channel": "gmail",
            "to": to_email,
            "message_id": "",
            "error": err_msg,
        }
    except requests.RequestException as exc:
        logger.warning("Gmail alert request failed: %s", exc)
        return {
            "sent": False,
            "channel": "gmail",
            "to": to_email,
            "message_id": "",
            "error": str(exc),
        }


def send_ntfy_alert(
    *,
    topic: str,
    ip: str,
    port: int,
    pid: int,
    process_name: str,
    reason: str,
    is_test: bool = False,
) -> dict[str, Any]:
    """Optional instant mobile push notification via ntfy.sh (4s timeout)."""
    clean_topic = (topic or "").strip()
    if not clean_topic:
        return {"sent": False, "channel": "ntfy", "topic": "", "error": "No ntfy topic set."}

    url = f"https://ntfy.sh/{clean_topic}"
    title = (
        "CyberShield Mesh: Test Push Verified"
        if is_test
        else f"CyberShield Alert: Intrusion to {ip}"
    )
    peer = f"{ip}:{port}" if port else ip
    body = (
        f"Host: {socket.gethostname()}\n"
        f"Process: {process_name} (PID {pid})\n"
        f"Remote: {peer}\n"
        f"Reason: {reason}"
    )

    try:
        resp = requests.post(
            url,
            data=body.encode("utf-8"),
            headers={
                "Title": title,
                "Priority": "default" if is_test else "high",
                "Tags": "white_check_mark,shield" if is_test else "rotating_light,shield",
            },
            timeout=4,
        )
        ok = 200 <= resp.status_code < 300
        return {
            "sent": ok,
            "channel": "ntfy",
            "topic": clean_topic,
            "http_status": resp.status_code,
            "error": "" if ok else f"HTTP {resp.status_code}",
        }
    except requests.RequestException as exc:
        logger.warning("ntfy push failed (non-fatal): %s", exc)
        return {
            "sent": False,
            "channel": "ntfy",
            "topic": clean_topic,
            "http_status": None,
            "error": str(exc),
        }


def dispatch_user_alert(
    *,
    ip: str,
    port: int,
    pid: int,
    process_name: str,
    reason: str,
    ai_summary: str = "",
    is_test: bool = False,
) -> dict[str, Any]:
    """Dispatch alert across enabled channels (Gmail API primary + optional ntfy push)."""
    cfg = db.get_settings()
    gmail_enabled = bool(cfg.get("gmail_alerts_enabled", True))
    ntfy_enabled = bool(cfg.get("ntfy_alerts_enabled", True))
    ntfy_topic = str(cfg.get("ntfy_topic") or "")

    gmail_res: dict[str, Any] = {"sent": False, "channel": "gmail", "skipped": True}
    ntfy_res: dict[str, Any] = {"sent": False, "channel": "ntfy", "skipped": True}

    if gmail_enabled:
        gmail_res = send_gmail_alert(
            ip=ip,
            port=port,
            pid=pid,
            process_name=process_name,
            reason=reason,
            ai_summary=ai_summary,
            is_test=is_test,
        )

    if ntfy_enabled and ntfy_topic:
        ntfy_res = send_ntfy_alert(
            topic=ntfy_topic,
            ip=ip,
            port=port,
            pid=pid,
            process_name=process_name,
            reason=reason,
            is_test=is_test,
        )

    return {
        "ok": True,
        "any_delivered": bool(gmail_res.get("sent") or ntfy_res.get("sent")),
        "gmail": gmail_res,
        "ntfy": ntfy_res,
    }
