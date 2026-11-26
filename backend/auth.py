"""Real Google OAuth 2.0 authentication & automatic access-token refresh.

Scopes requested:
- openid
- https://www.googleapis.com/auth/userinfo.email
- https://www.googleapis.com/auth/userinfo.profile
- https://www.googleapis.com/auth/gmail.send

Designed for both Electron desktop (external system browser callback to
http://127.0.0.1:8000/auth/google/callback) and standard web browser usage.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from typing import Any, Optional
from urllib.parse import urlencode

import requests

from backend.config import settings
from backend.db import db

logger = logging.getLogger("cybershield.auth")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"

OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.send",
]

_state_lock = threading.RLock()
_pending_states: dict[str, float] = {}
STATE_TTL_SECONDS = 600.0


def _prune_states() -> None:
    now = time.time()
    expired = [k for k, exp in _pending_states.items() if exp < now]
    for k in expired:
        _pending_states.pop(k, None)


def create_google_login_url() -> str:
    """Build a CSRF-protected Google OAuth 2.0 consent URL."""
    if not settings.has_google_oauth_config:
        raise ValueError(
            "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not configured yet."
        )

    state_token = secrets.token_urlsafe(24)
    with _state_lock:
        _prune_states()
        _pending_states[state_token] = time.time() + STATE_TTL_SECONDS

    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": " ".join(OAUTH_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state_token,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def _consume_state(state_token: str) -> bool:
    with _state_lock:
        _prune_states()
        exp = _pending_states.pop(state_token, None)
        return exp is not None and exp >= time.time()


def sanitize_user(session: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Return safe public user fields (never exposes OAuth access/refresh tokens)."""
    if not session:
        return None
    scopes = str(session.get("scopes") or "")
    return {
        "google_sub": session.get("google_sub", ""),
        "email": session.get("email", ""),
        "name": session.get("name", ""),
        "picture": session.get("picture", ""),
        "signed_in_at": session.get("signed_in_at", ""),
        "gmail_authorized": "gmail.send" in scopes,
        "has_refresh_token": bool(session.get("refresh_token")),
    }


def get_current_user() -> Optional[dict[str, Any]]:
    return sanitize_user(db.get_auth_session())


def handle_google_callback(code: str, state_token: str) -> dict[str, Any]:
    """Exchange OAuth authorization code for tokens, load Google profile, save to DB."""
    if not settings.has_google_oauth_config:
        raise ValueError("Google OAuth client credentials are not configured.")

    if not state_token or not _consume_state(state_token):
        raise ValueError("Invalid or expired OAuth state token. Please try signing in again.")

    token_resp = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "redirect_uri": settings.google_redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        raise ValueError(
            f"Google token exchange failed (HTTP {token_resp.status_code}): {token_resp.text[:250]}"
        )

    token_data = token_resp.json()
    access_token = str(token_data.get("access_token") or "")
    refresh_token = str(token_data.get("refresh_token") or "")
    expires_in = float(token_data.get("expires_in", 3600))
    granted_scopes = str(token_data.get("scope") or " ".join(OAUTH_SCOPES))
    if not access_token:
        raise ValueError("Google token response did not include an access_token.")

    userinfo_resp = requests.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if userinfo_resp.status_code != 200:
        raise ValueError(
            f"Failed to fetch Google profile (HTTP {userinfo_resp.status_code})."
        )

    profile = userinfo_resp.json()
    email = str(profile.get("email") or "").strip()
    name = str(profile.get("name") or email or "Google User").strip()
    picture = str(profile.get("picture") or "").strip()
    google_sub = str(profile.get("sub") or email).strip()

    if not email:
        raise ValueError("Google account profile did not include an email address.")

    session = db.save_auth_session(
        google_sub=google_sub,
        email=email,
        name=name,
        picture=picture,
        access_token=access_token,
        refresh_token=refresh_token,
        token_expiry=time.time() + max(60.0, expires_in),
        scopes=granted_scopes,
    )
    logger.info("Authenticated Google user: %s (%s)", name, email)
    return sanitize_user(session) or {}


def get_valid_access_token() -> tuple[Optional[str], Optional[dict[str, Any]], str]:
    """Return a valid Google OAuth access token, refreshing automatically if expired."""
    session = db.get_auth_session()
    if not session:
        return None, None, "No Google account is currently signed in."

    access_token = str(session.get("access_token") or "")
    token_expiry = float(session.get("token_expiry") or 0.0)
    refresh_token = str(session.get("refresh_token") or "")

    # Still valid with >60s buffer
    if access_token and token_expiry > (time.time() + 60.0):
        return access_token, session, ""

    if not refresh_token:
        return (
            None,
            session,
            "Google OAuth token expired and no refresh token is stored. Please sign in again.",
        )

    if not settings.has_google_oauth_config:
        return None, session, "Google OAuth client credentials missing for token refresh."

    try:
        resp = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=10,
        )
        if resp.status_code != 200:
            return (
                None,
                session,
                f"Failed to refresh Google token (HTTP {resp.status_code}). Please sign in again.",
            )
        data = resp.json()
        new_access = str(data.get("access_token") or "")
        expires_in = float(data.get("expires_in", 3600))
        if not new_access:
            return None, session, "Token refresh response missing access_token."
        new_expiry = time.time() + max(60.0, expires_in)
        db.update_auth_tokens(new_access, new_expiry)
        session["access_token"] = new_access
        session["token_expiry"] = new_expiry
        return new_access, session, ""
    except requests.RequestException as exc:
        return None, session, f"Network error refreshing Google token: {exc}"


def logout_google_user() -> dict[str, Any]:
    """Revoke active OAuth token (best-effort) and clear persisted session."""
    session = db.get_auth_session()
    revoked = False
    if session and session.get("access_token"):
        try:
            r = requests.post(
                GOOGLE_REVOKE_URL,
                params={"token": session["access_token"]},
                timeout=3,
            )
            revoked = r.status_code == 200
        except requests.RequestException:
            revoked = False
    db.clear_auth_session()
    logger.info("Signed out Google user.")
    return {"signed_out": True, "revoked": revoked}
