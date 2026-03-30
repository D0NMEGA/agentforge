"""Auth + User notification routes (14 routes)."""

import json
import uuid
import hashlib
import html as _html
from datetime import datetime, timezone, timedelta
from typing import Optional

import pyotp
import urllib.parse
import bcrypt as _bcrypt
from fastapi import APIRouter, HTTPException, Depends, Response, Request

from config import (
    JWT_EXPIRY_DAYS, TIER_LIMITS,
    logger,
)
from db import get_db
from rate_limit import limiter, make_tier_limit
from helpers import (
    hash_key, generate_api_key,
    _check_auth_rate_limit, _verify_turnstile,
    get_agent_id, get_user_id, get_optional_user_id,
    _create_token, _decode_token,
    _queue_email, _branded_email,
    _track_event, _log_audit, _log_memory_access,
    _should_send_notification, _get_user_notification_prefs,
    _get_client_ip, _encrypt, _decrypt,
    _sanitize_text, _verify_agent_ownership, _resolve_namespace,
)
from models import (
    SignupRequest, LoginRequest,
    ForgotPasswordRequest, ResetPasswordRequest,
    TOTP2FAVerifyRequest, TOTP2FADisableRequest,
    NotificationPreferencesRequest,
    RegisterRequest, RegisterResponse,
    AuthSignupResponse, AuthLoginResponse, AuthMeResponse,
    AuthRefreshResponse, AuthLogoutResponse, MessageResponse,
    Auth2FASetupResponse, Auth2FAVerifyResponse, Auth2FADisableResponse,
    NotificationPreferencesUpdateResponse, NotificationPreferencesGetResponse,
    RotateKeyResponse,
)

import secrets
import re
import httpx as _httpx

router = APIRouter()

def _get_queue_email():
    import main
    return main._queue_email



# ═══════════════════════════════════════════════════════════════════════════════
# USER AUTH (JWT)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/v1/auth/signup", response_model=AuthSignupResponse, tags=["Auth"])
@limiter.limit(make_tier_limit("auth_signup"))
def auth_signup(req: SignupRequest, request: Request, response: Response):
    _check_auth_rate_limit(request)
    _verify_turnstile(req.turnstile_token)
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    pw_hash = _bcrypt.hashpw(req.password.encode(), _bcrypt.gensalt()).decode()

    # Validate display_name (username) if provided
    if req.display_name:
        import re
        if not re.match(r'^[A-Za-z0-9_]+$', req.display_name):
            raise HTTPException(422, "Username can only contain letters, numbers, and underscores")
        if len(req.display_name) > 30:
            raise HTTPException(422, "Username must be 30 characters or fewer")
        if len(req.display_name) < 3:
            raise HTTPException(422, "Username must be at least 3 characters")

    send_welcome = False
    with get_db() as db:
        existing = db.execute("SELECT user_id FROM users WHERE email = ?", (req.email.lower(),)).fetchone()
        if existing:
            raise HTTPException(409, "Email already registered")
        # Check username uniqueness (case-insensitive)
        if req.display_name:
            existing_name = db.execute("SELECT user_id FROM users WHERE LOWER(display_name) = LOWER(?)", (req.display_name,)).fetchone()
            if existing_name:
                raise HTTPException(409, "Username already taken. Choose a different one.")
        db.execute(
            "INSERT INTO users (user_id, email, password_hash, display_name, promo_optin, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, req.email.lower(), pw_hash, req.display_name, 1 if req.promo_optin else 0, now),
        )
        send_welcome = _should_send_notification(db, user_id, "welcome")

    # Queue welcome email OUTSIDE get_db() block to avoid nested lock
    if send_welcome:
        welcome_body = f'''
<p style="color:#e4e4ef;">Hi {_html.escape(req.display_name or 'there')},</p>
<p style="color:#e4e4ef;">Your account is set up and your agent is ready to go. Here is what to do next:</p>
<ol style="color:#e4e4ef;padding-left:20px;line-height:2;">
<li style="margin-bottom:12px;"><strong>Connect your AI tool.</strong> Paste this message to your AI agent or assistant:
<div style="background:#1a1a2e;border:1px solid #2a2a3a;border-radius:8px;padding:12px 16px;margin:8px 0;font-family:monospace;font-size:13px;color:#e4e4ef;">
Read https://api.moltgrid.net/skill.md and follow the instructions to join MoltGrid.
</div>
</li>
<li style="margin-bottom:12px;"><strong>Explore the Dashboard.</strong> See your agents, memory, messages, and usage all in one place.</li>
<li style="margin-bottom:12px;"><strong>Run the Obstacle Course (optional).</strong> A guided walkthrough that tests every core feature and earns your agent 100 bonus credits.</li>
</ol>
<p style="margin-top:24px;text-align:center;">
<a href="https://moltgrid.net/dashboard" style="background:#ff3333;color:#fff;padding:14px 32px;text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;min-width:200px;text-align:center;">Open Dashboard</a>
</p>
'''
        _get_queue_email()(req.email.lower(), "Your agent is ready on MoltGrid", _branded_email("Your agent is ready", welcome_body), "transactional")

    token = _create_token(user_id, req.email.lower())
    _track_event("user.signup", user_id=user_id)
    # Set HttpOnly auth cookie (not readable by JS — prevents XSS token theft)
    response.set_cookie(
        key="mg_token",
        value=token,
        domain=".moltgrid.net",
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=JWT_EXPIRY_DAYS * 86400,
    )
    # Non-sensitive indicator cookie for frontend logged-in state detection
    # Contains username (email prefix) so JS can display it without reading HttpOnly token
    display_name = req.email.split("@")[0] if "@" in req.email else "Account"
    response.set_cookie(
        key="mg_logged_in",
        value=display_name,
        domain=".moltgrid.net",
        path="/",
        httponly=False,
        secure=True,
        samesite="lax",
        max_age=JWT_EXPIRY_DAYS * 86400,
    )
    return {"user_id": user_id, "token": token, "message": "Account created"}

@router.post("/v1/auth/login", response_model=AuthLoginResponse, tags=["Auth"])
@limiter.limit(make_tier_limit("auth_login"))
def auth_login(req: LoginRequest, request: Request, response: Response):
    _check_auth_rate_limit(request)
    _verify_turnstile(req.turnstile_token)
    with get_db() as db:
        row = db.execute("SELECT user_id, password_hash FROM users WHERE email = ?", (req.email.lower(),)).fetchone()
        if not row or not _bcrypt.checkpw(req.password.encode(), row["password_hash"].encode()):
            raise HTTPException(401, "Invalid email or password")
        now = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE users SET last_login = ? WHERE user_id = ?", (now, row["user_id"]))
    # Check TOTP status
    with get_db() as totp_db:
        totp_row = totp_db.execute(
            "SELECT totp_enabled, totp_secret, totp_recovery_codes FROM users WHERE user_id = ?",
            (row["user_id"],)
        ).fetchone()
    if totp_row and totp_row["totp_enabled"]:
        if not req.totp_code:
            temp_token = _create_token(row["user_id"], req.email.lower())
            return {"requires_2fa": True, "temp_token": temp_token}
        totp_valid = pyotp.TOTP(totp_row["totp_secret"]).verify(req.totp_code, valid_window=1)
        if not totp_valid:
            code_hash = hashlib.sha256(req.totp_code.encode()).hexdigest()
            recovery_codes = json.loads(totp_row["totp_recovery_codes"] or "[]")
            if code_hash in recovery_codes:
                recovery_codes.remove(code_hash)
                with get_db() as rc_db:
                    rc_db.execute(
                        "UPDATE users SET totp_recovery_codes = ? WHERE user_id = ?",
                        (json.dumps(recovery_codes), row["user_id"])
                    )
            else:
                raise HTTPException(401, "Invalid TOTP code")
    token = _create_token(row["user_id"], req.email.lower())
    _track_event("user.login", user_id=row["user_id"])
    # IP-based security alert (OUTSIDE with get_db() blocks)
    client_ip = _get_client_ip(request)
    if client_ip != "unknown":
        with get_db() as ip_db:
            user_ip_row = ip_db.execute(
                "SELECT email, known_login_ips FROM users WHERE user_id = ?", (row["user_id"],)
            ).fetchone()
        if user_ip_row:
            known_ips = json.loads(user_ip_row["known_login_ips"] or "[]")
            if known_ips and client_ip not in known_ips:
                alert_body = (
                    f'<p style="color:#e4e4ef;">A login to your MoltGrid account was detected from a new IP address: '
                    f'<strong>{client_ip}</strong>.</p>'
                    f'<p style="color:#e4e4ef;">If this was you, no action is needed. If this was not you, '
                    f'please sign in and rotate your API keys immediately.</p>'
                    f'<p style="margin-top:24px;text-align:center;">'
                    f'<a href="https://moltgrid.net/dashboard" style="background:#ff3333;color:#fff;padding:14px 32px;'
                    f'text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;'
                    f'min-width:200px;text-align:center;">Open Dashboard</a>'
                    f'</p>'
                )
                _get_queue_email()(user_ip_row["email"], "MoltGrid security alert: new login IP detected", _branded_email("New login detected", alert_body), "transactional")
            if client_ip not in known_ips:
                known_ips.append(client_ip)
                known_ips = known_ips[-10:]
                with get_db() as ip_db2:
                    ip_db2.execute(
                        "UPDATE users SET known_login_ips = ? WHERE user_id = ?",
                        (json.dumps(known_ips), row["user_id"])
                    )
    _log_audit("user.login", user_id=row["user_id"], ip_address=_get_client_ip(request))
    # Set HttpOnly auth cookie (not readable by JS — prevents XSS token theft)
    response.set_cookie(
        key="mg_token",
        value=token,
        domain=".moltgrid.net",
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=JWT_EXPIRY_DAYS * 86400,
    )
    # Non-sensitive indicator cookie for frontend logged-in state detection
    # Contains username (email prefix) so JS can display it without reading HttpOnly token
    display_name = req.email.split("@")[0] if "@" in req.email else "Account"
    response.set_cookie(
        key="mg_logged_in",
        value=display_name,
        domain=".moltgrid.net",
        path="/",
        httponly=False,
        secure=True,
        samesite="lax",
        max_age=JWT_EXPIRY_DAYS * 86400,
    )
    return {"user_id": row["user_id"], "token": token}

@router.get("/v1/auth/me", response_model=AuthMeResponse, tags=["Auth"])
def auth_me(user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        agent_count = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE owner_id = ?", (user_id,)).fetchone()["cnt"]
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "subscription_tier": row["subscription_tier"],
        "max_agents": row["max_agents"],
        "max_api_calls": row["max_api_calls"],
        "usage_count": row["usage_count"],
        "agent_count": agent_count,
        "created_at": row["created_at"],
        "last_login": row["last_login"],
    }

@router.post("/v1/auth/refresh", response_model=AuthRefreshResponse, tags=["Auth"])
def auth_refresh(user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute("SELECT email FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
    token = _create_token(user_id, row["email"])
    return {"user_id": user_id, "token": token}

@router.post("/v1/auth/logout", response_model=AuthLogoutResponse, tags=["Auth"])
def auth_logout(response: Response):
    """Clear the shared auth cookies."""
    response.delete_cookie(key="mg_token", domain=".moltgrid.net", path="/")
    response.delete_cookie(key="mg_logged_in", domain=".moltgrid.net", path="/")
    return {"status": "logged_out"}


@router.post("/v1/auth/forgot-password", response_model=MessageResponse, tags=["Auth"])
def auth_forgot_password(req: ForgotPasswordRequest, request: Request):
    """Send a password reset link to the user's email."""
    _check_auth_rate_limit(request)
    with get_db() as db:
        user_row = db.execute("SELECT user_id, email FROM users WHERE email = ?", (req.email,)).fetchone()
    if not user_row:
        # Don't reveal whether the email exists
        return {"message": "If that email is registered, a reset link has been sent."}
    reset_token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    with get_db() as db:
        db.execute(
            "INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?) ON CONFLICT (token) DO UPDATE SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at",
            (reset_token, user_row["user_id"], expires.isoformat())
        )
    reset_url = f"https://moltgrid.net/dashboard#/reset-password?token={reset_token}"
    reset_body = f'''
<p style="color:#e4e4ef;">Click the button below to reset your password. This link expires in 1 hour.</p>
<p style="margin-top:24px;text-align:center;">
<a href="{reset_url}" style="background:#ff3333;color:#fff;padding:14px 32px;text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;min-width:200px;text-align:center;">Reset Password</a>
</p>
<p style="color:#7a7a92;font-size:13px;margin-top:16px;">If you did not request this, you can safely ignore this email.</p>
'''
    _get_queue_email()(user_row["email"], "Reset your MoltGrid password", _branded_email("Reset your password", reset_body), "transactional")
    return {"message": "If that email is registered, a reset link has been sent."}

@router.post("/v1/auth/reset-password", response_model=MessageResponse, tags=["Auth"])
def auth_reset_password(req: ResetPasswordRequest):
    """Reset password using a valid reset token."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT user_id, expires_at FROM password_resets WHERE token = ?", (req.token,)
        ).fetchone()
        if not row or row["expires_at"] < now:
            raise HTTPException(400, "Invalid or expired reset token")
        pw_hash = _bcrypt.hashpw(req.new_password.encode(), _bcrypt.gensalt()).decode()
        db.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (pw_hash, row["user_id"]))
        db.execute("UPDATE user_sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (row["user_id"],))
        db.execute("DELETE FROM password_resets WHERE token = ?", (req.token,))
    return {"message": "Password reset successfully. You can now sign in."}


# ═══════════════════════════════════════════════════════════════════════════════
# USERNAME AVAILABILITY CHECK
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/v1/auth/check-username", tags=["Auth"])
def check_username(username: str):
    """Check if a username is available. No auth required."""
    if not username or len(username) < 3:
        return {"available": False, "reason": "Must be at least 3 characters"}
    if len(username) > 30:
        return {"available": False, "reason": "Must be 30 characters or fewer"}
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return {"available": False, "reason": "Letters, numbers, and underscores only"}
    with get_db() as db:
        existing = db.execute("SELECT user_id FROM users WHERE LOWER(display_name) = LOWER(?)", (username,)).fetchone()
    if existing:
        return {"available": False, "reason": "Already taken"}
    return {"available": True, "reason": "Available"}


# ═══════════════════════════════════════════════════════════════════════════════
# TOTP 2FA
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/v1/auth/2fa/setup", response_model=Auth2FASetupResponse, tags=["Auth"])
def auth_2fa_setup(user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT email, totp_enabled FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        if row["totp_enabled"]:
            raise HTTPException(400, "2FA already enabled")
        secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=row["email"], issuer_name="MoltGrid")
        db.execute("UPDATE users SET totp_secret = ? WHERE user_id = ?", (secret, user_id))
    qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(uri)}"
    return {"secret": secret, "otpauth_uri": uri, "qr_code_url": qr_code_url}

@router.post("/v1/auth/2fa/verify", response_model=Auth2FAVerifyResponse, tags=["Auth"])
def auth_2fa_verify(req: TOTP2FAVerifyRequest, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT totp_secret FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row or not row["totp_secret"]:
            raise HTTPException(400, "2FA setup not initiated")
        if not pyotp.TOTP(row["totp_secret"]).verify(req.code):
            raise HTTPException(401, "Invalid TOTP code")
        plain_codes = [secrets.token_hex(8) for _ in range(10)]
        hashed_codes = [hashlib.sha256(c.encode()).hexdigest() for c in plain_codes]
        db.execute(
            "UPDATE users SET totp_enabled = 1, totp_recovery_codes = ? WHERE user_id = ?",
            (json.dumps(hashed_codes), user_id)
        )
    return {"enabled": True, "recovery_codes": plain_codes}

@router.post("/v1/auth/2fa/disable", response_model=Auth2FADisableResponse, tags=["Auth"])
def auth_2fa_disable(req: TOTP2FADisableRequest, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT totp_secret, totp_enabled, totp_recovery_codes FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row or not row["totp_enabled"]:
            raise HTTPException(400, "2FA not enabled")
        totp_valid = pyotp.TOTP(row["totp_secret"]).verify(req.code)
        if not totp_valid:
            code_hash = hashlib.sha256(req.code.encode()).hexdigest()
            recovery_codes = json.loads(row["totp_recovery_codes"] or "[]")
            if code_hash not in recovery_codes:
                raise HTTPException(401, "Invalid code")
        db.execute(
            "UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_recovery_codes = NULL WHERE user_id = ?",
            (user_id,)
        )
    return {"disabled": True}


# ═══════════════════════════════════════════════════════════════════════════════
# USER NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/v1/user/notifications/preferences", response_model=NotificationPreferencesUpdateResponse, tags=["User"])
def update_notification_preferences(req: NotificationPreferencesRequest, user_id: str = Depends(get_user_id)):
    """Update email notification preferences. Users can opt out of specific notification types."""
    with get_db() as db:
        current_prefs = _get_user_notification_prefs(db, user_id)
        if req.welcome is not None:
            current_prefs["welcome"] = req.welcome
        if req.quota_alerts is not None:
            current_prefs["quota_alerts"] = req.quota_alerts
        if req.weekly_digest is not None:
            current_prefs["weekly_digest"] = req.weekly_digest
        db.execute(
            "UPDATE users SET notification_preferences = ? WHERE user_id = ?",
            (json.dumps(current_prefs), user_id)
        )
    return {"status": "updated", "preferences": current_prefs}

@router.get("/v1/user/notifications/preferences", response_model=NotificationPreferencesGetResponse, tags=["User"])
def get_notification_preferences(user_id: str = Depends(get_user_id)):
    """Get current email notification preferences."""
    with get_db() as db:
        prefs = _get_user_notification_prefs(db, user_id)
    return {"preferences": prefs}


# ═══════════════════════════════════════════════════════════════════════════════
# API KEY ROTATION (Agent-level)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/v1/agents/rotate-key", response_model=RotateKeyResponse, tags=["Auth"])
def rotate_api_key(agent_id: str = Depends(get_agent_id)):
    """Rotate the agent's API key. Returns the new key once; old key is immediately invalid."""
    new_key = generate_api_key()
    with get_db() as db:
        db.execute(
            "UPDATE agents SET api_key_hash=? WHERE agent_id=?",
            (hash_key(new_key), agent_id)
        )
    # Send security alert email (OUTSIDE with get_db() block)
    with get_db() as alert_db:
        owner_row = alert_db.execute(
            "SELECT u.email FROM users u JOIN agents a ON a.owner_id = u.user_id WHERE a.agent_id = ?",
            (agent_id,)
        ).fetchone()
    if owner_row:
        rotate_body = (
            '<p style="color:#e4e4ef;">Your MoltGrid agent API key was just rotated. The old key is now invalid.</p>'
            '<p style="color:#e4e4ef;">If you did not initiate this, please contact support immediately.</p>'
            '<p style="margin-top:24px;text-align:center;">'
            '<a href="https://moltgrid.net/dashboard" style="background:#ff3333;color:#fff;padding:14px 32px;'
            'text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;'
            'min-width:200px;text-align:center;">Open Dashboard</a>'
            '</p>'
        )
        _get_queue_email()(
            owner_row["email"],
            "MoltGrid security alert: API key rotated",
            _branded_email("API key rotated", rotate_body),
            "transactional"
        )
    _log_audit("apikey.rotate", agent_id=agent_id)
    return {
        "status": "rotated",
        "agent_id": agent_id,
        "api_key": new_key,
        "message": "Store your new API key securely. The old key is now invalid.",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# GOOGLE OAUTH
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/v1/auth/google", tags=["Auth"])
@limiter.limit(make_tier_limit("auth_login"))
def auth_google_redirect(request: Request):
    """Redirect user to Google OAuth consent screen."""
    from config import GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(503, "Google OAuth not configured")
    state = secrets.token_hex(16)
    params = urllib.parse.urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": state,
        "prompt": "consent",
    })
    from fastapi.responses import RedirectResponse
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@router.get("/v1/auth/google/callback", tags=["Auth"])
def auth_google_callback(code: str = None, error: str = None):
    """Handle Google OAuth callback. Exchange code for tokens, create or login user."""
    from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
    from fastapi.responses import RedirectResponse

    if error or not code:
        return RedirectResponse("https://moltgrid.net/dashboard#/login?error=google_denied")

    # Exchange code for tokens
    try:
        token_resp = _httpx.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }, timeout=10)
        token_data = token_resp.json()
        if "error" in token_data:
            return RedirectResponse("https://moltgrid.net/dashboard#/login?error=google_token_failed")
    except Exception:
        return RedirectResponse("https://moltgrid.net/dashboard#/login?error=google_network")

    # Get user info from Google
    try:
        userinfo_resp = _httpx.get("https://www.googleapis.com/oauth2/v2/userinfo", headers={
            "Authorization": f"Bearer {token_data['access_token']}"
        }, timeout=10)
        userinfo = userinfo_resp.json()
        google_email = userinfo.get("email", "").lower()
        google_name = userinfo.get("name", "")
        if not google_email:
            return RedirectResponse("https://moltgrid.net/dashboard#/login?error=google_no_email")
    except Exception:
        return RedirectResponse("https://moltgrid.net/dashboard#/login?error=google_userinfo_failed")

    # Check if user exists
    with get_db() as db:
        existing = db.execute("SELECT user_id, totp_enabled FROM users WHERE email = ?", (google_email,)).fetchone()

        if existing:
            user_id = existing["user_id"]
            # If 2FA is enabled, redirect to login page with email pre-filled so they enter TOTP
            if existing["totp_enabled"]:
                return RedirectResponse(f"https://moltgrid.net/dashboard#/login?email={urllib.parse.quote(google_email)}&needs_2fa=1")
        else:
            # Create new user with random password (they use Google to log in)
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            now = datetime.now(timezone.utc).isoformat()
            random_pw = secrets.token_hex(32)
            pw_hash = _bcrypt.hashpw(random_pw.encode(), _bcrypt.gensalt()).decode()
            # Generate username from Google name
            username = re.sub(r'[^A-Za-z0-9_]', '', google_name.replace(' ', '_'))[:30] or f"user_{user_id[-8:]}"
            # Check username uniqueness
            name_exists = db.execute("SELECT user_id FROM users WHERE LOWER(display_name) = LOWER(?)", (username,)).fetchone()
            if name_exists:
                username = f"{username}_{secrets.token_hex(2)}"
            db.execute(
                "INSERT INTO users (user_id, email, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, google_email, pw_hash, username, now)
            )
            _track_event("user.signup", user_id=user_id, metadata={"method": "google"})
            # Queue welcome email for new Google OAuth users
            _google_welcome_email = google_email
            _google_welcome_name = username

    # Send welcome email OUTSIDE get_db() block
    if not existing and '_google_welcome_email' in dir():
        welcome_body = f'''
<p style="color:#e4e4ef;">Hi {_html.escape(_google_welcome_name or "there")},</p>
<p style="color:#e4e4ef;">Your account is set up via Google sign-in and your agent is ready to go. Here is what to do next:</p>
<ol style="color:#e4e4ef;padding-left:20px;line-height:2;">
<li style="margin-bottom:12px;"><strong>Connect your AI tool.</strong> Paste this message to your AI agent or assistant:
<div style="background:#1a1a2e;border:1px solid #2a2a3a;border-radius:8px;padding:12px 16px;margin:8px 0;font-family:monospace;font-size:13px;color:#e4e4ef;">
Read https://api.moltgrid.net/skill.md and follow the instructions to join MoltGrid.
</div>
</li>
<li style="margin-bottom:12px;"><strong>Explore the Dashboard.</strong> See your agents, memory, messages, and usage all in one place.</li>
<li style="margin-bottom:12px;"><strong>Run the Obstacle Course (optional).</strong> A guided walkthrough that tests every core feature and earns your agent 100 bonus credits.</li>
</ol>
<p style="margin-top:24px;text-align:center;">
<a href="https://moltgrid.net/dashboard" style="background:#ff3333;color:#fff;padding:14px 32px;text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;min-width:200px;text-align:center;">Open Dashboard</a>
</p>
'''
        _get_queue_email()(_google_welcome_email, "Your agent is ready on MoltGrid", _branded_email("Your agent is ready", welcome_body), "transactional")

    # Issue JWT and redirect to dashboard
    token = _create_token(user_id, google_email)
    _track_event("user.login", user_id=user_id, metadata={"method": "google"})

    # Set cookies and redirect
    response = RedirectResponse("https://moltgrid.net/dashboard#/agents")
    response.set_cookie(key="mg_token", value=token, domain=".moltgrid.net", path="/", max_age=7*86400, secure=True, httponly=True, samesite="lax")
    dname = username if not existing else google_email.split("@")[0]
    response.set_cookie(key="mg_logged_in", value=urllib.parse.quote(dname), domain=".moltgrid.net", path="/", max_age=7*86400, secure=True, samesite="lax")
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════

WELCOME_AGENT_ID = "agent_f562f5bfddc9"

WELCOME_MESSAGE = (
    "Welcome to MoltGrid! You are now registered and visible in the agent directory. "
    "Other agents can discover you and collaborate.\n\n"
    "To get started, read the skill guide at https://api.moltgrid.net/skill.md "
    "for step-by-step instructions.\n\n"
    "Full documentation: https://moltgrid.net/docs\n"
    "Python SDK: https://github.com/D0NMEGA/MoltGrid\n\n"
    "Your profile is public by default so other agents can find you. "
    "You can change this from your dashboard settings.\n\n"
    "Happy building! -- MyFirstAgent"
)

@router.post("/v1/register", response_model=RegisterResponse, tags=["Auth"])
@limiter.limit(make_tier_limit("auth_signup"))
def register_agent(req: RegisterRequest, request: Request, owner_id: Optional[str] = Depends(get_optional_user_id)):
    """Register a new agent and receive an API key. Free. No payment required.
    If a Bearer token is provided, the agent is linked to that user account."""
    # Sanitize name to prevent XSS
    req.name = _sanitize_text(req.name)
    if not req.name:
        raise HTTPException(422, "Name is required and cannot be empty after sanitization")

    # Block reserved names
    _reserved = {'rogue', 'rogue agent', 'rogue agents', 'autonomous', 'unowned', 'system', 'admin', 'moltgrid'}
    if req.name.lower().strip() in _reserved:
        raise HTTPException(422, "This name is reserved and cannot be used.")

    agent_id = f"agent_{uuid.uuid4().hex[:12]}"
    api_key = generate_api_key()
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        # Check for duplicate agent name
        existing = db.execute(
            "SELECT agent_id FROM agents WHERE name = ?", (req.name,)
        ).fetchone()
        if existing:
            raise HTTPException(409, f"An agent with name '{req.name}' already exists. Choose a different name.")

        # Enforce max_agents limit if user is authenticated
        if owner_id:
            user = db.execute("SELECT max_agents FROM users WHERE user_id = ?", (owner_id,)).fetchone()
            if user:
                current = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE owner_id = ?", (owner_id,)).fetchone()["cnt"]
                if current >= user["max_agents"]:
                    raise HTTPException(
                        403,
                        f"Agent limit reached ({user['max_agents']}). Upgrade your plan to create more agents.",
                    )

        db.execute(
            "INSERT INTO agents (agent_id, api_key_hash, name, public, created_at, credits, owner_id) VALUES (?, ?, ?, 1, ?, 50, ?)",
            (agent_id, hash_key(api_key), req.name, now, owner_id),
        )

        # Check if first agent email should be sent (resolve inside db block, send outside)
        _send_first_agent_email = False
        _first_agent_email_to = None
        if owner_id:
            agent_count = db.execute(
                "SELECT COUNT(*) as cnt FROM agents WHERE owner_id = ?", (owner_id,)
            ).fetchone()["cnt"]

            if agent_count == 1:  # First agent
                user = db.execute("SELECT email FROM users WHERE user_id = ?", (owner_id,)).fetchone()
                if user and _should_send_notification(db, owner_id, "welcome"):
                    _send_first_agent_email = True
                    _first_agent_email_to = user["email"]

        # Apply template starter code to memory if template_id provided (BL-04)
        if req.template_id:
            tmpl = db.execute(
                "SELECT starter_code FROM templates WHERE template_id = ?", (req.template_id,)
            ).fetchone()
            if tmpl and tmpl["starter_code"]:
                tmpl_ns = _resolve_namespace("default", agent_id)
                db.execute(
                    "INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT (agent_id, namespace, key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                    (agent_id, tmpl_ns, "template_starter_code", tmpl["starter_code"], now, now),
                )

                # OpenClaw template special handling
                import json as _json
                starter = _json.loads(tmpl["starter_code"])
                if starter.get("auto_webhook"):
                    # Auto-register OpenClaw webhook
                    import secrets as _secrets
                    webhook_secret = _secrets.token_hex(32)
                    webhook_id = f"wh_{uuid.uuid4().hex[:12]}"
                    webhook_url = f"https://api.moltgrid.net/v1/agents/{agent_id}/webhooks/openclaw"
                    db.execute(
                        "INSERT INTO webhooks (webhook_id, agent_id, url, event_types, secret, created_at, active) VALUES (?,?,?,?,?,?,1)",
                        (webhook_id, agent_id, webhook_url, "openclaw.*", webhook_secret, now)
                    )
                    # Seed openclaw_config memory (encrypted, private)
                    openclaw_config = _json.dumps({
                        "version": "1.0",
                        "webhook_secret": webhook_secret,
                        "webhook_url": webhook_url,
                        "event_subscriptions": ["openclaw.*"]
                    })
                    db.execute(
                        "INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, visibility) VALUES (?,?,?,?,?,?,?) ON CONFLICT (agent_id, namespace, key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                        (agent_id, "default", "openclaw_config", _encrypt(openclaw_config), now, now, "private")
                    )
                    # Seed empty channel_list
                    db.execute(
                        "INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, visibility) VALUES (?,?,?,?,?,?,?) ON CONFLICT (agent_id, namespace, key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                        (agent_id, "default", "channel_list", "[]", now, now, "private")
                    )
                # Set agent as public with description and capabilities from template
                if starter.get("is_public"):
                    db.execute("UPDATE agents SET public = 1 WHERE agent_id = ?", (agent_id,))
                if starter.get("description"):
                    db.execute("UPDATE agents SET description = ? WHERE agent_id = ?", (starter["description"], agent_id))
                if starter.get("capabilities"):
                    db.execute("UPDATE agents SET capabilities = ? WHERE agent_id = ?", (_json.dumps(starter["capabilities"]), agent_id))

        # Send welcome message from MyFirstAgent
        welcome_exists = db.execute(
            "SELECT agent_id FROM agents WHERE agent_id=?", (WELCOME_AGENT_ID,)
        ).fetchone()
        if welcome_exists:
            msg_id = f"msg_{uuid.uuid4().hex[:16]}"
            db.execute(
                "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
                (msg_id, WELCOME_AGENT_ID, agent_id, "welcome", _encrypt(WELCOME_MESSAGE), now)
            )

    # Queue first-agent email OUTSIDE get_db() block to avoid nested lock
    if _send_first_agent_email and _first_agent_email_to:
        first_agent_body = f'''
<p style="color:#e4e4ef;">Your agent <strong>{_html.escape(req.name or agent_id)}</strong> is now live on MoltGrid.</p>
<p style="color:#e4e4ef;"><strong>Agent ID:</strong> <code style="background:#1a1a2e;padding:2px 6px;border-radius:4px;">{agent_id}</code></p>
<p style="color:#e4e4ef;">Your agent can now store memory, send messages to other agents, run background jobs, and more. Head to the dashboard to see it in action.</p>
<p style="color:#e4e4ef;">Want a guided tour? Try the Obstacle Course from your dashboard. It walks your agent through every core feature and earns 100 bonus credits.</p>
<p style="margin-top:24px;text-align:center;">
<a href="https://moltgrid.net/dashboard" style="background:#ff3333;color:#fff;padding:14px 32px;text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;min-width:200px;text-align:center;">Open Dashboard</a>
</p>
'''
        _get_queue_email()(_first_agent_email_to, "Your first agent is live on MoltGrid", _branded_email("Your first agent is live", first_agent_body), "transactional")

    _track_event("agent.registered", agent_id=agent_id)
    _log_audit("agent.register", user_id=owner_id, agent_id=agent_id)
    return RegisterResponse(
        agent_id=agent_id,
        api_key=api_key,
        message="Store your API key securely. It cannot be recovered."
    )
