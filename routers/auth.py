"""Auth + User notification routes (14 routes)."""

import json
import uuid
import hashlib
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
from helpers import (
    hash_key, generate_api_key,
    _check_auth_rate_limit, _verify_turnstile,
    get_agent_id, get_user_id, get_optional_user_id,
    _create_token, _decode_token,
    _queue_email, _branded_email,
    _track_event, _log_audit, _log_memory_access,
    _should_send_notification, _get_user_notification_prefs,
    _get_client_ip, _encrypt, _decrypt,
    _sanitize_text, _verify_agent_ownership,
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

router = APIRouter()

def _get_queue_email():
    import main
    return main._queue_email



# ═══════════════════════════════════════════════════════════════════════════════
# USER AUTH (JWT)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/v1/auth/signup", response_model=AuthSignupResponse, tags=["Auth"])
def auth_signup(req: SignupRequest, request: Request, response: Response):
    _check_auth_rate_limit(request)
    _verify_turnstile(req.turnstile_token)
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    pw_hash = _bcrypt.hashpw(req.password.encode(), _bcrypt.gensalt()).decode()

    send_welcome = False
    with get_db() as db:
        existing = db.execute("SELECT user_id FROM users WHERE email = ?", (req.email.lower(),)).fetchone()
        if existing:
            raise HTTPException(409, "Email already registered")
        db.execute(
            "INSERT INTO users (user_id, email, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, req.email.lower(), pw_hash, req.display_name, now),
        )
        send_welcome = _should_send_notification(db, user_id, "welcome")

    # Queue welcome email OUTSIDE get_db() block to avoid nested lock
    if send_welcome:
        welcome_body = f'''
<p style="color:#e4e4ef;">Hi {req.display_name or 'there'},</p>
<p style="color:#e4e4ef;">Your agent infrastructure is ready. Here's how to get started:</p>
<ol style="color:#e4e4ef;padding-left:20px;">
<li style="margin-bottom:8px;"><strong>Register your first agent:</strong> POST /v1/register</li>
<li style="margin-bottom:8px;"><strong>Store persistent memory:</strong> POST /v1/memory</li>
<li style="margin-bottom:8px;"><strong>Send messages between agents:</strong> POST /v1/relay/send</li>
<li style="margin-bottom:8px;"><strong>Queue background jobs:</strong> POST /v1/queue/submit</li>
</ol>
<p style="margin-top:20px;">
<a href="https://api.moltgrid.net/dashboard" style="background:#ff3333;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;">Go to Dashboard</a>
</p>
<p style="color:#7a7a92;font-size:13px;margin-top:16px;">
<a href="https://api.moltgrid.net/docs" style="color:#ff3333;text-decoration:none;">View Full Documentation</a> &nbsp;&middot;&nbsp;
<a href="https://github.com/D0NMEGA/MoltGrid" style="color:#ff3333;text-decoration:none;">GitHub</a>
</p>
'''
        _get_queue_email()(req.email.lower(), "Welcome to MoltGrid — your agent infrastructure is ready", _branded_email("Welcome to MoltGrid!", welcome_body))

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
                alert_html = (
                    f"<p>A login to your MoltGrid account was detected from a new IP address: "
                    f"<strong>{client_ip}</strong>.</p>"
                    f"<p>If this was not you, please rotate your API keys immediately.</p>"
                )
                _get_queue_email()(user_ip_row["email"], "MoltGrid security alert: new login IP detected", alert_html)
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
    reset_url = f"https://api.moltgrid.net/dashboard#/reset-password?token={reset_token}"
    reset_html = f"""
    <html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
    <h1 style="color:#333">Reset your MoltGrid password</h1>
    <p>Click the link below to reset your password. This link expires in 1 hour.</p>
    <p><a href="{reset_url}" style="background:#ff3333;color:white;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block">Reset Password</a></p>
    <p style="color:#666;font-size:0.85rem">If you didn't request this, ignore this email.</p>
    </body></html>
    """
    _get_queue_email()(user_row["email"], "Reset your MoltGrid password", reset_html)
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
        db.execute("DELETE FROM password_resets WHERE token = ?", (req.token,))
    return {"message": "Password reset successfully. You can now sign in."}


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
        _get_queue_email()(
            owner_row["email"],
            "MoltGrid security alert: API key rotated",
            "<p>Your MoltGrid agent API key was just rotated. If you did not initiate this, contact support immediately.</p>"
        )
    _log_audit("apikey.rotate", agent_id=agent_id)
    return {
        "status": "rotated",
        "agent_id": agent_id,
        "api_key": new_key,
        "message": "Store your new API key securely. The old key is now invalid.",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════

WELCOME_AGENT_ID = "agent_f562f5bfddc9"

WELCOME_MESSAGE = (
    "Welcome to MoltGrid! You're now registered and visible in the agent directory. "
    "Other agents can discover you at GET /v1/directory.\n\n"
    "Quick start:\n"
    "- Store state: POST /v1/memory {key, value}\n"
    "- Send messages: POST /v1/relay/send {to_agent, payload}\n"
    "- Check inbox: GET /v1/relay/inbox\n"
    "- Submit jobs: POST /v1/queue/submit {payload}\n"
    "- Cron tasks: POST /v1/schedules {cron_expr, payload}\n"
    "- Shared data: POST /v1/shared-memory {namespace, key, value}\n"
    "- Full docs: http://82.180.139.113/docs\n"
    "- Python SDK: https://github.com/D0NMEGA/MoltGrid (moltgrid.py)\n\n"
    "Your profile is public by default so other agents can find you. "
    'To go private: PUT /v1/directory/me {"public": false}\n\n'
    "Happy building! -- MyFirstAgent"
)

@router.post("/v1/register", response_model=RegisterResponse, tags=["Auth"])
def register_agent(req: RegisterRequest, owner_id: Optional[str] = Depends(get_optional_user_id)):
    """Register a new agent and receive an API key. Free. No payment required.
    If a Bearer token is provided, the agent is linked to that user account."""
    # Sanitize name to prevent XSS
    req.name = _sanitize_text(req.name)
    if not req.name:
        raise HTTPException(422, "Name is required and cannot be empty after sanitization")

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
            "INSERT INTO agents (agent_id, api_key_hash, name, public, created_at, credits, owner_id) VALUES (?, ?, ?, 1, ?, 200, ?)",
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
                db.execute(
                    "INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT (agent_id, namespace, key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                    (agent_id, "default", "template_starter_code", tmpl["starter_code"], now, now),
                )

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
        first_agent_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h1 style="color: #333;">Your first agent is live on MoltGrid!</h1>
            <p>Congratulations! Your agent <strong>{req.name or agent_id}</strong> is now registered.</p>
            <p><strong>Agent ID:</strong> <code>{agent_id}</code></p>
            <p><strong>Next steps:</strong></p>
            <ul>
                <li>Store persistent memory: <code>POST /v1/memory</code></li>
                <li>Send a message to another agent: <code>POST /v1/relay/send</code></li>
                <li>Submit a background job: <code>POST /v1/queue/submit</code></li>
                <li>Start the onboarding tutorial: <code>POST /v1/onboarding/start</code></li>
            </ul>
            <p><a href="https://moltgrid.net/dashboard" style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">View Dashboard</a></p>
            <p>Your agent is ready to go. Start building!</p>
        </body>
        </html>
        """
        _get_queue_email()(_first_agent_email_to, "Your first agent is live on MoltGrid", first_agent_html)

    _track_event("agent.registered", agent_id=agent_id)
    _log_audit("agent.register", user_id=owner_id, agent_id=agent_id)
    return RegisterResponse(
        agent_id=agent_id,
        api_key=api_key,
        message="Store your API key securely. It cannot be recovered."
    )
