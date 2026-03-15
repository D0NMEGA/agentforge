"""
MoltGrid Shared Helpers — cross-cutting helper functions and background loops.
Extracted from main.py to serve as shared utilities for router modules.
"""

import os
import json
import time
import uuid
import hashlib
import hmac as _hmac
import secrets
import threading
import logging
import re as _re
import html as _html
import smtplib
import ipaddress
import socket
import base64
import io
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from typing import Optional, List

import httpx
import jwt as pyjwt
import bcrypt as _bcrypt
import stripe
import pyotp
import urllib.parse
import qrcode
import qrcode.image.svg
import numpy as np
from croniter import croniter
from sentence_transformers import SentenceTransformer
from fastapi import HTTPException, Header, Depends, Query, Request

from config import (
    MAX_MEMORY_VALUE_SIZE, MAX_QUEUE_PAYLOAD_SIZE,
    RATE_LIMIT_WINDOW, RATE_LIMIT_MAX,
    TIER_RATE_LIMITS, TIER_LIMITS,
    ADMIN_PASSWORD_HASH, ADMIN_SESSION_TTL,
    ENCRYPTION_KEY, _fernet,
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_DAYS,
    MOLTBOOK_SERVICE_KEY,
    STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
    STRIPE_TIER_PRICES,
    SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_TO, SMTP_PASSWORD,
    TURNSTILE_SECRET_KEY,
    AUTH_RATE_LIMIT_MAX, AUTH_RATE_LIMIT_WINDOW,
    logger,
)
from state import _ws_connections, _auth_rate_limits, _embed_model, _embed_lock
from db import get_db, get_standalone_conn, DB_PATH, DB_BACKEND


# ═══════════════════════════════════════════════════════════════════════════════
# ENCRYPTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _encrypt(plaintext: str) -> str:
    """Encrypt a value for storage. No-op if ENCRYPTION_KEY is not set."""
    if not _fernet:
        return plaintext
    return "ENC:" + _fernet.encrypt(plaintext.encode()).decode()

def _decrypt(ciphertext: str) -> str:
    """Decrypt a value from storage. Handles both encrypted and plaintext."""
    if not ciphertext or not _fernet:
        return ciphertext or ""
    if ciphertext.startswith("ENC:"):
        try:
            from cryptography.fernet import InvalidToken
            return _fernet.decrypt(ciphertext[4:].encode()).decode()
        except (InvalidToken, Exception):
            return ciphertext  # Return as-is if decryption fails
    return ciphertext  # Plaintext (pre-encryption data)


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def generate_api_key() -> str:
    return f"af_{uuid.uuid4().hex}"

def _http_code_to_slug(status: int) -> str:
    return {
        400: "bad_request", 401: "unauthorized", 403: "forbidden",
        404: "not_found", 409: "conflict", 422: "validation_error",
        429: "rate_limit_exceeded", 500: "internal_error", 503: "service_unavailable",
    }.get(status, f"http_{status}")

def _check_auth_rate_limit(request: "Request"):
    """Block auth attempts if IP exceeds 10 requests per 5 minutes."""
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
    if ip == "testclient":
        return  # skip rate limiting in test environment
    now = time.time()
    attempts = _auth_rate_limits.get(ip, [])
    attempts = [t for t in attempts if now - t < AUTH_RATE_LIMIT_WINDOW]
    if len(attempts) >= AUTH_RATE_LIMIT_MAX:
        raise HTTPException(429, "Too many authentication attempts. Try again in a few minutes.")
    attempts.append(now)
    _auth_rate_limits[ip] = attempts


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYTICS / TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

def _track_event(event_name: str, user_id: str = None, agent_id: str = None, metadata: dict = None):
    """Insert a lightweight analytics event. Non-blocking best-effort."""
    conn = None
    try:
        conn = get_standalone_conn()
        conn.execute(
            "INSERT INTO analytics_events (id, event_name, user_id, agent_id, metadata, created_at) VALUES (?,?,?,?,?,?)",
            (f"evt_{uuid.uuid4().hex[:16]}", event_name, user_id, agent_id,
             json.dumps(metadata) if metadata else None,
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    except Exception:
        pass  # Never let analytics break the app
    finally:
        if conn:
            conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION PREFERENCES
# ═══════════════════════════════════════════════════════════════════════════════

def _get_user_notification_prefs(db, user_id: str) -> dict:
    """Get user notification preferences. Returns dict with default True for all if not set."""
    row = db.execute(
        "SELECT notification_preferences FROM users WHERE user_id=?",
        (user_id,)
    ).fetchone()

    if not row or not row["notification_preferences"]:
        return {
            "welcome": True,
            "quota_alerts": True,
            "weekly_digest": True
        }

    return json.loads(row["notification_preferences"])

def _should_send_notification(db, user_id: str, notification_type: str) -> bool:
    """Check if user has enabled this notification type."""
    prefs = _get_user_notification_prefs(db, user_id)
    return prefs.get(notification_type, True)


# ═══════════════════════════════════════════════════════════════════════════════
# USAGE QUOTA
# ═══════════════════════════════════════════════════════════════════════════════

def _check_usage_quota(db, agent_id: str):
    """Check if the agent's owner is within their monthly API call quota."""
    row = db.execute("SELECT owner_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row or not row["owner_id"]:
        return  # unowned agent, no quota
    owner = db.execute(
        "SELECT user_id, email, subscription_tier, usage_count, max_api_calls FROM users WHERE user_id = ?",
        (row["owner_id"],),
    ).fetchone()
    if not owner:
        return
    tier = owner["subscription_tier"] or "free"
    limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])["max_api_calls"]

    # Check if approaching quota (80%) and send warning email once
    if limit is not None and _should_send_notification(db, owner["user_id"], "quota_alerts"):
        usage_pct = (owner["usage_count"] / limit) * 100

        # Send 80% warning (only once)
        if 80 <= usage_pct < 81:
            _track_event("quota.warning_80pct", user_id=owner["user_id"], metadata={"tier": tier, "usage_pct": round(usage_pct, 1)})
            warning_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h1 style="color: #ff9800;">Warning: You're approaching your API limit</h1>
                <p>Your MoltGrid usage is at <strong>{usage_pct:.1f}%</strong> of your monthly quota.</p>
                <p><strong>Current usage:</strong> {owner["usage_count"]:,} / {limit:,} API calls</p>
                <p><strong>Tier:</strong> {tier}</p>
                <p>To avoid service interruption, consider upgrading your plan:</p>
                <p><a href="https://moltgrid.net/dashboard#/billing" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Upgrade Plan</a></p>
            </body>
            </html>
            """
            _queue_email(owner["email"], "You're approaching your API limit", warning_html)

    if limit is not None and owner["usage_count"] >= limit:
        # Send quota exceeded email (only once when hitting limit)
        if owner["usage_count"] == limit and _should_send_notification(db, owner["user_id"], "quota_alerts"):
            exceeded_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h1 style="color: #dc3545;">API limit reached -- your agents may be affected</h1>
                <p>You've reached your monthly API call quota for the <strong>{tier}</strong> tier.</p>
                <p><strong>Limit:</strong> {limit:,} API calls per month</p>
                <p>Your agents will receive 429 errors until:</p>
                <ul>
                    <li>Your quota resets at the start of next month, OR</li>
                    <li>You upgrade to a higher tier</li>
                </ul>
                <p><a href="https://moltgrid.net/dashboard#/billing" style="background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Upgrade Now</a></p>
            </body>
            </html>
            """
            _queue_email(owner["email"], "API limit reached -- your agents may be affected", exceeded_html)
        _track_event("quota.exceeded", user_id=owner["user_id"], metadata={"tier": tier, "limit": limit})
        raise HTTPException(429, f"Monthly API call quota exceeded for '{tier}' tier ({limit:,} calls)")

    db.execute("UPDATE users SET usage_count = usage_count + 1 WHERE user_id = ?", (owner["user_id"],))


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT AUTH (FastAPI Depends)
# ═══════════════════════════════════════════════════════════════════════════════

async def get_agent_id(request: Request) -> str:
    # Handle X-API-Key header case-insensitively (nginx/proxies may lowercase it)
    x_api_key = None
    for header_name, header_value in request.headers.items():
        if header_name.lower() == "x-api-key":
            x_api_key = header_value
            break

    if not x_api_key:
        raise HTTPException(401, "Missing X-API-Key header")

    with get_db() as db:
        row = db.execute(
            "SELECT agent_id FROM agents WHERE api_key_hash = ?",
            (hash_key(x_api_key),)
        ).fetchone()
        if not row:
            raise HTTPException(401, "Invalid API key")

        now = datetime.now(timezone.utc).isoformat()
        # Rate limiting
        window = int(time.time()) // RATE_LIMIT_WINDOW
        db.execute("""
            INSERT INTO rate_limits (agent_id, window_start, count)
            VALUES (?, ?, 1)
            ON CONFLICT(agent_id, window_start) DO UPDATE SET count = rate_limits.count + 1
        """, (row["agent_id"], window))
        rl = db.execute(
            "SELECT count FROM rate_limits WHERE agent_id = ? AND window_start = ?",
            (row["agent_id"], window)
        ).fetchone()
        current_count = rl["count"] if rl else 0
        # Tier-aware rate limit lookup
        owner_row = db.execute(
            "SELECT u.subscription_tier FROM users u "
            "JOIN agents a ON a.owner_id = u.user_id WHERE a.agent_id = ?",
            (row["agent_id"],)
        ).fetchone()
        tier = (owner_row["subscription_tier"] if owner_row else None) or "free"
        tier_limit = TIER_RATE_LIMITS.get(tier, TIER_RATE_LIMITS["free"])
        request.state.rate_limit_max = tier_limit  # consumed by header middleware
        request.state.rate_limit_remaining = max(0, tier_limit - current_count)
        request.state.rate_limit_reset = (window + 1) * RATE_LIMIT_WINDOW
        if current_count > tier_limit:
            raise HTTPException(429, f"Rate limit exceeded ({tier_limit}/min for {tier} tier)")

        # Usage quota check (per owner's subscription tier)
        _check_usage_quota(db, row["agent_id"])

        db.execute(
            "UPDATE agents SET last_seen = ?, request_count = request_count + 1 WHERE agent_id = ?",
            (now, row["agent_id"])
        )
        return row["agent_id"]


# ═══════════════════════════════════════════════════════════════════════════════
# JWT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRY_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _decode_token(token: str) -> dict:
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

async def get_user_id(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    claims = _decode_token(auth[7:])
    return claims["user_id"]

async def get_optional_user_id(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        claims = _decode_token(auth[7:])
        return claims["user_id"]
    except HTTPException:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# TURNSTILE / CAPTCHA
# ═══════════════════════════════════════════════════════════════════════════════

def _verify_turnstile(token: Optional[str]):
    """Verify Cloudflare Turnstile CAPTCHA token. Skips if not configured."""
    if not TURNSTILE_SECRET_KEY:
        return
    if not token:
        raise HTTPException(400, "CAPTCHA verification required")
    try:
        ts_resp = httpx.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET_KEY, "response": token},
            timeout=10,
        )
        if not ts_resp.json().get("success"):
            raise HTTPException(400, "CAPTCHA verification failed")
    except httpx.HTTPError:
        raise HTTPException(400, "CAPTCHA verification failed")


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT OWNERSHIP VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

def _verify_agent_ownership(db, agent_id: str, user_id: str):
    """Verify agent exists and belongs to this user. Returns agent row or raises 403."""
    agent = db.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not agent:
        raise HTTPException(404, "Agent not found")
    if agent["owner_id"] != user_id:
        raise HTTPException(403, "You do not own this agent")
    return agent


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT / LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

def _log_memory_access(action, agent_id, namespace, key,
                       actor_agent_id=None, actor_user_id=None,
                       old_visibility=None, new_visibility=None, authorized=1):
    """Fire-and-forget audit log -- never raises, uses direct connection to avoid transaction interference."""
    conn = None
    try:
        conn = get_standalone_conn()
        conn.execute(
            "INSERT INTO memory_access_log "
            "(id, agent_id, namespace, key, action, actor_agent_id, actor_user_id, "
            " old_visibility, new_visibility, authorized, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (f"mal_{uuid.uuid4().hex[:16]}", agent_id, namespace, key, action,
             actor_agent_id, actor_user_id, old_visibility, new_visibility, authorized,
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    except Exception:
        pass
    finally:
        if conn:
            conn.close()


def _log_audit(
    action: str,
    user_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Fire-and-forget audit log writer. Uses own connection -- call OUTSIDE with get_db() blocks."""
    try:
        log_id = f"log_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc).isoformat()
        conn = get_standalone_conn()
        conn.execute(
            "INSERT INTO audit_logs (log_id, user_id, agent_id, action, details, ip_address, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (log_id, user_id, agent_id, action, details, ip_address, now),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # Never raise from audit logger


def _queue_agent_event(agent_id: str, event_type: str, payload: dict):
    """Insert an event into agent_events. Uses own connection -- call OUTSIDE get_db() blocks."""
    try:
        event_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        conn = get_standalone_conn()
        conn.execute(
            "INSERT INTO agent_events (event_id, agent_id, event_type, payload, acknowledged, created_at) "
            "VALUES (?,?,?,?,0,?)",
            (event_id, agent_id, event_type, json.dumps(payload), now)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # fire-and-forget


# ═══════════════════════════════════════════════════════════════════════════════
# MEMORY VISIBILITY
# ═══════════════════════════════════════════════════════════════════════════════

def _check_memory_visibility(db, target_agent_id: str, namespace: str, key: str, requester_agent_id: str) -> bool:
    """Return True if requester_agent_id is allowed to read this memory entry."""
    row = db.execute(
        "SELECT visibility, shared_agents FROM memory WHERE agent_id=? AND namespace=? AND key=?",
        (target_agent_id, namespace, key)
    ).fetchone()
    if not row:
        return False
    vis = row["visibility"] or "private"
    if vis == "public":
        return True
    if vis == "shared":
        sa = json.loads(row["shared_agents"] or "[]")
        return requester_agent_id in sa
    return False  # private or unknown


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT SANITIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def _sanitize_text(text: Optional[str]) -> Optional[str]:
    """Strip HTML tags and escape to prevent XSS. Returns None for None input."""
    if text is None:
        return None
    # Remove HTML tags
    cleaned = _re.sub(r'<[^>]+>', '', text)
    # Escape remaining HTML entities
    cleaned = _html.escape(cleaned)
    return cleaned.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT IP
# ═══════════════════════════════════════════════════════════════════════════════

def _get_client_ip(request: Request) -> str:
    """Extract client IP, honoring X-Forwarded-For for nginx-proxied requests."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL
# ═══════════════════════════════════════════════════════════════════════════════

def _branded_email(title: str, body_content: str) -> str:
    """Generate a branded MoltGrid HTML email with dark theme, logo, header, and footer."""
    return f'''<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0f;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#12121a;border:1px solid #2a2a3a;border-radius:12px;overflow:hidden;">
<!-- Header -->
<tr><td style="padding:24px 32px;border-bottom:1px solid #2a2a3a;background:#12121a;">
<img src="https://moltgrid.net/public/logo-full.png" alt="MoltGrid" height="28" style="display:block;">
</td></tr>
<!-- Title -->
<tr><td style="padding:32px 32px 16px;color:#e4e4ef;font-size:22px;font-weight:700;">
{title}
</td></tr>
<!-- Body -->
<tr><td style="padding:0 32px 32px;color:#e4e4ef;font-size:15px;line-height:1.7;">
{body_content}
</td></tr>
<!-- Footer -->
<tr><td style="padding:20px 32px;border-top:1px solid #2a2a3a;background:#0a0a0f;">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td style="color:#7a7a92;font-size:12px;">
<a href="https://moltgrid.net" style="color:#ff3333;text-decoration:none;">moltgrid.net</a> &nbsp;&middot;&nbsp;
<a href="https://api.moltgrid.net/docs" style="color:#ff3333;text-decoration:none;">Docs</a> &nbsp;&middot;&nbsp;
<a href="https://github.com/D0NMEGA/MoltGrid" style="color:#ff3333;text-decoration:none;">GitHub</a> &nbsp;&middot;&nbsp;
<a href="https://api.moltgrid.net/dashboard" style="color:#ff3333;text-decoration:none;">Dashboard</a>
</td></tr>
<tr><td style="color:#7a7a92;font-size:11px;padding-top:12px;">
MoltGrid &mdash; Infrastructure for Autonomous Agents<br>
<a href="https://api.moltgrid.net/privacy" style="color:#7a7a92;text-decoration:none;">Privacy Policy</a> &nbsp;&middot;&nbsp;
<a href="https://api.moltgrid.net/terms" style="color:#7a7a92;text-decoration:none;">Terms of Service</a>
</td></tr>
</table>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>'''


def _queue_email(to_email: str, subject: str, body_html: str):
    """Queue an email for sending. Uses independent connection to avoid nested locks."""
    email_id = f"email_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    conn = None
    try:
        conn = get_standalone_conn()
        conn.execute(
            "INSERT INTO email_queue (id, to_email, subject, body_html, status, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (email_id, to_email, subject, body_html, now)
        )
        conn.commit()
        logger.info(f"Queued email {email_id} to {to_email}: {subject}")
    except Exception as e:
        logger.error(f"Failed to queue email {email_id}: {e}")
    finally:
        if conn:
            conn.close()
    return email_id


def _send_email_smtp(to_email: str, subject: str, body_html: str) -> bool:
    """Send email via SMTP. Returns True if successful, False otherwise."""
    if not SMTP_FROM or not SMTP_TO or not SMTP_PASSWORD:
        logger.warning("SMTP not configured, skipping email send")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email

        # Add HTML part
        html_part = MIMEText(body_html, "html")
        msg.attach(html_part)

        # Send via SMTP (Hostinger / configurable provider)
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_FROM, SMTP_PASSWORD)
            server.send_message(msg)

        logger.info(f"Sent email to {to_email}: {subject}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════════════

WEBHOOK_EVENT_TYPES = {"message.received", "message.broadcast", "job.completed", "job.failed", "marketplace.task.claimed", "marketplace.task.delivered", "marketplace.task.completed"}
WEBHOOK_TIMEOUT = 5.0  # seconds

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/32"),
]

def _is_safe_url(url: str) -> bool:
    """Validate that a webhook URL does not point to a private/internal address (SSRF prevention)."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname.lower() in ("localhost", "0.0.0.0"):
            return False
        resolved_ips = socket.getaddrinfo(hostname, None)
        for _family, _type, _proto, _canonname, sockaddr in resolved_ips:
            ip = ipaddress.ip_address(sockaddr[0])
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    return False
        return True
    except Exception:
        return False


def _fire_webhooks(agent_id: str, event_type: str, data: dict):
    """Queue webhook deliveries for an agent. Delivery happens via background worker with retries."""
    now = datetime.now(timezone.utc).isoformat()
    body = json.dumps({"event": event_type, "data": data, "timestamp": now})

    with get_db() as db:
        rows = db.execute(
            "SELECT webhook_id, event_types FROM webhooks WHERE agent_id=? AND active=1",
            (agent_id,)
        ).fetchall()

        for r in rows:
            if event_type in json.loads(r["event_types"]):
                delivery_id = f"whd_{uuid.uuid4().hex[:16]}"
                db.execute(
                    "INSERT INTO webhook_deliveries (delivery_id, webhook_id, event_type, payload, status, attempt_count, max_attempts, next_retry_at, created_at) "
                    "VALUES (?, ?, ?, ?, 'pending', 0, 5, ?, ?)",
                    (delivery_id, r["webhook_id"], event_type, body, now, now)
                )


# ═══════════════════════════════════════════════════════════════════════════════
# BILLING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_tier(db, user_id: str, tier: str):
    """Update a user's subscription tier and associated limits."""
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    max_calls = limits["max_api_calls"] if limits["max_api_calls"] is not None else 999999999
    db.execute(
        "UPDATE users SET subscription_tier = ?, max_agents = ?, max_api_calls = ?, payment_failed = 0 WHERE user_id = ?",
        (tier, limits["max_agents"], max_calls, user_id),
    )

def _get_or_create_stripe_customer(db, user_id: str, email: str) -> str:
    """Get existing Stripe customer ID or create a new one."""
    row = db.execute("SELECT stripe_customer_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row and row["stripe_customer_id"]:
        return row["stripe_customer_id"]
    customer = stripe.Customer.create(email=email, metadata={"moltgrid_user_id": user_id})
    db.execute("UPDATE users SET stripe_customer_id = ? WHERE user_id = ?", (customer.id, user_id))
    return customer.id

def _tier_from_price(price_id: str) -> str:
    """Map a Stripe price ID back to a MoltGrid tier name."""
    for tier, pid in STRIPE_TIER_PRICES.items():
        if pid and pid == price_id:
            return tier
    return "free"


# ═══════════════════════════════════════════════════════════════════════════════
# EMBEDDING / VECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def _get_embed_model():
    """Load embedding model once and cache it. Thread-safe."""
    import state as _state
    if _state._embed_model is None:
        with _state._embed_lock:
            if _state._embed_model is None:  # Double-check after acquiring lock
                logger.info("Loading embedding model 'all-MiniLM-L6-v2' (80MB, ~2s)...")
                _state._embed_model = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Embedding model loaded successfully")
    return _state._embed_model


# ═══════════════════════════════════════════════════════════════════════════════
# ONBOARDING
# ═══════════════════════════════════════════════════════════════════════════════

def _check_onboarding_progress(db, agent_id: str) -> dict:
    """Check onboarding progress for an agent. Returns dict with steps, progress, total, reward."""

    # Check each step
    steps = [
        {
            "id": "register",
            "title": "Register an agent",
            "completed": True,  # Always true if we have an agent_id
            "endpoint": "POST /v1/register"
        },
        {
            "id": "memory",
            "title": "Store something in memory",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM memory WHERE agent_id = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/memory"
        },
        {
            "id": "message",
            "title": "Send a message",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM relay WHERE from_agent = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/relay/send"
        },
        {
            "id": "queue",
            "title": "Submit a job",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM queue WHERE agent_id = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/queue/submit"
        },
        {
            "id": "schedule",
            "title": "Create a schedule",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM scheduled_tasks WHERE agent_id = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/schedules"
        },
        {
            "id": "directory",
            "title": "Update your directory profile",
            "completed": db.execute(
                "SELECT description FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()["description"] is not None,
            "endpoint": "PUT /v1/directory/me"
        },
        {
            "id": "heartbeat",
            "title": "Send a heartbeat",
            "completed": db.execute(
                "SELECT heartbeat_at FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()["heartbeat_at"] is not None,
            "endpoint": "POST /v1/agents/heartbeat"
        }
    ]

    progress = sum(1 for step in steps if step["completed"])
    total = len(steps)

    # Check if all steps complete and not yet rewarded
    agent_row = db.execute(
        "SELECT onboarding_completed, credits FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()

    if progress == total and not agent_row["onboarding_completed"]:
        # Award 100 credits and mark onboarding complete
        db.execute(
            "UPDATE agents SET credits = credits + 100, onboarding_completed = 1 WHERE agent_id = ?",
            (agent_id,)
        )
        _track_event("onboarding.completed", agent_id=agent_id)

    return {
        "steps": steps,
        "progress": progress,
        "total": total,
        "reward": "Complete all steps to earn 100 bonus credits!"
    }


# ═══════════════════════════════════════════════════════════════════════════════
# BACKGROUND LOOPS
# ═══════════════════════════════════════════════════════════════════════════════

def _webhook_delivery_loop():
    """Background thread: process pending webhook deliveries every 15 seconds."""
    while True:
        try:
            _run_webhook_delivery_tick()
        except Exception as e:
            logger.error(f"Webhook delivery loop error: {e}")
        time.sleep(15)


def _run_webhook_delivery_tick():
    """Attempt delivery for pending webhooks whose next_retry_at has passed."""
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        pending = db.execute(
            "SELECT d.delivery_id, d.webhook_id, d.event_type, d.payload, d.attempt_count, d.max_attempts, "
            "w.url, w.secret "
            "FROM webhook_deliveries d JOIN webhooks w ON d.webhook_id = w.webhook_id "
            "WHERE d.status='pending' AND d.next_retry_at <= ? "
            "ORDER BY d.next_retry_at ASC LIMIT 20",
            (now,)
        ).fetchall()

        for row in pending:
            delivery_id = row["delivery_id"]
            attempt = row["attempt_count"] + 1
            body = row["payload"]

            try:
                # Re-validate URL at delivery time (DNS may have changed since registration)
                if not _is_safe_url(row["url"]):
                    raise ValueError("Webhook URL points to a private/internal address")
                headers = {"Content-Type": "application/json", "X-MoltGrid-Event": row["event_type"]}
                if row["secret"]:
                    sig = _hmac.new(row["secret"].encode(), body.encode(), hashlib.sha256).hexdigest()
                    headers["X-MoltGrid-Signature"] = sig
                with httpx.Client(timeout=WEBHOOK_TIMEOUT) as hc:
                    resp = hc.post(row["url"], content=body, headers=headers)
                    resp.raise_for_status()

                db.execute(
                    "UPDATE webhook_deliveries SET status='delivered', attempt_count=?, delivered_at=? WHERE delivery_id=?",
                    (attempt, datetime.now(timezone.utc).isoformat(), delivery_id)
                )
            except Exception as e:
                if attempt >= row["max_attempts"]:
                    db.execute(
                        "UPDATE webhook_deliveries SET status='failed', attempt_count=?, last_error=? WHERE delivery_id=?",
                        (attempt, str(e)[:500], delivery_id)
                    )
                else:
                    retry_seconds = 60 * (2 ** attempt)
                    next_retry = (datetime.now(timezone.utc) + timedelta(seconds=retry_seconds)).isoformat()
                    db.execute(
                        "UPDATE webhook_deliveries SET attempt_count=?, next_retry_at=?, last_error=? WHERE delivery_id=?",
                        (attempt, next_retry, str(e)[:500], delivery_id)
                    )


def _run_scheduler_tick():
    """Execute due scheduled tasks. Called by the background scheduler loop."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    triggered_events = []
    with get_db() as db:
        due = db.execute(
            "SELECT * FROM scheduled_tasks WHERE enabled=1 AND next_run_at <= ?",
            (now_iso,)
        ).fetchall()

        for task in due:
            # Create a job in the queue
            job_id = f"job_{uuid.uuid4().hex[:16]}"
            db.execute(
                "INSERT INTO queue (job_id, agent_id, queue_name, payload, priority, created_at) VALUES (?,?,?,?,?,?)",
                (job_id, task["agent_id"], task["queue_name"], task["payload"], task["priority"], now_iso)
            )

            # Advance next_run_at
            cron = croniter(task["cron_expr"], now)
            next_run = cron.get_next(datetime).isoformat()
            db.execute(
                "UPDATE scheduled_tasks SET next_run_at=?, last_run_at=?, run_count=run_count+1 WHERE task_id=?",
                (next_run, now_iso, task["task_id"])
            )
            triggered_events.append((task["agent_id"], task["task_id"], task["queue_name"]))

    # Queue events OUTSIDE the with get_db() block (fire-and-forget pattern)
    for agent_id_ev, sched_id, action in triggered_events:
        _queue_agent_event(agent_id_ev, "schedule_triggered", {"schedule_id": sched_id, "action": action})


def _scheduler_loop():
    """Background thread that checks for due scheduled tasks every 30 seconds."""
    while True:
        try:
            _run_scheduler_tick()
        except Exception as e:
            logger.error(f"Scheduler tick error: {e}")
        time.sleep(30)


def _uptime_check():
    """Record a single uptime check by probing the database."""
    start = time.time()
    try:
        with get_db() as db:
            db.execute("SELECT COUNT(*) FROM agents").fetchone()
        elapsed_ms = (time.time() - start) * 1000
        status = "up"
    except Exception:
        elapsed_ms = (time.time() - start) * 1000
        status = "down"
    try:
        with get_db() as db:
            db.execute("INSERT INTO uptime_checks (checked_at, status, response_ms) VALUES (?,?,?)",
                       (datetime.now(timezone.utc).isoformat(), status, round(elapsed_ms, 2)))
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            db.execute("DELETE FROM uptime_checks WHERE checked_at < ?", (cutoff,))
    except Exception as ex:
        logger.error(f"Uptime recording failed: {ex}")


def _uptime_loop():
    """Background thread that records uptime checks every 60 seconds."""
    while True:
        try:
            _uptime_check()
        except Exception as e:
            logger.error(f"Uptime loop error: {e}")
        time.sleep(60)


def _run_liveness_check():
    """Mark agents offline when heartbeats go stale. Called by the liveness loop."""
    now = datetime.now(timezone.utc)
    with get_db() as db:
        rows = db.execute(
            "SELECT agent_id, heartbeat_at, heartbeat_interval FROM agents "
            "WHERE heartbeat_at IS NOT NULL AND heartbeat_status != 'offline'"
        ).fetchall()
        for row in rows:
            interval = row["heartbeat_interval"] or 60
            hb_at = datetime.fromisoformat(row["heartbeat_at"])
            if (now - hb_at).total_seconds() > interval * 2:
                db.execute(
                    "UPDATE agents SET heartbeat_status='offline' WHERE agent_id=?",
                    (row["agent_id"],)
                )


def _liveness_loop():
    """Background thread that marks agents offline when heartbeats go stale."""
    while True:
        try:
            _run_liveness_check()
        except Exception as e:
            logger.error(f"Liveness loop error: {e}")
        time.sleep(60)


def _run_usage_reset():
    """Reset usage_count for all users on the 1st of each month."""
    now = datetime.now(timezone.utc)
    if now.day == 1:
        with get_db() as db:
            db.execute("UPDATE users SET usage_count = 0")
        logger.info("Monthly usage reset completed")

def _usage_reset_loop():
    """Background thread: check daily at midnight UTC whether to reset usage counters."""
    while True:
        try:
            _run_usage_reset()
        except Exception as e:
            logger.error(f"Usage reset loop error: {e}")
        time.sleep(86400)  # 24 hours


def _email_loop():
    """Background thread: process pending emails every 30 seconds."""
    while True:
        try:
            _run_email_tick()
        except Exception as e:
            logger.error(f"Email loop error: {e}")
        time.sleep(30)  # 30 seconds

def _run_email_tick():
    """Process up to 10 pending emails."""
    with get_db() as db:
        pending = db.execute(
            "SELECT id, to_email, subject, body_html FROM email_queue "
            "WHERE status='pending' ORDER BY created_at ASC LIMIT 10"
        ).fetchall()

        for email in pending:
            email_id = email["id"]
            to_email = email["to_email"]
            subject = email["subject"]
            body_html = email["body_html"]

            success = _send_email_smtp(to_email, subject, body_html)
            now = datetime.now(timezone.utc).isoformat()

            if success:
                db.execute(
                    "UPDATE email_queue SET status='sent', sent_at=? WHERE id=?",
                    (now, email_id)
                )
            else:
                db.execute(
                    "UPDATE email_queue SET status='failed', error='SMTP error' WHERE id=?",
                    (email_id,)
                )
