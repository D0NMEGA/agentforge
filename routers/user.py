"""User account settings routes."""

import json
import uuid
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

import re
import bcrypt as _bcrypt
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel, Field, validator
from typing import Optional, List

from db import get_db
from helpers import (
    get_user_id, _create_token, _decode_token,
    _track_event, _log_audit, _get_client_ip,
    _queue_email, _branded_email, hash_key,
)

from rate_limit import limiter, make_tier_limit

router = APIRouter()


# ── Models ────────────────────────────────────────────────────────────
class ProfileUpdate(BaseModel):
    display_name: Optional[str] = Field(None, min_length=1, max_length=100)
    timezone: Optional[str] = Field(None, max_length=64)

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., max_length=128)

    @validator('new_password')
    def password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', v):
            raise ValueError('Password must contain at least one special character')
        if not re.match(r'^[\x20-\x7E]+$', v):
            raise ValueError('Password must contain only standard ASCII characters')
        return v

class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    scope: str = Field("live", pattern="^(live|test)$")

class DeleteAccountRequest(BaseModel):
    confirm_email: str = Field(..., max_length=256)


# ── Profile ───────────────────────────────────────────────────────────
@router.get("/v1/user/profile", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def get_profile(request: Request, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        user = db.execute(
            "SELECT user_id, email, display_name, timezone, avatar_url, "
            "totp_enabled, subscription_tier, created_at FROM users WHERE user_id = ?",
            (user_id,)
        ).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
    return dict(user)


@router.patch("/v1/user/profile", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def update_profile(request: Request, req: ProfileUpdate, user_id: str = Depends(get_user_id)):
    VALID_TIMEZONES = [
        "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
        "America/Anchorage", "Pacific/Honolulu", "America/Phoenix",
        "America/Toronto", "America/Vancouver", "America/Sao_Paulo",
        "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Moscow",
        "Asia/Tokyo", "Asia/Shanghai", "Asia/Kolkata", "Asia/Singapore",
        "Asia/Dubai", "Australia/Sydney", "Pacific/Auckland", "UTC",
    ]
    if req.timezone and req.timezone not in VALID_TIMEZONES:
        raise HTTPException(422, f"Invalid timezone. Must be one of: {', '.join(VALID_TIMEZONES)}")

    updates = []
    params = []
    if req.display_name is not None:
        # Validate username format
        if not re.match(r'^[A-Za-z0-9_]+$', req.display_name):
            raise HTTPException(422, "Username can only contain letters, numbers, and underscores")
        if len(req.display_name) < 3:
            raise HTTPException(422, "Username must be at least 3 characters")
        if len(req.display_name) > 30:
            raise HTTPException(422, "Username must be 30 characters or fewer")
        # Check cooldown and uniqueness
        with get_db() as db:
            current = db.execute(
                "SELECT display_name, last_username_change FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
            if current and current["display_name"] and current["display_name"].lower() != req.display_name.lower():
                # Different username -- enforce cooldown
                if current.get("last_username_change"):
                    last_change = datetime.fromisoformat(current["last_username_change"])
                    if datetime.now(timezone.utc) - last_change < timedelta(days=14):
                        days_left = 14 - (datetime.now(timezone.utc) - last_change).days
                        raise HTTPException(429, f"Username can only be changed once every 14 days. {days_left} days remaining.")
                # Check uniqueness
                existing = db.execute(
                    "SELECT user_id FROM users WHERE LOWER(display_name) = LOWER(?) AND user_id != ?",
                    (req.display_name, user_id)
                ).fetchone()
                if existing:
                    raise HTTPException(409, "Username already taken")
                # Track the change timestamp
                updates.append("last_username_change = ?")
                params.append(datetime.now(timezone.utc).isoformat())
        updates.append("display_name = ?")
        params.append(req.display_name)
    if req.timezone is not None:
        updates.append("timezone = ?")
        params.append(req.timezone)
    if not updates:
        raise HTTPException(422, "No fields to update")
    params.append(user_id)

    with get_db() as db:
        db.execute(f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?", params)
    _log_audit("user.profile_updated", user_id, None, json.dumps({"fields": [u.split(" = ")[0] for u in updates]}), None)
    return {"message": "Profile updated"}


# ── Password ──────────────────────────────────────────────────────────
@router.post("/v1/auth/change-password", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def change_password(request: Request, req: ChangePasswordRequest, user_id: str = Depends(get_user_id)):
    if req.new_password != req.confirm_password:
        raise HTTPException(422, "Passwords do not match")
    with get_db() as db:
        user = db.execute("SELECT password_hash FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        if not _bcrypt.checkpw(req.current_password.encode(), user["password_hash"].encode()):
            raise HTTPException(401, "Current password is incorrect")
        new_hash = _bcrypt.hashpw(req.new_password.encode(), _bcrypt.gensalt()).decode()
        db.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (new_hash, user_id))
        # Revoke all other sessions
        db.execute("UPDATE user_sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,))
    _log_audit("user.password_changed", user_id, None, None, None)
    return {"message": "Password changed successfully"}


# ── API Keys ──────────────────────────────────────────────────────────
@router.get("/v1/user/keys", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def list_keys(request: Request, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        keys = db.execute(
            "SELECT id, name, key_prefix, key_hint, created_at, last_used, status "
            "FROM user_keys WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
    return [dict(k) for k in keys]


@router.post("/v1/user/keys", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def create_key(request: Request, req: CreateKeyRequest, user_id: str = Depends(get_user_id)):
    prefix = "mg_live_" if req.scope == "live" else "mg_test_"
    raw_key = prefix + secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_hint = raw_key[-4:]
    key_id = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO user_keys (id, user_id, name, key_prefix, key_hash, key_hint, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (key_id, user_id, req.name, prefix, key_hash, key_hint, now)
        )
    _log_audit("user.key_created", user_id, None, json.dumps({"key_name": req.name}), None)
    return {"id": key_id, "name": req.name, "key": raw_key, "key_hint": key_hint, "created_at": now}


@router.delete("/v1/user/keys/{key_id}", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def revoke_key(request: Request, key_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        key = db.execute("SELECT id FROM user_keys WHERE id = ? AND user_id = ?", (key_id, user_id)).fetchone()
        if not key:
            raise HTTPException(404, "Key not found")
        db.execute("UPDATE user_keys SET status = 'revoked' WHERE id = ?", (key_id,))
    _log_audit("user.key_revoked", user_id, None, json.dumps({"key_id": key_id}), None)
    return {"message": "Key revoked"}


# ── Sessions ──────────────────────────────────────────────────────────
@router.get("/v1/user/sessions", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def list_sessions(request: Request, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        sessions = db.execute(
            "SELECT id, device, browser, ip_address, last_active, created_at "
            "FROM user_sessions WHERE user_id = ? AND revoked = 0 ORDER BY last_active DESC",
            (user_id,)
        ).fetchall()
    return [dict(s) for s in sessions]


@router.delete("/v1/user/sessions/{session_id}", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def revoke_session(request: Request, session_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        session = db.execute(
            "SELECT id FROM user_sessions WHERE id = ? AND user_id = ? AND revoked = 0",
            (session_id, user_id)
        ).fetchone()
        if not session:
            raise HTTPException(404, "Session not found")
        db.execute("UPDATE user_sessions SET revoked = 1 WHERE id = ?", (session_id,))
    return {"message": "Session revoked"}


@router.post("/v1/user/sessions/revoke-all", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def revoke_all_sessions(request: Request, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        result = db.execute(
            "UPDATE user_sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0",
            (user_id,)
        )
        count = result.rowcount
    return {"message": f"Revoked {count} sessions"}


# ── Data Export ───────────────────────────────────────────────────────
@router.post("/v1/user/export", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def export_data(request: Request, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        user = db.execute(
            "SELECT user_id, email, display_name, timezone, subscription_tier, "
            "totp_enabled, created_at, last_login FROM users WHERE user_id = ?",
            (user_id,)
        ).fetchone()
        if not user:
            raise HTTPException(404, "User not found")

        agents = db.execute(
            "SELECT agent_id, name, description, capabilities, created_at, last_seen "
            "FROM agents WHERE owner_id = ?", (user_id,)
        ).fetchall()

        agent_ids = [a["agent_id"] for a in agents]
        memory = []
        webhooks = []
        for aid in agent_ids:
            mem = db.execute(
                "SELECT agent_id, namespace, key, value, visibility, created_at "
                "FROM memory WHERE agent_id = ?", (aid,)
            ).fetchall()
            memory.extend([dict(m) for m in mem])
            wh = db.execute(
                "SELECT webhook_id, agent_id, url, event_types, active, created_at "
                "FROM webhooks WHERE agent_id = ?", (aid,)
            ).fetchall()
            webhooks.extend([dict(w) for w in wh])

        keys = db.execute(
            "SELECT id, name, key_prefix, key_hint, created_at, last_used, status "
            "FROM user_keys WHERE user_id = ?", (user_id,)
        ).fetchall()

    export = {
        "export_version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "user": dict(user),
        "agents": [dict(a) for a in agents],
        "memory": memory,
        "webhooks": webhooks,
        "api_keys": [dict(k) for k in keys],
    }
    _log_audit("user.data_exported", user_id, None, None, None)
    return Response(
        content=json.dumps(export, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=moltgrid-export-{datetime.now().strftime('%Y%m%d')}.json"}
    )


# ── Account Deletion ─────────────────────────────────────────────────
@router.delete("/v1/user/account", tags=["User Settings"])
@limiter.limit(make_tier_limit("admin"))
def delete_account(request: Request, req: DeleteAccountRequest, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        user = db.execute("SELECT email FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        if req.confirm_email.lower() != user["email"].lower():
            raise HTTPException(422, "Email does not match")

        # Get all agent IDs owned by this user
        agent_ids = [r["agent_id"] for r in db.execute(
            "SELECT agent_id FROM agents WHERE owner_id = ?", (user_id,)
        ).fetchall()]

        # Cascade delete all agent data
        for aid in agent_ids:
            db.execute("DELETE FROM memory WHERE agent_id = ?", (aid,))
            db.execute("DELETE FROM vector_memory WHERE agent_id = ?", (aid,))
            db.execute("DELETE FROM queue WHERE agent_id = ?", (aid,))
            db.execute("DELETE FROM relay WHERE from_agent = ? OR to_agent = ?", (aid, aid))
            db.execute("DELETE FROM webhooks WHERE agent_id = ?", (aid,))
            db.execute("DELETE FROM scheduled_tasks WHERE agent_id = ?", (aid,))
            db.execute("DELETE FROM sessions WHERE agent_id = ?", (aid,))

        # Delete agents
        db.execute("DELETE FROM agents WHERE owner_id = ?", (user_id,))

        # Delete user data
        db.execute("DELETE FROM user_keys WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM audit_logs WHERE user_id = ?", (user_id,))

        # Delete user
        db.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

    # NOTE: Issued JWTs remain valid until expiry. A revoked_tokens table
    # or per-request user existence check should be added in a future security hardening pass.
    _log_audit("user.account_deleted", user_id, None, None, None)
    return {"message": "Account deleted"}
