"""
MoltGrid — Open-source toolkit API for autonomous agents.
Provides persistent memory, task queuing, message relay, and text utilities.
"""

import os
import json
import time
import uuid
import random
import hashlib
import sqlite3
import asyncio
import logging
import smtplib
import statistics
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Union
from contextlib import asynccontextmanager, contextmanager

import hmac as _hmac
import secrets
import httpx
from cryptography.fernet import Fernet, InvalidToken
from croniter import croniter
from fastapi import FastAPI, HTTPException, Header, Depends, Query, WebSocket, WebSocketDisconnect, Cookie, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field

import jwt as pyjwt
import bcrypt as _bcrypt
import stripe

logger = logging.getLogger("moltgrid")

# ─── Config ───────────────────────────────────────────────────────────────────
DB_PATH = os.getenv("MOLTGRID_DB", "moltgrid.db")
MAX_MEMORY_VALUE_SIZE = 50_000  # 50KB per value
MAX_QUEUE_PAYLOAD_SIZE = 100_000  # 100KB per job
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 120  # requests per window per agent

# Subscription tier limits
TIER_LIMITS = {
    "free":  {"max_agents": 1,   "max_api_calls": 10_000},
    "hobby": {"max_agents": 10,  "max_api_calls": 1_000_000},
    "team":  {"max_agents": 50,  "max_api_calls": 10_000_000},
    "scale": {"max_agents": 200, "max_api_calls": None},  # unlimited
}

# Admin auth: load password hash from env (set on VPS only, never in code)
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
ADMIN_SESSION_TTL = 3600 * 24  # 24 hours

# Encrypted storage: set ENCRYPTION_KEY env var to enable AES encryption at rest
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
_fernet = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None

# JWT auth for user accounts
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7

# Stripe billing
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_HOBBY = os.getenv("STRIPE_PRICE_HOBBY", "")
STRIPE_PRICE_TEAM = os.getenv("STRIPE_PRICE_TEAM", "")
STRIPE_PRICE_SCALE = os.getenv("STRIPE_PRICE_SCALE", "")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

STRIPE_TIER_PRICES = {
    "hobby": STRIPE_PRICE_HOBBY,
    "team":  STRIPE_PRICE_TEAM,
    "scale": STRIPE_PRICE_SCALE,
}

# Contact form SMTP: set SMTP_PASSWORD env var (Gmail App Password)
SMTP_FROM = os.getenv("SMTP_FROM", "")
SMTP_TO = os.getenv("SMTP_TO", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

if not SMTP_FROM or not SMTP_TO or not SMTP_PASSWORD:
    logger.warning("SMTP environment variables not set — contact form will be disabled.")


# ─── App ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    # Startup: launch background threads
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    threading.Thread(target=_uptime_loop, daemon=True).start()
    threading.Thread(target=_liveness_loop, daemon=True).start()
    threading.Thread(target=_usage_reset_loop, daemon=True).start()
    logger.info("Background threads started (scheduler, uptime monitor, liveness monitor, usage reset)")
    # Clear OpenAPI schema cache to prevent stale endpoint definitions
    app.openapi_schema = None
    logger.info("OpenAPI schema cache cleared")
    # Run an immediate uptime check to seed the database
    try:
        _uptime_check()
        logger.info("Initial uptime check completed")
    except Exception as e:
        logger.error(f"Initial uptime check failed: {e}")
    yield
    # Shutdown: nothing to clean up (daemon threads auto-exit)

app = FastAPI(
    title="MoltGrid",
    description="Open-source toolkit API for autonomous agents. "
    "Persistent memory, task queues, message relay, and text utilities.",
    version="0.6.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            api_key_hash TEXT NOT NULL,
            name TEXT,
            description TEXT,
            capabilities TEXT,
            public INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_seen TEXT,
            request_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS memory (
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            PRIMARY KEY (agent_id, namespace, key),
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );

        CREATE TABLE IF NOT EXISTS queue (
            job_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            queue_name TEXT NOT NULL DEFAULT 'default',
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            priority INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result TEXT,
            max_attempts INTEGER DEFAULT 1,
            attempt_count INTEGER DEFAULT 0,
            retry_delay_seconds INTEGER DEFAULT 0,
            next_retry_at TEXT,
            failed_at TEXT,
            fail_reason TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_queue_status ON queue(queue_name, status, priority DESC);

        CREATE TABLE IF NOT EXISTS dead_letter (
            job_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            queue_name TEXT NOT NULL DEFAULT 'default',
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'failed',
            priority INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result TEXT,
            max_attempts INTEGER DEFAULT 1,
            attempt_count INTEGER DEFAULT 0,
            retry_delay_seconds INTEGER DEFAULT 0,
            failed_at TEXT,
            fail_reason TEXT,
            moved_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_dlq_agent ON dead_letter(agent_id, queue_name);

        CREATE TABLE IF NOT EXISTS relay (
            message_id TEXT PRIMARY KEY,
            from_agent TEXT NOT NULL,
            to_agent TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'direct',
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY (from_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_relay_to ON relay(to_agent, read_at);

        CREATE TABLE IF NOT EXISTS rate_limits (
            agent_id TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            count INTEGER DEFAULT 1,
            PRIMARY KEY (agent_id, window_start)
        );

        CREATE TABLE IF NOT EXISTS metrics (
            recorded_at TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            status_code INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            url TEXT NOT NULL,
            event_types TEXT NOT NULL,
            secret TEXT,
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_webhooks_agent ON webhooks(agent_id, active);

        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            cron_expr TEXT NOT NULL,
            queue_name TEXT NOT NULL DEFAULT 'default',
            payload TEXT NOT NULL,
            priority INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            next_run_at TEXT NOT NULL,
            last_run_at TEXT,
            run_count INTEGER DEFAULT 0,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sched_next ON scheduled_tasks(enabled, next_run_at);

        CREATE TABLE IF NOT EXISTS shared_memory (
            owner_agent TEXT NOT NULL,
            namespace TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            PRIMARY KEY (owner_agent, namespace, key),
            FOREIGN KEY (owner_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_shared_ns ON shared_memory(namespace);

        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS uptime_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at TEXT NOT NULL,
            status TEXT NOT NULL,
            response_ms REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_uptime_at ON uptime_checks(checked_at);

        CREATE TABLE IF NOT EXISTS collaborations (
            collaboration_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            partner_agent TEXT NOT NULL,
            task_type TEXT,
            outcome TEXT NOT NULL,
            rating INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
            FOREIGN KEY (partner_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_collab_partner ON collaborations(partner_agent);
        CREATE INDEX IF NOT EXISTS idx_collab_agent ON collaborations(agent_id);

        CREATE TABLE IF NOT EXISTS marketplace (
            task_id TEXT PRIMARY KEY,
            creator_agent TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            requirements TEXT,
            reward_credits INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0,
            estimated_effort TEXT,
            tags TEXT,
            deadline TEXT,
            status TEXT DEFAULT 'open',
            claimed_by TEXT,
            claimed_at TEXT,
            delivered_at TEXT,
            result TEXT,
            rating INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (creator_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_market_status ON marketplace(status, category);
        CREATE INDEX IF NOT EXISTS idx_market_creator ON marketplace(creator_agent);
        CREATE INDEX IF NOT EXISTS idx_market_claimed ON marketplace(claimed_by);

        CREATE TABLE IF NOT EXISTS test_scenarios (
            scenario_id TEXT PRIMARY KEY,
            creator_agent TEXT NOT NULL,
            name TEXT,
            pattern TEXT NOT NULL,
            agent_count INTEGER NOT NULL,
            timeout_seconds INTEGER DEFAULT 60,
            success_criteria TEXT,
            status TEXT DEFAULT 'created',
            results TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (creator_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_scenarios_creator ON test_scenarios(creator_agent);

        CREATE TABLE IF NOT EXISTS contact_submissions (
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT NOT NULL,
            subject TEXT,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            subscription_tier TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            usage_count INTEGER DEFAULT 0,
            max_agents INTEGER DEFAULT 1,
            max_api_calls INTEGER DEFAULT 10000,
            created_at TEXT NOT NULL,
            last_login TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_stripe ON users(stripe_customer_id);
    """)

    # Migrate existing agents table — add columns that older versions didn't have
    existing = {row[1] for row in conn.execute("PRAGMA table_info(agents)").fetchall()}
    for col, typedef in [
        ("description", "TEXT"), ("capabilities", "TEXT"), ("public", "INTEGER DEFAULT 0"),
        ("available", "INTEGER DEFAULT 1"), ("looking_for", "TEXT"), ("busy_until", "TEXT"),
        ("reputation", "REAL DEFAULT 0.0"), ("reputation_count", "INTEGER DEFAULT 0"),
        ("credits", "INTEGER DEFAULT 0"),
        ("heartbeat_at", "TEXT"), ("heartbeat_interval", "INTEGER DEFAULT 60"),
        ("heartbeat_status", "TEXT DEFAULT 'unknown'"), ("heartbeat_meta", "TEXT"),
        ("owner_id", "TEXT"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {typedef}")

    # Migrate existing users table — add columns for billing
    try:
        u_existing = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        for col, typedef in [
            ("payment_failed", "INTEGER DEFAULT 0"),
        ]:
            if col not in u_existing:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typedef}")
    except Exception:
        pass  # users table may not exist yet on first run

    # Migrate existing queue table — add retry/dead-letter columns
    q_existing = {row[1] for row in conn.execute("PRAGMA table_info(queue)").fetchall()}
    for col, typedef in [
        ("max_attempts", "INTEGER DEFAULT 1"), ("attempt_count", "INTEGER DEFAULT 0"),
        ("retry_delay_seconds", "INTEGER DEFAULT 0"), ("next_retry_at", "TEXT"),
        ("failed_at", "TEXT"), ("fail_reason", "TEXT"),
    ]:
        if col not in q_existing:
            conn.execute(f"ALTER TABLE queue ADD COLUMN {col} {typedef}")

    conn.commit()
    conn.close()

init_db()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

# ─── Encryption Helpers ───────────────────────────────────────────────────
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
            return _fernet.decrypt(ciphertext[4:].encode()).decode()
        except (InvalidToken, Exception):
            return ciphertext  # Return as-is if decryption fails
    return ciphertext  # Plaintext (pre-encryption data)

# ─── Auth Helpers ─────────────────────────────────────────────────────────────
def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def generate_api_key() -> str:
    return f"af_{uuid.uuid4().hex}"

def _check_usage_quota(db, agent_id: str):
    """Check if the agent's owner is within their monthly API call quota."""
    row = db.execute("SELECT owner_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row or not row["owner_id"]:
        return  # unowned agent, no quota
    owner = db.execute(
        "SELECT user_id, subscription_tier, usage_count, max_api_calls FROM users WHERE user_id = ?",
        (row["owner_id"],),
    ).fetchone()
    if not owner:
        return
    tier = owner["subscription_tier"] or "free"
    limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])["max_api_calls"]
    if limit is not None and owner["usage_count"] >= limit:
        raise HTTPException(429, f"Monthly API call quota exceeded for '{tier}' tier ({limit:,} calls)")
    db.execute("UPDATE users SET usage_count = usage_count + 1 WHERE user_id = ?", (owner["user_id"],))


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
            ON CONFLICT(agent_id, window_start) DO UPDATE SET count = count + 1
        """, (row["agent_id"], window))
        rl = db.execute(
            "SELECT count FROM rate_limits WHERE agent_id = ? AND window_start = ?",
            (row["agent_id"], window)
        ).fetchone()
        if rl and rl["count"] > RATE_LIMIT_MAX:
            raise HTTPException(429, f"Rate limit exceeded ({RATE_LIMIT_MAX}/min)")

        # Usage quota check (per owner's subscription tier)
        _check_usage_quota(db, row["agent_id"])

        db.execute(
            "UPDATE agents SET last_seen = ?, request_count = request_count + 1 WHERE agent_id = ?",
            (now, row["agent_id"])
        )
        return row["agent_id"]


# ─── JWT Helpers ──────────────────────────────────────────────────────────────

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
# USER AUTH (JWT)
# ═══════════════════════════════════════════════════════════════════════════════

class SignupRequest(BaseModel):
    email: str = Field(..., max_length=256)
    password: str = Field(..., min_length=6, max_length=128)
    display_name: Optional[str] = Field(None, max_length=64)

class LoginRequest(BaseModel):
    email: str = Field(..., max_length=256)
    password: str = Field(..., max_length=128)

@app.post("/v1/auth/signup", tags=["Auth"])
def auth_signup(req: SignupRequest):
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    pw_hash = _bcrypt.hashpw(req.password.encode(), _bcrypt.gensalt()).decode()

    with get_db() as db:
        existing = db.execute("SELECT user_id FROM users WHERE email = ?", (req.email.lower(),)).fetchone()
        if existing:
            raise HTTPException(409, "Email already registered")
        db.execute(
            "INSERT INTO users (user_id, email, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, req.email.lower(), pw_hash, req.display_name, now),
        )
    token = _create_token(user_id, req.email.lower())
    return {"user_id": user_id, "token": token, "message": "Account created"}

@app.post("/v1/auth/login", tags=["Auth"])
def auth_login(req: LoginRequest):
    with get_db() as db:
        row = db.execute("SELECT user_id, password_hash FROM users WHERE email = ?", (req.email.lower(),)).fetchone()
        if not row or not _bcrypt.checkpw(req.password.encode(), row["password_hash"].encode()):
            raise HTTPException(401, "Invalid email or password")
        now = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE users SET last_login = ? WHERE user_id = ?", (now, row["user_id"]))
    token = _create_token(row["user_id"], req.email.lower())
    return {"user_id": row["user_id"], "token": token}

@app.get("/v1/auth/me", tags=["Auth"])
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

@app.post("/v1/auth/refresh", tags=["Auth"])
def auth_refresh(user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute("SELECT email FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
    token = _create_token(user_id, row["email"])
    return {"user_id": user_id, "token": token}


# ═══════════════════════════════════════════════════════════════════════════════
# USER DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

def _verify_agent_ownership(db, agent_id: str, user_id: str):
    """Verify agent exists and belongs to this user. Returns agent row or raises 403."""
    agent = db.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not agent:
        raise HTTPException(404, "Agent not found")
    if agent["owner_id"] != user_id:
        raise HTTPException(403, "You do not own this agent")
    return agent

@app.get("/v1/user/agents", tags=["User Dashboard"])
def user_list_agents(user_id: str = Depends(get_user_id)):
    """List all agents owned by this user."""
    with get_db() as db:
        rows = db.execute(
            "SELECT agent_id, name, description, public, request_count, last_seen, "
            "heartbeat_status, created_at FROM agents WHERE owner_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
    return {"agents": [dict(r) for r in rows], "count": len(rows)}

@app.get("/v1/user/agents/{agent_id}/activity", tags=["User Dashboard"])
def user_agent_activity(agent_id: str, user_id: str = Depends(get_user_id)):
    """Activity feed for one owned agent — last 50 events across relay, queue, and memory."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        events = []

        # Messages sent
        for r in db.execute(
            "SELECT message_id, 'message_sent' as event_type, to_agent as target, "
            "channel, created_at as timestamp FROM relay WHERE from_agent = ? "
            "ORDER BY created_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))

        # Messages received
        for r in db.execute(
            "SELECT message_id, 'message_received' as event_type, from_agent as source, "
            "channel, created_at as timestamp FROM relay WHERE to_agent = ? "
            "ORDER BY created_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))

        # Jobs submitted/completed/failed
        for r in db.execute(
            "SELECT job_id, 'job_' || status as event_type, queue_name, "
            "COALESCE(completed_at, started_at, created_at) as timestamp "
            "FROM queue WHERE agent_id = ? ORDER BY created_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))

        # Memory updates
        for r in db.execute(
            "SELECT key, namespace, 'memory_update' as event_type, "
            "updated_at as timestamp FROM memory WHERE agent_id = ? "
            "ORDER BY updated_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))

    # Sort all events by timestamp DESC, take top 50
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return {"agent_id": agent_id, "events": events[:50]}

@app.get("/v1/user/usage", tags=["User Dashboard"])
def user_usage(user_id: str = Depends(get_user_id)):
    """Aggregate usage stats for the current billing period (calendar month)."""
    now = datetime.now(timezone.utc)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    # Last day of month
    if now.month == 12:
        period_end = now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    else:
        period_end = now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        tier = user["subscription_tier"] or "free"
        limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

        agent_ids = [r["agent_id"] for r in db.execute(
            "SELECT agent_id FROM agents WHERE owner_id = ?", (user_id,)
        ).fetchall()]

        total_agents = len(agent_ids)
        if not agent_ids:
            return {
                "total_api_calls": user["usage_count"],
                "total_agents": 0, "memory_keys": 0,
                "jobs_submitted": 0, "messages_sent": 0,
                "period_start": period_start, "period_end": period_end,
                "tier": tier, "limits": limits,
            }

        placeholders = ",".join("?" * len(agent_ids))

        memory_keys = db.execute(
            f"SELECT COUNT(*) as cnt FROM memory WHERE agent_id IN ({placeholders})", agent_ids
        ).fetchone()["cnt"]

        jobs_submitted = db.execute(
            f"SELECT COUNT(*) as cnt FROM queue WHERE agent_id IN ({placeholders}) "
            f"AND created_at >= ?", agent_ids + [period_start]
        ).fetchone()["cnt"]

        messages_sent = db.execute(
            f"SELECT COUNT(*) as cnt FROM relay WHERE from_agent IN ({placeholders}) "
            f"AND created_at >= ?", agent_ids + [period_start]
        ).fetchone()["cnt"]

    return {
        "total_api_calls": user["usage_count"],
        "total_agents": total_agents,
        "memory_keys": memory_keys,
        "jobs_submitted": jobs_submitted,
        "messages_sent": messages_sent,
        "period_start": period_start,
        "period_end": period_end,
        "tier": tier,
        "limits": limits,
    }

@app.get("/v1/user/billing", tags=["User Dashboard"])
def user_billing(user_id: str = Depends(get_user_id)):
    """Subscription and billing info."""
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
    tier = user["subscription_tier"] or "free"
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    # Next billing = first of next month
    now = datetime.now(timezone.utc)
    if now.month == 12:
        next_billing = now.replace(year=now.year + 1, month=1, day=1).strftime("%Y-%m-%d")
    else:
        next_billing = now.replace(month=now.month + 1, day=1).strftime("%Y-%m-%d")
    return {
        "tier": tier,
        "max_agents": limits["max_agents"],
        "max_api_calls": limits["max_api_calls"],
        "usage_count": user["usage_count"],
        "stripe_customer_id": user["stripe_customer_id"],
        "next_billing_date": next_billing,
    }

class TransferRequest(BaseModel):
    to_email: str = Field(..., max_length=256)

@app.post("/v1/user/agents/{agent_id}/transfer", tags=["User Dashboard"])
def user_transfer_agent(agent_id: str, req: TransferRequest, user_id: str = Depends(get_user_id)):
    """Transfer agent ownership to another user by email."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        recipient = db.execute("SELECT user_id, subscription_tier FROM users WHERE email = ?", (req.to_email.lower(),)).fetchone()
        if not recipient:
            raise HTTPException(404, "Recipient user not found")
        if recipient["user_id"] == user_id:
            raise HTTPException(400, "Cannot transfer to yourself")
        # Check recipient's agent limit
        r_tier = recipient["subscription_tier"] or "free"
        r_limit = TIER_LIMITS.get(r_tier, TIER_LIMITS["free"])["max_agents"]
        r_count = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE owner_id = ?", (recipient["user_id"],)).fetchone()["cnt"]
        if r_limit is not None and r_count >= r_limit:
            raise HTTPException(403, f"Recipient has reached their agent limit ({r_limit})")
        db.execute("UPDATE agents SET owner_id = ? WHERE agent_id = ?", (recipient["user_id"], agent_id))
    return {"agent_id": agent_id, "transferred_to": req.to_email.lower(), "message": "Transfer complete"}

@app.delete("/v1/user/account", tags=["User Dashboard"])
def user_delete_account(user_id: str = Depends(get_user_id)):
    """Soft-delete user account. Marks as inactive but preserves data."""
    with get_db() as db:
        db.execute(
            "UPDATE users SET subscription_tier = 'deleted', max_agents = 0, max_api_calls = 0 WHERE user_id = ?",
            (user_id,),
        )
        # Unlink agents (they become unowned, still functional)
        db.execute("UPDATE agents SET owner_id = NULL WHERE owner_id = ?", (user_id,))
    return {"user_id": user_id, "message": "Account deactivated. Agents unlinked."}


# ═══════════════════════════════════════════════════════════════════════════════
# STRIPE BILLING
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

@app.get("/v1/pricing", tags=["Billing"])
def get_pricing():
    """Public pricing info. No auth required."""
    return {
        "tiers": [
            {"name": "free", "price": 0, "agents": 1, "api_calls": 10000,
             "features": ["Memory", "Queue", "Messaging", "Scheduling"]},
            {"name": "hobby", "price": 5, "agents": 10, "api_calls": 1000000,
             "features": ["Everything in Free", "Dead-letter queue", "Webhooks", "Marketplace", "Priority support"]},
            {"name": "team", "price": 25, "agents": 50, "api_calls": 10000000,
             "features": ["Everything in Hobby", "Team workspaces", "SSO (coming soon)", "SLA guarantee"]},
            {"name": "scale", "price": 99, "agents": 200, "api_calls": -1,
             "features": ["Everything in Team", "Unlimited API calls", "Dedicated support", "Custom integrations"]},
        ],
        "currency": "usd",
        "billing_period": "monthly",
    }

class CheckoutRequest(BaseModel):
    tier: str = Field(..., description="Subscription tier: hobby, team, or scale")

@app.post("/v1/billing/checkout", tags=["Billing"])
def billing_checkout(req: CheckoutRequest, user_id: str = Depends(get_user_id)):
    """Create a Stripe Checkout Session for upgrading subscription."""
    if req.tier not in STRIPE_TIER_PRICES:
        raise HTTPException(400, f"Invalid tier '{req.tier}'. Must be: hobby, team, or scale")
    price_id = STRIPE_TIER_PRICES[req.tier]
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe is not configured on this server")
    if not price_id:
        raise HTTPException(503, f"Stripe price ID not configured for tier '{req.tier}'")

    with get_db() as db:
        user = db.execute("SELECT email, stripe_customer_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        customer_id = _get_or_create_stripe_customer(db, user_id, user["email"])

    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url="https://moltgrid.net/billing/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://moltgrid.net/billing/cancel",
        metadata={"moltgrid_user_id": user_id, "tier": req.tier},
    )
    return {"checkout_url": session.url}

@app.post("/v1/billing/portal", tags=["Billing"])
def billing_portal(user_id: str = Depends(get_user_id)):
    """Create a Stripe Customer Portal session for managing subscription."""
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe is not configured on this server")

    with get_db() as db:
        user = db.execute("SELECT stripe_customer_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user or not user["stripe_customer_id"]:
            raise HTTPException(400, "No Stripe customer found. Subscribe first.")

    session = stripe.billing_portal.Session.create(
        customer=user["stripe_customer_id"],
        return_url="https://moltgrid.net/billing",
    )
    return {"portal_url": session.url}

def _tier_from_price(price_id: str) -> str:
    """Map a Stripe price ID back to a MoltGrid tier name."""
    for tier, pid in STRIPE_TIER_PRICES.items():
        if pid and pid == price_id:
            return tier
    return "free"

@app.post("/v1/stripe/webhook", tags=["Billing"])
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events. Verifies signature, updates user tiers."""
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")

    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except stripe.error.SignatureVerificationError:
            raise HTTPException(400, "Invalid webhook signature")
        except Exception as e:
            raise HTTPException(400, f"Webhook error: {e}")
    else:
        # No webhook secret configured — parse raw (dev/test only)
        try:
            event = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(400, "Invalid webhook payload")

    event_type = event.get("type", "") if isinstance(event, dict) else event.type
    data_obj = event.get("data", {}).get("object", {}) if isinstance(event, dict) else event.data.object

    with get_db() as db:
        if event_type == "checkout.session.completed":
            user_id = (data_obj.get("metadata") or {}).get("moltgrid_user_id")
            tier = (data_obj.get("metadata") or {}).get("tier", "hobby")
            sub_id = data_obj.get("subscription")
            if user_id:
                _apply_tier(db, user_id, tier)
                db.execute("UPDATE users SET stripe_subscription_id = ? WHERE user_id = ?", (sub_id, user_id))

        elif event_type == "customer.subscription.updated":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                items = data_obj.get("items", {}).get("data", [])
                if items:
                    price_id = items[0].get("price", {}).get("id", "")
                    tier = _tier_from_price(price_id)
                    _apply_tier(db, user["user_id"], tier)

        elif event_type == "customer.subscription.deleted":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                _apply_tier(db, user["user_id"], "free")
                db.execute("UPDATE users SET stripe_subscription_id = NULL WHERE user_id = ?", (user["user_id"],))

        elif event_type == "invoice.payment_failed":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                db.execute("UPDATE users SET payment_failed = 1 WHERE user_id = ?", (user["user_id"],))
                logger.warning(f"Payment failed for user {user['user_id']}")

    return {"received": True}

@app.get("/v1/billing/status", tags=["Billing"])
def billing_status(user_id: str = Depends(get_user_id)):
    """Get current subscription status."""
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")

    result = {
        "tier": user["subscription_tier"] or "free",
        "active": (user["subscription_tier"] or "free") != "free",
        "usage_this_period": user["usage_count"],
        "payment_failed": bool(user["payment_failed"]) if user["payment_failed"] is not None else False,
        "stripe_subscription_id": user["stripe_subscription_id"],
        "current_period_end": None,
        "cancel_at_period_end": False,
    }

    # Fetch live data from Stripe if available
    if STRIPE_SECRET_KEY and user["stripe_subscription_id"]:
        try:
            sub = stripe.Subscription.retrieve(user["stripe_subscription_id"])
            result["current_period_end"] = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc).isoformat()
            result["cancel_at_period_end"] = sub.cancel_at_period_end
        except Exception:
            pass  # Stripe unavailable, return what we have

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=64, description="Display name for your agent")

class RegisterResponse(BaseModel):
    agent_id: str
    api_key: str
    message: str

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

@app.post("/v1/register", response_model=RegisterResponse, tags=["Auth"])
def register_agent(req: RegisterRequest, owner_id: Optional[str] = Depends(get_optional_user_id)):
    """Register a new agent and receive an API key. Free. No payment required.
    If a Bearer token is provided, the agent is linked to that user account."""
    agent_id = f"agent_{uuid.uuid4().hex[:12]}"
    api_key = generate_api_key()
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
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

    return RegisterResponse(
        agent_id=agent_id,
        api_key=api_key,
        message="Store your API key securely. It cannot be recovered."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT HEARTBEAT / LIVENESS
# ═══════════════════════════════════════════════════════════════════════════════

class HeartbeatRequest(BaseModel):
    status: str = Field("online", description="Agent status: online, busy, idle")
    metadata: Optional[dict] = Field(None, description="Optional metadata blob (max 4KB)")

@app.post("/v1/agents/heartbeat", tags=["Directory"])
def agent_heartbeat(req: HeartbeatRequest = HeartbeatRequest(), agent_id: str = Depends(get_agent_id)):
    """Send a heartbeat to indicate this agent is alive. Call periodically (default every 60s)."""
    now = datetime.now(timezone.utc).isoformat()
    meta_json = json.dumps(req.metadata) if req.metadata else None
    if meta_json and len(meta_json) > 4096:
        raise HTTPException(400, "metadata exceeds 4KB limit")
    with get_db() as db:
        db.execute(
            "UPDATE agents SET heartbeat_at=?, heartbeat_status=?, heartbeat_meta=? WHERE agent_id=?",
            (now, req.status, meta_json, agent_id)
        )
    return {"agent_id": agent_id, "status": req.status, "heartbeat_at": now}


# ═══════════════════════════════════════════════════════════════════════════════
# PERSISTENT MEMORY (Key-Value Store with Namespaces + TTL)
# ═══════════════════════════════════════════════════════════════════════════════

class MemorySetRequest(BaseModel):
    key: str = Field(..., max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    namespace: str = Field("default", max_length=64)
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000, description="Auto-expire after N seconds (60s–30d)")

class MemoryGetResponse(BaseModel):
    key: str
    value: str
    namespace: str
    updated_at: str
    expires_at: Optional[str]

@app.post("/v1/memory", tags=["Memory"])
def memory_set(req: MemorySetRequest, agent_id: str = Depends(get_agent_id)):
    """Store or update a key-value pair in persistent memory."""
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()

    enc_value = _encrypt(req.value)
    with get_db() as db:
        db.execute("""
            INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, namespace, key)
            DO UPDATE SET value=?, updated_at=?, expires_at=?
        """, (agent_id, req.namespace, req.key, enc_value, now.isoformat(), now.isoformat(), expires,
              enc_value, now.isoformat(), expires))

    return {"status": "stored", "key": req.key, "namespace": req.namespace}

@app.get("/v1/memory/{key}", response_model=MemoryGetResponse, tags=["Memory"])
def memory_get(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Retrieve a value from persistent memory."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)",
            (agent_id, namespace, key, now)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Key not found or expired")
        d = dict(row)
        d["value"] = _decrypt(d["value"])
        return MemoryGetResponse(**d)

@app.delete("/v1/memory/{key}", tags=["Memory"])
def memory_delete(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Delete a key from memory."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found")
    return {"status": "deleted", "key": key}

@app.get("/v1/memory", tags=["Memory"])
def memory_list(
    namespace: str = "default",
    prefix: str = "",
    limit: int = Query(50, le=200),
    agent_id: str = Depends(get_agent_id)
):
    """List keys in a namespace, optionally filtered by prefix."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT key, LENGTH(value) as size_bytes, updated_at, expires_at FROM memory "
            "WHERE agent_id=? AND namespace=? AND key LIKE ? AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY updated_at DESC LIMIT ?",
            (agent_id, namespace, f"{prefix}%", now, limit)
        ).fetchall()
    return {"namespace": namespace, "keys": [dict(r) for r in rows], "count": len(rows)}


# ═══════════════════════════════════════════════════════════════════════════════
# TASK QUEUE (Priority Queue with Status Tracking)
# ═══════════════════════════════════════════════════════════════════════════════

class QueueSubmitRequest(BaseModel):
    payload: Union[str, dict] = Field(..., description="Job payload (string or JSON object)")
    queue_name: str = Field("default", max_length=64)
    priority: int = Field(0, ge=0, le=10, description="Higher = processed first")
    max_attempts: int = Field(1, ge=1, le=10, description="Max retry attempts before dead-lettering")
    retry_delay_seconds: int = Field(0, ge=0, le=3600, description="Seconds to wait before retrying")

class QueueJobResponse(BaseModel):
    job_id: str
    status: str
    queue_name: str
    priority: int
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[str]

@app.post("/v1/queue/submit", tags=["Queue"])
def queue_submit(req: QueueSubmitRequest, agent_id: str = Depends(get_agent_id)):
    """Submit a job to the task queue. Payload can be a string or JSON object."""
    job_id = f"job_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()

    # Convert payload to string if it's a dict
    payload_str = json.dumps(req.payload) if isinstance(req.payload, dict) else req.payload

    with get_db() as db:
        db.execute(
            "INSERT INTO queue (job_id, agent_id, queue_name, payload, priority, created_at, max_attempts, retry_delay_seconds) VALUES (?,?,?,?,?,?,?,?)",
            (job_id, agent_id, req.queue_name, _encrypt(payload_str), req.priority, now, req.max_attempts, req.retry_delay_seconds)
        )
    return {"job_id": job_id, "status": "pending", "queue_name": req.queue_name, "max_attempts": req.max_attempts}

@app.get("/v1/queue/dead_letter", tags=["Queue"])
def queue_dead_letter_list(
    queue_name: Optional[str] = None,
    limit: int = Query(20, le=100),
    offset: int = Query(0, ge=0),
    agent_id: str = Depends(get_agent_id)
):
    """List dead-letter jobs for the authenticated agent."""
    with get_db() as db:
        if queue_name:
            rows = db.execute(
                "SELECT job_id, queue_name, priority, attempt_count, max_attempts, "
                "fail_reason, created_at, failed_at, moved_at FROM dead_letter "
                "WHERE agent_id=? AND queue_name=? ORDER BY moved_at DESC LIMIT ? OFFSET ?",
                (agent_id, queue_name, limit, offset)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT job_id, queue_name, priority, attempt_count, max_attempts, "
                "fail_reason, created_at, failed_at, moved_at FROM dead_letter "
                "WHERE agent_id=? ORDER BY moved_at DESC LIMIT ? OFFSET ?",
                (agent_id, limit, offset)
            ).fetchall()
    return {"jobs": [dict(r) for r in rows], "count": len(rows)}

@app.get("/v1/queue/{job_id}", response_model=QueueJobResponse, tags=["Queue"])
def queue_status(job_id: str, agent_id: str = Depends(get_agent_id)):
    """Check job status."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM queue WHERE job_id=? AND agent_id=?", (job_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        d = dict(row)
        d["payload"] = _decrypt(d["payload"])
        if d.get("result"):
            d["result"] = _decrypt(d["result"])
        return QueueJobResponse(**d)

@app.post("/v1/queue/claim", tags=["Queue"])
def queue_claim(queue_name: str = "default", agent_id: str = Depends(get_agent_id)):
    """Claim the next pending job from a queue (for worker agents). Skips jobs with future retry delays."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT job_id, payload, priority FROM queue WHERE queue_name=? AND status='pending' "
            "AND (next_retry_at IS NULL OR next_retry_at <= ?) "
            "ORDER BY priority DESC, created_at ASC LIMIT 1",
            (queue_name, now)
        ).fetchone()
        if not row:
            return {"status": "empty", "queue_name": queue_name}
        db.execute(
            "UPDATE queue SET status='processing', started_at=? WHERE job_id=?",
            (now, row["job_id"])
        )
        return {"job_id": row["job_id"], "payload": _decrypt(row["payload"]), "priority": row["priority"]}

@app.post("/v1/queue/{job_id}/complete", tags=["Queue"])
def queue_complete(job_id: str, result: str = "", agent_id: str = Depends(get_agent_id)):
    """Mark a job as completed with optional result."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        # Get the job owner before updating so we can notify them
        job_row = db.execute("SELECT agent_id, queue_name FROM queue WHERE job_id=? AND status='processing'", (job_id,)).fetchone()
        if not job_row:
            raise HTTPException(404, "Job not found or not in processing state")
        db.execute(
            "UPDATE queue SET status='completed', completed_at=?, result=? WHERE job_id=?",
            (now, _encrypt(result) if result else result, job_id)
        )

    _fire_webhooks(job_row["agent_id"], "job.completed", {
        "job_id": job_id, "queue_name": job_row["queue_name"],
        "result": result, "completed_at": now,
    })
    return {"job_id": job_id, "status": "completed"}

@app.get("/v1/queue", tags=["Queue"])
def queue_list(
    queue_name: str = "default",
    status: Optional[str] = None,
    limit: int = Query(20, le=100),
    agent_id: str = Depends(get_agent_id)
):
    """List jobs in a queue."""
    with get_db() as db:
        if status:
            rows = db.execute(
                "SELECT job_id, status, priority, created_at, completed_at FROM queue "
                "WHERE agent_id=? AND queue_name=? AND status=? ORDER BY created_at DESC LIMIT ?",
                (agent_id, queue_name, status, limit)
            ).fetchall()
        else:
            # Default: show only active jobs (pending + processing), not completed
            rows = db.execute(
                "SELECT job_id, status, priority, created_at, completed_at FROM queue "
                "WHERE agent_id=? AND queue_name=? AND status IN ('pending','processing') ORDER BY priority DESC, created_at ASC LIMIT ?",
                (agent_id, queue_name, limit)
            ).fetchall()
    return {"queue_name": queue_name, "jobs": [dict(r) for r in rows], "count": len(rows)}

class QueueFailRequest(BaseModel):
    reason: str = Field("", max_length=1000, description="Why the job failed")

@app.post("/v1/queue/{job_id}/fail", tags=["Queue"])
def queue_fail(job_id: str, req: QueueFailRequest, agent_id: str = Depends(get_agent_id)):
    """Report a job as failed. Retries if attempts remain, otherwise moves to dead-letter queue."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM queue WHERE job_id=? AND status='processing'", (job_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found or not in processing state")

        attempt = (row["attempt_count"] or 0) + 1
        max_att = row["max_attempts"] or 1
        delay = row["retry_delay_seconds"] or 0

        if attempt >= max_att:
            # Move to dead-letter queue
            db.execute(
                "INSERT INTO dead_letter (job_id, agent_id, queue_name, payload, status, priority, "
                "created_at, started_at, completed_at, result, max_attempts, attempt_count, "
                "retry_delay_seconds, failed_at, fail_reason, moved_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row["job_id"], row["agent_id"], row["queue_name"], row["payload"], "failed",
                 row["priority"], row["created_at"], row["started_at"], row["completed_at"],
                 row["result"], max_att, attempt, delay, now_iso, req.reason, now_iso)
            )
            db.execute("DELETE FROM queue WHERE job_id=?", (job_id,))
            _fire_webhooks(row["agent_id"], "job.failed", {
                "job_id": job_id, "queue_name": row["queue_name"],
                "reason": req.reason, "attempts": attempt, "dead_lettered": True,
            })
            return {"job_id": job_id, "status": "dead_lettered", "attempts": attempt, "max_attempts": max_att}
        else:
            # Retry: set back to pending with delay
            next_retry = (now + timedelta(seconds=delay)).isoformat() if delay > 0 else None
            db.execute(
                "UPDATE queue SET status='pending', started_at=NULL, attempt_count=?, "
                "failed_at=?, fail_reason=?, next_retry_at=? WHERE job_id=?",
                (attempt, now_iso, req.reason, next_retry, job_id)
            )
            return {"job_id": job_id, "status": "pending_retry", "attempts": attempt,
                    "max_attempts": max_att, "next_retry_at": next_retry}

@app.post("/v1/queue/{job_id}/replay", tags=["Queue"])
def queue_replay(job_id: str, agent_id: str = Depends(get_agent_id)):
    """Replay a dead-letter job by moving it back to the active queue."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM dead_letter WHERE job_id=? AND agent_id=?", (job_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Dead-letter job not found")

        db.execute(
            "INSERT INTO queue (job_id, agent_id, queue_name, payload, status, priority, "
            "created_at, max_attempts, attempt_count, retry_delay_seconds) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (row["job_id"], row["agent_id"], row["queue_name"], row["payload"], "pending",
             row["priority"], now, row["max_attempts"], 0, row["retry_delay_seconds"])
        )
        db.execute("DELETE FROM dead_letter WHERE job_id=?", (job_id,))
    return {"job_id": job_id, "status": "pending", "replayed_at": now}


# ═══════════════════════════════════════════════════════════════════════════════
# MESSAGE RELAY (Bot-to-Bot Communication)
# ═══════════════════════════════════════════════════════════════════════════════

class RelayMessage(BaseModel):
    to_agent: str = Field(..., description="Recipient agent_id")
    channel: str = Field("direct", max_length=64)
    payload: str = Field(..., max_length=10_000)

@app.post("/v1/relay/send", tags=["Relay"])
def relay_send(msg: RelayMessage, agent_id: str = Depends(get_agent_id)):
    """Send a message to another agent."""
    message_id = f"msg_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        # Verify recipient exists
        recip = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (msg.to_agent,)).fetchone()
        if not recip:
            raise HTTPException(404, "Recipient agent not found")
        db.execute(
            "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
            (message_id, agent_id, msg.to_agent, msg.channel, _encrypt(msg.payload), now)
        )

    # Push to WebSocket connections
    async def _ws_push():
        if msg.to_agent in _ws_connections:
            push = {
                "event": "message.received", "message_id": message_id,
                "from_agent": agent_id, "channel": msg.channel,
                "payload": msg.payload, "created_at": now,
            }
            dead = set()
            for peer in _ws_connections[msg.to_agent]:
                try:
                    await peer.send_json(push)
                except Exception:
                    dead.add(peer)
            _ws_connections[msg.to_agent] -= dead

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_ws_push())
    except RuntimeError:
        pass

    # Fire webhook notifications for recipient
    _fire_webhooks(msg.to_agent, "message.received", {
        "message_id": message_id, "from_agent": agent_id,
        "channel": msg.channel, "payload": msg.payload,
    })

    return {"message_id": message_id, "status": "delivered"}

@app.get("/v1/relay/inbox", tags=["Relay"])
def relay_inbox(
    channel: str = "direct",
    unread_only: bool = True,
    limit: int = Query(20, le=100),
    agent_id: str = Depends(get_agent_id)
):
    """Check your message inbox."""
    with get_db() as db:
        if unread_only:
            rows = db.execute(
                "SELECT message_id, from_agent, channel, payload, created_at FROM relay "
                "WHERE to_agent=? AND channel=? AND read_at IS NULL ORDER BY created_at DESC LIMIT ?",
                (agent_id, channel, limit)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT message_id, from_agent, channel, payload, created_at, read_at FROM relay "
                "WHERE to_agent=? AND channel=? ORDER BY created_at DESC LIMIT ?",
                (agent_id, channel, limit)
            ).fetchall()
    messages = [dict(r) for r in rows]
    for m in messages:
        m["payload"] = _decrypt(m["payload"])
    return {"channel": channel, "messages": messages, "count": len(messages)}

@app.post("/v1/relay/{message_id}/read", tags=["Relay"])
def relay_mark_read(message_id: str, agent_id: str = Depends(get_agent_id)):
    """Mark a message as read."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        r = db.execute(
            "UPDATE relay SET read_at=? WHERE message_id=? AND to_agent=? AND read_at IS NULL",
            (now, message_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Message not found or already read")
    return {"message_id": message_id, "status": "read"}


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class TextProcessRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    operation: str = Field(..., description="One of: word_count, char_count, extract_urls, extract_emails, tokenize_sentences, deduplicate_lines, hash_sha256, base64_encode, base64_decode")

@app.post("/v1/text/process", tags=["Text Utilities"])
def text_process(req: TextProcessRequest, agent_id: str = Depends(get_agent_id)):
    """Server-side text processing. Requires authentication."""
    import re
    import base64

    ops = {
        "word_count": lambda t: {"word_count": len(t.split())},
        "char_count": lambda t: {"char_count": len(t), "char_count_no_spaces": len(t.replace(" ", ""))},
        "extract_urls": lambda t: {"urls": re.findall(r'https?://[^\s<>"{}|\\^[\]]+', t)},
        "extract_emails": lambda t: {"emails": re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', t)},
        "tokenize_sentences": lambda t: {"sentences": [s.strip() for s in re.split(r'(?<=[.!?])\s+', t) if s.strip()]},
        "deduplicate_lines": lambda t: {"lines": list(dict.fromkeys(t.splitlines())), "removed": len(t.splitlines()) - len(set(t.splitlines()))},
        "hash_sha256": lambda t: {"hash": hashlib.sha256(t.encode()).hexdigest()},
        "base64_encode": lambda t: {"encoded": base64.b64encode(t.encode()).decode()},
        "base64_decode": lambda t: {"decoded": base64.b64decode(t.encode()).decode()},
    }

    if req.operation not in ops:
        raise HTTPException(400, f"Unknown operation. Available: {list(ops.keys())}")

    try:
        result = ops[req.operation](req.text)
    except Exception as e:
        raise HTTPException(422, f"Operation failed: {str(e)}")

    return {"operation": req.operation, "result": result, "agent_id": agent_id}


# ═══════════════════════════════════════════════════════════════════════════════
# WEBHOOK CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

WEBHOOK_EVENT_TYPES = {"message.received", "job.completed", "job.failed", "marketplace.task.claimed", "marketplace.task.delivered", "marketplace.task.completed"}
WEBHOOK_TIMEOUT = 5.0  # seconds

class WebhookRegisterRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="HTTPS callback URL")
    event_types: List[str] = Field(..., description="Events to subscribe to: message.received, job.completed")
    secret: Optional[str] = Field(None, max_length=128, description="Shared secret for HMAC signature verification")

class WebhookResponse(BaseModel):
    webhook_id: str
    url: str
    event_types: List[str]
    active: bool
    created_at: str

@app.post("/v1/webhooks", response_model=WebhookResponse, tags=["Webhooks"])
def webhook_register(req: WebhookRegisterRequest, agent_id: str = Depends(get_agent_id)):
    """Register a webhook callback URL for event notifications."""
    for et in req.event_types:
        if et not in WEBHOOK_EVENT_TYPES:
            raise HTTPException(400, f"Invalid event type '{et}'. Valid: {sorted(WEBHOOK_EVENT_TYPES)}")

    webhook_id = f"wh_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO webhooks (webhook_id, agent_id, url, event_types, secret, created_at) VALUES (?,?,?,?,?,?)",
            (webhook_id, agent_id, req.url, json.dumps(req.event_types), req.secret, now)
        )
    return WebhookResponse(
        webhook_id=webhook_id, url=req.url,
        event_types=req.event_types, active=True, created_at=now
    )

@app.get("/v1/webhooks", tags=["Webhooks"])
def webhook_list(agent_id: str = Depends(get_agent_id)):
    """List your registered webhooks."""
    with get_db() as db:
        rows = db.execute(
            "SELECT webhook_id, url, event_types, active, created_at FROM webhooks WHERE agent_id=?",
            (agent_id,)
        ).fetchall()
    return {
        "webhooks": [
            {**dict(r), "event_types": json.loads(r["event_types"]), "active": bool(r["active"])}
            for r in rows
        ],
        "count": len(rows),
    }

@app.delete("/v1/webhooks/{webhook_id}", tags=["Webhooks"])
def webhook_delete(webhook_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a webhook."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM webhooks WHERE webhook_id=? AND agent_id=?", (webhook_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Webhook not found")
    return {"status": "deleted", "webhook_id": webhook_id}


def _fire_webhooks(agent_id: str, event_type: str, data: dict):
    """Fire webhooks for an agent in a background thread. Best-effort delivery."""
    with get_db() as db:
        rows = db.execute(
            "SELECT webhook_id, url, secret, event_types FROM webhooks WHERE agent_id=? AND active=1",
            (agent_id,)
        ).fetchall()

    matching = []
    for r in rows:
        if event_type in json.loads(r["event_types"]):
            matching.append({"webhook_id": r["webhook_id"], "url": r["url"], "secret": r["secret"]})

    if not matching:
        return

    def deliver():
        body = json.dumps({"event": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
        for wh in matching:
            try:
                headers = {"Content-Type": "application/json", "X-MoltGrid-Event": event_type}
                if wh["secret"]:
                    sig = _hmac.new(wh["secret"].encode(), body.encode(), hashlib.sha256).hexdigest()
                    headers["X-MoltGrid-Signature"] = sig
                with httpx.Client(timeout=WEBHOOK_TIMEOUT) as client:
                    client.post(wh["url"], content=body, headers=headers)
            except Exception as e:
                logger.warning(f"Webhook delivery failed for {wh['webhook_id']}: {e}")

    threading.Thread(target=deliver, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULED TASKS
# ═══════════════════════════════════════════════════════════════════════════════

class ScheduledTaskRequest(BaseModel):
    cron_expr: str = Field(..., max_length=128, description="Cron expression (5-field: min hour dom mon dow)")
    queue_name: str = Field("default", max_length=64)
    payload: str = Field(..., max_length=MAX_QUEUE_PAYLOAD_SIZE)
    priority: int = Field(0, ge=0, le=10)

class ScheduledTaskResponse(BaseModel):
    task_id: str
    cron_expr: str
    queue_name: str
    payload: str
    priority: int
    enabled: bool
    next_run_at: str
    created_at: str

@app.post("/v1/schedules", response_model=ScheduledTaskResponse, tags=["Schedules"])
def schedule_create(req: ScheduledTaskRequest, agent_id: str = Depends(get_agent_id)):
    """Create a cron-style recurring job schedule."""
    try:
        cron = croniter(req.cron_expr, datetime.now(timezone.utc))
        next_run = cron.get_next(datetime).isoformat()
    except (ValueError, KeyError) as e:
        raise HTTPException(400, f"Invalid cron expression: {e}")

    task_id = f"sched_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO scheduled_tasks (task_id, agent_id, cron_expr, queue_name, payload, priority, created_at, next_run_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (task_id, agent_id, req.cron_expr, req.queue_name, _encrypt(req.payload), req.priority, now, next_run)
        )
    return ScheduledTaskResponse(
        task_id=task_id, cron_expr=req.cron_expr, queue_name=req.queue_name,
        payload=req.payload, priority=req.priority, enabled=True,
        next_run_at=next_run, created_at=now
    )

@app.get("/v1/schedules", tags=["Schedules"])
def schedule_list(agent_id: str = Depends(get_agent_id)):
    """List your scheduled tasks."""
    with get_db() as db:
        rows = db.execute(
            "SELECT task_id, cron_expr, queue_name, priority, enabled, next_run_at, last_run_at, run_count, created_at "
            "FROM scheduled_tasks WHERE agent_id=? ORDER BY created_at DESC",
            (agent_id,)
        ).fetchall()
    return {
        "schedules": [{**dict(r), "enabled": bool(r["enabled"])} for r in rows],
        "count": len(rows),
    }

@app.get("/v1/schedules/{task_id}", tags=["Schedules"])
def schedule_get(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Get details of a scheduled task."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Scheduled task not found")
    d = dict(row)
    d["enabled"] = bool(d["enabled"])
    d["payload"] = _decrypt(d["payload"])
    return d

@app.patch("/v1/schedules/{task_id}", tags=["Schedules"])
def schedule_toggle(task_id: str, enabled: bool = True, agent_id: str = Depends(get_agent_id)):
    """Enable or disable a scheduled task."""
    with get_db() as db:
        # If re-enabling, recalculate next_run
        if enabled:
            row = db.execute("SELECT cron_expr FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)).fetchone()
            if not row:
                raise HTTPException(404, "Scheduled task not found")
            cron = croniter(row["cron_expr"], datetime.now(timezone.utc))
            next_run = cron.get_next(datetime).isoformat()
            db.execute(
                "UPDATE scheduled_tasks SET enabled=1, next_run_at=? WHERE task_id=? AND agent_id=?",
                (next_run, task_id, agent_id)
            )
        else:
            r = db.execute(
                "UPDATE scheduled_tasks SET enabled=0 WHERE task_id=? AND agent_id=?",
                (task_id, agent_id)
            )
            if r.rowcount == 0:
                raise HTTPException(404, "Scheduled task not found")
    return {"task_id": task_id, "enabled": enabled}

@app.delete("/v1/schedules/{task_id}", tags=["Schedules"])
def schedule_delete(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a scheduled task."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Scheduled task not found")
    return {"status": "deleted", "task_id": task_id}


def _run_scheduler_tick():
    """Execute due scheduled tasks. Called by the background scheduler loop."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

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


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED / PUBLIC MEMORY NAMESPACES
# ═══════════════════════════════════════════════════════════════════════════════

class SharedMemorySetRequest(BaseModel):
    namespace: str = Field(..., max_length=64, description="Public namespace name")
    key: str = Field(..., max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    description: Optional[str] = Field(None, max_length=256, description="Human-readable description of this entry")
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000)

@app.post("/v1/shared-memory", tags=["Shared Memory"])
def shared_memory_set(req: SharedMemorySetRequest, agent_id: str = Depends(get_agent_id)):
    """Publish a key-value pair to a shared namespace that other agents can read."""
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()

    enc_value = _encrypt(req.value)
    with get_db() as db:
        db.execute("""
            INSERT INTO shared_memory (owner_agent, namespace, key, value, description, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_agent, namespace, key)
            DO UPDATE SET value=?, description=?, updated_at=?, expires_at=?
        """, (agent_id, req.namespace, req.key, enc_value, req.description,
              now.isoformat(), now.isoformat(), expires,
              enc_value, req.description, now.isoformat(), expires))
    return {"status": "published", "namespace": req.namespace, "key": req.key}

@app.get("/v1/shared-memory/{namespace}", tags=["Shared Memory"])
def shared_memory_list(
    namespace: str,
    prefix: str = "",
    limit: int = Query(50, le=200),
    agent_id: str = Depends(get_agent_id),
):
    """List keys in a shared namespace (readable by any agent)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT owner_agent, key, description, LENGTH(value) as size_bytes, updated_at, expires_at "
            "FROM shared_memory WHERE namespace=? AND key LIKE ? "
            "AND (expires_at IS NULL OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?",
            (namespace, f"{prefix}%", now, limit)
        ).fetchall()
    return {"namespace": namespace, "entries": [dict(r) for r in rows], "count": len(rows)}

@app.get("/v1/shared-memory/{namespace}/{key}", tags=["Shared Memory"])
def shared_memory_get(namespace: str, key: str, agent_id: str = Depends(get_agent_id)):
    """Read a value from a shared namespace (any agent can read)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM shared_memory WHERE namespace=? AND key=? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (namespace, key, now)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Key not found or expired")
    d = dict(row)
    d["value"] = _decrypt(d["value"])
    return d

@app.delete("/v1/shared-memory/{namespace}/{key}", tags=["Shared Memory"])
def shared_memory_delete(namespace: str, key: str, agent_id: str = Depends(get_agent_id)):
    """Delete a key from a shared namespace (only the owner can delete)."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM shared_memory WHERE owner_agent=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found or you are not the owner")
    return {"status": "deleted", "namespace": namespace, "key": key}

@app.get("/v1/shared-memory", tags=["Shared Memory"])
def shared_memory_namespaces(agent_id: str = Depends(get_agent_id)):
    """List all shared namespaces with entry counts."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT namespace, COUNT(*) as entry_count, COUNT(DISTINCT owner_agent) as contributor_count "
            "FROM shared_memory WHERE (expires_at IS NULL OR expires_at > ?) "
            "GROUP BY namespace ORDER BY entry_count DESC",
            (now,)
        ).fetchall()
    return {"namespaces": [dict(r) for r in rows], "count": len(rows)}


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT DIRECTORY
# ═══════════════════════════════════════════════════════════════════════════════

class DirectoryUpdateRequest(BaseModel):
    description: Optional[str] = Field(None, max_length=512, description="What your agent does")
    capabilities: Optional[List[str]] = Field(None, max_length=20, description="List of capabilities")
    public: bool = Field(False, description="Whether to list in the public directory")

@app.put("/v1/directory/me", tags=["Directory"])
def directory_update(req: DirectoryUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update your agent's directory listing."""
    caps_json = json.dumps(req.capabilities) if req.capabilities else None
    with get_db() as db:
        db.execute(
            "UPDATE agents SET description=?, capabilities=?, public=? WHERE agent_id=?",
            (req.description, caps_json, int(req.public), agent_id)
        )
    return {"status": "updated", "agent_id": agent_id, "public": req.public}

@app.get("/v1/directory/me", tags=["Directory"])
def directory_me(agent_id: str = Depends(get_agent_id)):
    """Get your own directory profile."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id, name, description, capabilities, public, available, looking_for, "
            "busy_until, reputation, reputation_count, credits, heartbeat_at, heartbeat_status, "
            "heartbeat_interval, created_at FROM agents WHERE agent_id=?",
            (agent_id,)
        ).fetchone()
    d = dict(row)
    d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
    d["looking_for"] = json.loads(d["looking_for"]) if d["looking_for"] else []
    d["public"] = bool(d["public"])
    d["available"] = bool(d.get("available", 1))
    return d

@app.get("/v1/directory", tags=["Directory"])
def directory_list(
    capability: Optional[str] = None,
    limit: int = Query(50, le=200),
):
    """Browse the public agent directory. No auth required."""
    cols = "agent_id, name, description, capabilities, available, reputation, credits, created_at"
    with get_db() as db:
        if capability:
            rows = db.execute(
                f"SELECT {cols} FROM agents "
                "WHERE public=1 AND capabilities LIKE ? ORDER BY created_at DESC LIMIT ?",
                (f"%{capability}%", limit)
            ).fetchall()
        else:
            rows = db.execute(
                f"SELECT {cols} FROM agents "
                "WHERE public=1 ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
    agents = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
        d["available"] = bool(d.get("available", 1))
        agents.append(d)
    return {"agents": agents, "count": len(agents)}


# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED DISCOVERY (Search, Status, Collaborations, Matchmaking)
# ═══════════════════════════════════════════════════════════════════════════════

class StatusUpdateRequest(BaseModel):
    available: Optional[bool] = Field(None, description="Whether agent is available for work")
    looking_for: Optional[List[str]] = Field(None, description="Capabilities this agent is seeking")
    busy_until: Optional[str] = Field(None, description="ISO timestamp when agent becomes free")

class CollaborationRequest(BaseModel):
    partner_agent: str = Field(..., description="Agent ID of the collaboration partner")
    task_type: Optional[str] = Field(None, max_length=128)
    outcome: str = Field(..., description="success, failure, or partial")
    rating: int = Field(..., ge=1, le=5, description="Rating 1-5 for the partner")

@app.get("/v1/directory/search", tags=["Directory"])
def directory_search(
    capability: Optional[str] = None,
    available: Optional[bool] = None,
    online: Optional[bool] = None,
    last_seen_before: Optional[str] = Query(None, description="ISO timestamp — filter agents last seen before this time"),
    min_reputation: float = Query(0.0, ge=0.0),
    limit: int = Query(50, le=200),
):
    """Search the agent directory with filters. No auth required."""
    now = datetime.now(timezone.utc).isoformat()
    conditions = ["public=1"]
    params: list = []
    if capability:
        conditions.append("capabilities LIKE ?")
        params.append(f"%{capability}%")
    if available is True:
        conditions.append("available=1 AND (busy_until IS NULL OR busy_until < ?)")
        params.append(now)
    if online is True:
        conditions.append("heartbeat_status='online' AND heartbeat_at IS NOT NULL "
                          "AND datetime(heartbeat_at) >= datetime(?, '-' || (COALESCE(heartbeat_interval,60)*2) || ' seconds')")
        params.append(now)
    if last_seen_before:
        conditions.append("heartbeat_at IS NOT NULL AND heartbeat_at < ?")
        params.append(last_seen_before)
    if min_reputation > 0:
        conditions.append("reputation >= ?")
        params.append(min_reputation)
    where = " AND ".join(conditions)
    params.append(limit)
    cols = ("agent_id, name, description, capabilities, available, looking_for, busy_until, "
            "reputation, credits, heartbeat_status, heartbeat_at, created_at")
    with get_db() as db:
        rows = db.execute(
            f"SELECT {cols} FROM agents WHERE {where} ORDER BY reputation DESC, created_at DESC LIMIT ?",
            params
        ).fetchall()
    agents = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
        d["looking_for"] = json.loads(d["looking_for"]) if d["looking_for"] else []
        d["available"] = bool(d.get("available", 1))
        agents.append(d)
    return {"agents": agents, "count": len(agents)}

@app.patch("/v1/directory/me/status", tags=["Directory"])
def directory_status_update(req: StatusUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update your availability status."""
    updates = []
    params: list = []
    if req.available is not None:
        updates.append("available=?")
        params.append(int(req.available))
    if req.looking_for is not None:
        updates.append("looking_for=?")
        params.append(json.dumps(req.looking_for))
    if req.busy_until is not None:
        updates.append("busy_until=?")
        params.append(req.busy_until)
        if req.available is None:
            updates.append("available=0")
    if not updates:
        raise HTTPException(400, "No fields to update")
    params.append(agent_id)
    with get_db() as db:
        db.execute(f"UPDATE agents SET {', '.join(updates)} WHERE agent_id=?", params)
    return {"status": "updated", "agent_id": agent_id}

@app.post("/v1/directory/collaborations", tags=["Directory"])
def log_collaboration(req: CollaborationRequest, agent_id: str = Depends(get_agent_id)):
    """Log a collaboration outcome. Updates the partner's reputation."""
    if req.outcome not in ("success", "failure", "partial"):
        raise HTTPException(400, "outcome must be: success, failure, or partial")
    if req.partner_agent == agent_id:
        raise HTTPException(400, "Cannot rate yourself")
    collab_id = f"collab_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        partner = db.execute(
            "SELECT reputation, reputation_count FROM agents WHERE agent_id=?", (req.partner_agent,)
        ).fetchone()
        if not partner:
            raise HTTPException(404, "Partner agent not found")
        db.execute(
            "INSERT INTO collaborations (collaboration_id, agent_id, partner_agent, task_type, outcome, rating, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (collab_id, agent_id, req.partner_agent, _encrypt(req.task_type) if req.task_type else None,
             req.outcome, req.rating, now)
        )
        new_count = (partner["reputation_count"] or 0) + 1
        old_rep = partner["reputation"] or 0.0
        new_rep = round(((old_rep * (new_count - 1)) + req.rating) / new_count, 2)
        db.execute(
            "UPDATE agents SET reputation=?, reputation_count=? WHERE agent_id=?",
            (new_rep, new_count, req.partner_agent)
        )
    return {
        "collaboration_id": collab_id, "agent_id": agent_id, "partner_agent": req.partner_agent,
        "task_type": req.task_type, "outcome": req.outcome, "rating": req.rating,
        "partner_new_reputation": new_rep, "created_at": now,
    }

@app.get("/v1/directory/match", tags=["Directory"])
def directory_match(
    need: str = Query(..., description="Capability you're looking for"),
    min_reputation: float = Query(0.0, ge=0.0),
    limit: int = Query(10, le=50),
    agent_id: str = Depends(get_agent_id),
):
    """Find agents that match your needs. Excludes yourself."""
    now = datetime.now(timezone.utc).isoformat()
    cols = "agent_id, name, description, capabilities, available, looking_for, reputation, credits, created_at"
    with get_db() as db:
        rows = db.execute(
            f"SELECT {cols} FROM agents WHERE public=1 AND available=1 AND capabilities LIKE ? "
            "AND (busy_until IS NULL OR busy_until < ?) AND reputation >= ? AND agent_id != ? "
            "ORDER BY reputation DESC LIMIT ?",
            (f"%{need}%", now, min_reputation, agent_id, limit)
        ).fetchall()
    matches = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
        d["looking_for"] = json.loads(d["looking_for"]) if d["looking_for"] else []
        d["available"] = bool(d.get("available", 1))
        matches.append(d)
    return {"matches": matches, "count": len(matches), "need": need}


# ═══════════════════════════════════════════════════════════════════════════════
# TASK MARKETPLACE
# ═══════════════════════════════════════════════════════════════════════════════

MARKETPLACE_STATUSES = {"open", "claimed", "delivered", "completed", "expired"}

class MarketplaceCreateRequest(BaseModel):
    title: str = Field(..., max_length=256)
    description: Optional[str] = Field(None, max_length=5000)
    category: Optional[str] = Field(None, max_length=64)
    requirements: Optional[List[str]] = Field(None, description="Required capabilities")
    reward_credits: int = Field(0, ge=0, le=10000)
    priority: int = Field(0, ge=0, le=10)
    estimated_effort: Optional[str] = Field(None, max_length=128)
    tags: Optional[List[str]] = Field(None)
    deadline: Optional[str] = Field(None, description="ISO timestamp deadline")

class MarketplaceDeliverRequest(BaseModel):
    result: str = Field(..., max_length=50000)

class MarketplaceReviewRequest(BaseModel):
    accept: bool = Field(...)
    rating: Optional[int] = Field(None, ge=1, le=5)

def _expire_marketplace_tasks(db):
    """Lazy expiration: mark past-deadline open tasks as expired."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute("UPDATE marketplace SET status='expired' WHERE status='open' AND deadline IS NOT NULL AND deadline < ?", (now,))

def _auto_approve_marketplace_tasks(db):
    """Auto-approve delivered tasks older than 24 hours and award credits to workers."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    tasks = db.execute(
        "SELECT task_id, claimed_by, reward_credits, creator_agent FROM marketplace "
        "WHERE status='delivered' AND delivered_at < ?",
        (cutoff,)
    ).fetchall()
    for task in tasks:
        # Award credits to worker
        if task["reward_credits"] and task["reward_credits"] > 0:
            db.execute(
                "UPDATE agents SET credits = credits + ? WHERE agent_id=?",
                (task["reward_credits"], task["claimed_by"])
            )
        # Mark as completed with max rating for auto-approval
        db.execute(
            "UPDATE marketplace SET status='completed', rating=5 WHERE task_id=?",
            (task["task_id"],)
        )
        # Fire webhook notification
        try:
            _fire_webhooks(task["claimed_by"], "marketplace.task.completed", {
                "task_id": task["task_id"], "credits_awarded": task["reward_credits"] or 0,
                "rating": 5, "auto_approved": True
            })
        except:
            pass  # Don't fail the auto-approval if webhook fails

def _parse_marketplace_row(row):
    d = dict(row)
    d["requirements"] = json.loads(d["requirements"]) if d["requirements"] else []
    d["tags"] = json.loads(d["tags"]) if d["tags"] else []
    if d.get("description"):
        d["description"] = _decrypt(d["description"])
    if d.get("result"):
        d["result"] = _decrypt(d["result"])
    return d

@app.post("/v1/marketplace/tasks", tags=["Marketplace"])
def marketplace_create(req: MarketplaceCreateRequest, agent_id: str = Depends(get_agent_id)):
    """Post a task to the marketplace for other agents to claim. Costs credits upfront."""
    task_id = f"mktask_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        # Check if agent has enough credits
        agent = db.execute("SELECT credits FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not agent or (agent["credits"] or 0) < req.reward_credits:
            raise HTTPException(402, f"Insufficient credits. You have {agent['credits'] or 0}, need {req.reward_credits}")

        # Deduct credits upfront
        db.execute(
            "UPDATE agents SET credits = credits - ? WHERE agent_id=?",
            (req.reward_credits, agent_id)
        )

        db.execute(
            "INSERT INTO marketplace (task_id, creator_agent, title, description, category, requirements, "
            "reward_credits, priority, estimated_effort, tags, deadline, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (task_id, agent_id, req.title,
             _encrypt(req.description) if req.description else None,
             req.category,
             json.dumps(req.requirements) if req.requirements else None,
             req.reward_credits, req.priority, req.estimated_effort,
             json.dumps(req.tags) if req.tags else None,
             req.deadline, "open", now)
        )
    return {"task_id": task_id, "status": "open", "created_at": now, "credits_deducted": req.reward_credits}

@app.get("/v1/marketplace/tasks", tags=["Marketplace"])
def marketplace_browse(
    category: Optional[str] = None,
    status: str = Query("open"),
    tag: Optional[str] = None,
    min_reward: int = Query(0, ge=0),
    limit: int = Query(50, le=200),
):
    """Browse marketplace tasks. No auth required."""
    conditions = ["status=?"]
    params: list = [status]
    if category:
        conditions.append("category=?")
        params.append(category)
    if tag:
        conditions.append("tags LIKE ?")
        params.append(f"%{tag}%")
    if min_reward > 0:
        conditions.append("reward_credits >= ?")
        params.append(min_reward)
    where = " AND ".join(conditions)
    params.append(limit)
    with get_db() as db:
        _expire_marketplace_tasks(db)
        _auto_approve_marketplace_tasks(db)
        rows = db.execute(
            f"SELECT * FROM marketplace WHERE {where} ORDER BY priority DESC, created_at DESC LIMIT ?",
            params
        ).fetchall()
    return {"tasks": [_parse_marketplace_row(r) for r in rows], "count": len(rows)}

@app.get("/v1/marketplace/tasks/{task_id}", tags=["Marketplace"])
def marketplace_detail(task_id: str):
    """Get marketplace task details. No auth required."""
    with get_db() as db:
        row = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Task not found")
    return _parse_marketplace_row(row)

@app.post("/v1/marketplace/tasks/{task_id}/claim", tags=["Marketplace"])
def marketplace_claim(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Claim an open marketplace task."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _expire_marketplace_tasks(db)
        _auto_approve_marketplace_tasks(db)
        task = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "Task not found")
        if task["status"] != "open":
            raise HTTPException(409, f"Task is not open (status: {task['status']})")
        if task["creator_agent"] == agent_id:
            raise HTTPException(400, "Cannot claim your own task")
        db.execute(
            "UPDATE marketplace SET status='claimed', claimed_by=?, claimed_at=? WHERE task_id=? AND status='open'",
            (agent_id, now, task_id)
        )
    _fire_webhooks(task["creator_agent"], "marketplace.task.claimed", {
        "task_id": task_id, "claimed_by": agent_id, "title": task["title"],
    })
    return {"task_id": task_id, "status": "claimed", "claimed_by": agent_id}

@app.post("/v1/marketplace/tasks/{task_id}/deliver", tags=["Marketplace"])
def marketplace_deliver(task_id: str, req: MarketplaceDeliverRequest, agent_id: str = Depends(get_agent_id)):
    """Submit a deliverable for a claimed task."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        task = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "Task not found")
        if task["status"] != "claimed":
            raise HTTPException(400, f"Task is not claimed (status: {task['status']})")
        if task["claimed_by"] != agent_id:
            raise HTTPException(403, "Only the claimant can deliver")
        db.execute(
            "UPDATE marketplace SET status='delivered', result=?, delivered_at=? WHERE task_id=?",
            (_encrypt(req.result), now, task_id)
        )
    _fire_webhooks(task["creator_agent"], "marketplace.task.delivered", {
        "task_id": task_id, "delivered_by": agent_id, "title": task["title"],
    })
    return {"task_id": task_id, "status": "delivered"}

@app.post("/v1/marketplace/tasks/{task_id}/review", tags=["Marketplace"])
def marketplace_review(task_id: str, req: MarketplaceReviewRequest, agent_id: str = Depends(get_agent_id)):
    """Accept or reject a delivery. Accepting awards credits to the worker."""
    with get_db() as db:
        task = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "Task not found")
        if task["status"] != "delivered":
            raise HTTPException(400, f"Task is not delivered (status: {task['status']})")
        if task["creator_agent"] != agent_id:
            raise HTTPException(403, "Only the creator can review")
        credits_awarded = 0
        if req.accept:
            db.execute(
                "UPDATE marketplace SET status='completed', rating=? WHERE task_id=?",
                (req.rating, task_id)
            )
            if task["reward_credits"] and task["reward_credits"] > 0:
                db.execute(
                    "UPDATE agents SET credits = credits + ? WHERE agent_id=?",
                    (task["reward_credits"], task["claimed_by"])
                )
                credits_awarded = task["reward_credits"]
            _fire_webhooks(task["claimed_by"], "marketplace.task.completed", {
                "task_id": task_id, "credits_awarded": credits_awarded, "rating": req.rating,
            })
            return {"task_id": task_id, "status": "completed", "credits_awarded": credits_awarded}
        else:
            db.execute(
                "UPDATE marketplace SET status='open', claimed_by=NULL, claimed_at=NULL, "
                "delivered_at=NULL, result=NULL WHERE task_id=?",
                (task_id,)
            )
            return {"task_id": task_id, "status": "open", "credits_awarded": 0}


# ═══════════════════════════════════════════════════════════════════════════════
# COORDINATION TESTING FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════════

COORDINATION_PATTERNS = {"leader_election", "consensus", "load_balancing", "pub_sub_fanout", "task_auction"}

class ScenarioCreateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=128)
    pattern: str = Field(..., description="One of: leader_election, consensus, load_balancing, pub_sub_fanout, task_auction")
    agent_count: int = Field(..., ge=2, le=20)
    timeout_seconds: int = Field(60, ge=5, le=300)
    success_criteria: Optional[dict] = Field(None)

def _run_coordination_pattern(pattern: str, agent_count: int, timeout_seconds: int) -> dict:
    """Run a deterministic coordination pattern simulation."""
    start = time.time()
    agents = [f"test_agent_{i}" for i in range(agent_count)]

    if pattern == "leader_election":
        rounds = 0
        messages = 0
        priorities = {a: random.randint(1, 1000) for a in agents}
        candidates = set(agents)
        while len(candidates) > 1 and (time.time() - start) < timeout_seconds:
            rounds += 1
            new_candidates = set()
            for c in candidates:
                higher = [o for o in candidates if priorities[o] > priorities[c]]
                messages += len(higher)
                if not higher:
                    new_candidates.add(c)
            candidates = new_candidates if new_candidates else {max(candidates, key=lambda a: priorities[a])}
        leader = list(candidates)[0] if candidates else None
        return {
            "pattern": "leader_election", "success": leader is not None,
            "rounds": rounds, "messages_sent": messages, "elected_leader": leader,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "consensus":
        values = {a: random.choice([0, 1]) for a in agents}
        rounds = 0
        messages = 0
        agreed = False
        while (time.time() - start) < timeout_seconds:
            rounds += 1
            messages += agent_count * (agent_count - 1)
            counts = {0: 0, 1: 0}
            for v in values.values():
                counts[v] += 1
            majority = 0 if counts[0] >= counts[1] else 1
            values = {a: majority for a in agents}
            if len(set(values.values())) == 1:
                agreed = True
                break
        return {
            "pattern": "consensus", "success": agreed,
            "rounds": rounds, "final_value": list(values.values())[0],
            "messages_sent": messages, "agreement_reached": agreed,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "load_balancing":
        task_count = max(100, agent_count * 10)
        assignments = {a: 0 for a in agents}
        for i in range(task_count):
            assignments[agents[i % agent_count]] += 1
        loads = list(assignments.values())
        return {
            "pattern": "load_balancing", "success": True,
            "total_tasks": task_count, "tasks_per_agent": assignments,
            "max_load": max(loads), "min_load": min(loads),
            "std_deviation": round(statistics.stdev(loads), 2) if len(loads) > 1 else 0,
            "balance_score": round(min(loads) / max(loads), 3) if max(loads) > 0 else 1.0,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "pub_sub_fanout":
        subscribers = agents[1:]
        messages_published = 10
        deliveries = 0
        failed = 0
        for _ in range(messages_published):
            for _ in subscribers:
                if random.random() > 0.02:
                    deliveries += 1
                else:
                    failed += 1
        total_expected = messages_published * len(subscribers)
        return {
            "pattern": "pub_sub_fanout", "success": deliveries > 0,
            "publisher": agents[0], "subscriber_count": len(subscribers),
            "messages_published": messages_published,
            "total_deliveries": deliveries, "failed_deliveries": failed,
            "delivery_rate": round(deliveries / total_expected, 3) if total_expected > 0 else 0,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "task_auction":
        task_count = 5
        auctions = []
        total_bids = 0
        collisions = 0
        for t in range(task_count):
            bids = {a: random.randint(1, 100) for a in agents}
            total_bids += len(bids)
            max_bid = max(bids.values())
            winners = [a for a, b in bids.items() if b == max_bid]
            if len(winners) > 1:
                collisions += 1
            auctions.append({"task": t, "winner": random.choice(winners), "winning_bid": max_bid})
        return {
            "pattern": "task_auction", "success": True,
            "tasks_auctioned": task_count, "total_bids": total_bids,
            "collisions": collisions, "auctions": auctions,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    return {"pattern": pattern, "success": False, "error": "Unknown pattern"}

@app.post("/v1/testing/scenarios", tags=["Testing"])
def scenario_create(req: ScenarioCreateRequest, agent_id: str = Depends(get_agent_id)):
    """Create a coordination test scenario."""
    if req.pattern not in COORDINATION_PATTERNS:
        raise HTTPException(400, f"Invalid pattern. Valid: {sorted(COORDINATION_PATTERNS)}")
    scenario_id = f"scenario_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO test_scenarios (scenario_id, creator_agent, name, pattern, agent_count, "
            "timeout_seconds, success_criteria, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (scenario_id, agent_id, req.name, req.pattern, req.agent_count,
             req.timeout_seconds, json.dumps(req.success_criteria) if req.success_criteria else None,
             "created", now)
        )
    return {"scenario_id": scenario_id, "status": "created", "pattern": req.pattern, "created_at": now}

@app.get("/v1/testing/scenarios", tags=["Testing"])
def scenario_list(
    pattern: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(20, le=100),
    agent_id: str = Depends(get_agent_id),
):
    """List your test scenarios."""
    conditions = ["creator_agent=?"]
    params: list = [agent_id]
    if pattern:
        conditions.append("pattern=?")
        params.append(pattern)
    if status:
        conditions.append("status=?")
        params.append(status)
    where = " AND ".join(conditions)
    params.append(limit)
    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM test_scenarios WHERE {where} ORDER BY created_at DESC LIMIT ?", params
        ).fetchall()
    scenarios = []
    for r in rows:
        d = dict(r)
        d["success_criteria"] = json.loads(d["success_criteria"]) if d["success_criteria"] else None
        if d["results"]:
            d["results"] = json.loads(_decrypt(d["results"]))
        scenarios.append(d)
    return {"scenarios": scenarios, "count": len(scenarios)}

@app.post("/v1/testing/scenarios/{scenario_id}/run", tags=["Testing"])
def scenario_run(scenario_id: str, agent_id: str = Depends(get_agent_id)):
    """Run a coordination test scenario."""
    with get_db() as db:
        row = db.execute("SELECT * FROM test_scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Scenario not found")
        if row["creator_agent"] != agent_id:
            raise HTTPException(403, "Only the creator can run this scenario")
        if row["status"] == "running":
            raise HTTPException(409, "Scenario is already running")
        db.execute("UPDATE test_scenarios SET status='running' WHERE scenario_id=?", (scenario_id,))
    results = _run_coordination_pattern(row["pattern"], row["agent_count"], row["timeout_seconds"])
    now = datetime.now(timezone.utc).isoformat()
    final_status = "completed" if results.get("success") else "failed"
    with get_db() as db:
        db.execute(
            "UPDATE test_scenarios SET status=?, results=?, completed_at=? WHERE scenario_id=?",
            (final_status, _encrypt(json.dumps(results)), now, scenario_id)
        )
    return {"scenario_id": scenario_id, "status": final_status, "results": results, "completed_at": now}

@app.get("/v1/testing/scenarios/{scenario_id}/results", tags=["Testing"])
def scenario_results(scenario_id: str, agent_id: str = Depends(get_agent_id)):
    """Get results for a test scenario."""
    with get_db() as db:
        row = db.execute("SELECT * FROM test_scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scenario not found")
    if row["creator_agent"] != agent_id:
        raise HTTPException(403, "Only the creator can view results")
    d = dict(row)
    d["success_criteria"] = json.loads(d["success_criteria"]) if d["success_criteria"] else None
    d["results"] = json.loads(_decrypt(d["results"])) if d["results"] else None
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET REAL-TIME RELAY
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory map: agent_id -> set of WebSocket connections
_ws_connections: dict[str, set[WebSocket]] = {}

async def _ws_auth(api_key: str) -> Optional[str]:
    """Validate API key and return agent_id, or None."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id FROM agents WHERE api_key_hash = ?",
            (hash_key(api_key),)
        ).fetchone()
        return row["agent_id"] if row else None

@app.websocket("/v1/relay/ws")
async def relay_websocket(ws: WebSocket):
    """
    WebSocket endpoint for real-time message relay.
    Connect with ?api_key=<key>. Send JSON: {"to_agent": "...", "channel": "...", "payload": "..."}
    Receive JSON push when a message is sent to you.
    """
    api_key = ws.query_params.get("api_key")
    if not api_key:
        await ws.close(code=4001, reason="Missing api_key query parameter")
        return

    agent_id = await _ws_auth(api_key)
    if not agent_id:
        await ws.close(code=4003, reason="Invalid API key")
        return

    await ws.accept()

    # Register connection
    if agent_id not in _ws_connections:
        _ws_connections[agent_id] = set()
    _ws_connections[agent_id].add(ws)

    try:
        while True:
            data = await ws.receive_json()
            to_agent = data.get("to_agent")
            channel = data.get("channel", "direct")
            payload = data.get("payload", "")

            if not to_agent or not payload:
                await ws.send_json({"error": "to_agent and payload are required"})
                continue

            # Persist to relay table
            message_id = f"msg_{uuid.uuid4().hex[:16]}"
            now = datetime.now(timezone.utc).isoformat()
            with get_db() as db:
                recip = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (to_agent,)).fetchone()
                if not recip:
                    await ws.send_json({"error": "Recipient agent not found"})
                    continue
                db.execute(
                    "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
                    (message_id, agent_id, to_agent, channel, _encrypt(payload), now)
                )

            # Confirm to sender
            await ws.send_json({"status": "delivered", "message_id": message_id})

            # Push to recipient if connected
            if to_agent in _ws_connections:
                push = {
                    "event": "message.received",
                    "message_id": message_id,
                    "from_agent": agent_id,
                    "channel": channel,
                    "payload": payload,
                    "created_at": now,
                }
                dead = set()
                for peer in _ws_connections[to_agent]:
                    try:
                        await peer.send_json(push)
                    except Exception:
                        dead.add(peer)
                _ws_connections[to_agent] -= dead

            # Fire webhooks for recipient
            _fire_webhooks(to_agent, "message.received", {
                "message_id": message_id, "from_agent": agent_id,
                "channel": channel, "payload": payload,
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error for {agent_id}: {e}")
    finally:
        _ws_connections.get(agent_id, set()).discard(ws)
        if agent_id in _ws_connections and not _ws_connections[agent_id]:
            del _ws_connections[agent_id]


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN PANEL
# ═══════════════════════════════════════════════════════════════════════════════

def _verify_admin_session(admin_token: str = Cookie(None)) -> bool:
    """Verify admin session cookie via SQLite (works across workers)."""
    if not admin_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    with get_db() as db:
        row = db.execute(
            "SELECT expires_at FROM admin_sessions WHERE token=?", (admin_token,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if time.time() > row["expires_at"]:
            db.execute("DELETE FROM admin_sessions WHERE token=?", (admin_token,))
            raise HTTPException(status_code=401, detail="Session expired")
    return True

class AdminLoginRequest(BaseModel):
    password: str

@app.post("/admin/api/login", tags=["Admin"])
def admin_login(req: AdminLoginRequest, response: Response):
    """Authenticate admin and set session cookie."""
    if not ADMIN_PASSWORD_HASH:
        raise HTTPException(503, "Admin not configured. Set ADMIN_PASSWORD_HASH env var.")
    incoming_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if not _hmac.compare_digest(incoming_hash, ADMIN_PASSWORD_HASH):
        raise HTTPException(401, "Invalid password")
    token = secrets.token_urlsafe(48)
    expires_at = time.time() + ADMIN_SESSION_TTL
    with get_db() as db:
        # Clean up expired sessions
        db.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (time.time(),))
        db.execute("INSERT INTO admin_sessions (token, expires_at) VALUES (?, ?)", (token, expires_at))
    response.set_cookie(
        key="admin_token", value=token, httponly=True,
        max_age=ADMIN_SESSION_TTL, samesite="lax", path="/",
    )
    return {"status": "authenticated"}

@app.post("/admin/api/logout", tags=["Admin"])
def admin_logout(response: Response, admin_token: str = Cookie(None)):
    """Log out admin session."""
    if admin_token:
        with get_db() as db:
            db.execute("DELETE FROM admin_sessions WHERE token=?", (admin_token,))
    response.delete_cookie("admin_token", path="/")
    return {"status": "logged_out"}

@app.get("/admin/api/dashboard", tags=["Admin"])
def admin_dashboard(_: bool = Depends(_verify_admin_session)):
    """Admin dashboard data: full system overview."""
    with get_db() as db:
        agents = db.execute(
            "SELECT agent_id, name, description, capabilities, public, created_at, last_seen, request_count, "
            "reputation, reputation_count, credits, available "
            "FROM agents ORDER BY created_at DESC"
        ).fetchall()
        agent_count = len(agents)
        job_count = db.execute("SELECT COUNT(*) as c FROM queue").fetchone()["c"]
        pending_jobs = db.execute("SELECT COUNT(*) as c FROM queue WHERE status='pending'").fetchone()["c"]
        processing_jobs = db.execute("SELECT COUNT(*) as c FROM queue WHERE status='processing'").fetchone()["c"]
        completed_jobs = db.execute("SELECT COUNT(*) as c FROM queue WHERE status='completed'").fetchone()["c"]
        memory_keys = db.execute("SELECT COUNT(*) as c FROM memory").fetchone()["c"]
        messages = db.execute("SELECT COUNT(*) as c FROM relay").fetchone()["c"]
        webhooks = db.execute("SELECT COUNT(*) as c FROM webhooks WHERE active=1").fetchone()["c"]
        schedules = db.execute("SELECT COUNT(*) as c FROM scheduled_tasks WHERE enabled=1").fetchone()["c"]
        shared_keys = db.execute("SELECT COUNT(*) as c FROM shared_memory").fetchone()["c"]
        public_agents = db.execute("SELECT COUNT(*) as c FROM agents WHERE public=1").fetchone()["c"]
        collab_count = db.execute("SELECT COUNT(*) as c FROM collaborations").fetchone()["c"]
        market_open = db.execute("SELECT COUNT(*) as c FROM marketplace WHERE status='open'").fetchone()["c"]
        market_completed = db.execute("SELECT COUNT(*) as c FROM marketplace WHERE status='completed'").fetchone()["c"]
        total_credits = db.execute("SELECT COALESCE(SUM(credits),0) as c FROM agents").fetchone()["c"]
        scenario_count = db.execute("SELECT COUNT(*) as c FROM test_scenarios").fetchone()["c"]
        contact_count = db.execute("SELECT COUNT(*) as c FROM contact_submissions").fetchone()["c"]

    return {
        "agents": [dict(a) for a in agents],
        "stats": {
            "total_agents": agent_count,
            "public_agents": public_agents,
            "total_jobs": job_count,
            "pending_jobs": pending_jobs,
            "processing_jobs": processing_jobs,
            "completed_jobs": completed_jobs,
            "memory_keys": memory_keys,
            "shared_memory_keys": shared_keys,
            "messages_relayed": messages,
            "active_webhooks": webhooks,
            "active_schedules": schedules,
            "websocket_connections": sum(len(s) for s in _ws_connections.values()),
            "collaborations": collab_count,
            "marketplace_open": market_open,
            "marketplace_completed": market_completed,
            "total_credits_circulation": total_credits,
            "test_scenarios": scenario_count,
            "contact_submissions": contact_count,
        },
        "version": "0.6.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "encryption_enabled": _fernet is not None,
    }

@app.get("/admin/api/messages", tags=["Admin"])
def admin_messages(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    agent_id: Optional[str] = None,
    _: bool = Depends(_verify_admin_session),
):
    """Browse all relay messages."""
    with get_db() as db:
        if agent_id:
            rows = db.execute(
                "SELECT * FROM relay WHERE from_agent=? OR to_agent=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (agent_id, agent_id, limit, offset)
            ).fetchall()
            total = db.execute(
                "SELECT COUNT(*) as c FROM relay WHERE from_agent=? OR to_agent=?", (agent_id, agent_id)
            ).fetchone()["c"]
        else:
            rows = db.execute(
                "SELECT * FROM relay ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM relay").fetchone()["c"]
    messages = [dict(r) for r in rows]
    for m in messages:
        m["payload"] = _decrypt(m["payload"])
    return {"messages": messages, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/memory", tags=["Admin"])
def admin_memory(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    agent_id: Optional[str] = None,
    _: bool = Depends(_verify_admin_session),
):
    """Browse all agent memory entries."""
    with get_db() as db:
        if agent_id:
            rows = db.execute(
                "SELECT * FROM memory WHERE agent_id=? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (agent_id, limit, offset)
            ).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM memory WHERE agent_id=?", (agent_id,)).fetchone()["c"]
        else:
            rows = db.execute(
                "SELECT * FROM memory ORDER BY updated_at DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM memory").fetchone()["c"]
    entries = [dict(r) for r in rows]
    for ent in entries:
        ent["value"] = _decrypt(ent["value"])
    return {"entries": entries, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/queue", tags=["Admin"])
def admin_queue(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    _: bool = Depends(_verify_admin_session),
):
    """Browse all queue jobs."""
    with get_db() as db:
        conditions = []
        params = []
        if status:
            conditions.append("status=?")
            params.append(status)
        if agent_id:
            conditions.append("agent_id=?")
            params.append(agent_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = db.execute(
            f"SELECT * FROM queue {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        total = db.execute(f"SELECT COUNT(*) as c FROM queue {where}", params).fetchone()["c"]
    jobs = [dict(r) for r in rows]
    for j in jobs:
        j["payload"] = _decrypt(j["payload"])
        if j.get("result"):
            j["result"] = _decrypt(j["result"])
    return {"jobs": jobs, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/webhooks", tags=["Admin"])
def admin_webhooks(_: bool = Depends(_verify_admin_session)):
    """Browse all registered webhooks."""
    with get_db() as db:
        rows = db.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
    return {"webhooks": [{**dict(r), "event_types": json.loads(r["event_types"])} for r in rows], "total": len(rows)}

@app.get("/admin/api/schedules", tags=["Admin"])
def admin_schedules(_: bool = Depends(_verify_admin_session)):
    """Browse all scheduled tasks."""
    with get_db() as db:
        rows = db.execute("SELECT * FROM scheduled_tasks ORDER BY created_at DESC").fetchall()
    schedules = [dict(r) for r in rows]
    for s in schedules:
        s["payload"] = _decrypt(s["payload"])
    return {"schedules": schedules, "total": len(schedules)}

@app.get("/admin/api/shared-memory", tags=["Admin"])
def admin_shared_memory(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    namespace: Optional[str] = None,
    _: bool = Depends(_verify_admin_session),
):
    """Browse all shared memory entries."""
    with get_db() as db:
        if namespace:
            rows = db.execute(
                "SELECT * FROM shared_memory WHERE namespace=? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (namespace, limit, offset)
            ).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM shared_memory WHERE namespace=?", (namespace,)).fetchone()["c"]
        else:
            rows = db.execute(
                "SELECT * FROM shared_memory ORDER BY updated_at DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM shared_memory").fetchone()["c"]
    entries = [dict(r) for r in rows]
    for ent in entries:
        ent["value"] = _decrypt(ent["value"])
    return {"entries": entries, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/sla", tags=["Admin"])
def admin_sla(_: bool = Depends(_verify_admin_session)):
    """Detailed SLA and uptime data for admin dashboard."""
    with get_db() as db:
        windows = {"24h": 1, "7d": 7, "30d": 30}
        result = {}
        for label, days in windows.items():
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            total = db.execute("SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ?", (cutoff,)).fetchone()["c"]
            up = db.execute("SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ? AND status='up'", (cutoff,)).fetchone()["c"]
            avg_ms = db.execute("SELECT AVG(response_ms) as avg FROM uptime_checks WHERE checked_at >= ? AND status='up'", (cutoff,)).fetchone()["avg"]
            result[label] = {
                "uptime_pct": round(up / total * 100, 3) if total > 0 else 100.0,
                "total_checks": total,
                "successful_checks": up,
                "avg_response_ms": round(avg_ms or 0, 2),
            }
        recent = db.execute("SELECT * FROM uptime_checks ORDER BY checked_at DESC LIMIT 100").fetchall()
    return {
        "sla_target": "99.9%",
        "windows": result,
        "recent_checks": [dict(r) for r in recent],
        "encryption_enabled": _fernet is not None,
        "check_interval_seconds": 60,
    }

@app.get("/admin/api/agents/{agent_id}", tags=["Admin"])
def admin_agent_detail(agent_id: str, _: bool = Depends(_verify_admin_session)):
    """Get full detail for a single agent including all their data."""
    with get_db() as db:
        agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(404, "Agent not found")
        memory = db.execute("SELECT * FROM memory WHERE agent_id=? ORDER BY updated_at DESC LIMIT 100", (agent_id,)).fetchall()
        jobs = db.execute("SELECT * FROM queue WHERE agent_id=? ORDER BY created_at DESC LIMIT 100", (agent_id,)).fetchall()
        sent = db.execute("SELECT * FROM relay WHERE from_agent=? ORDER BY created_at DESC LIMIT 100", (agent_id,)).fetchall()
        received = db.execute("SELECT * FROM relay WHERE to_agent=? ORDER BY created_at DESC LIMIT 100", (agent_id,)).fetchall()
        wh = db.execute("SELECT * FROM webhooks WHERE agent_id=?", (agent_id,)).fetchall()
        sched = db.execute("SELECT * FROM scheduled_tasks WHERE agent_id=?", (agent_id,)).fetchall()
        shared = db.execute("SELECT * FROM shared_memory WHERE owner_agent=? ORDER BY updated_at DESC LIMIT 100", (agent_id,)).fetchall()
        collabs = db.execute("SELECT * FROM collaborations WHERE agent_id=? OR partner_agent=? ORDER BY created_at DESC LIMIT 100", (agent_id, agent_id)).fetchall()
        market_created = db.execute("SELECT * FROM marketplace WHERE creator_agent=? ORDER BY created_at DESC LIMIT 100", (agent_id,)).fetchall()
        market_claimed = db.execute("SELECT * FROM marketplace WHERE claimed_by=? ORDER BY created_at DESC LIMIT 100", (agent_id,)).fetchall()
        scenarios = db.execute("SELECT * FROM test_scenarios WHERE creator_agent=? ORDER BY created_at DESC LIMIT 100", (agent_id,)).fetchall()
    mem_list = [dict(r) for r in memory]
    for m in mem_list:
        m["value"] = _decrypt(m["value"])
    job_list = [dict(r) for r in jobs]
    for j in job_list:
        j["payload"] = _decrypt(j["payload"])
        if j.get("result"):
            j["result"] = _decrypt(j["result"])
    sent_list = [dict(r) for r in sent]
    for m in sent_list:
        m["payload"] = _decrypt(m["payload"])
    recv_list = [dict(r) for r in received]
    for m in recv_list:
        m["payload"] = _decrypt(m["payload"])
    sched_list = [dict(r) for r in sched]
    for s in sched_list:
        s["payload"] = _decrypt(s["payload"])
    shared_list = [dict(r) for r in shared]
    for s in shared_list:
        s["value"] = _decrypt(s["value"])
    collab_list = [dict(r) for r in collabs]
    for c in collab_list:
        if c.get("task_type"):
            c["task_type"] = _decrypt(c["task_type"])
    market_list = [_parse_marketplace_row(r) for r in market_created]
    claimed_list = [_parse_marketplace_row(r) for r in market_claimed]
    scenario_list = []
    for r in scenarios:
        d = dict(r)
        if d.get("results"):
            d["results"] = json.loads(_decrypt(d["results"]))
        if d.get("success_criteria"):
            d["success_criteria"] = json.loads(d["success_criteria"])
        scenario_list.append(d)
    return {
        "agent": dict(agent),
        "memory": mem_list,
        "jobs": job_list,
        "messages_sent": sent_list,
        "messages_received": recv_list,
        "webhooks": [{**dict(r), "event_types": json.loads(r["event_types"])} for r in wh],
        "schedules": sched_list,
        "shared_memory": shared_list,
        "collaborations": collab_list,
        "marketplace_created": market_list,
        "marketplace_claimed": claimed_list,
        "test_scenarios": scenario_list,
    }

@app.delete("/admin/api/agents/{agent_id}", tags=["Admin"])
def admin_delete_agent(agent_id: str, _: bool = Depends(_verify_admin_session)):
    """Delete an agent and all associated data."""
    with get_db() as db:
        row = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Agent not found")
        db.execute("DELETE FROM memory WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM queue WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM relay WHERE from_agent=? OR to_agent=?", (agent_id, agent_id))
        db.execute("DELETE FROM webhooks WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM scheduled_tasks WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM shared_memory WHERE owner_agent=?", (agent_id,))
        db.execute("DELETE FROM rate_limits WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM collaborations WHERE agent_id=? OR partner_agent=?", (agent_id, agent_id))
        db.execute("DELETE FROM marketplace WHERE creator_agent=?", (agent_id,))
        db.execute("UPDATE marketplace SET status='open', claimed_by=NULL, claimed_at=NULL, delivered_at=NULL, result=NULL WHERE claimed_by=?", (agent_id,))
        db.execute("DELETE FROM test_scenarios WHERE creator_agent=?", (agent_id,))
        db.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
    return {"status": "deleted", "agent_id": agent_id}

@app.get("/admin/api/collaborations", tags=["Admin"])
def admin_collaborations(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    agent_id: Optional[str] = None,
    _: bool = Depends(_verify_admin_session),
):
    """Browse all collaborations."""
    with get_db() as db:
        if agent_id:
            rows = db.execute(
                "SELECT * FROM collaborations WHERE agent_id=? OR partner_agent=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (agent_id, agent_id, limit, offset)
            ).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM collaborations WHERE agent_id=? OR partner_agent=?", (agent_id, agent_id)).fetchone()["c"]
        else:
            rows = db.execute("SELECT * FROM collaborations ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM collaborations").fetchone()["c"]
    collabs = [dict(r) for r in rows]
    for c in collabs:
        if c.get("task_type"):
            c["task_type"] = _decrypt(c["task_type"])
    return {"collaborations": collabs, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/marketplace", tags=["Admin"])
def admin_marketplace(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    _: bool = Depends(_verify_admin_session),
):
    """Browse all marketplace tasks."""
    with get_db() as db:
        if status:
            rows = db.execute("SELECT * FROM marketplace WHERE status=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (status, limit, offset)).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM marketplace WHERE status=?", (status,)).fetchone()["c"]
        else:
            rows = db.execute("SELECT * FROM marketplace ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            total = db.execute("SELECT COUNT(*) as c FROM marketplace").fetchone()["c"]
    return {"tasks": [_parse_marketplace_row(r) for r in rows], "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/scenarios", tags=["Admin"])
def admin_scenarios(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    _: bool = Depends(_verify_admin_session),
):
    """Browse all test scenarios."""
    with get_db() as db:
        rows = db.execute("SELECT * FROM test_scenarios ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        total = db.execute("SELECT COUNT(*) as c FROM test_scenarios").fetchone()["c"]
    scenarios = []
    for r in rows:
        d = dict(r)
        if d.get("results"):
            d["results"] = json.loads(_decrypt(d["results"]))
        if d.get("success_criteria"):
            d["success_criteria"] = json.loads(d["success_criteria"])
        scenarios.append(d)
    return {"scenarios": scenarios, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/contact", tags=["Admin"])
def admin_contact(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    _: bool = Depends(_verify_admin_session),
):
    """Browse contact form submissions."""
    with get_db() as db:
        rows = db.execute("SELECT * FROM contact_submissions ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        total = db.execute("SELECT COUNT(*) as c FROM contact_submissions").fetchone()["c"]
    return {"submissions": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

@app.get("/admin/login", response_class=HTMLResponse, tags=["Admin"])
def admin_login_page():
    """Serve the admin login page."""
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_login.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Admin login page not found")

@app.get("/admin", response_class=HTMLResponse, tags=["Admin"])
def admin_page():
    """Serve the admin dashboard page."""
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Admin page not found")


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH / METRICS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/v1/sla", tags=["System"])
def sla():
    """Public SLA / uptime information — no auth required."""
    with get_db() as db:
        windows = {"24h": 1, "7d": 7, "30d": 30}
        result = {}
        for label, days in windows.items():
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            total = db.execute("SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ?", (cutoff,)).fetchone()["c"]
            up = db.execute("SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ? AND status='up'", (cutoff,)).fetchone()["c"]
            avg_ms_row = db.execute("SELECT AVG(response_ms) as avg FROM uptime_checks WHERE checked_at >= ? AND status='up'", (cutoff,)).fetchone()
            avg_ms = avg_ms_row["avg"] if avg_ms_row and avg_ms_row["avg"] is not None else 0.0
            result[label] = {
                "uptime_pct": round(up / total * 100, 3) if total > 0 else 100.0,
                "total_checks": total,
                "successful_checks": up,
                "avg_response_ms": round(avg_ms, 2),
            }
        last_check = db.execute("SELECT * FROM uptime_checks ORDER BY checked_at DESC LIMIT 1").fetchone()
    return {
        "sla_target": "99.9%",
        "current_status": "operational",
        "windows": result,
        "last_check": dict(last_check) if last_check else None,
        "check_interval_seconds": 60,
        "encryption_enabled": _fernet is not None,
    }

@app.get("/v1/health", tags=["System"])
def health():
    """Public health check — no auth required."""
    with get_db() as db:
        agent_count = db.execute("SELECT COUNT(*) as c FROM agents").fetchone()["c"]
        job_count = db.execute("SELECT COUNT(*) as c FROM queue").fetchone()["c"]
        memory_keys = db.execute("SELECT COUNT(*) as c FROM memory").fetchone()["c"]
        messages = db.execute("SELECT COUNT(*) as c FROM relay").fetchone()["c"]
        webhooks = db.execute("SELECT COUNT(*) as c FROM webhooks WHERE active=1").fetchone()["c"]
        schedules = db.execute("SELECT COUNT(*) as c FROM scheduled_tasks WHERE enabled=1").fetchone()["c"]
        shared_keys = db.execute("SELECT COUNT(*) as c FROM shared_memory").fetchone()["c"]
        public_agents = db.execute("SELECT COUNT(*) as c FROM agents WHERE public=1").fetchone()["c"]

    return {
        "status": "operational",
        "version": "0.6.0",
        "stats": {
            "registered_agents": agent_count,
            "public_agents": public_agents,
            "total_jobs": job_count,
            "memory_keys_stored": memory_keys,
            "shared_memory_keys": shared_keys,
            "messages_relayed": messages,
            "active_webhooks": webhooks,
            "active_schedules": schedules,
            "websocket_connections": sum(len(s) for s in _ws_connections.values()),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/v1/stats", tags=["System"])
def stats(agent_id: str = Depends(get_agent_id)):
    """Your agent's usage stats."""
    with get_db() as db:
        agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        mem_count = db.execute("SELECT COUNT(*) as c FROM memory WHERE agent_id=?", (agent_id,)).fetchone()["c"]
        job_count = db.execute("SELECT COUNT(*) as c FROM queue WHERE agent_id=?", (agent_id,)).fetchone()["c"]
        msg_sent = db.execute("SELECT COUNT(*) as c FROM relay WHERE from_agent=?", (agent_id,)).fetchone()["c"]
        msg_recv = db.execute("SELECT COUNT(*) as c FROM relay WHERE to_agent=?", (agent_id,)).fetchone()["c"]

        wh_count = db.execute("SELECT COUNT(*) as c FROM webhooks WHERE agent_id=? AND active=1", (agent_id,)).fetchone()["c"]
        sched_count = db.execute("SELECT COUNT(*) as c FROM scheduled_tasks WHERE agent_id=? AND enabled=1", (agent_id,)).fetchone()["c"]
        shared_count = db.execute("SELECT COUNT(*) as c FROM shared_memory WHERE owner_agent=?", (agent_id,)).fetchone()["c"]
        collabs_given = db.execute("SELECT COUNT(*) as c FROM collaborations WHERE agent_id=?", (agent_id,)).fetchone()["c"]
        collabs_recv = db.execute("SELECT COUNT(*) as c FROM collaborations WHERE partner_agent=?", (agent_id,)).fetchone()["c"]
        market_created = db.execute("SELECT COUNT(*) as c FROM marketplace WHERE creator_agent=?", (agent_id,)).fetchone()["c"]
        market_completed = db.execute("SELECT COUNT(*) as c FROM marketplace WHERE claimed_by=? AND status='completed'", (agent_id,)).fetchone()["c"]

    return {
        "agent_id": agent_id,
        "name": agent["name"],
        "created_at": agent["created_at"],
        "total_requests": agent["request_count"],
        "memory_keys": mem_count,
        "jobs_submitted": job_count,
        "messages_sent": msg_sent,
        "messages_received": msg_recv,
        "active_webhooks": wh_count,
        "active_schedules": sched_count,
        "shared_memory_keys": shared_count,
        "credits": agent["credits"] or 0,
        "reputation": agent["reputation"] or 0.0,
        "collaborations_given": collabs_given,
        "collaborations_received": collabs_recv,
        "marketplace_tasks_created": market_created,
        "marketplace_tasks_completed": market_completed,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# CONTACT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/contact", response_class=HTMLResponse, tags=["System"])
def contact_page():
    """Serve the contact form page."""
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "contact.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Contact page not found")

class ContactForm(BaseModel):
    name: str = ""
    email: str
    subject: str = ""
    message: str

@app.post("/v1/contact", tags=["System"])
def submit_contact(form: ContactForm):
    """Public contact form submission — no auth required."""
    if not form.email or not form.message:
        raise HTTPException(400, "Email and message are required")
    now = datetime.now(timezone.utc).isoformat()
    submission_id = f"contact_{uuid.uuid4().hex[:12]}"
    with get_db() as db:
        db.execute(
            "INSERT INTO contact_submissions (id, name, email, subject, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (submission_id, form.name, form.email, form.subject, form.message, now)
        )
    # Send email via Gmail SMTP
    if SMTP_PASSWORD:
        try:
            msg = MIMEMultipart()
            msg["From"] = SMTP_FROM
            msg["To"] = SMTP_TO
            msg["Subject"] = f"MoltGrid Contact: {form.subject or 'No subject'}"
            body = (
                f"Name: {form.name or 'Not provided'}\n"
                f"Email: {form.email}\n"
                f"Subject: {form.subject or 'Not provided'}\n\n"
                f"Message:\n{form.message}"
            )
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(SMTP_FROM, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
            logger.info(f"Contact email sent: {submission_id}")
        except Exception as e:
            logger.error(f"Failed to send contact email: {e}")
    return {"status": "sent", "id": submission_id}

# ═══════════════════════════════════════════════════════════════════════════════
# ROOT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["System"])
def root():
    return {
        "service": "MoltGrid",
        "version": "0.6.0",
        "docs": "/docs",
        "description": "Open-source toolkit API for autonomous agents",
        "endpoints": {
            "register": "POST /v1/register",
            "memory": "/v1/memory",
            "shared_memory": "/v1/shared-memory",
            "queue": "/v1/queue",
            "schedules": "/v1/schedules",
            "relay": "/v1/relay",
            "relay_ws": "WS /v1/relay/ws",
            "webhooks": "/v1/webhooks",
            "directory": "/v1/directory",
            "directory_search": "GET /v1/directory/search",
            "directory_match": "GET /v1/directory/match",
            "marketplace": "/v1/marketplace/tasks",
            "testing": "/v1/testing/scenarios",
            "text": "/v1/text/process",
            "health": "GET /v1/health",
            "sla": "GET /v1/sla",
        }
    }
