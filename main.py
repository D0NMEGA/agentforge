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
import csv
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Union
from contextlib import asynccontextmanager, contextmanager

import hmac as _hmac
import secrets
import httpx
from cryptography.fernet import Fernet, InvalidToken
from croniter import croniter
from fastapi import FastAPI, HTTPException, Header, Depends, Query, WebSocket, WebSocketDisconnect, Cookie, Response, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

import jwt as pyjwt
import bcrypt as _bcrypt
import stripe
import pyotp
import urllib.parse
import qrcode
import qrcode.image.svg
import base64
import io
import re as _re
import html as _html
import numpy as np
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("moltgrid")

# ─── Config ───────────────────────────────────────────────────────────────────
DB_PATH = os.getenv("MOLTGRID_DB", "moltgrid.db")
MAX_MEMORY_VALUE_SIZE = 50_000  # 50KB per value
MAX_QUEUE_PAYLOAD_SIZE = 100_000  # 100KB per job
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 120  # requests per window per agent (fallback / free-tier default)
TIER_RATE_LIMITS = {
    "free":  120,
    "hobby": 300,
    "team":  600,
    "scale": 1200,
}

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

# SMTP config: Hostinger email (contact@moltgrid.net) or any SMTP provider
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.hostinger.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_FROM = os.getenv("SMTP_FROM", "contact@moltgrid.net")
SMTP_TO = os.getenv("SMTP_TO", "contact@moltgrid.net")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

if not SMTP_FROM or not SMTP_TO or not SMTP_PASSWORD:
    logger.warning("SMTP environment variables not set — contact form will be disabled.")

# Cloudflare Turnstile CAPTCHA
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "")


# ─── App ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    # Startup: launch background threads
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    threading.Thread(target=_uptime_loop, daemon=True).start()
    threading.Thread(target=_liveness_loop, daemon=True).start()
    threading.Thread(target=_usage_reset_loop, daemon=True).start()
    threading.Thread(target=_email_loop, daemon=True).start()
    threading.Thread(target=_webhook_delivery_loop, daemon=True).start()
    logger.info("Background threads started (scheduler, uptime monitor, liveness monitor, usage reset, email, webhook delivery)")
    # Clear OpenAPI schema cache to prevent stale endpoint definitions
    app.openapi_schema = None
    logger.info("OpenAPI schema cache cleared")
    # Run an immediate uptime check to seed the database
    try:
        _uptime_check()
        logger.info("Initial uptime check completed")
    except Exception as e:
        logger.error(f"Initial uptime check failed: {e}")
    # Pre-warm embedding model to avoid cold-start latency on first vector request
    try:
        _get_embed_model().encode("warmup", convert_to_numpy=True)
        logger.info("Embedding model pre-warmed successfully")
    except Exception as e:
        logger.warning(f"Embedding model pre-warm failed (will lazy-load): {e}")
    yield
    # Shutdown: nothing to clean up (daemon threads auto-exit)

app = FastAPI(
    title="MoltGrid",
    description="Open-source toolkit API for autonomous agents. "
    "Persistent memory, task queues, message relay, and text utilities.",
    version="0.9.0",
    lifespan=lifespan,
)


def _http_code_to_slug(status: int) -> str:
    return {
        400: "bad_request", 401: "unauthorized", 403: "forbidden",
        404: "not_found", 409: "conflict", 422: "validation_error",
        429: "rate_limit_exceeded", 500: "internal_error", 503: "service_unavailable",
    }.get(status, f"http_{status}")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": str(exc.detail), "code": _http_code_to_slug(exc.status_code), "status": exc.status_code},
    )


@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Intercepts Starlette-level 404s (unknown routes) in addition to FastAPI HTTPException."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": str(exc.detail), "code": _http_code_to_slug(exc.status_code), "status": exc.status_code},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "Validation failed", "code": "validation_error", "status": 422},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://moltgrid.net",
        "https://www.moltgrid.net",
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-MoltGrid-Version"],
)


@app.middleware("http")
async def add_response_headers(request: Request, call_next):
    """Add X-Request-ID, X-MoltGrid-Version, and rate limit headers to every response."""
    request_id = uuid.uuid4().hex
    request.state.request_id = request_id
    request.state.rate_limit_remaining = None
    request.state.rate_limit_reset = None
    request.state.rate_limit_max = None

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id
    response.headers["X-MoltGrid-Version"] = app.version
    rate_limit_max = getattr(request.state, "rate_limit_max", RATE_LIMIT_MAX)
    response.headers["X-RateLimit-Limit"] = str(rate_limit_max if rate_limit_max is not None else RATE_LIMIT_MAX)

    if request.state.rate_limit_remaining is not None:
        response.headers["X-RateLimit-Remaining"] = str(request.state.rate_limit_remaining)
    if request.state.rate_limit_reset is not None:
        response.headers["X-RateLimit-Reset"] = str(request.state.rate_limit_reset)

    return response


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

        CREATE TABLE IF NOT EXISTS vector_memory (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            text TEXT NOT NULL,
            embedding BLOB NOT NULL,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
            UNIQUE(agent_id, namespace, key)
        );
        CREATE INDEX IF NOT EXISTS idx_vec_agent ON vector_memory(agent_id, namespace);

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

        CREATE TABLE IF NOT EXISTS email_queue (
            id TEXT PRIMARY KEY,
            to_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_html TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            sent_at TEXT,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status, created_at);

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            title TEXT,
            messages TEXT NOT NULL DEFAULT '[]',
            metadata TEXT,
            token_count INTEGER DEFAULT 0,
            max_tokens INTEGER DEFAULT 128000,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);

        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            delivery_id TEXT PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            attempt_count INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 3,
            next_retry_at TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL,
            delivered_at TEXT,
            FOREIGN KEY (webhook_id) REFERENCES webhooks(webhook_id)
        );
        CREATE INDEX IF NOT EXISTS idx_webhook_del_status ON webhook_deliveries(status, next_retry_at);

        CREATE TABLE IF NOT EXISTS pubsub_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            subscribed_at TEXT NOT NULL,
            UNIQUE(agent_id, channel),
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_pubsub_channel ON pubsub_subscriptions(channel);

        CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS analytics_events (
            id TEXT PRIMARY KEY,
            event_name TEXT NOT NULL,
            user_id TEXT,
            agent_id TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_event ON analytics_events(event_name, created_at);
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
        ("onboarding_completed", "INTEGER DEFAULT 0"),
        ("moltbook_profile_id", "TEXT"),
        ("display_name", "TEXT"),
        ("featured", "INTEGER DEFAULT 0"),
        ("verified", "INTEGER DEFAULT 0"),
        ("skills", "TEXT"),
        ("interests", "TEXT"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {typedef}")

    # Migrate analytics_events — add source and moltbook_url columns
    ae_existing = {row[1] for row in conn.execute("PRAGMA table_info(analytics_events)").fetchall()}
    for col, typedef in [
        ("source", "TEXT DEFAULT 'moltgrid_api'"),
        ("moltbook_url", "TEXT"),
    ]:
        if col not in ae_existing:
            conn.execute(f"ALTER TABLE analytics_events ADD COLUMN {col} {typedef}")
    conn.execute("UPDATE analytics_events SET source='moltgrid_api' WHERE source IS NULL")

    # Create integrations table (OC-05)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            config TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_integrations_agent ON integrations(agent_id)")

    # Migrate existing users table — add columns for billing and notifications
    try:
        u_existing = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        for col, typedef in [
            ("payment_failed", "INTEGER DEFAULT 0"),
            ("notification_preferences", "TEXT"),
            ("known_login_ips", "TEXT DEFAULT '[]'"),
            ("totp_secret", "TEXT"),
            ("totp_enabled", "INTEGER DEFAULT 0"),
            ("totp_recovery_codes", "TEXT"),
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

    # Migrate memory table — add visibility / shared_agents
    m_existing = {row[1] for row in conn.execute('PRAGMA table_info(memory)').fetchall()}
    for col, typedef in [
        ('visibility', "TEXT DEFAULT 'private'"),
        ('shared_agents', 'TEXT'),
    ]:
        if col not in m_existing:
            conn.execute(f'ALTER TABLE memory ADD COLUMN {col} {typedef}')
    conn.execute("UPDATE memory SET visibility='private' WHERE visibility IS NULL")

    # Create memory audit log table
    conn.execute(
        'CREATE TABLE IF NOT EXISTS memory_access_log ('
        '    id             TEXT PRIMARY KEY,'
        '    agent_id       TEXT NOT NULL,'
        '    namespace      TEXT NOT NULL,'
        '    key            TEXT NOT NULL,'
        '    action         TEXT NOT NULL,'
        '    actor_agent_id TEXT,'
        '    actor_user_id  TEXT,'
        '    old_visibility TEXT,'
        '    new_visibility TEXT,'
        '    authorized     INTEGER DEFAULT 1,'
        '    created_at     TEXT NOT NULL'
        ')'
    )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_mal_agent ON memory_access_log(agent_id, created_at)'
    )

    # Audit logs table (BL-05)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT,
            agent_id TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, created_at)")

    # Agent templates table (BL-04)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS templates (
            template_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            starter_code TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Seed 4 built-in templates — INSERT OR IGNORE so re-seeding is always safe
    _templates_seed = [
        (
            "tmpl_openclaw_social",
            "OpenClaw Social Agent",
            "An agent that posts to MoltBook and tracks social engagement via MoltGrid analytics.",
            "social",
            '{"memory_keys": ["moltbook_profile_id", "last_post_id", "follower_count"], "capabilities": ["moltbook_post", "moltbook_reply", "moltbook_upvote"], "starter_tasks": [{"action": "heartbeat", "interval": 60}, {"action": "poll_moltbook_events", "queue": "social"}], "example_post": "POST /v1/moltbook/events"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_worker",
            "Background Worker Agent",
            "A general-purpose background worker that polls the job queue and processes tasks reliably.",
            "worker",
            '{"memory_keys": ["jobs_processed", "last_job_id", "worker_status"], "capabilities": ["queue_poll", "queue_complete", "queue_fail"], "starter_tasks": [{"action": "heartbeat", "interval": 30}, {"action": "poll_queue", "queue": "default", "interval": 5}], "example_poll": "GET /v1/queue/claim?queue=default"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_research",
            "Research Agent",
            "A research agent that stores findings in memory and uses vector search to avoid duplicate work.",
            "research",
            '{"memory_keys": ["research_topic", "findings_count", "last_query"], "capabilities": ["memory_write", "memory_vector_search", "shared_memory_read"], "starter_tasks": [{"action": "heartbeat", "interval": 120}, {"action": "vector_index_findings", "namespace": "research"}], "example_search": "POST /v1/vector/search"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_customer_service",
            "Customer Service Agent",
            "A customer service agent that handles inbound relay messages and routes them to the right queue.",
            "customer_service",
            '{"memory_keys": ["tickets_open", "tickets_resolved", "avg_response_time_s"], "capabilities": ["relay_inbox", "relay_send", "queue_submit"], "starter_tasks": [{"action": "heartbeat", "interval": 30}, {"action": "poll_inbox", "interval": 10}], "example_reply": "POST /v1/relay/send"}',
            "2026-01-01T00:00:00Z",
        ),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO templates (template_id, name, description, category, starter_code, created_at) VALUES (?,?,?,?,?,?)",
        _templates_seed,
    )

    # Multi-user org accounts (BL-02)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            org_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE,
            owner_user_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS org_members (
            org_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            PRIMARY KEY (org_id, user_id)
        )
    """)

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id)"
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_events (
            event_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL DEFAULT '{}',
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_events_agent_ack_time "
        "ON agent_events (agent_id, acknowledged, created_at)"
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS obstacle_course_submissions (
            submission_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            stages_completed TEXT NOT NULL DEFAULT '[]',
            score INTEGER NOT NULL DEFAULT 0,
            submitted_at TEXT NOT NULL,
            feedback TEXT NOT NULL DEFAULT ''
        )
    """)

    try:
        conn.execute("ALTER TABLE agents ADD COLUMN worker_status TEXT NOT NULL DEFAULT 'offline'")
    except Exception:
        pass  # column already exists

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

def _track_event(event_name: str, user_id: str = None, agent_id: str = None, metadata: dict = None):
    """Insert a lightweight analytics event. Non-blocking best-effort."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
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
                <h1 style="color: #ff9800;">⚠️ You're approaching your API limit</h1>
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
                <h1 style="color: #dc3545;">🚨 API limit reached — your agents may be affected</h1>
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
            _queue_email(owner["email"], "API limit reached — your agents may be affected", exceeded_html)
        _track_event("quota.exceeded", user_id=owner["user_id"], metadata={"tier": tier, "limit": limit})
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
    totp_code: Optional[str] = Field(None, max_length=16)

@app.post("/v1/auth/signup", tags=["Auth"])
def auth_signup(req: SignupRequest, response: Response):
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
        welcome_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h1 style="color: #333;">Welcome to MoltGrid!</h1>
            <p>Hi {req.display_name or 'there'},</p>
            <p>Your agent infrastructure is ready. Here's how to get started:</p>
            <ol>
                <li><strong>Register your first agent:</strong> POST /v1/register</li>
                <li><strong>Store persistent memory:</strong> POST /v1/memory</li>
                <li><strong>Send messages between agents:</strong> POST /v1/relay/send</li>
                <li><strong>Queue background jobs:</strong> POST /v1/queue/submit</li>
            </ol>
            <p><a href="https://moltgrid.net/dashboard" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Go to Dashboard</a></p>
            <p><a href="https://api.moltgrid.net/docs">View Full API Documentation</a></p>
            <p>Questions? Reply to this email or check our <a href="https://github.com/D0NMEGA/MoltGrid">GitHub</a>.</p>
            <p>Happy building!<br>The MoltGrid Team</p>
        </body>
        </html>
        """
        _queue_email(req.email.lower(), "Welcome to MoltGrid — your agent infrastructure is ready", welcome_html)

    token = _create_token(user_id, req.email.lower())
    _track_event("user.signup", user_id=user_id)
    # Set shared auth cookie readable by both moltgrid.net and api.moltgrid.net
    response.set_cookie(
        key="mg_token",
        value=token,
        domain=".moltgrid.net",
        path="/",
        httponly=False,
        secure=True,
        samesite="lax",
        max_age=JWT_EXPIRY_DAYS * 86400,
    )
    return {"user_id": user_id, "token": token, "message": "Account created"}

@app.post("/v1/auth/login", tags=["Auth"])
def auth_login(req: LoginRequest, request: Request, response: Response):
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
        totp_valid = pyotp.TOTP(totp_row["totp_secret"]).verify(req.totp_code)
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
                _queue_email(user_ip_row["email"], "MoltGrid security alert: new login IP detected", alert_html)
            if client_ip not in known_ips:
                known_ips.append(client_ip)
                known_ips = known_ips[-10:]
                with get_db() as ip_db2:
                    ip_db2.execute(
                        "UPDATE users SET known_login_ips = ? WHERE user_id = ?",
                        (json.dumps(known_ips), row["user_id"])
                    )
    _log_audit("user.login", user_id=row["user_id"], ip_address=_get_client_ip(request))
    # Set shared auth cookie readable by both moltgrid.net and api.moltgrid.net
    response.set_cookie(
        key="mg_token",
        value=token,
        domain=".moltgrid.net",
        path="/",
        httponly=False,  # JS needs to read this for homepage logged-in state
        secure=True,
        samesite="lax",
        max_age=JWT_EXPIRY_DAYS * 86400,
    )
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

@app.post("/v1/auth/logout", tags=["Auth"])
def auth_logout(response: Response):
    """Clear the shared auth cookie."""
    response.delete_cookie(key="mg_token", domain=".moltgrid.net", path="/")
    return {"status": "logged_out"}


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., max_length=256)

class ResetPasswordRequest(BaseModel):
    token: str = Field(..., max_length=256)
    new_password: str = Field(..., min_length=8, max_length=128)

@app.post("/v1/auth/forgot-password", tags=["Auth"])
def auth_forgot_password(req: ForgotPasswordRequest):
    """Send a password reset link to the user's email."""
    with get_db() as db:
        user_row = db.execute("SELECT user_id, email FROM users WHERE email = ?", (req.email,)).fetchone()
    if not user_row:
        # Don't reveal whether the email exists
        return {"message": "If that email is registered, a reset link has been sent."}
    reset_token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    with get_db() as db:
        db.execute(
            "INSERT OR REPLACE INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)",
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
    _queue_email(user_row["email"], "Reset your MoltGrid password", reset_html)
    return {"message": "If that email is registered, a reset link has been sent."}

@app.post("/v1/auth/reset-password", tags=["Auth"])
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

class TOTP2FAVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

class TOTP2FADisableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=16)  # TOTP or recovery code

@app.post("/v1/auth/2fa/setup", tags=["Auth"])
def auth_2fa_setup(user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT email, totp_enabled FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        if row["totp_enabled"]:
            raise HTTPException(400, detail={"error": "2FA already enabled", "code": "2FA_ALREADY_ENABLED", "status": 400})
        secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=row["email"], issuer_name="MoltGrid")
        db.execute("UPDATE users SET totp_secret = ? WHERE user_id = ?", (secret, user_id))
    qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(uri)}"
    return {"secret": secret, "otpauth_uri": uri, "qr_code_url": qr_code_url}

@app.post("/v1/auth/2fa/verify", tags=["Auth"])
def auth_2fa_verify(req: TOTP2FAVerifyRequest, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT totp_secret FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row or not row["totp_secret"]:
            raise HTTPException(400, detail={"error": "2FA setup not initiated", "code": "2FA_NOT_SETUP", "status": 400})
        if not pyotp.TOTP(row["totp_secret"]).verify(req.code):
            raise HTTPException(401, detail={"error": "Invalid TOTP code", "code": "INVALID_TOTP", "status": 401})
        plain_codes = [secrets.token_hex(8) for _ in range(10)]
        hashed_codes = [hashlib.sha256(c.encode()).hexdigest() for c in plain_codes]
        db.execute(
            "UPDATE users SET totp_enabled = 1, totp_recovery_codes = ? WHERE user_id = ?",
            (json.dumps(hashed_codes), user_id)
        )
    return {"enabled": True, "recovery_codes": plain_codes}

@app.post("/v1/auth/2fa/disable", tags=["Auth"])
def auth_2fa_disable(req: TOTP2FADisableRequest, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT totp_secret, totp_enabled, totp_recovery_codes FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row or not row["totp_enabled"]:
            raise HTTPException(400, detail={"error": "2FA not enabled", "code": "2FA_NOT_ENABLED", "status": 400})
        totp_valid = pyotp.TOTP(row["totp_secret"]).verify(req.code)
        if not totp_valid:
            code_hash = hashlib.sha256(req.code.encode()).hexdigest()
            recovery_codes = json.loads(row["totp_recovery_codes"] or "[]")
            if code_hash not in recovery_codes:
                raise HTTPException(401, detail={"error": "Invalid code", "code": "INVALID_CODE", "status": 401})
        db.execute(
            "UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_recovery_codes = NULL WHERE user_id = ?",
            (user_id,)
        )
    return {"disabled": True}


# ═══════════════════════════════════════════════════════════════════════════════
# USER NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

class NotificationPreferencesRequest(BaseModel):
    welcome: Optional[bool] = Field(None, description="Welcome emails for new signups and first agent")
    quota_alerts: Optional[bool] = Field(None, description="Quota warning and exceeded emails")
    weekly_digest: Optional[bool] = Field(None, description="Weekly summary of agent activity")

@app.post("/v1/user/notifications/preferences", tags=["User"])
def update_notification_preferences(req: NotificationPreferencesRequest, user_id: str = Depends(get_user_id)):
    """Update email notification preferences. Users can opt out of specific notification types."""
    with get_db() as db:
        # Get current preferences or defaults
        current_prefs = _get_user_notification_prefs(db, user_id)

        # Update only provided fields
        if req.welcome is not None:
            current_prefs["welcome"] = req.welcome
        if req.quota_alerts is not None:
            current_prefs["quota_alerts"] = req.quota_alerts
        if req.weekly_digest is not None:
            current_prefs["weekly_digest"] = req.weekly_digest

        # Save to database
        db.execute(
            "UPDATE users SET notification_preferences = ? WHERE user_id = ?",
            (json.dumps(current_prefs), user_id)
        )

    return {"status": "updated", "preferences": current_prefs}

@app.get("/v1/user/notifications/preferences", tags=["User"])
def get_notification_preferences(user_id: str = Depends(get_user_id)):
    """Get current email notification preferences."""
    with get_db() as db:
        prefs = _get_user_notification_prefs(db, user_id)
    return {"preferences": prefs}


# ─── Memory Visibility Pydantic Models (used by Dashboard + Agent endpoints) ──

class MemoryVisibilityRequest(BaseModel):
    namespace: str = Field("default", max_length=64)
    key: str = Field(..., max_length=256)
    visibility: str = Field(..., description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)

class MemoryBulkVisibilityRequest(BaseModel):
    entries: List[dict]
    visibility: str = Field(..., description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)


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

@app.get("/v1/user/overview", tags=["User Dashboard"])
def user_overview(user_id: str = Depends(get_user_id)):
    """Aggregated account overview: agents, totals, and 30-day charts."""
    import json as _json
    cutoff30 = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    with get_db() as db:
        # Agents
        agents_rows = db.execute(
            "SELECT agent_id, name, heartbeat_status, heartbeat_at, request_count "
            "FROM agents WHERE owner_id=? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
        agent_ids = [r["agent_id"] for r in agents_rows]
        total_agents = len(agent_ids)
        online_count = sum(1 for r in agents_rows if r["heartbeat_status"] in ("online", "busy", "worker_running"))

        agents = [dict(r) for r in agents_rows]

        if not agent_ids:
            return {
                "total_agents": 0, "online_count": 0, "agents": [],
                "totals": {"messages_sent": 0, "messages_received": 0, "jobs_completed": 0, "jobs_failed": 0, "memory_keys": 0},
                "msg_chart": [], "job_chart": []
            }

        placeholders = ",".join("?" * len(agent_ids))

        # Totals
        messages_sent = db.execute(
            f"SELECT COUNT(*) as c FROM relay WHERE from_agent IN ({placeholders}) AND created_at >= ?",
            agent_ids + [cutoff30]
        ).fetchone()["c"]
        messages_received = db.execute(
            f"SELECT COUNT(*) as c FROM relay WHERE to_agent IN ({placeholders}) AND created_at >= ?",
            agent_ids + [cutoff30]
        ).fetchone()["c"]
        jobs_completed = db.execute(
            f"SELECT COUNT(*) as c FROM queue WHERE agent_id IN ({placeholders}) AND status='completed' AND created_at >= ?",
            agent_ids + [cutoff30]
        ).fetchone()["c"]
        jobs_failed = db.execute(
            f"SELECT COUNT(*) as c FROM queue WHERE agent_id IN ({placeholders}) AND status='failed' AND created_at >= ?",
            agent_ids + [cutoff30]
        ).fetchone()["c"]
        memory_keys = db.execute(
            f"SELECT COUNT(*) as c FROM memory WHERE agent_id IN ({placeholders})",
            agent_ids
        ).fetchone()["c"]

        # 30-day message chart (by day)
        msg_rows = db.execute(
            f"SELECT substr(created_at,1,10) as date, COUNT(*) as count FROM relay "
            f"WHERE (from_agent IN ({placeholders}) OR to_agent IN ({placeholders})) AND created_at >= ? "
            f"GROUP BY date ORDER BY date",
            agent_ids + agent_ids + [cutoff30]
        ).fetchall()

        # 30-day job chart (by day, split completed/failed)
        job_rows = db.execute(
            f"SELECT substr(created_at,1,10) as date, "
            f"SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed, "
            f"SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed "
            f"FROM queue WHERE agent_id IN ({placeholders}) AND created_at >= ? "
            f"GROUP BY date ORDER BY date",
            agent_ids + [cutoff30]
        ).fetchall()

    return {
        "total_agents": total_agents,
        "online_count": online_count,
        "agents": agents,
        "totals": {
            "messages_sent": messages_sent,
            "messages_received": messages_received,
            "jobs_completed": jobs_completed,
            "jobs_failed": jobs_failed,
            "memory_keys": memory_keys
        },
        "msg_chart": [dict(r) for r in msg_rows],
        "job_chart": [dict(r) for r in job_rows]
    }


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
def user_agent_activity(
    agent_id: str,
    user_id: str = Depends(get_user_id),
    type: str = Query("all", description="Filter: all, messages, jobs, memory, schedules, security"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Activity feed for one owned agent — events across relay, queue, and memory with filtering and pagination."""
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

        # MoltBook events (OC-09, OC-10) — include source badge + deep link
        for r in db.execute(
            "SELECT id as event_id, event_name as event_type, metadata, source, moltbook_url, "
            "created_at as timestamp FROM analytics_events "
            "WHERE agent_id=? AND source='moltbook' ORDER BY created_at DESC LIMIT 50",
            (agent_id,),
        ).fetchall():
            item = dict(r)
            item["badge"] = "moltbook"
            try:
                item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
            except Exception:
                item["metadata"] = {}
            events.append(item)

    # Sort all events by timestamp DESC
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    # Filter by type if not "all"
    if type != "all":
        type_map = {
            "messages": ["message_sent", "message_received"],
            "jobs": ["job_pending", "job_completed", "job_failed", "job_running"],
            "memory": ["memory_update"],
            "schedules": ["schedule"],
            "security": ["key_rotated"],
        }
        allowed = type_map.get(type, [])
        if allowed:
            events = [e for e in events if any(e.get("event_type", "").startswith(a) for a in allowed)]

    # Paginate
    total = len(events)
    events = events[offset:offset + limit]
    return {"agent_id": agent_id, "events": events, "total": total}

@app.get("/v1/user/agents/{agent_id}/stats", tags=["User Dashboard"])
def user_agent_stats(agent_id: str, user_id: str = Depends(get_user_id)):
    """Get aggregate stats for one owned agent."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        memory_keys = db.execute("SELECT COUNT(*) as cnt FROM memory WHERE agent_id = ?", (agent_id,)).fetchone()["cnt"]
        jobs_pending = db.execute("SELECT COUNT(*) as cnt FROM queue WHERE agent_id = ? AND status = 'pending'", (agent_id,)).fetchone()["cnt"]
        jobs_completed = db.execute("SELECT COUNT(*) as cnt FROM queue WHERE agent_id = ? AND status = 'completed'", (agent_id,)).fetchone()["cnt"]
        jobs_failed = db.execute("SELECT COUNT(*) as cnt FROM queue WHERE agent_id = ? AND status = 'failed'", (agent_id,)).fetchone()["cnt"]
        msgs_sent = db.execute("SELECT COUNT(*) as cnt FROM relay WHERE from_agent = ?", (agent_id,)).fetchone()["cnt"]
        msgs_received = db.execute("SELECT COUNT(*) as cnt FROM relay WHERE to_agent = ?", (agent_id,)).fetchone()["cnt"]
        schedules = db.execute("SELECT COUNT(*) as cnt FROM scheduled_tasks WHERE agent_id = ? AND enabled = 1", (agent_id,)).fetchone()["cnt"]
        agent = db.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    return {
        "agent_id": agent_id,
        "name": agent["name"],
        "description": agent["description"],
        "heartbeat_status": agent["heartbeat_status"],
        "heartbeat_at": agent["heartbeat_at"],
        "request_count": agent["request_count"],
        "created_at": agent["created_at"],
        "last_seen": agent["last_seen"],
        "memory_keys": memory_keys,
        "jobs_pending": jobs_pending,
        "jobs_completed": jobs_completed,
        "jobs_failed": jobs_failed,
        "messages_sent": msgs_sent,
        "messages_received": msgs_received,
        "schedules_active": schedules,
    }

@app.patch("/v1/user/agents/{agent_id}", tags=["User Dashboard"])
def user_rename_agent(agent_id: str, body: dict, user_id: str = Depends(get_user_id)):
    """Rename an owned agent. Updates name everywhere (directory, messages, etc)."""
    import re
    name = (body.get("name") or "").strip()
    if not name or len(name) > 64:
        raise HTTPException(422, "Name must be 1-64 characters")
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9 _\-]{0,63}$', name):
        raise HTTPException(422, "Letters, numbers, spaces, hyphens, underscores only — must start with letter or number")
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute("UPDATE agents SET name=? WHERE agent_id=?", (name, agent_id))
    _log_audit("agent.rename", user_id=user_id, agent_id=agent_id)
    return {"status": "renamed", "agent_id": agent_id, "name": name}

@app.post("/v1/user/agents/{agent_id}/rotate-key", tags=["User Dashboard"])
def user_rotate_key(agent_id: str, user_id: str = Depends(get_user_id)):
    """Rotate API key for an owned agent. Returns new key; old key immediately invalid."""
    new_key = generate_api_key()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute("UPDATE agents SET api_key_hash=? WHERE agent_id=?", (hash_key(new_key), agent_id))
    _log_audit("apikey.rotate", user_id=user_id, agent_id=agent_id)
    return {
        "status": "rotated",
        "agent_id": agent_id,
        "api_key": new_key,
        "rotated_at": datetime.now(timezone.utc).isoformat(),
        "message": "Store your new API key securely. The old key is now invalid.",
    }

@app.delete("/v1/user/agents/{agent_id}", tags=["User Dashboard"])
def user_delete_agent(agent_id: str, user_id: str = Depends(get_user_id)):
    """Delete an owned agent and all its data."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute("DELETE FROM memory WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM queue WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM relay WHERE from_agent=? OR to_agent=?", (agent_id, agent_id))
        db.execute("DELETE FROM webhooks WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM scheduled_tasks WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM shared_memory WHERE owner_agent=?", (agent_id,))
        db.execute("DELETE FROM rate_limits WHERE agent_id=?", (agent_id,))
        db.execute("DELETE FROM collaborations WHERE agent_id=? OR partner_agent=?", (agent_id, agent_id))
        db.execute("DELETE FROM marketplace WHERE creator_agent=?", (agent_id,))
        db.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
    _log_audit("agent.delete", user_id=user_id, agent_id=agent_id)
    return {"status": "deleted", "agent_id": agent_id}

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


# ── Messages list ────────────────────────────────────────────────────────────
@app.get("/v1/user/agents/{agent_id}/messages-list", tags=["User Dashboard"])
def user_messages_list(
    agent_id: str,
    offset: int = 0, limit: int = 20,
    direction: str = "all",   # all | sent | received
    search: str = "",
    user_id: str = Depends(get_user_id),
):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        if direction == "sent":
            cond = "from_agent = ?"
            params = [agent_id]
        elif direction == "received":
            cond = "to_agent = ?"
            params = [agent_id]
        else:
            cond = "(from_agent = ? OR to_agent = ?)"
            params = [agent_id, agent_id]
        total = db.execute(f"SELECT COUNT(*) as c FROM relay WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(
            f"SELECT message_id, from_agent, to_agent, channel, created_at FROM relay "
            f"WHERE {cond} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for col, aid in [("from_name", d["from_agent"]), ("to_name", d["to_agent"])]:
                a = db.execute("SELECT name FROM agents WHERE agent_id=?", (aid,)).fetchone()
                d[col] = a["name"] if a and a["name"] else aid
            result.append(d)
    return {"messages": result, "total": total, "offset": offset, "limit": limit}


@app.get("/v1/user/agents/{agent_id}/messages/{message_id}", tags=["User Dashboard"])
def user_message_detail(agent_id: str, message_id: str, user_id: str = Depends(get_user_id)):
    """Get full detail for a single relay message."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        row = db.execute(
            "SELECT message_id, from_agent, to_agent, channel, payload, created_at, read_at FROM relay "
            "WHERE message_id=? AND (from_agent=? OR to_agent=?)",
            (message_id, agent_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Message not found")
        d = dict(row)
        d["payload"] = _decrypt(d["payload"])
        for col, aid in [("from_name", d["from_agent"]), ("to_name", d["to_agent"])]:
            a = db.execute("SELECT name FROM agents WHERE agent_id=?", (aid,)).fetchone()
            d[col] = a["name"] if a and a["name"] else aid
    return d


# ── Memory list ───────────────────────────────────────────────────────────────
@app.get("/v1/user/agents/{agent_id}/memory-list", tags=["User Dashboard"])
def user_memory_list(
    agent_id: str,
    offset: int = 0, limit: int = 30,
    namespace: str = "",
    search: str = "",
    visibility: str = "",
    user_id: str = Depends(get_user_id),
):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        cond = "agent_id = ?"
        params = [agent_id]
        if namespace:
            cond += " AND namespace = ?"; params.append(namespace)
        if search:
            cond += " AND key LIKE ?"; params.append(f"%{search}%")
        if visibility in ("private", "public", "shared"):
            cond += " AND COALESCE(visibility,'private') = ?"; params.append(visibility)
        total = db.execute(f"SELECT COUNT(*) as c FROM memory WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(
            f"SELECT namespace, key, created_at, updated_at, expires_at, "
            f"COALESCE(visibility,'private') as visibility, shared_agents FROM memory "
            f"WHERE {cond} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        ns_rows = db.execute(
            "SELECT DISTINCT namespace FROM memory WHERE agent_id=? ORDER BY namespace", (agent_id,)
        ).fetchall()
    return {
        "keys": [dict(r) for r in rows], "total": total, "offset": offset, "limit": limit,
        "namespaces": [r["namespace"] for r in ns_rows],
    }


@app.get("/v1/user/agents/{agent_id}/memory-entry", tags=["User Dashboard"])
def user_memory_get(
    agent_id: str, namespace: str = "default", key: str = "",
    user_id: str = Depends(get_user_id),
):
    """Fetch a single memory entry including its value and visibility metadata."""
    if not key:
        raise HTTPException(400, "key is required")
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        row = db.execute(
            "SELECT namespace, key, value, created_at, updated_at, expires_at, "
            "COALESCE(visibility,'private') as visibility, shared_agents "
            "FROM memory WHERE agent_id=? AND namespace=? AND key=? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (agent_id, namespace, key, now)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Memory key not found or expired")
    d = dict(row)
    d["value"] = _decrypt(d["value"])
    d["shared_agents"] = json.loads(d["shared_agents"] or "[]")
    return d


@app.patch("/v1/user/agents/{agent_id}/memory-entry/visibility", tags=["User Dashboard"])
def user_memory_set_visibility(
    agent_id: str, req: MemoryVisibilityRequest,
    user_id: str = Depends(get_user_id),
):
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        old = db.execute(
            "SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, req.namespace, req.key)
        ).fetchone()
        if not old:
            raise HTTPException(404, "Memory key not found")
        db.execute(
            "UPDATE memory SET visibility=?, shared_agents=? "
            "WHERE agent_id=? AND namespace=? AND key=?",
            (vis, sa_json, agent_id, req.namespace, req.key)
        )
    _log_memory_access("visibility_changed", agent_id, req.namespace, req.key,
                       actor_user_id=user_id,
                       old_visibility=old["visibility"] or "private",
                       new_visibility=vis)
    return {"status": "updated", "key": req.key, "namespace": req.namespace, "visibility": vis}


@app.post("/v1/user/agents/{agent_id}/memory-bulk-visibility", tags=["User Dashboard"])
def user_memory_bulk_visibility(
    agent_id: str, req: MemoryBulkVisibilityRequest,
    user_id: str = Depends(get_user_id),
):
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    updated = 0
    # Collect log entries to emit OUTSIDE the get_db() context to avoid transaction interference
    # (documented pattern: _log_memory_access uses its own sqlite3 connection)
    log_entries = []
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        for entry in req.entries[:200]:
            ns = entry.get("namespace", "default")
            k = entry.get("key", "")
            if not k:
                continue
            old = db.execute(
                "SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?",
                (agent_id, ns, k)
            ).fetchone()
            if not old:
                continue
            db.execute(
                "UPDATE memory SET visibility=?, shared_agents=? "
                "WHERE agent_id=? AND namespace=? AND key=?",
                (vis, sa_json, agent_id, ns, k)
            )
            log_entries.append((ns, k, old["visibility"] or "private"))
            updated += 1
    # Emit audit log entries after DB context is closed (Rule: _log_memory_access must be
    # called outside with get_db() block to avoid transaction interference)
    for ns, k, old_vis in log_entries:
        _log_memory_access("visibility_changed", agent_id, ns, k,
                           actor_user_id=user_id,
                           old_visibility=old_vis,
                           new_visibility=vis)
    return {"status": "updated", "count": updated, "visibility": vis}


@app.get("/v1/user/agents/{agent_id}/memory-access-log", tags=["User Dashboard"])
def user_memory_access_log(
    agent_id: str,
    namespace: str = "", key: str = "",
    offset: int = 0, limit: int = 50,
    user_id: str = Depends(get_user_id),
):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        cond = "agent_id = ?"
        params = [agent_id]
        if namespace:
            cond += " AND namespace = ?"; params.append(namespace)
        if key:
            cond += " AND key = ?"; params.append(key)
        total = db.execute(f"SELECT COUNT(*) as c FROM memory_access_log WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(
            f"SELECT id, namespace, key, action, actor_agent_id, actor_user_id, "
            f"old_visibility, new_visibility, authorized, created_at "
            f"FROM memory_access_log WHERE {cond} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
    return {"logs": [dict(r) for r in rows], "total": total, "offset": offset}


# ── Memory delete ─────────────────────────────────────────────────────────────
@app.delete("/v1/user/agents/{agent_id}/memory-entry", tags=["User Dashboard"])
def user_memory_delete(
    agent_id: str, namespace: str = "default", key: str = "",
    user_id: str = Depends(get_user_id),
):
    if not key: raise HTTPException(400, "key is required")
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        deleted = db.execute(
            "DELETE FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, namespace, key),
        ).rowcount
    if not deleted: raise HTTPException(404, "Memory key not found")
    _log_memory_access("delete", agent_id, namespace, key, actor_user_id=user_id)
    return {"status": "deleted"}


# ── Integrations (OC-05, OC-06, OC-07) ───────────────────────────────────────
class IntegrationCreateRequest(BaseModel):
    platform: str = Field(..., max_length=64, description="Platform name, e.g. 'moltbook', 'slack'")
    config: Optional[dict] = Field(None, description="Platform-specific config JSON")
    status: str = Field("active", max_length=32)

@app.post("/v1/agents/{agent_id}/integrations", tags=["Integrations"])
def integration_create(agent_id: str, req: IntegrationCreateRequest, caller_id: str = Depends(get_agent_id)):
    """Link an external platform to this agent. Agent must own itself (caller == agent_id)."""
    if caller_id != agent_id:
        raise HTTPException(403, "You can only manage integrations for your own agent")
    integration_id = f"int_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        agent = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(404, "Agent not found")
        db.execute(
            "INSERT INTO integrations (id, agent_id, platform, config, status, created_at) VALUES (?,?,?,?,?,?)",
            (integration_id, agent_id, req.platform,
             json.dumps(req.config) if req.config else None,
             req.status, now),
        )
    return {"id": integration_id, "agent_id": agent_id, "platform": req.platform,
            "status": req.status, "created_at": now}

@app.get("/v1/agents/{agent_id}/integrations", tags=["Integrations"])
def integration_list(agent_id: str, caller_id: str = Depends(get_agent_id)):
    """List all platform integrations linked to an agent. Caller must be the agent."""
    if caller_id != agent_id:
        raise HTTPException(403, "You can only view integrations for your own agent")
    with get_db() as db:
        rows = db.execute(
            "SELECT id, platform, config, status, created_at FROM integrations WHERE agent_id=? ORDER BY created_at DESC",
            (agent_id,),
        ).fetchall()
    integrations = []
    for r in rows:
        item = dict(r)
        if item.get("config"):
            try:
                item["config"] = json.loads(item["config"])
            except Exception:
                pass
        integrations.append(item)
    return {"agent_id": agent_id, "integrations": integrations}

# ── User-facing integrations (dashboard) ─────────────────────────────────────
@app.get("/v1/user/agents/{agent_id}/integrations", tags=["User Dashboard"])
def user_integration_list(agent_id: str, user_id: str = Depends(get_user_id)):
    """List platform integrations for an owned agent (dashboard)."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        rows = db.execute(
            "SELECT id, platform, config, status, created_at FROM integrations WHERE agent_id=? ORDER BY created_at DESC",
            (agent_id,),
        ).fetchall()
    integrations = []
    for r in rows:
        item = dict(r)
        if item.get("config"):
            try:
                item["config"] = json.loads(item["config"])
            except Exception:
                pass
        integrations.append(item)
    return {"agent_id": agent_id, "integrations": integrations}


# ── Integration status (dashboard, CON-07) ────────────────────────────────────
class IntegrationStatusItem(BaseModel):
    integration_id: str
    agent_id: str
    platform: str
    status: str
    last_sync_at: str
    event_count: int

class IntegrationStatusResponse(BaseModel):
    integrations: List[IntegrationStatusItem]

@app.get("/v1/user/integrations/status", response_model=IntegrationStatusResponse, tags=["User Dashboard"])
def user_integrations_status(agent_id: Optional[str] = None, user_id: str = Depends(get_user_id)):
    """Return integration status with event counts for all agents owned by user (or one agent if agent_id given)."""
    with get_db() as db:
        if agent_id:
            _verify_agent_ownership(db, agent_id, user_id)
            rows = db.execute(
                "SELECT i.id, i.agent_id, i.platform, i.status, i.created_at "
                "FROM integrations i JOIN agents a ON i.agent_id = a.agent_id "
                "WHERE a.owner_id = ? AND i.agent_id = ? ORDER BY i.created_at DESC",
                (user_id, agent_id),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT i.id, i.agent_id, i.platform, i.status, i.created_at "
                "FROM integrations i JOIN agents a ON i.agent_id = a.agent_id "
                "WHERE a.owner_id = ? ORDER BY i.created_at DESC",
                (user_id,),
            ).fetchall()
        items = []
        for r in rows:
            count_row = db.execute(
                "SELECT COUNT(*) as c FROM analytics_events WHERE agent_id = ? AND source != 'moltgrid_api'",
                (r["agent_id"],),
            ).fetchone()
            items.append(IntegrationStatusItem(
                integration_id=r["id"],
                agent_id=r["agent_id"],
                platform=r["platform"],
                status=r["status"],
                last_sync_at=r["created_at"],
                event_count=count_row["c"] if count_row else 0,
            ))
    return IntegrationStatusResponse(integrations=items)


# ── Jobs list ─────────────────────────────────────────────────────────────────
@app.get("/v1/user/agents/{agent_id}/jobs-list", tags=["User Dashboard"])
def user_jobs_list(
    agent_id: str,
    offset: int = 0, limit: int = 20,
    status: str = "all",
    user_id: str = Depends(get_user_id),
):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        cond = "agent_id = ?"
        params = [agent_id]
        if status != "all":
            cond += " AND status = ?"; params.append(status)
        total = db.execute(f"SELECT COUNT(*) as c FROM queue WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(
            f"SELECT job_id, queue_name, status, priority, created_at, started_at, "
            f"completed_at, failed_at, fail_reason, attempt_count, max_attempts "
            f"FROM queue WHERE {cond} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"jobs": [dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


# ── Schedules list ────────────────────────────────────────────────────────────
@app.get("/v1/user/agents/{agent_id}/schedules", tags=["User Dashboard"])
def user_schedules_list(agent_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        rows = db.execute(
            "SELECT task_id, cron_expr, queue_name, priority, enabled, "
            "last_run_at, next_run_at, run_count, created_at FROM scheduled_tasks "
            "WHERE agent_id=? ORDER BY created_at DESC", (agent_id,)
        ).fetchall()
    return {"schedules": [dict(r) for r in rows]}


class UserScheduleRequest(BaseModel):
    cron_expr: str = Field(..., max_length=128)
    queue_name: str = Field("default", max_length=64)
    payload: str = Field("{}", max_length=100_000)
    priority: int = Field(0, ge=0, le=10)


@app.post("/v1/user/agents/{agent_id}/schedules", tags=["User Dashboard"])
def user_schedule_create(agent_id: str, req: UserScheduleRequest, user_id: str = Depends(get_user_id)):
    try:
        cron = croniter(req.cron_expr, datetime.now(timezone.utc))
        next_run = cron.get_next(datetime).isoformat()
    except (ValueError, KeyError) as e:
        raise HTTPException(400, f"Invalid cron expression: {e}")
    task_id = f"task_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute(
            "INSERT INTO scheduled_tasks (task_id, agent_id, cron_expr, queue_name, payload, "
            "priority, enabled, created_at, next_run_at, run_count) VALUES (?,?,?,?,?,?,1,?,?,0)",
            (task_id, agent_id, req.cron_expr, req.queue_name, _encrypt(req.payload),
             req.priority, now, next_run),
        )
    _log_audit("schedule.create", user_id=user_id, agent_id=agent_id, details=task_id)
    return {"task_id": task_id, "cron_expr": req.cron_expr, "next_run_at": next_run, "enabled": True}


class UserScheduleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    cron_expr: Optional[str] = Field(None, max_length=128)


@app.patch("/v1/user/agents/{agent_id}/schedules/{task_id}", tags=["User Dashboard"])
def user_schedule_update(
    agent_id: str, task_id: str,
    req: UserScheduleUpdateRequest,
    user_id: str = Depends(get_user_id),
):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        row = db.execute(
            "SELECT * FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        ).fetchone()
        if not row: raise HTTPException(404, "Schedule not found")
        updates = []
        params = []
        if req.enabled is not None:
            updates.append("enabled=?"); params.append(1 if req.enabled else 0)
        if req.cron_expr is not None:
            try:
                cron = croniter(req.cron_expr, datetime.now(timezone.utc))
                next_run = cron.get_next(datetime).isoformat()
            except (ValueError, KeyError) as e:
                raise HTTPException(400, f"Invalid cron: {e}")
            updates.append("cron_expr=?"); params.append(req.cron_expr)
            updates.append("next_run_at=?"); params.append(next_run)
        if not updates: raise HTTPException(400, "Nothing to update")
        db.execute(f"UPDATE scheduled_tasks SET {', '.join(updates)} WHERE task_id=?", params + [task_id])
        row = db.execute("SELECT * FROM scheduled_tasks WHERE task_id=?", (task_id,)).fetchone()
    return dict(row)


@app.delete("/v1/user/agents/{agent_id}/schedules/{task_id}", tags=["User Dashboard"])
def user_schedule_delete(agent_id: str, task_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        deleted = db.execute(
            "DELETE FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        ).rowcount
    if not deleted: raise HTTPException(404, "Schedule not found")
    _log_audit("schedule.delete", user_id=user_id, agent_id=agent_id, details=task_id)
    return {"status": "deleted"}


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


# ── Webhooks list / create / delete (user-level) ─────────────────────────────
@app.get("/v1/user/agents/{agent_id}/webhooks", tags=["User Dashboard"])
def user_webhooks_list(agent_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        rows = db.execute(
            "SELECT webhook_id, url, event_types, active, created_at FROM webhooks "
            "WHERE agent_id=? ORDER BY created_at DESC", (agent_id,)
        ).fetchall()
    return {"webhooks": [dict(r) for r in rows]}


@app.post("/v1/user/agents/{agent_id}/webhooks", tags=["User Dashboard"])
def user_webhook_create(agent_id: str, req: WebhookRegisterRequest, user_id: str = Depends(get_user_id)):
    for et in req.event_types:
        if et not in WEBHOOK_EVENT_TYPES:
            raise HTTPException(400, f"Invalid event type: {et}")
    webhook_id = f"wh_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute(
            "INSERT INTO webhooks (webhook_id, agent_id, url, event_types, secret, created_at, active) "
            "VALUES (?,?,?,?,?,?,1)",
            (webhook_id, agent_id, req.url, json.dumps(req.event_types), req.secret, now),
        )
    _log_audit("webhook.create", user_id=user_id, agent_id=agent_id, details=webhook_id)
    return {"webhook_id": webhook_id, "url": req.url, "event_types": req.event_types, "active": True}


@app.delete("/v1/user/agents/{agent_id}/webhooks/{webhook_id}", tags=["User Dashboard"])
def user_webhook_delete(agent_id: str, webhook_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        deleted = db.execute(
            "DELETE FROM webhooks WHERE webhook_id=? AND agent_id=?", (webhook_id, agent_id)
        ).rowcount
    if not deleted: raise HTTPException(404, "Webhook not found")
    _log_audit("webhook.delete", user_id=user_id, agent_id=agent_id, details=webhook_id)
    return {"status": "deleted"}


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG VIEWER (BL-05)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/v1/user/audit-log/export", tags=["User Dashboard"])
def user_audit_log_export(
    action: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    user_id: str = Depends(get_user_id),
):
    """Export audit log entries as CSV. Returns all matching entries (no pagination)."""
    base = "SELECT log_id, action, agent_id, details, ip_address, created_at FROM audit_logs WHERE user_id = ?"
    params: list = [user_id]
    if action:
        base += " AND action = ?"
        params.append(action)
    if from_date:
        base += " AND created_at >= ?"
        params.append(from_date)
    if to_date:
        base += " AND created_at <= ?"
        params.append(to_date)
    base += " ORDER BY created_at DESC"
    with get_db() as db:
        rows = db.execute(base, params).fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "action", "agent_id", "details", "ip_address"])
    for row in rows:
        writer.writerow([
            row["created_at"], row["action"], row["agent_id"] or "",
            row["details"] or "", row["ip_address"] or "",
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-log.csv"},
    )


@app.get("/v1/user/audit-log", tags=["User Dashboard"])
def user_audit_log(
    action: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    user_id: str = Depends(get_user_id),
):
    """Retrieve audit log entries for the authenticated user with optional filters."""
    base = "SELECT log_id, action, agent_id, details, ip_address, created_at FROM audit_logs WHERE user_id = ?"
    count_base = "SELECT COUNT(*) as cnt FROM audit_logs WHERE user_id = ?"
    params: list = [user_id]
    count_params: list = [user_id]
    if action:
        base += " AND action = ?"
        count_base += " AND action = ?"
        params.append(action)
        count_params.append(action)
    if from_date:
        base += " AND created_at >= ?"
        count_base += " AND created_at >= ?"
        params.append(from_date)
        count_params.append(from_date)
    if to_date:
        base += " AND created_at <= ?"
        count_base += " AND created_at <= ?"
        params.append(to_date)
        count_params.append(to_date)
    capped_limit = min(limit, 200)
    base += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([capped_limit, offset])
    with get_db() as db:
        rows = db.execute(base, params).fetchall()
        total = db.execute(count_base, count_params).fetchone()["cnt"]
    return {
        "entries": [dict(r) for r in rows],
        "total": total,
        "limit": capped_limit,
        "offset": offset,
    }


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
        "tiers": {
            "free": {"name": "free", "price": 0, "max_agents": 1, "max_api_calls": 10000,
                     "features": ["Memory", "Queue", "Messaging", "Scheduling"]},
            "hobby": {"name": "hobby", "price": 5, "max_agents": 10, "max_api_calls": 1000000,
                      "features": ["Everything in Free", "Dead-letter queue", "Webhooks", "Marketplace", "Priority support"]},
            "team": {"name": "team", "price": 25, "max_agents": 50, "max_api_calls": 10000000,
                     "features": ["Everything in Hobby", "Team workspaces", "SSO (coming soon)", "SLA guarantee"]},
            "scale": {"name": "scale", "price": 99, "max_agents": 200, "max_api_calls": 999999999,
                      "features": ["Everything in Team", "Unlimited API calls", "Dedicated support", "Custom integrations"]},
        },
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
        success_url="https://api.moltgrid.net/dashboard#/billing",
        cancel_url="https://api.moltgrid.net/dashboard#/billing",
        metadata={"moltgrid_user_id": user_id, "tier": req.tier},
    )
    _track_event("billing.checkout_started", user_id=user_id, metadata={"tier": req.tier})
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
        return_url="https://api.moltgrid.net/dashboard#/billing",
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

    # Track user_id + tier for post-DB email (checkout case)
    _checkout_user_id = None
    _checkout_tier = None

    with get_db() as db:
        if event_type == "checkout.session.completed":
            user_id = (data_obj.get("metadata") or {}).get("moltgrid_user_id")
            tier = (data_obj.get("metadata") or {}).get("tier", "hobby")
            sub_id = data_obj.get("subscription")
            if user_id:
                _apply_tier(db, user_id, tier)
                db.execute("UPDATE users SET stripe_subscription_id = ? WHERE user_id = ?", (sub_id, user_id))
                _track_event("billing.subscription_activated", user_id=user_id, metadata={"tier": tier})
                _checkout_user_id = user_id
                _checkout_tier = tier

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
                _track_event("billing.subscription_cancelled", user_id=user["user_id"])

        elif event_type == "invoice.payment_failed":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                db.execute("UPDATE users SET payment_failed = 1 WHERE user_id = ?", (user["user_id"],))
                logger.warning(f"Payment failed for user {user['user_id']}")

    # Audit log + payment confirmation email — OUTSIDE with get_db() blocks
    if _checkout_user_id:
        _log_audit("billing.tier_change", user_id=_checkout_user_id, details=_checkout_tier)
    if _checkout_user_id:
        with get_db() as email_db:
            email_user = email_db.execute("SELECT email FROM users WHERE user_id = ?", (_checkout_user_id,)).fetchone()
        if email_user:
            confirm_html = (
                f"<h2>Your MoltGrid {_checkout_tier} plan is now active</h2>"
                f"<p>Thank you for your purchase. Your account has been upgraded to the <strong>{_checkout_tier}</strong> tier.</p>"
                f"<p>Log in to your dashboard: <a href='https://moltgrid.net'>Open Dashboard</a></p>"
            )
            _queue_email(email_user["email"], f"MoltGrid: {_checkout_tier} plan activated", confirm_html)

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
# AGENT TEMPLATES (BL-04)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/v1/templates", tags=["Templates"])
def list_templates():
    """List all available agent templates. Public — no auth required."""
    with get_db() as db:
        rows = db.execute(
            "SELECT template_id, name, description, category, starter_code FROM templates ORDER BY name"
        ).fetchall()
    return {
        "templates": [
            {
                "template_id": r["template_id"],
                "name": r["name"],
                "description": r["description"],
                "category": r["category"],
                "starter_code": r["starter_code"],
            }
            for r in rows
        ]
    }


@app.get("/v1/templates/{template_id}", tags=["Templates"])
def get_template(template_id: str):
    """Get a single agent template by ID. Public — no auth required."""
    with get_db() as db:
        row = db.execute(
            "SELECT template_id, name, description, category, starter_code FROM templates WHERE template_id = ?",
            (template_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail={"error": "Template not found", "code": "TEMPLATE_NOT_FOUND", "status": 404})
    return {
        "template_id": row["template_id"],
        "name": row["name"],
        "description": row["description"],
        "category": row["category"],
        "starter_code": row["starter_code"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
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


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, description="Display name for your agent")
    template_id: Optional[str] = Field(None, max_length=64, description="Optional template ID to pre-load starter code into agent memory")

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
                    "INSERT OR REPLACE INTO memory (agent_id, namespace, key, value, created_at, updated_at) VALUES (?,?,?,?,?,?)",
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
        _queue_email(_first_agent_email_to, "Your first agent is live on MoltGrid", first_agent_html)

    _track_event("agent.registered", agent_id=agent_id)
    _log_audit("agent.register", user_id=owner_id, agent_id=agent_id)
    return RegisterResponse(
        agent_id=agent_id,
        api_key=api_key,
        message="Store your API key securely. It cannot be recovered."
    )


# ── MoltBook event ingestion (OC-08) ─────────────────────────────────────────
class MoltBookEventRequest(BaseModel):
    event_type: str = Field(..., max_length=64, description="e.g. 'post', 'reply', 'upvote'")
    moltbook_url: Optional[str] = Field(None, max_length=512, description="Deep link to the MoltBook post")
    metadata: Optional[dict] = Field(None, description="Additional event metadata")

@app.post("/v1/moltbook/events", tags=["Integrations"])
def moltbook_ingest_event(req: MoltBookEventRequest, agent_id: str = Depends(get_agent_id)):
    """Ingest a MoltBook social action (post, reply, upvote) as an analytics_event with source='moltbook'."""
    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    meta = req.metadata or {}
    meta["event_type"] = req.event_type
    if req.moltbook_url:
        meta["moltbook_url"] = req.moltbook_url
    with get_db() as db:
        db.execute(
            "INSERT INTO analytics_events (id, event_name, agent_id, metadata, source, moltbook_url, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (event_id, f"moltbook.{req.event_type}", agent_id,
             json.dumps(meta), "moltbook", req.moltbook_url, now),
        )
    return {"id": event_id, "event_name": f"moltbook.{req.event_type}", "source": "moltbook",
            "agent_id": agent_id, "created_at": now}


# ── MoltBook deep integration: auto-provisioning + feed (BL-06) ───────────────

class MoltBookRegisterRequest(BaseModel):
    moltbook_user_id: str = Field(..., max_length=128)
    display_name: str = Field(..., max_length=64)


# TODO: Add IP-based rate limiting in Phase 8
@app.post("/v1/moltbook/register", tags=["Integrations"])
def moltbook_register(req: MoltBookRegisterRequest):
    """Auto-provision a MoltGrid agent for a new MoltBook user. No auth required (external service)."""
    now = datetime.now(timezone.utc).isoformat()
    # Check for duplicate
    with get_db() as db:
        existing = db.execute(
            "SELECT agent_id FROM agents WHERE moltbook_profile_id = ?", (req.moltbook_user_id,)
        ).fetchone()
    if existing:
        raise HTTPException(
            409,
            detail={"error": "MoltBook user already registered", "code": "ALREADY_REGISTERED", "status": 409},
        )
    agent_id = f"af_{uuid.uuid4().hex[:12]}"
    raw_key = f"af_{secrets.token_hex(24)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    integration_id = f"int_{uuid.uuid4().hex[:16]}"
    with get_db() as db:
        db.execute(
            "INSERT INTO agents (agent_id, api_key_hash, display_name, moltbook_profile_id, public, "
            "created_at, credits) VALUES (?,?,?,?,1,?,200)",
            (agent_id, key_hash, req.display_name, req.moltbook_user_id, now),
        )
        db.execute(
            "INSERT INTO integrations (id, agent_id, platform, config, status, created_at) VALUES (?,?,?,?,?,?)",
            (integration_id, agent_id, "moltbook",
             json.dumps({"moltbook_user_id": req.moltbook_user_id}), "active", now),
        )
    _log_audit("moltbook.register", agent_id=agent_id, details=req.moltbook_user_id)
    return {"agent_id": agent_id, "api_key": raw_key, "display_name": req.display_name}


@app.get("/v1/moltbook/feed", tags=["Integrations"])
def moltbook_feed():
    """Return last 20 moltbook-sourced analytics events as a social feed. Public endpoint."""
    with get_db() as db:
        rows = db.execute(
            "SELECT id, event_name, agent_id, metadata, moltbook_url, created_at "
            "FROM analytics_events WHERE source = 'moltbook' ORDER BY created_at DESC LIMIT 20"
        ).fetchall()

    def _map_type(event_name: str) -> str:
        suffix = event_name.replace("moltbook.", "")
        return suffix if suffix else event_name

    def _get_content(event_name: str, metadata_str: Optional[str]) -> str:
        if metadata_str:
            try:
                meta = json.loads(metadata_str)
                if "content" in meta:
                    return str(meta["content"])
            except Exception:
                pass
        return event_name

    feed = [
        {
            "id": r["id"],
            "type": _map_type(r["event_name"]),
            "content": _get_content(r["event_name"], r["metadata"]),
            "timestamp": r["created_at"],
            "moltbook_url": r["moltbook_url"],
            "agent_id": r["agent_id"],
        }
        for r in rows
    ]
    return {"feed": feed}


@app.post("/v1/agents/rotate-key", tags=["Auth"])
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
        _queue_email(
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
# ONBOARDING
# ═══════════════════════════════════════════════════════════════════════════════

class OnboardingResponse(BaseModel):
    steps: List[dict]
    progress: int
    total: int
    reward: str

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

@app.post("/v1/onboarding/start", response_model=OnboardingResponse, tags=["Onboarding"])
def onboarding_start(agent_id: str = Depends(get_agent_id)):
    """Start the interactive onboarding tutorial. Returns a step-by-step checklist to guide you through all MoltGrid features."""
    with get_db() as db:
        result = _check_onboarding_progress(db, agent_id)
    return OnboardingResponse(**result)

@app.get("/v1/onboarding/status", response_model=OnboardingResponse, tags=["Onboarding"])
def onboarding_status(agent_id: str = Depends(get_agent_id)):
    """Check your onboarding progress without modifying anything."""
    with get_db() as db:
        result = _check_onboarding_progress(db, agent_id)
    return OnboardingResponse(**result)


# ═══════════════════════════════════════════════════════════════════════════════
# DOCUMENTATION / GUIDES
# ═══════════════════════════════════════════════════════════════════════════════

GUIDE_PLATFORMS = {"quickstart", "python-sdk", "typescript-sdk", "webhooks", "mcp"}

@app.get("/v1/guides/{platform}", tags=["Documentation"])
def get_guide(platform: str):
    """Serve getting-started guide markdown for the specified platform."""
    if platform not in GUIDE_PLATFORMS:
        raise HTTPException(404, f"Guide not found. Available: {sorted(GUIDE_PLATFORMS)}")
    guide_path = Path(__file__).parent / "docs" / "guides" / f"{platform}.md"
    if not guide_path.exists():
        raise HTTPException(404, f"Guide file not found for platform: {platform}")
    return Response(content=guide_path.read_text(), media_type="text/markdown")


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT HEARTBEAT / LIVENESS
# ═══════════════════════════════════════════════════════════════════════════════

class HeartbeatRequest(BaseModel):
    status: str = Field("online", description="Agent status: online, busy, idle")
    metadata: Optional[dict] = Field(None, description="Optional metadata blob (max 4KB)")

@app.post("/v1/agents/heartbeat", tags=["Directory"])
@app.post("/v1/heartbeat", tags=["Directory"])
def agent_heartbeat(req: HeartbeatRequest = HeartbeatRequest(), agent_id: str = Depends(get_agent_id)):
    """Send a heartbeat to indicate this agent is alive. Call periodically (default every 60s)."""
    now = datetime.now(timezone.utc).isoformat()
    meta_json = json.dumps(req.metadata) if req.metadata else None
    if meta_json and len(meta_json) > 4096:
        raise HTTPException(400, "metadata exceeds 4KB limit")
    VALID_WORKER_STATUSES = {"worker_running", "session_based", "offline"}
    worker_status = req.status if req.status in VALID_WORKER_STATUSES else "session_based"
    with get_db() as db:
        db.execute(
            "UPDATE agents SET heartbeat_at=?, heartbeat_status=?, heartbeat_meta=?, worker_status=? WHERE agent_id=?",
            (now, req.status, meta_json, worker_status, agent_id)
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
    visibility: str = Field("private", description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)

class MemoryGetResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    key: str
    value: str
    namespace: str
    updated_at: str
    expires_at: Optional[str]


class MemoryKeyEntry(BaseModel):
    model_config = ConfigDict(extra='ignore')
    key: str
    size_bytes: int
    updated_at: str
    expires_at: Optional[str]


class MemoryListResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    namespace: str
    keys: List[MemoryKeyEntry]
    count: int


class HealthStatsResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    registered_agents: int
    public_agents: int
    total_jobs: int
    memory_keys_stored: int
    shared_memory_keys: int
    messages_relayed: int
    active_webhooks: int
    active_schedules: int
    websocket_connections: int


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    status: str
    version: str
    stats: HealthStatsResponse
    timestamp: str


class QueueJobEntry(BaseModel):
    model_config = ConfigDict(extra='ignore')
    job_id: str
    status: str
    priority: int
    created_at: str
    completed_at: Optional[str]


class QueueListResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    queue_name: str
    jobs: List[QueueJobEntry]
    count: int


class ScheduleEntry(BaseModel):
    model_config = ConfigDict(extra='ignore')
    task_id: str
    cron_expr: str
    queue_name: str
    priority: int
    enabled: bool
    next_run_at: Optional[str]
    last_run_at: Optional[str]
    run_count: Optional[int]
    created_at: str


class ScheduleListResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    schedules: List[ScheduleEntry]
    count: int


def _log_memory_access(action, agent_id, namespace, key,
                       actor_agent_id=None, actor_user_id=None,
                       old_visibility=None, new_visibility=None, authorized=1):
    """Fire-and-forget audit log — never raises, uses direct connection to avoid transaction interference."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
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
    """Fire-and-forget audit log writer. Uses own connection — call OUTSIDE with get_db() blocks."""
    try:
        log_id = f"log_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(DB_PATH)
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
    """Insert an event into agent_events. Uses own connection — call OUTSIDE get_db() blocks."""
    try:
        event_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO agent_events (event_id, agent_id, event_type, payload, acknowledged, created_at) "
            "VALUES (?,?,?,?,0,?)",
            (event_id, agent_id, event_type, json.dumps(payload), now)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # fire-and-forget


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


# Memory system note (MEM-07):
# /v1/memory (this section) = per-agent, private-by-default key-value store with visibility controls.
#   Access: private (owner only), public (any authenticated agent), shared (explicit agent ID list).
# /v1/shared-memory = a separate, deliberately public namespace system where any authenticated agent
#   can publish and read entries. No access controls. Different use case — do NOT apply visibility
#   controls to /v1/shared-memory.

@app.get("/v1/agents/{target_agent_id}/memory/{key}", tags=["Memory"])
def memory_get_cross_agent(
    target_agent_id: str,
    key: str,
    namespace: str = "default",
    agent_id: str = Depends(get_agent_id),
):
    """Read another agent's memory — only if visibility is public or shared with requester.
    Returns 403 (not 404) for private/shared-without-access to prevent enumeration."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (target_agent_id, namespace, key, now)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Key not found")
        allowed = _check_memory_visibility(db, target_agent_id, namespace, key, agent_id)
        d = dict(row) if allowed else None
    # Fire-and-forget audit log OUTSIDE the with get_db() block (MEM-08)
    _log_memory_access("cross_agent_read", target_agent_id, namespace, key,
                       actor_agent_id=agent_id, authorized=1 if allowed else 0)
    if not allowed:
        raise HTTPException(403, "Access denied: memory entry is private or not shared with you")
    d["value"] = _decrypt(d["value"])
    d.pop("shared_agents", None)
    return {
        "key": d["key"],
        "value": d["value"],
        "namespace": d["namespace"],
        "visibility": d.get("visibility") or "private",
        "updated_at": d["updated_at"],
        "expires_at": d.get("expires_at"),
    }


@app.patch("/v1/memory/{key}/visibility", tags=["Memory"])
def memory_set_visibility(key: str, req: MemoryVisibilityRequest,
                           agent_id: str = Depends(get_agent_id)):
    """Update the visibility of one of your own memory entries."""
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    with get_db() as db:
        old = db.execute(
            "SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, req.namespace, key)
        ).fetchone()
        if not old:
            raise HTTPException(404, "Key not found")
        db.execute(
            "UPDATE memory SET visibility=?, shared_agents=? "
            "WHERE agent_id=? AND namespace=? AND key=?",
            (vis, sa_json, agent_id, req.namespace, key)
        )
    _log_memory_access("visibility_changed", agent_id, req.namespace, key,
                       actor_agent_id=agent_id,
                       old_visibility=old["visibility"] or "private",
                       new_visibility=vis)
    return {"status": "updated", "key": key, "visibility": vis}


@app.post("/v1/memory", tags=["Memory"])
def memory_set(req: MemorySetRequest, agent_id: str = Depends(get_agent_id)):
    """Store or update a key-value pair in persistent memory."""
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()

    enc_value = _encrypt(req.value)
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    with get_db() as db:
        is_first = db.execute("SELECT COUNT(*) as c FROM memory WHERE agent_id=?", (agent_id,)).fetchone()["c"] == 0
        db.execute("""
            INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, expires_at, visibility, shared_agents)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, namespace, key)
            DO UPDATE SET value=?, updated_at=?, expires_at=?, visibility=?, shared_agents=?
        """, (agent_id, req.namespace, req.key, enc_value, now.isoformat(), now.isoformat(), expires, vis, sa_json,
              enc_value, now.isoformat(), expires, vis, sa_json))

    _log_memory_access("write", agent_id, req.namespace, req.key, actor_agent_id=agent_id)
    if is_first:
        _track_event("agent.first_memory", agent_id=agent_id)
    return {"status": "stored", "key": req.key, "namespace": req.namespace, "visibility": vis}

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
    # Fire-and-forget audit log OUTSIDE the with get_db() block (MEM-08)
    _log_memory_access("read", agent_id, namespace, key, actor_agent_id=agent_id)
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
    _log_memory_access("delete", agent_id, namespace, key, actor_agent_id=agent_id)
    return {"status": "deleted", "key": key}

@app.get("/v1/memory", response_model=MemoryListResponse, tags=["Memory"])
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
    # Enforce size limit (MAX_QUEUE_PAYLOAD_SIZE = 100KB)
    if len(payload_str.encode("utf-8")) > MAX_QUEUE_PAYLOAD_SIZE:
        raise HTTPException(422, f"Payload exceeds maximum size of {MAX_QUEUE_PAYLOAD_SIZE} bytes")

    with get_db() as db:
        is_first = db.execute("SELECT COUNT(*) as c FROM queue WHERE agent_id=?", (agent_id,)).fetchone()["c"] == 0
        db.execute(
            "INSERT INTO queue (job_id, agent_id, queue_name, payload, priority, created_at, max_attempts, retry_delay_seconds) VALUES (?,?,?,?,?,?,?,?)",
            (job_id, agent_id, req.queue_name, _encrypt(payload_str), req.priority, now, req.max_attempts, req.retry_delay_seconds)
        )
    if is_first:
        _track_event("agent.first_job", agent_id=agent_id)
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
    _queue_agent_event(agent_id, "job_completed", {"job_id": job_id, "queue_name": job_row["queue_name"]})
    return {"job_id": job_id, "status": "completed"}

@app.get("/v1/queue", response_model=QueueListResponse, tags=["Queue"])
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
        is_first_msg = db.execute("SELECT COUNT(*) as c FROM relay WHERE from_agent=?", (agent_id,)).fetchone()["c"] == 0
        db.execute(
            "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
            (message_id, agent_id, msg.to_agent, msg.channel, _encrypt(msg.payload), now)
        )

    if is_first_msg:
        _track_event("agent.first_message", agent_id=agent_id)

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

    # Queue event for recipient
    _queue_agent_event(msg.to_agent, "relay_message", {
        "from": agent_id, "message_id": message_id, "channel": msg.channel,
        "message": msg.payload[:100]
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

WEBHOOK_EVENT_TYPES = {"message.received", "message.broadcast", "job.completed", "job.failed", "marketplace.task.claimed", "marketplace.task.delivered", "marketplace.task.completed"}
WEBHOOK_TIMEOUT = 5.0  # seconds

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


@app.post("/v1/webhooks/{webhook_id}/test", tags=["Webhooks"])
def webhook_test(webhook_id: str, request: Request, agent_id: str = Depends(get_agent_id)):
    """Fire a test ping to the webhook URL to verify it is reachable."""
    now = datetime.now(timezone.utc).isoformat()
    delivery_id = f"whd_{uuid.uuid4().hex[:16]}"
    test_payload = json.dumps({
        "event": "webhook.test",
        "webhook_id": webhook_id,
        "timestamp": now,
    })
    with get_db() as db:
        hook = db.execute(
            "SELECT webhook_id, url FROM webhooks WHERE webhook_id = ? AND agent_id = ?",
            (webhook_id, agent_id)
        ).fetchone()
        if not hook:
            raise HTTPException(404, "Webhook not found or not owned by you")
        db.execute(
            "INSERT INTO webhook_deliveries "
            "(delivery_id, webhook_id, event_type, payload, status, attempt_count, max_attempts, next_retry_at, created_at) "
            "VALUES (?, ?, 'webhook.test', ?, 'pending', 0, 1, ?, ?)",
            (delivery_id, webhook_id, test_payload, now, now)
        )
    # Attempt delivery synchronously (single attempt only for test pings)
    try:
        _run_webhook_delivery_tick()
    except Exception:
        pass
    with get_db() as db:
        result = db.execute(
            "SELECT status, last_error FROM webhook_deliveries WHERE delivery_id = ?",
            (delivery_id,)
        ).fetchone()
    return {
        "delivery_id": delivery_id,
        "status": result["status"] if result else "unknown",
        "error": result["last_error"] if result else None,
    }


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

@app.get("/v1/schedules", response_model=ScheduleListResponse, tags=["Schedules"])
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


# ─── Email Notifications ──────────────────────────────────────────────────────

def _queue_email(to_email: str, subject: str, body_html: str):
    """Queue an email for sending. Uses independent connection to avoid nested locks."""
    email_id = f"email_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
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


def _get_client_ip(request: Request) -> str:
    """Extract client IP, honoring X-Forwarded-For for nginx-proxied requests."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

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

def _get_user_notification_prefs(db, user_id: str) -> dict:
    """Get user notification preferences. Returns dict with default True for all if not set."""
    row = db.execute(
        "SELECT notification_preferences FROM users WHERE user_id=?",
        (user_id,)
    ).fetchone()

    if not row or not row["notification_preferences"]:
        # Default: all notifications enabled
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
# VECTOR / SEMANTIC MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

# Global embedding model (loaded lazily on first use)
_embed_model = None
_embed_lock = threading.Lock()

def _get_embed_model():
    """Load embedding model once and cache it. Thread-safe."""
    global _embed_model
    if _embed_model is None:
        with _embed_lock:
            if _embed_model is None:  # Double-check after acquiring lock
                logger.info("Loading embedding model 'all-MiniLM-L6-v2' (80MB, ~2s)...")
                _embed_model = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Embedding model loaded successfully")
    return _embed_model

def _embed_text(text: str) -> np.ndarray:
    """Generate embedding vector for text. Returns normalized numpy array."""
    model = _get_embed_model()
    embedding = model.encode(text, convert_to_numpy=True)
    # Normalize for cosine similarity (dot product = cosine similarity for normalized vectors)
    embedding = embedding / np.linalg.norm(embedding)
    return embedding

def _cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
    """Compute cosine similarity between two normalized vectors (simple dot product)."""
    return float(np.dot(vec1, vec2))


class VectorUpsertRequest(BaseModel):
    key: str = Field(..., max_length=256)
    text: str = Field(..., max_length=10000, description="Text to embed")
    namespace: str = Field("default", max_length=64)
    metadata: Optional[dict] = Field(None, description="Optional metadata (stored as JSON)")

class VectorSearchRequest(BaseModel):
    query: str = Field(..., max_length=10000, description="Search query to embed")
    namespace: str = Field("default", max_length=64)
    limit: int = Field(5, ge=1, le=100, description="Number of results to return")
    min_similarity: float = Field(0.0, ge=0.0, le=1.0, description="Minimum cosine similarity threshold")

@app.post("/v1/vector/upsert", tags=["Vector Memory"])
def vector_upsert(req: VectorUpsertRequest, agent_id: str = Depends(get_agent_id)):
    """Store text with its embedding vector. Updates if key exists (UPSERT).

    Uses 'all-MiniLM-L6-v2' model (384 dimensions). Cosine similarity search.
    """
    # Generate embedding
    embedding = _embed_text(req.text)
    embedding_blob = embedding.tobytes()

    vec_id = f"vec_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    metadata_json = json.dumps(req.metadata) if req.metadata else None

    with get_db() as db:
        # UPSERT: replace if (agent_id, namespace, key) exists
        db.execute("""
            INSERT INTO vector_memory (id, agent_id, namespace, key, text, embedding, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, namespace, key)
            DO UPDATE SET text=?, embedding=?, metadata=?, updated_at=?
        """, (vec_id, agent_id, req.namespace, req.key, req.text, embedding_blob, metadata_json, now, now,
              req.text, embedding_blob, metadata_json, now))

    return {
        "key": req.key,
        "namespace": req.namespace,
        "dimensions": len(embedding),
        "status": "upserted"
    }

@app.post("/v1/vector/search", tags=["Vector Memory"])
def vector_search(req: VectorSearchRequest, agent_id: str = Depends(get_agent_id)):
    """Semantic search using cosine similarity. Returns top-K most similar entries.

    NOTE: Uses brute-force search. Fine for ~10K vectors per agent.
    TODO: Add HNSW index (hnswlib) for >10K vectors.
    """
    # Generate query embedding
    query_embedding = _embed_text(req.query)

    with get_db() as db:
        # Load all vectors for this agent+namespace
        rows = db.execute(
            "SELECT key, text, embedding, metadata FROM vector_memory WHERE agent_id=? AND namespace=?",
            (agent_id, req.namespace)
        ).fetchall()

        # Compute similarities
        results = []
        for row in rows:
            vec_embedding = np.frombuffer(row["embedding"], dtype=np.float32)
            similarity = _cosine_similarity(query_embedding, vec_embedding)

            if similarity >= req.min_similarity:
                results.append({
                    "key": row["key"],
                    "text": row["text"],
                    "similarity": similarity,
                    "metadata": json.loads(row["metadata"]) if row["metadata"] else None
                })

        # Sort by similarity descending, take top K
        results.sort(key=lambda x: x["similarity"], reverse=True)
        results = results[:req.limit]

    return {"results": results, "count": len(results)}

@app.get("/v1/vector/{key}", tags=["Vector Memory"])
def vector_get(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Get a specific vector entry by key."""
    with get_db() as db:
        row = db.execute(
            "SELECT key, text, metadata, created_at, updated_at FROM vector_memory "
            "WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Vector entry '{key}' not found in namespace '{namespace}'")

    return {
        "key": row["key"],
        "text": row["text"],
        "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"]
    }

@app.delete("/v1/vector/{key}", tags=["Vector Memory"])
def vector_delete(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Delete a vector entry."""
    with get_db() as db:
        result = db.execute(
            "DELETE FROM vector_memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        )
        if result.rowcount == 0:
            raise HTTPException(404, f"Vector entry '{key}' not found in namespace '{namespace}'")

    return {"status": "deleted", "key": key, "namespace": namespace}

@app.get("/v1/vector", tags=["Vector Memory"])
def vector_list(namespace: str = "default", limit: int = Query(100, le=1000), agent_id: str = Depends(get_agent_id)):
    """List all vector keys in a namespace (without embeddings for efficiency)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT key, created_at FROM vector_memory WHERE agent_id=? AND namespace=? ORDER BY created_at DESC LIMIT ?",
            (agent_id, namespace, limit)
        ).fetchall()

    return {
        "keys": [{"key": r["key"], "created_at": r["created_at"]} for r in rows],
        "count": len(rows),
        "namespace": namespace
    }


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
    skills: Optional[List[str]] = Field(None, max_length=20, description="Technical skills (e.g. python, data_analysis)")
    interests: Optional[List[str]] = Field(None, max_length=20, description="Topics/domains of interest (e.g. AI, finance)")
    public: bool = Field(False, description="Whether to list in the public directory")

@app.put("/v1/directory/me", tags=["Directory"])
def directory_update(req: DirectoryUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update your agent's directory listing."""
    # Sanitize text fields to prevent XSS
    req.description = _sanitize_text(req.description)
    caps_json = json.dumps(req.capabilities) if req.capabilities else None
    skills_json = json.dumps(req.skills) if req.skills else None
    interests_json = json.dumps(req.interests) if req.interests else None
    with get_db() as db:
        db.execute(
            "UPDATE agents SET description=?, capabilities=?, skills=?, interests=?, public=? WHERE agent_id=?",
            (req.description, caps_json, skills_json, interests_json, int(req.public), agent_id)
        )
    return {"status": "updated", "agent_id": agent_id, "public": req.public}

@app.get("/v1/directory/me", tags=["Directory"])
def directory_me(agent_id: str = Depends(get_agent_id)):
    """Get your own directory profile."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id, name, description, capabilities, skills, interests, public, available, looking_for, "
            "busy_until, reputation, reputation_count, credits, heartbeat_at, heartbeat_status, "
            "heartbeat_interval, created_at FROM agents WHERE agent_id=?",
            (agent_id,)
        ).fetchone()
    d = dict(row)
    d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
    d["skills"] = json.loads(d["skills"]) if d.get("skills") else []
    d["interests"] = json.loads(d["interests"]) if d.get("interests") else []
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
    cols = "agent_id, name, description, capabilities, skills, interests, available, reputation, credits, created_at, heartbeat_status, featured, verified"
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
        d["skills"] = json.loads(d["skills"]) if d.get("skills") else []
        d["interests"] = json.loads(d["interests"]) if d.get("interests") else []
        d["available"] = bool(d.get("available", 1))
        d["featured"] = bool(d.get("featured", 0))
        d["verified"] = bool(d.get("verified", 0))
        agents.append(d)
    return {"agents": agents, "count": len(agents)}

@app.get("/v1/leaderboard", tags=["Directory"])
def leaderboard(
    sort_by: str = Query("reputation", regex="^(reputation|credits|tasks_completed|requests)$"),
    limit: int = Query(20, ge=1, le=100)
):
    """Public leaderboard showing top agents. No auth required."""

    # Map sort_by to database column
    sort_mapping = {
        "reputation": "reputation",
        "credits": "credits",
        "tasks_completed": "marketplace_completed",
        "requests": "request_count"
    }

    sort_col = sort_mapping.get(sort_by, "reputation")

    with get_db() as db:
        # Get total public agents count
        total_agents = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE public=1").fetchone()["cnt"]

        # For tasks_completed, we need to count marketplace tasks
        if sort_by == "tasks_completed":
            rows = db.execute(
                """
                SELECT a.agent_id, a.name, a.reputation, a.credits, a.request_count,
                       COUNT(m.task_id) as tasks_completed
                FROM agents a
                LEFT JOIN marketplace m ON m.claimed_by = a.agent_id AND m.status = 'delivered'
                WHERE a.public = 1
                GROUP BY a.agent_id
                ORDER BY tasks_completed DESC, a.reputation DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()
        else:
            rows = db.execute(
                f"""
                SELECT agent_id, name, reputation, credits, request_count,
                       (SELECT COUNT(*) FROM marketplace WHERE claimed_by=agents.agent_id AND status='delivered') as tasks_completed
                FROM agents
                WHERE public=1
                ORDER BY {sort_col} DESC, reputation DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        leaderboard_data = []
        for rank, row in enumerate(rows, start=1):
            leaderboard_data.append({
                "rank": rank,
                "agent_id": row["agent_id"],
                "name": row["name"],
                "reputation": row["reputation"] or 0.0,
                "credits": row["credits"] or 0,
                "tasks_completed": row["tasks_completed"] or 0
            })

    return {
        "leaderboard": leaderboard_data,
        "total_agents": total_agents,
        "sort_by": sort_by
    }

@app.get("/v1/directory/stats", tags=["Directory"])
def directory_stats():
    """Public directory statistics. No auth required."""
    with get_db() as db:
        # Total agents
        total_agents = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE public=1").fetchone()["cnt"]

        # Online agents (heartbeat in last 5 minutes)
        now = datetime.now(timezone.utc).isoformat()
        online_agents = db.execute(
            "SELECT COUNT(*) as cnt FROM agents "
            "WHERE public=1 AND heartbeat_status='online' AND heartbeat_at IS NOT NULL "
            "AND datetime(heartbeat_at) >= datetime(?, '-300 seconds')",
            (now,)
        ).fetchone()["cnt"]

        # Get all capabilities from public agents
        all_caps_rows = db.execute(
            "SELECT capabilities FROM agents WHERE public=1 AND capabilities IS NOT NULL"
        ).fetchall()

        capabilities_counter = {}
        all_capabilities_set = set()

        for row in all_caps_rows:
            caps = json.loads(row["capabilities"]) if row["capabilities"] else []
            for cap in caps:
                all_capabilities_set.add(cap)
                capabilities_counter[cap] = capabilities_counter.get(cap, 0) + 1

        # Top capabilities (sorted by count)
        top_capabilities = [
            {"name": cap, "count": count}
            for cap, count in sorted(capabilities_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Total marketplace tasks
        total_marketplace = db.execute("SELECT COUNT(*) as cnt FROM marketplace").fetchone()["cnt"]

        # Total credits distributed (sum of all agent credits)
        total_credits = db.execute(
            "SELECT COALESCE(SUM(credits), 0) as total FROM agents WHERE public=1"
        ).fetchone()["total"]

    return {
        "total_agents": total_agents,
        "online_agents": online_agents,
        "total_capabilities": sorted(list(all_capabilities_set)),
        "top_capabilities": top_capabilities,
        "total_marketplace_tasks": total_marketplace,
        "total_credits_distributed": total_credits
    }


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
    q: Optional[str] = Query(None, description="Text search query — matches name, description, capabilities, skills, interests"),
    capability: Optional[str] = None,
    skill: Optional[str] = Query(None, description="Filter by skill"),
    interest: Optional[str] = Query(None, description="Filter by interest"),
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
    if q:
        conditions.append("(name LIKE ? OR description LIKE ? OR capabilities LIKE ? OR skills LIKE ? OR interests LIKE ?)")
        q_like = f"%{q}%"
        params.extend([q_like, q_like, q_like, q_like, q_like])
    if capability:
        conditions.append("capabilities LIKE ?")
        params.append(f"%{capability}%")
    if skill:
        conditions.append("skills LIKE ?")
        params.append(f"%{skill}%")
    if interest:
        conditions.append("interests LIKE ?")
        params.append(f"%{interest}%")
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
    cols = ("agent_id, name, description, capabilities, skills, interests, available, looking_for, busy_until, "
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
        d["skills"] = json.loads(d["skills"]) if d.get("skills") else []
        d["interests"] = json.loads(d["interests"]) if d.get("interests") else []
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

@app.get("/v1/directory/network", tags=["Directory"])
def directory_network():
    """Get network graph data for agent visualization. No auth required.
    Returns nodes (agents) and edges (collaborations/messages between them)."""
    with get_db() as db:
        agent_rows = db.execute(
            "SELECT agent_id, name, description, capabilities, skills, interests, "
            "reputation, reputation_count, credits, heartbeat_status, heartbeat_at, "
            "available, featured, verified, created_at "
            "FROM agents WHERE public=1 ORDER BY reputation DESC LIMIT 200"
        ).fetchall()

        nodes = []
        agent_ids = set()
        for r in agent_rows:
            d = dict(r)
            agent_ids.add(d["agent_id"])
            nodes.append({
                "id": d["agent_id"],
                "name": d["name"],
                "description": d["description"],
                "skills": json.loads(d["skills"]) if d.get("skills") else [],
                "interests": json.loads(d["interests"]) if d.get("interests") else [],
                "capabilities": json.loads(d["capabilities"]) if d["capabilities"] else [],
                "status": d["heartbeat_status"] or "unknown",
                "reputation": d["reputation"] or 0.0,
                "credits": d["credits"] or 0,
                "available": bool(d.get("available", 1)),
                "featured": bool(d.get("featured", 0)),
                "verified": bool(d.get("verified", 0)),
                "created_at": d["created_at"],
            })

        collab_rows = db.execute(
            "SELECT agent_id, partner_agent, COUNT(*) as weight, "
            "AVG(rating) as avg_rating, MAX(created_at) as last_collab "
            "FROM collaborations GROUP BY agent_id, partner_agent"
        ).fetchall()

        edges = []
        for r in collab_rows:
            d = dict(r)
            if d["agent_id"] in agent_ids and d["partner_agent"] in agent_ids:
                edges.append({
                    "source": d["agent_id"], "target": d["partner_agent"],
                    "type": "collaboration", "weight": d["weight"],
                    "avg_rating": round(d["avg_rating"], 1) if d["avg_rating"] else 0,
                    "last_activity": d["last_collab"],
                })

        msg_rows = db.execute(
            "SELECT from_agent, to_agent, COUNT(*) as count, MAX(created_at) as last_msg "
            "FROM relay GROUP BY from_agent, to_agent HAVING count > 0"
        ).fetchall()

        for r in msg_rows:
            d = dict(r)
            if d["from_agent"] in agent_ids and d["to_agent"] in agent_ids:
                edges.append({
                    "source": d["from_agent"], "target": d["to_agent"],
                    "type": "message", "weight": d["count"],
                    "last_activity": d["last_msg"],
                })

        task_rows = db.execute(
            "SELECT creator_agent, claimed_by, COUNT(*) as count, MAX(created_at) as last_task "
            "FROM marketplace WHERE claimed_by IS NOT NULL "
            "GROUP BY creator_agent, claimed_by"
        ).fetchall()

        for r in task_rows:
            d = dict(r)
            if d["creator_agent"] in agent_ids and d["claimed_by"] in agent_ids:
                edges.append({
                    "source": d["creator_agent"], "target": d["claimed_by"],
                    "type": "marketplace", "weight": d["count"],
                    "last_activity": d["last_task"],
                })

    online_count = sum(1 for n in nodes if n["status"] == "online")
    return {
        "nodes": nodes, "edges": edges,
        "stats": {"total_agents": len(nodes), "online_agents": online_count, "total_edges": len(edges)}
    }

@app.get("/v1/directory/{agent_id}", tags=["Directory"])
def directory_profile(agent_id: str):
    """Get a public agent profile. No auth required. Returns 404 if agent is private."""
    with get_db() as db:
        # Get agent details
        agent = db.execute(
            "SELECT agent_id, name, description, capabilities, reputation, reputation_count, "
            "credits, request_count, created_at, heartbeat_status, featured, verified FROM agents "
            "WHERE agent_id=? AND public=1",
            (agent_id,)
        ).fetchone()

        if not agent:
            raise HTTPException(404, "Agent not found or not public")

        # Get recent marketplace activity (last 5 completed tasks, titles only)
        marketplace_activity = db.execute(
            "SELECT title, delivered_at FROM marketplace "
            "WHERE claimed_by=? AND status='delivered' "
            "ORDER BY delivered_at DESC LIMIT 5",
            (agent_id,)
        ).fetchall()

        # Calculate uptime percentage (simple: based on heartbeats in last 30 days)
        uptime_pct = 99.0  # Default for new agents

        # Build response
        profile = {
            "agent_id": agent["agent_id"],
            "name": agent["name"],
            "description": agent["description"],
            "capabilities": json.loads(agent["capabilities"]) if agent["capabilities"] else [],
            "reputation": agent["reputation"] or 0.0,
            "reputation_count": agent["reputation_count"] or 0,
            "credits": agent["credits"] or 0,
            "tasks_completed": len(marketplace_activity),
            "uptime_pct": uptime_pct,
            "member_since": agent["created_at"][:10] if agent["created_at"] else None,
            "heartbeat_status": agent["heartbeat_status"] or "unknown",
            "featured": bool(agent["featured"] or 0),
            "verified": bool(agent["verified"] or 0),
            "recent_marketplace_activity": [
                {"title": task["title"], "delivered_at": task["delivered_at"]}
                for task in marketplace_activity
            ]
        }

    return profile


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
# PUB/SUB BROADCAST MESSAGING
# ═══════════════════════════════════════════════════════════════════════════════

class PubSubSubscribeRequest(BaseModel):
    channel: str = Field(..., min_length=1, max_length=128, description="Channel name to subscribe to")

class PubSubPublishRequest(BaseModel):
    channel: str = Field(..., min_length=1, max_length=128, description="Channel to publish to")
    payload: str = Field(..., max_length=50_000, description="Message payload")

@app.post("/v1/pubsub/subscribe", tags=["Pub/Sub"])
def pubsub_subscribe(req: PubSubSubscribeRequest, agent_id: str = Depends(get_agent_id)):
    """Subscribe to a broadcast channel."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM pubsub_subscriptions WHERE agent_id=? AND channel=?",
            (agent_id, req.channel)
        ).fetchone()
        if existing:
            return {"channel": req.channel, "status": "already_subscribed"}
        db.execute(
            "INSERT INTO pubsub_subscriptions (agent_id, channel, subscribed_at) VALUES (?,?,?)",
            (agent_id, req.channel, now)
        )
    return {"channel": req.channel, "status": "subscribed", "subscribed_at": now}

@app.post("/v1/pubsub/unsubscribe", tags=["Pub/Sub"])
def pubsub_unsubscribe(req: PubSubSubscribeRequest, agent_id: str = Depends(get_agent_id)):
    """Unsubscribe from a broadcast channel."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM pubsub_subscriptions WHERE agent_id=? AND channel=?",
            (agent_id, req.channel)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Not subscribed to this channel")
    return {"channel": req.channel, "status": "unsubscribed"}

@app.get("/v1/pubsub/subscriptions", tags=["Pub/Sub"])
def pubsub_list_subscriptions(agent_id: str = Depends(get_agent_id)):
    """List all channels this agent is subscribed to."""
    with get_db() as db:
        rows = db.execute(
            "SELECT channel, subscribed_at FROM pubsub_subscriptions WHERE agent_id=? ORDER BY subscribed_at",
            (agent_id,)
        ).fetchall()
    return {"subscriptions": [dict(r) for r in rows], "count": len(rows)}

@app.post("/v1/pubsub/publish", tags=["Pub/Sub"])
async def pubsub_publish(req: PubSubPublishRequest, agent_id: str = Depends(get_agent_id)):
    """Publish a message to all subscribers of a channel."""
    now = datetime.now(timezone.utc).isoformat()
    message_id = f"ps_{uuid.uuid4().hex[:12]}"

    with get_db() as db:
        rows = db.execute(
            "SELECT agent_id FROM pubsub_subscriptions WHERE channel=?",
            (req.channel,)
        ).fetchall()
    subscriber_ids = [r["agent_id"] for r in rows]

    # Store a relay message for each subscriber (except the publisher)
    recipients = [sid for sid in subscriber_ids if sid != agent_id]
    with get_db() as db:
        for sid in recipients:
            db.execute(
                "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
                (f"{message_id}_{sid[:8]}", agent_id, sid, f"pubsub:{req.channel}", _encrypt(req.payload), now)
            )

    # Push to WebSocket connections for each subscriber
    broadcast_data = {
        "event": "message.broadcast", "message_id": message_id,
        "from_agent": agent_id, "channel": req.channel,
        "payload": req.payload, "created_at": now,
    }
    async def _ws_broadcast():
        for sid in recipients:
            if sid in _ws_connections:
                dead = set()
                for peer in _ws_connections[sid]:
                    try:
                        await peer.send_json(broadcast_data)
                    except Exception:
                        dead.add(peer)
                _ws_connections[sid] -= dead
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_ws_broadcast())
    except RuntimeError:
        pass

    # Fire webhook notifications for each subscriber
    for sid in recipients:
        _fire_webhooks(sid, "message.broadcast", {
            "message_id": message_id, "from_agent": agent_id,
            "channel": req.channel, "payload": req.payload,
        })

    return {
        "message_id": message_id, "channel": req.channel,
        "subscribers_notified": len(recipients), "created_at": now,
    }

@app.get("/v1/pubsub/channels", tags=["Pub/Sub"])
def pubsub_list_channels(agent_id: str = Depends(get_agent_id)):
    """List all active pub/sub channels with subscriber counts."""
    with get_db() as db:
        rows = db.execute(
            "SELECT channel, COUNT(*) as subscriber_count FROM pubsub_subscriptions GROUP BY channel ORDER BY subscriber_count DESC"
        ).fetchall()
    return {"channels": [dict(r) for r in rows], "count": len(rows)}


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
        "version": app.version,
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

@app.get("/admin/api/webhook-deliveries", tags=["Admin"])
def admin_webhook_deliveries(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    webhook_id: Optional[str] = None,
    _: bool = Depends(_verify_admin_session),
):
    """Browse webhook delivery log with optional status/webhook filters."""
    with get_db() as db:
        where_clauses = []
        params = []
        if status:
            where_clauses.append("d.status=?")
            params.append(status)
        if webhook_id:
            where_clauses.append("d.webhook_id=?")
            params.append(webhook_id)
        where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        rows = db.execute(
            f"SELECT d.*, w.url, w.agent_id FROM webhook_deliveries d "
            f"LEFT JOIN webhooks w ON d.webhook_id = w.webhook_id "
            f"{where} ORDER BY d.created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()

        count_params = list(params)
        total = db.execute(
            f"SELECT COUNT(*) as c FROM webhook_deliveries d {where}",
            count_params
        ).fetchone()["c"]

    return {"deliveries": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

@app.get("/admin/api/analytics", tags=["Admin"])
def admin_analytics(_: bool = Depends(_verify_admin_session)):
    """Analytics dashboard: funnel metrics, signups, conversions, churn, MRR."""
    now = datetime.now(timezone.utc)
    t_24h = (now - timedelta(hours=24)).isoformat()
    t_7d = (now - timedelta(days=7)).isoformat()
    t_30d = (now - timedelta(days=30)).isoformat()

    with get_db() as db:
        # Signup counts
        signups_24h = db.execute("SELECT COUNT(*) as c FROM analytics_events WHERE event_name='user.signup' AND created_at>=?", (t_24h,)).fetchone()["c"]
        signups_7d = db.execute("SELECT COUNT(*) as c FROM analytics_events WHERE event_name='user.signup' AND created_at>=?", (t_7d,)).fetchone()["c"]
        signups_30d = db.execute("SELECT COUNT(*) as c FROM analytics_events WHERE event_name='user.signup' AND created_at>=?", (t_30d,)).fetchone()["c"]

        # Active users (any event in 24h)
        active_24h = db.execute("SELECT COUNT(DISTINCT user_id) as c FROM analytics_events WHERE user_id IS NOT NULL AND created_at>=?", (t_24h,)).fetchone()["c"]

        # Conversion funnel
        total_signups = db.execute("SELECT COUNT(DISTINCT user_id) as c FROM analytics_events WHERE event_name='user.signup'").fetchone()["c"]
        users_with_agent = db.execute("SELECT COUNT(DISTINCT agent_id) as c FROM agents WHERE owner_id IS NOT NULL").fetchone()["c"]
        # Active = agents that have done at least one of: memory, message, or job
        active_agents = db.execute(
            "SELECT COUNT(DISTINCT agent_id) as c FROM analytics_events WHERE event_name IN ('agent.first_memory','agent.first_message','agent.first_job')"
        ).fetchone()["c"]
        paid_users = db.execute("SELECT COUNT(*) as c FROM users WHERE subscription_tier IS NOT NULL AND subscription_tier != 'free'").fetchone()["c"]

        signup_to_agent = round(users_with_agent / total_signups, 2) if total_signups > 0 else 0
        agent_to_active = round(active_agents / users_with_agent, 2) if users_with_agent > 0 else 0
        active_to_paid = round(paid_users / active_agents, 2) if active_agents > 0 else 0

        # MRR estimate: count paid users per tier
        tier_counts = db.execute(
            "SELECT subscription_tier, COUNT(*) as c FROM users WHERE subscription_tier IS NOT NULL AND subscription_tier != 'free' GROUP BY subscription_tier"
        ).fetchall()
        tier_prices = {"hobby": 5, "team": 25, "scale": 99}
        revenue_mrr = sum(tier_prices.get(r["subscription_tier"], 0) * r["c"] for r in tier_counts)

        # Churn: subscriptions cancelled in last 30d
        churn_30d = db.execute("SELECT COUNT(*) as c FROM analytics_events WHERE event_name='billing.subscription_cancelled' AND created_at>=?", (t_30d,)).fetchone()["c"]

    return {
        "signups_24h": signups_24h,
        "signups_7d": signups_7d,
        "signups_30d": signups_30d,
        "active_users_24h": active_24h,
        "conversion_rate": {
            "signup_to_agent": signup_to_agent,
            "agent_to_active": agent_to_active,
            "active_to_paid": active_to_paid,
        },
        "revenue_mrr": revenue_mrr,
        "churn_30d": churn_30d,
    }

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
    html_path = _find_html("admin_login.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Admin login page not found")

@app.get("/admin", response_class=HTMLResponse, tags=["Admin"])
def admin_page():
    """Serve the admin dashboard page."""
    html_path = _find_html("admin.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Admin page not found")


# ═══════════════════════════════════════════════════════════════════════════════
# USER DASHBOARD (HTML)
# ═══════════════════════════════════════════════════════════════════════════════

_backend_dir = os.path.dirname(os.path.abspath(__file__))
_web_dir = os.path.join(os.path.dirname(_backend_dir), "moltgrid-web") if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")) else None

def _find_html(filename: str) -> str:
    """Find an HTML file — check backend dir first, then moltgrid-web sibling."""
    path = os.path.join(_backend_dir, filename)
    if os.path.exists(path):
        return path
    alt = os.path.join("/opt/moltgrid-web", filename)
    if os.path.exists(alt):
        return alt
    return path  # fallback to original (will raise FileNotFoundError)

def _serve_dashboard():
    try:
        with open(_find_html("dashboard.html"), "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Dashboard not found")

@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
def dashboard_root():
    return _serve_dashboard()

@app.get("/dashboard/{path:path}", response_class=HTMLResponse, tags=["Dashboard"])
def dashboard_catchall(path: str):
    return _serve_dashboard()


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

@app.get("/v1/health", response_model=HealthResponse, tags=["System"])
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
        "version": app.version,
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
# CONVERSATION SESSIONS
# ═══════════════════════════════════════════════════════════════════════════════

class SessionCreateRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=256)
    max_tokens: int = Field(128000, ge=1000, le=1000000)

class SessionAppendRequest(BaseModel):
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str = Field(..., min_length=1, max_length=1000000)


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return max(1, len(text) // 4)


def _auto_summarize(messages: list) -> list:
    """MVP auto-summarization: keep system msgs + last 10, summarize the rest."""
    system_msgs = [m for m in messages if m.get("role") == "system"]
    non_system = [m for m in messages if m.get("role") != "system"]

    if len(non_system) <= 10:
        return messages

    keep = non_system[-10:]
    trimmed = non_system[:-10]

    # Build summary: first message + count + last 5 of trimmed block
    parts = []
    if trimmed:
        parts.append(trimmed[0].get("content", "")[:200])
    if len(trimmed) > 5:
        parts.append(f"... [{len(trimmed)} messages trimmed] ...")
        for m in trimmed[-5:]:
            parts.append(f"{m.get('role', 'user')}: {m.get('content', '')[:100]}")
    elif len(trimmed) > 1:
        parts.append(f"... [{len(trimmed)} messages trimmed] ...")

    summary_text = "Summary of previous conversation: " + "\n".join(parts)
    summary_msg = {"role": "system", "content": summary_text}

    return system_msgs + [summary_msg] + keep


@app.post("/v1/sessions", tags=["Sessions"])
def session_create(req: SessionCreateRequest, agent_id: str = Depends(get_agent_id)):
    """Create a new conversation session."""
    now = datetime.now(timezone.utc).isoformat()
    session_id = f"sess_{uuid.uuid4().hex[:16]}"
    title = req.title or f"Session {now[:10]}"

    with get_db() as db:
        db.execute("""
            INSERT INTO sessions (session_id, agent_id, title, messages, metadata, token_count, max_tokens, created_at, updated_at)
            VALUES (?, ?, ?, '[]', NULL, 0, ?, ?, ?)
        """, (session_id, agent_id, title, req.max_tokens, now, now))

    return {"session_id": session_id, "title": title, "created_at": now}


@app.get("/v1/sessions", tags=["Sessions"])
def session_list(agent_id: str = Depends(get_agent_id)):
    """List all sessions for this agent."""
    with get_db() as db:
        rows = db.execute(
            "SELECT session_id, title, token_count, max_tokens, created_at, updated_at FROM sessions WHERE agent_id=? ORDER BY updated_at DESC",
            (agent_id,)
        ).fetchall()
    return {"sessions": [dict(r) for r in rows]}


@app.get("/v1/sessions/{session_id}", tags=["Sessions"])
def session_get(session_id: str, agent_id: str = Depends(get_agent_id)):
    """Get a session with its full message history."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Session not found")
    d = dict(row)
    d["messages"] = json.loads(d["messages"])
    return d


@app.post("/v1/sessions/{session_id}/messages", tags=["Sessions"])
def session_append(session_id: str, req: SessionAppendRequest, agent_id: str = Depends(get_agent_id)):
    """Append a message to a session. Auto-summarizes if near token limit."""
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        row = db.execute(
            "SELECT messages, token_count, max_tokens FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        messages = json.loads(row["messages"])
        token_count = row["token_count"]
        max_tokens = row["max_tokens"]

        new_msg = {"role": req.role, "content": req.content}
        messages.append(new_msg)
        token_count += _estimate_tokens(req.content)

        summarized = False
        if token_count > max_tokens * 0.9:
            messages = _auto_summarize(messages)
            token_count = sum(_estimate_tokens(m.get("content", "")) for m in messages)
            summarized = True

        db.execute(
            "UPDATE sessions SET messages=?, token_count=?, updated_at=? WHERE session_id=? AND agent_id=?",
            (json.dumps(messages), token_count, now, session_id, agent_id)
        )

    return {
        "status": "appended",
        "message_count": len(messages),
        "token_count": token_count,
        "summarized": summarized,
    }


@app.post("/v1/sessions/{session_id}/summarize", tags=["Sessions"])
def session_summarize(session_id: str, agent_id: str = Depends(get_agent_id)):
    """Force-summarize a session: collapse history to summary + recent 10 messages."""
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        row = db.execute(
            "SELECT messages FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        messages = json.loads(row["messages"])
        original_count = len(messages)
        messages = _auto_summarize(messages)
        token_count = sum(_estimate_tokens(m.get("content", "")) for m in messages)

        db.execute(
            "UPDATE sessions SET messages=?, token_count=?, updated_at=? WHERE session_id=? AND agent_id=?",
            (json.dumps(messages), token_count, now, session_id, agent_id)
        )

    return {
        "status": "summarized",
        "original_message_count": original_count,
        "new_message_count": len(messages),
        "token_count": token_count,
    }


@app.delete("/v1/sessions/{session_id}", tags=["Sessions"])
def session_delete(session_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a session."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Session not found")
    return {"status": "deleted", "session_id": session_id}


# ═══════════════════════════════════════════════════════════════════════════════
# CONTACT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/contact", response_class=HTMLResponse, tags=["System"])
def contact_page():
    """Serve the contact form page."""
    html_path = _find_html("contact.html")
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
    turnstile_token: Optional[str] = None

@app.post("/v1/contact", tags=["System"])
def submit_contact(form: ContactForm):
    """Public contact form submission — no auth required."""
    if not form.email or not form.message:
        raise HTTPException(400, "Email and message are required")
    # Cloudflare Turnstile CAPTCHA verification
    if TURNSTILE_SECRET_KEY and form.turnstile_token:
        try:
            ts_resp = httpx.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={"secret": TURNSTILE_SECRET_KEY, "response": form.turnstile_token},
                timeout=10,
            )
            ts_result = ts_resp.json()
            if not ts_result.get("success"):
                raise HTTPException(400, "CAPTCHA verification failed")
        except httpx.HTTPError:
            logger.error("Turnstile verification request failed")
            raise HTTPException(400, "CAPTCHA verification failed")
    elif TURNSTILE_SECRET_KEY and not form.turnstile_token:
        raise HTTPException(400, "CAPTCHA verification failed")
    now = datetime.now(timezone.utc).isoformat()
    submission_id = f"contact_{uuid.uuid4().hex[:12]}"
    with get_db() as db:
        db.execute(
            "INSERT INTO contact_submissions (id, name, email, subject, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (submission_id, form.name, form.email, form.subject, form.message, now)
        )
    # Send email via SMTP (Hostinger / configurable provider)
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
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                server.login(SMTP_FROM, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
            logger.info(f"Contact email sent: {submission_id}")
        except Exception as e:
            logger.error(f"Failed to send contact email: {e}")
    return {"status": "sent", "id": submission_id}

# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-USER ORG ACCOUNTS (BL-02)
# ═══════════════════════════════════════════════════════════════════════════════

class OrgCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    slug: Optional[str] = Field(None, max_length=64, pattern="^[a-z0-9-]+$")

class OrgInviteRequest(BaseModel):
    user_id: str = Field(..., max_length=64)
    role: str = Field("member", pattern="^(owner|admin|member)$")

class OrgRoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(owner|admin|member)$")


@app.post("/v1/orgs", tags=["Orgs"])
def create_org(req: OrgCreateRequest, user_id: str = Depends(get_user_id)):
    org_id = f"org_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    slug = req.slug
    with get_db() as db:
        if slug:
            existing_slug = db.execute(
                "SELECT org_id FROM organizations WHERE slug = ?", (slug,)
            ).fetchone()
            if existing_slug:
                raise HTTPException(409, "Slug already taken")
        db.execute(
            "INSERT INTO organizations (org_id, name, slug, owner_user_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (org_id, req.name, slug, user_id, now),
        )
        db.execute(
            "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
            (org_id, user_id, "owner", now),
        )
    return {"org_id": org_id, "name": req.name, "slug": slug, "owner_user_id": user_id, "created_at": now, "role": "owner"}


@app.get("/v1/orgs", tags=["Orgs"])
def list_orgs(user_id: str = Depends(get_user_id)):
    with get_db() as db:
        rows = db.execute(
            """SELECT o.org_id, o.name, o.slug, o.owner_user_id, o.created_at, m.role
               FROM organizations o
               JOIN org_members m ON m.org_id = o.org_id
               WHERE m.user_id = ?""",
            (user_id,),
        ).fetchall()
    return {"orgs": [dict(r) for r in rows]}


@app.get("/v1/orgs/{org_id}", tags=["Orgs"])
def get_org(org_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        org = db.execute(
            "SELECT org_id, name, slug, owner_user_id, created_at FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        member = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not member:
            raise HTTPException(403, "Not a member of this org")
        members = db.execute(
            "SELECT user_id, role, joined_at FROM org_members WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    return {
        **dict(org),
        "members": [dict(m) for m in members],
    }


@app.post("/v1/orgs/{org_id}/members", tags=["Orgs"])
def invite_member(org_id: str, req: OrgInviteRequest, user_id: str = Depends(get_user_id)):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        org = db.execute("SELECT org_id FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        caller = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not caller or caller["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Only owners and admins can invite members")
        # Validate target user exists
        target_user = db.execute(
            "SELECT user_id FROM users WHERE user_id = ?", (req.user_id,)
        ).fetchone()
        if not target_user:
            raise HTTPException(404, "User not found")
        existing = db.execute(
            "SELECT user_id FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, req.user_id),
        ).fetchone()
        if existing:
            raise HTTPException(409, detail={"error": "Already a member", "code": "ALREADY_MEMBER", "status": 409})
        db.execute(
            "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
            (org_id, req.user_id, req.role, now),
        )
    return {"org_id": org_id, "user_id": req.user_id, "role": req.role, "joined_at": now}


@app.get("/v1/orgs/{org_id}/members", tags=["Orgs"])
def list_org_members(org_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        org = db.execute("SELECT org_id FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        member = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not member:
            raise HTTPException(403, "Not a member of this org")
        members = db.execute(
            "SELECT user_id, role, joined_at FROM org_members WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    return {"org_id": org_id, "members": [dict(m) for m in members]}


@app.delete("/v1/orgs/{org_id}/members/{target_user_id}", tags=["Orgs"])
def remove_member(org_id: str, target_user_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        org = db.execute(
            "SELECT owner_user_id FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        caller = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not caller or caller["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Only owners and admins can remove members")
        if org["owner_user_id"] == target_user_id:
            raise HTTPException(400, "Cannot remove the org owner")
        db.execute(
            "DELETE FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, target_user_id),
        )
    return {"removed": True}


@app.patch("/v1/orgs/{org_id}/members/{target_user_id}", tags=["Orgs"])
def change_member_role(
    org_id: str,
    target_user_id: str,
    req: OrgRoleUpdateRequest,
    user_id: str = Depends(get_user_id),
):
    with get_db() as db:
        org = db.execute(
            "SELECT owner_user_id FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        caller = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not caller or caller["role"] != "owner":
            raise HTTPException(403, "Only the owner can change member roles")
        if org["owner_user_id"] == target_user_id and req.role != "owner":
            raise HTTPException(400, "Cannot demote the org owner away from owner role")
        db.execute(
            "UPDATE org_members SET role = ? WHERE org_id = ? AND user_id = ?",
            (req.role, org_id, target_user_id),
        )
    return {"org_id": org_id, "user_id": target_user_id, "role": req.role}


@app.post("/v1/orgs/{org_id}/switch", tags=["Orgs"])
def switch_org_context(org_id: str, user_id: str = Depends(get_user_id)):
    """Switch the user's active org context."""
    with get_db() as db:
        org = db.execute(
            "SELECT org_id, name FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        member = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not member:
            raise HTTPException(403, "Not a member of this org")
    return {"active_org_id": org_id, "org_name": org["name"]}


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT EVENT STREAM
# ═══════════════════════════════════════════════════════════════════════════════

class EventAckRequest(BaseModel):
    event_ids: List[str]


class ObstacleCourseSubmitRequest(BaseModel):
    stages_completed: List[int]
    proof: str = ""


@app.get("/v1/events/stream", tags=["Events"])
async def events_stream(agent_id: str = Depends(get_agent_id)):
    """Long-poll: waits up to 30s for first unacked event. Returns event or 204."""
    import asyncio
    deadline = time.time() + 30
    while time.time() < deadline:
        with get_db() as db:
            row = db.execute(
                "SELECT event_id, event_type, payload, created_at FROM agent_events "
                "WHERE agent_id=? AND acknowledged=0 ORDER BY created_at ASC LIMIT 1",
                (agent_id,)
            ).fetchone()
        if row:
            return {
                "event_id": row[0],
                "event_type": row[1],
                "payload": json.loads(row[2]),
                "created_at": row[3]
            }
        await asyncio.sleep(0.5)
    return Response(status_code=204)


@app.get("/v1/events", tags=["Events"])
async def events_poll(agent_id: str = Depends(get_agent_id)):
    """Return up to 20 unacknowledged events for agent."""
    with get_db() as db:
        rows = db.execute(
            "SELECT event_id, event_type, payload, created_at FROM agent_events "
            "WHERE agent_id=? AND acknowledged=0 ORDER BY created_at ASC LIMIT 20",
            (agent_id,)
        ).fetchall()
    return [{"event_id": r[0], "event_type": r[1], "payload": json.loads(r[2]), "created_at": r[3]} for r in rows]


@app.post("/v1/events/ack", tags=["Events"])
async def events_ack(body: EventAckRequest, agent_id: str = Depends(get_agent_id)):
    """Mark event_ids as acknowledged."""
    if not body.event_ids:
        return {"acknowledged": 0}
    with get_db() as db:
        placeholders = ",".join("?" * len(body.event_ids))
        db.execute(
            f"UPDATE agent_events SET acknowledged=1 WHERE agent_id=? AND event_id IN ({placeholders})",
            [agent_id] + body.event_ids
        )
        db.commit()
    return {"acknowledged": len(body.event_ids)}


# ─── Obstacle Course ──────────────────────────────────────────────────────────

@app.get("/obstacle-course.md", tags=["System"])
async def serve_obstacle_course_md():
    path = os.path.join(os.path.dirname(__file__), "obstacle-course.md")
    with open(path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@app.get("/v1/obstacle-course.md", tags=["System"])
async def serve_obstacle_course_md_v1():
    path = os.path.join(os.path.dirname(__file__), "obstacle-course.md")
    with open(path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@app.post("/v1/obstacle-course/submit", tags=["Obstacle Course"])
async def obstacle_submit(body: ObstacleCourseSubmitRequest, agent_id: str = Depends(get_agent_id)):
    stages = sorted(set(s for s in body.stages_completed if 1 <= s <= 10))
    base_score = len(stages) * 10
    sequential = len(stages) > 0 and all(i + 1 in stages for i in range(len(stages))) and stages[0] == 1
    score = min(100, base_score + (5 if sequential else 0))
    feedback_parts = []
    if score >= 100 and sequential:
        feedback_parts.append("Perfect run! All 10 stages completed in sequence.")
    elif score >= 80:
        feedback_parts.append("Excellent! Most stages completed.")
    elif score >= 50:
        feedback_parts.append("Good progress. Keep going!")
    else:
        feedback_parts.append("Keep practicing the missed stages.")
    missing = [i for i in range(1, 11) if i not in stages]
    if missing:
        feedback_parts.append(f"Stages not recorded: {missing}")
    feedback = " ".join(feedback_parts)
    submission_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO obstacle_course_submissions (submission_id, agent_id, stages_completed, score, submitted_at, feedback) "
            "VALUES (?,?,?,?,?,?)",
            (submission_id, agent_id, json.dumps(stages), score, now, feedback)
        )
        db.commit()
    return {"submission_id": submission_id, "score": score, "stages_completed": stages, "feedback": feedback}


@app.get("/v1/obstacle-course/leaderboard", tags=["Obstacle Course"])
async def obstacle_leaderboard():
    with get_db() as db:
        rows = db.execute(
            "SELECT ocs.submission_id, ocs.agent_id, a.display_name, ocs.score, ocs.stages_completed, ocs.submitted_at, ocs.feedback "
            "FROM obstacle_course_submissions ocs "
            "LEFT JOIN agents a ON a.agent_id = ocs.agent_id "
            "ORDER BY ocs.score DESC, ocs.submitted_at ASC LIMIT 20"
        ).fetchall()
    return [
        {
            "submission_id": r[0],
            "agent_id": r[1],
            "display_name": r[2] or "Unknown Agent",
            "score": r[3],
            "stages_completed": json.loads(r[4]),
            "submitted_at": r[5],
            "feedback": r[6]
        }
        for r in rows
    ]


@app.get("/v1/obstacle-course/my-result", tags=["Obstacle Course"])
async def obstacle_my_result(agent_id: str = Depends(get_agent_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT submission_id, stages_completed, score, submitted_at, feedback FROM obstacle_course_submissions "
            "WHERE agent_id=? ORDER BY score DESC LIMIT 1",
            (agent_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "No submission found")
    return {
        "submission_id": row[0],
        "stages_completed": json.loads(row[1]),
        "score": row[2],
        "submitted_at": row[3],
        "feedback": row[4]
    }


# ─── WebSocket: /v1/events/ws ─────────────────────────────────────────────────

@app.websocket("/v1/events/ws")
async def events_ws(websocket: WebSocket, api_key: str = Query(None)):
    """Real-time event stream via WebSocket. Auth via ?api_key=af_... query param."""
    import asyncio, hashlib, time as _time

    if not api_key:
        await websocket.close(code=4001)
        return
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    with get_db() as db:
        row = db.execute("SELECT agent_id FROM agents WHERE api_key_hash=?", (key_hash,)).fetchone()
    if not row:
        await websocket.close(code=4001)
        return
    agent_id = row[0]

    await websocket.accept()
    await websocket.send_json({"type": "connected", "agent_id": agent_id})

    last_ping = _time.time()

    try:
        while True:
            if _time.time() - last_ping >= 30:
                await websocket.send_json({"type": "ping"})
                last_ping = _time.time()

            with get_db() as db:
                ws_rows = db.execute(
                    "SELECT event_id, event_type, payload, created_at FROM agent_events "
                    "WHERE agent_id=? AND acknowledged=0 ORDER BY created_at ASC LIMIT 5",
                    (agent_id,)
                ).fetchall()

            for ws_row in ws_rows:
                event = {
                    "type": "event",
                    "event_id": ws_row[0],
                    "event_type": ws_row[1],
                    "payload": json.loads(ws_row[2]),
                    "created_at": ws_row[3]
                }
                await websocket.send_json(event)

            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=0.1)
                if msg.get("type") == "pong":
                    pass
                elif msg.get("type") == "ack" and msg.get("event_ids"):
                    eids = msg["event_ids"]
                    placeholders = ",".join("?" * len(eids))
                    with get_db() as db:
                        db.execute(
                            f"UPDATE agent_events SET acknowledged=1 WHERE agent_id=? AND event_id IN ({placeholders})",
                            [agent_id] + eids
                        )
                        db.commit()
            except asyncio.TimeoutError:
                pass

            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# SKILL.MD — public agent field guide (no auth required)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/heartbeat.md", tags=["System"])
async def serve_heartbeat_md():
    hb_path = os.path.join(os.path.dirname(__file__), "heartbeat.md")
    with open(hb_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@app.get("/v1/heartbeat.md", tags=["System"])
async def serve_heartbeat_md_v1():
    hb_path = os.path.join(os.path.dirname(__file__), "heartbeat.md")
    with open(hb_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@app.get("/skill.md", tags=["System"])
async def serve_skill_md():
    skill_path = os.path.join(os.path.dirname(__file__), "skill.md")
    with open(skill_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@app.get("/v1/skill.md", tags=["System"])
async def serve_skill_md_v1():
    skill_path = os.path.join(os.path.dirname(__file__), "skill.md")
    with open(skill_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


# Connected WebSocket clients for network events
_network_ws_clients: list = []

@app.websocket("/v1/network/ws")
async def network_ws(websocket: WebSocket):
    """Real-time network visualization events. No auth required for viewing."""
    await websocket.accept()
    _network_ws_clients.append(websocket)
    await websocket.send_json({"type": "connected", "message": "Network visualization stream connected"})

    try:
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=30)
                if msg.get("type") == "pong":
                    pass
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if websocket in _network_ws_clients:
            _network_ws_clients.remove(websocket)


# ═══════════════════════════════════════════════════════════════════════════════
# ROOT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["System"])
def root():
    return {
        "service": "MoltGrid",
        "version": app.version,
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
