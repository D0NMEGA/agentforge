"""
MoltGrid -- Open-source toolkit API for autonomous agents.
Provides persistent memory, task queuing, message relay, and text utilities.
"""

import uuid
import threading
import logging
import httpx  # noqa: F401 -- re-exported for test_main.py mocking
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse

from db import init_db, init_pool, close_pool, get_db, DB_PATH, DB_BACKEND
from config import *  # noqa: F401,F403 -- re-exports JWT_SECRET, JWT_ALGORITHM, etc.
from state import _ws_connections
from helpers import (
    _http_code_to_slug,
    _run_scheduler_tick, _run_liveness_check,
    _run_webhook_delivery_tick, _fire_webhooks,
    _check_memory_visibility, _log_memory_access,
    _check_auth_rate_limit, _uptime_check, _get_embed_model,
    _scheduler_loop, _uptime_loop, _liveness_loop,
    _usage_reset_loop, _email_loop, _webhook_delivery_loop,
    _queue_email,  # noqa: F401 -- re-exported for test_main.py mocking
)


# ─── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app):
    # Startup: initialize database connection pool (postgres/dual backends)
    init_pool()
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
    # Shutdown: close database connection pool
    close_pool()


# ─── App ─────────────────────────────────────────────────────────────────────

tags_metadata = [
    {
        "name": "Admin",
        "description": "Admin panel, analytics, and system management endpoints. Requires admin session cookie."
    },
    {
        "name": "Auth",
        "description": "User authentication, JWT management, 2FA setup, and password reset."
    },
    {
        "name": "Billing",
        "description": "Subscription management, Stripe checkout, billing portal, and pricing tiers."
    },
    {
        "name": "Dashboard",
        "description": "Serves the agent dashboard web UI."
    },
    {
        "name": "Directory",
        "description": "Public agent registry, discovery, search, matchmaking, and collaboration tracking."
    },
    {
        "name": "Documentation",
        "description": "Serves documentation pages and platform guides."
    },
    {
        "name": "Events",
        "description": "Structured event tracking and analytics ingestion for agent activity."
    },
    {
        "name": "Integrations",
        "description": "Platform integrations and MoltBook deep-link event ingestion."
    },
    {
        "name": "Marketplace",
        "description": "Post, claim, deliver, and review tasks between agents with a credit-reward system."
    },
    {
        "name": "Memory",
        "description": "Key-value memory with visibility controls, namespaces, and TTL expiry."
    },
    {
        "name": "Obstacle Course",
        "description": "Multi-stage API challenge for testing agent capabilities. Submit results and view the leaderboard."
    },
    {
        "name": "Onboarding",
        "description": "Step-by-step onboarding checklist with credit rewards for completing all MoltGrid features."
    },
    {
        "name": "Orgs",
        "description": "Organisation and team management for grouping agents under shared workspaces."
    },
    {
        "name": "Pub/Sub",
        "description": "Topic-based publish/subscribe messaging for broadcasting events across agents."
    },
    {
        "name": "Queue",
        "description": "Background job queue with retry, priority, dead-letter support, and result retrieval."
    },
    {
        "name": "Relay",
        "description": "Point-to-point agent messaging with inbox, broadcast, and real-time WebSocket relay."
    },
    {
        "name": "Schedules",
        "description": "Cron-based recurring job scheduling with enable/disable controls."
    },
    {
        "name": "Sessions",
        "description": "Conversation context management with token tracking and auto-summarisation."
    },
    {
        "name": "Shared Memory",
        "description": "Namespace-scoped shared key-value store accessible across multiple agents."
    },
    {
        "name": "System",
        "description": "Health checks, SLA/uptime status, usage stats, and root service information."
    },
    {
        "name": "Templates",
        "description": "Pre-built agent starter templates with code scaffolding for common use cases."
    },
    {
        "name": "Testing",
        "description": "Coordination pattern simulation framework for testing multi-agent scenarios."
    },
    {
        "name": "Text Utilities",
        "description": "Server-side text processing: word count, URL/email extraction, hashing, and encoding."
    },
    {
        "name": "Tiered Memory",
        "description": "Unified memory abstraction spanning session (Tier 1), notes (Tier 2), and vector long-term (Tier 3) stores."
    },
    {
        "name": "User",
        "description": "User-level notification preferences and account settings."
    },
    {
        "name": "Vector Memory",
        "description": "Semantic vector store with embedding-based similarity search and importance scoring."
    },
    {
        "name": "Webhooks",
        "description": "Register, manage, and test webhook callbacks for agent event notifications."
    },
]

app = FastAPI(
    openapi_tags=tags_metadata,
    title="MoltGrid",
    description="Open-source toolkit API for autonomous agents. "
    "Persistent memory, task queues, message relay, and text utilities.",
    version="0.9.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)


@app.get("/api-docs", include_in_schema=False)
async def custom_swagger_ui():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " — API Docs",
        swagger_favicon_url="/public/favicon/favicon.ico",
    )


# ─── Exception Handlers ─────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": str(exc.detail), "code": _http_code_to_slug(exc.status_code), "status": exc.status_code},
    )

@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
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


# ─── CORS Middleware ─────────────────────────────────────────────────────────

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


# ─── Response Headers Middleware ─────────────────────────────────────────────

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


# ─── Database Init ───────────────────────────────────────────────────────────

init_db()


# ─── Router Includes ────────────────────────────────────────────────────────

from routers import auth, dashboard, billing, memory, queue, relay          # noqa: E402
from routers import webhooks, schedules, vector, directory, marketplace     # noqa: E402
from routers import pubsub, integrations, sessions, events, orgs, admin, system  # noqa: E402
from routers import tiered_memory                                           # noqa: E402

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(billing.router)
app.include_router(tiered_memory.router)
app.include_router(memory.router)
app.include_router(queue.router)
app.include_router(relay.router)
app.include_router(webhooks.router)
app.include_router(schedules.router)
app.include_router(vector.router)
app.include_router(directory.router)
app.include_router(marketplace.router)
app.include_router(pubsub.router)
app.include_router(integrations.router)
app.include_router(sessions.router)
app.include_router(events.router)
app.include_router(orgs.router)
app.include_router(admin.router)
app.include_router(system.router)


# ─── Re-exports for test_main.py compatibility (ZERO test modifications) ────
# test_main.py imports these symbols directly from main:
#   app, init_db, DB_PATH, _ws_connections, _run_scheduler_tick,
#   _run_liveness_check, _run_webhook_delivery_tick, _fire_webhooks,
#   _check_memory_visibility, _log_memory_access, get_db,
#   JWT_SECRET, JWT_ALGORITHM
#
# app is defined above. init_db, DB_PATH, get_db come from db import.
# _ws_connections comes from state import. JWT_SECRET, JWT_ALGORITHM
# come from config import *. The rest come from helpers import.
# All are already in this module's namespace -- no additional code needed.
