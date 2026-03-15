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

app = FastAPI(
    title="MoltGrid",
    description="Open-source toolkit API for autonomous agents. "
    "Persistent memory, task queues, message relay, and text utilities.",
    version="0.9.0",
    lifespan=lifespan,
    docs_url="/api-docs",
    redoc_url=None,
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
