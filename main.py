"""
MoltGrid -- Open-source toolkit API for autonomous agents.
Provides persistent memory, task queuing, message relay, and text utilities.
"""

import time
import uuid
import threading
import logging
import httpx  # noqa: F401 -- re-exported for test_main.py mocking
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse

from db import init_db, init_pool, close_pool, init_sqlite_pool, close_sqlite_pool, init_asyncpg_pool, close_asyncpg_pool, get_db, DB_PATH, DB_BACKEND
from cache import init_redis, close_redis
from leader import acquire_leadership, release_leadership, is_leader
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from rate_limit import limiter
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
    # Startup: initialize database connection pools
    init_pool()
    init_sqlite_pool()
    await init_asyncpg_pool()
    # Startup: initialize Redis cache
    await init_redis()
    # Startup: leader election for multi-worker background thread coordination
    is_leader_worker = acquire_leadership()
    # Startup: launch background threads (leader worker only)
    if is_leader_worker:
        threading.Thread(target=_scheduler_loop, daemon=True).start()
        threading.Thread(target=_uptime_loop, daemon=True).start()
        threading.Thread(target=_liveness_loop, daemon=True).start()
        threading.Thread(target=_usage_reset_loop, daemon=True).start()
        threading.Thread(target=_email_loop, daemon=True).start()
        threading.Thread(target=_webhook_delivery_loop, daemon=True).start()
        logger.info("Leader worker: background threads started (scheduler, uptime, liveness, usage reset, email, webhook delivery)")
    else:
        logger.info("Follower worker: skipping background threads (leader handles them)")
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
    # Shutdown: release leadership
    release_leadership()
    # Shutdown: close Redis cache
    await close_redis()
    # Shutdown: close database connection pools
    await close_asyncpg_pool()
    close_pool()
    close_sqlite_pool()


# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="MoltGrid",
    description="Open-source toolkit API for autonomous agents. "
    "Persistent memory, task queues, message relay, and text utilities.",
    version="0.9.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

# ─── Rate Limiting (slowapi) ────────────────────────────────────────────────
app.state.limiter = limiter

async def _custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Return JSON 429 with Retry-After header instead of plain text."""
    retry_after = exc.detail.split("per")[0].strip() if exc.detail else "60"
    # Extract seconds from the limit string (e.g., "Rate limit exceeded: 60 per 1 minute")
    try:
        retry_seconds = int(retry_after.split()[-1])
    except (ValueError, IndexError):
        retry_seconds = 60
    response = JSONResponse(
        status_code=429,
        content={"error": "Rate limit exceeded", "detail": str(exc.detail), "retry_after": retry_seconds},
    )
    response.headers["Retry-After"] = str(retry_seconds)
    return response

app.add_exception_handler(RateLimitExceeded, _custom_rate_limit_handler)

@app.middleware("http")
async def add_middleware(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000
    response.headers["X-Response-Time"] = f"{duration_ms:.1f}ms"
    logger.info(f"{request.method} {request.url.path} {response.status_code} {duration_ms:.1f}ms")
    return response


@app.get("/api-docs", include_in_schema=False)
async def custom_swagger_ui():
    from fastapi.responses import HTMLResponse
    return HTMLResponse("""<!DOCTYPE html>
<html><head>
<title>MoltGrid | API Docs</title>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="shortcut icon" href="/public/favicon/favicon.ico">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
<style>
body{background:#0a0a0f;}
.swagger-ui{background:#0a0a0f;}
.swagger-ui .topbar{background:#12121a;border-bottom:1px solid #2a2a3a;padding:8px 0;}
.swagger-ui .info .title{color:#ff3333;font-family:JetBrains Mono,monospace;font-weight:700;}
.swagger-ui .info p,.swagger-ui .info li,.swagger-ui .renderedMarkdown p{color:#7a7a92;}
.swagger-ui .info a{color:#ff3333;}
.swagger-ui .scheme-container{background:#12121a;border-color:#2a2a3a;box-shadow:none;}
.swagger-ui .opblock-tag{color:#e4e4ef;border-color:#2a2a3a;}
.swagger-ui .opblock-tag:hover{background:rgba(255,255,255,0.02);}
.swagger-ui .opblock{background:#12121a;border-color:#2a2a3a;box-shadow:none;}
.swagger-ui .opblock .opblock-summary{border-color:#2a2a3a;}
.swagger-ui .opblock .opblock-summary-description{color:#7a7a92;}
.swagger-ui .opblock .opblock-summary-path{color:#e4e4ef;}
.swagger-ui .opblock.opblock-get{background:rgba(68,136,255,0.04);border-color:rgba(68,136,255,0.15);}
.swagger-ui .opblock.opblock-get .opblock-summary-method{background:#4488ff;}
.swagger-ui .opblock.opblock-post{background:rgba(0,204,102,0.04);border-color:rgba(0,204,102,0.15);}
.swagger-ui .opblock.opblock-post .opblock-summary-method{background:#00cc66;}
.swagger-ui .opblock.opblock-put{background:rgba(204,153,0,0.04);border-color:rgba(204,153,0,0.15);}
.swagger-ui .opblock.opblock-put .opblock-summary-method{background:#cc9900;}
.swagger-ui .opblock.opblock-delete{background:rgba(255,51,51,0.04);border-color:rgba(255,51,51,0.15);}
.swagger-ui .opblock.opblock-delete .opblock-summary-method{background:#ff3333;}
.swagger-ui .opblock.opblock-patch{background:rgba(153,102,204,0.04);border-color:rgba(153,102,204,0.15);}
.swagger-ui .opblock.opblock-patch .opblock-summary-method{background:#9966cc;}
.swagger-ui .opblock-body{background:#0a0a0f;}
.swagger-ui .opblock-body pre,.swagger-ui .microlight{background:#12121a!important;color:#e4e4ef!important;}
.swagger-ui table thead tr th,.swagger-ui table thead tr td{color:#7a7a92;border-color:#2a2a3a;}
.swagger-ui table tbody tr td{color:#e4e4ef;border-color:#2a2a3a;}
.swagger-ui .parameter__name{color:#e4e4ef;}
.swagger-ui .parameter__type,.swagger-ui .parameter__in{color:#7a7a92;}
.swagger-ui .prop-type{color:#4488ff;}
.swagger-ui section.models{border-color:#2a2a3a;}
.swagger-ui section.models h4{color:#e4e4ef;border-color:#2a2a3a;}
.swagger-ui .model-container,.swagger-ui .model-box{background:#12121a;border-color:#2a2a3a;}
.swagger-ui .model,.swagger-ui .model-title{color:#e4e4ef;}
.swagger-ui .responses-inner{background:#0a0a0f;}
.swagger-ui .response-col_status{color:#e4e4ef;}
.swagger-ui .response-col_description{color:#7a7a92;}
.swagger-ui .btn{color:#e4e4ef;border-color:#2a2a3a;background:#12121a;}
.swagger-ui .btn:hover{background:#1a1a26;}
.swagger-ui .btn.authorize{color:#ff3333;border-color:#ff3333;}
.swagger-ui select{background:#12121a;color:#e4e4ef;border-color:#2a2a3a;}
.swagger-ui input[type=text],.swagger-ui textarea{background:#12121a;color:#e4e4ef;border-color:#2a2a3a;}
.swagger-ui .markdown p,.swagger-ui .markdown li{color:#7a7a92;}
.swagger-ui .servers-title,.swagger-ui .servers>label{color:#7a7a92;}
.swagger-ui .copy-to-clipboard{background:#1a1a26;}
.swagger-ui .opblock-description-wrapper p{color:#7a7a92;}
.swagger-ui .tab li{color:#7a7a92;}
.swagger-ui .tab li.active{color:#e4e4ef;}
.swagger-ui .response-control-media-type__accept-message{color:#7a7a92;}
.swagger-ui .loading-container .loading::after{color:#7a7a92;}
</style>
</head><body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
    url:"/openapi.json",
    dom_id:"#swagger-ui",
    presets:[SwaggerUIBundle.presets.apis,SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout:"BaseLayout",
    deepLinking:true,
    defaultModelsExpandDepth:-1
});
</script>
</body></html>""")


@app.get("/api-redoc", include_in_schema=False)
async def custom_redoc():
    from fastapi.responses import HTMLResponse
    return HTMLResponse("""<!DOCTYPE html>
<html><head>
<title>MoltGrid | API Reference</title>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="shortcut icon" href="/public/favicon/favicon.ico">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>body{margin:0;padding:0;background:#0a0a0f;}</style>
</head><body>
<div id="redoc-container"></div>
<script src="https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js"></script>
<script>
Redoc.init("/openapi.json",{
  theme:{
    colors:{
      primary:{main:"#ff3333"},
      success:{main:"#00ff88"},
      warning:{main:"#ffcc00"},
      error:{main:"#ff4444"},
      text:{primary:"#e4e4ef",secondary:"#7a7a92"},
      border:{dark:"#2a2a3a",light:"#2a2a3a"},
      http:{get:"#4488ff",post:"#00cc66",put:"#cc9900","delete":"#ff3333",patch:"#9966cc"}
    },
    typography:{
      fontSize:"14px",
      fontFamily:"Space Grotesk, sans-serif",
      headings:{fontFamily:"Space Grotesk, sans-serif",fontWeight:"600"},
      code:{fontFamily:"JetBrains Mono, monospace",fontSize:"13px",backgroundColor:"#12121a",color:"#e4e4ef"}
    },
    sidebar:{backgroundColor:"#0a0a0f",textColor:"#7a7a92",activeTextColor:"#ff3333"},
    rightPanel:{backgroundColor:"#12121a",textColor:"#e4e4ef"},
    schema:{nestedBackground:"#12121a",typeNameColor:"#4488ff",typeTitleColor:"#e4e4ef"}
  }
}, document.getElementById("redoc-container"));
</script>
<style>
body,.redoc-wrap{background:#0a0a0f!important;}
[class*="middle-panel"]{background:#0a0a0f!important;}
h1{color:#ff3333!important;font-family:JetBrains Mono,monospace!important;font-weight:700!important;}h2,h3,h4,h5{color:#e4e4ef!important;}
p,li{color:#7a7a92!important;}
a[href]{color:#ff3333!important;}
table,tr,td,th{border-color:#2a2a3a!important;}
tr{background:transparent!important;}
code{background:#12121a!important;color:#e4e4ef!important;}
pre{background:#12121a!important;}
[class*="search"] input{background:#12121a!important;color:#e4e4ef!important;border-color:#2a2a3a!important;}
[class*="menu-content"]{background:#0a0a0f!important;}
button{color:#e4e4ef!important;}
</style>
</body></html>""")

@app.get("/api-redoc", include_in_schema=False)
async def custom_redoc():
    from fastapi.responses import HTMLResponse
    return HTMLResponse("""<!DOCTYPE html>
<html><head>
<title>MoltGrid | API Reference</title>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="shortcut icon" href="/public/favicon/favicon.ico">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>body{margin:0;padding:0;background:#0a0a0f;}</style>
</head><body>
<div id="redoc-container"></div>
<script src="https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js"></script>
<script>
Redoc.init("/openapi.json",{
  theme:{
    colors:{
      primary:{main:"#ff3333"},
      success:{main:"#00ff88"},
      warning:{main:"#ffcc00"},
      error:{main:"#ff4444"},
      text:{primary:"#e4e4ef",secondary:"#7a7a92"},
      border:{dark:"#2a2a3a",light:"#2a2a3a"},
      http:{get:"#4488ff",post:"#00cc66",put:"#cc9900","delete":"#ff3333",patch:"#9966cc"}
    },
    typography:{
      fontSize:"14px",
      fontFamily:"Space Grotesk, sans-serif",
      headings:{fontFamily:"Space Grotesk, sans-serif",fontWeight:"600"},
      code:{fontFamily:"JetBrains Mono, monospace",fontSize:"13px",backgroundColor:"#12121a",color:"#e4e4ef"}
    },
    sidebar:{backgroundColor:"#0a0a0f",textColor:"#7a7a92",activeTextColor:"#ff3333"},
    rightPanel:{backgroundColor:"#12121a",textColor:"#e4e4ef"},
    schema:{nestedBackground:"#12121a",typeNameColor:"#4488ff",typeTitleColor:"#e4e4ef"}
  }
}, document.getElementById("redoc-container"));
</script>
<style>
body,.redoc-wrap{background:#0a0a0f!important;}
[class*="middle-panel"]{background:#0a0a0f!important;}
h1{color:#ff3333!important;font-family:JetBrains Mono,monospace!important;font-weight:700!important;}h2,h3,h4,h5{color:#e4e4ef!important;}
p,li{color:#7a7a92!important;}
a[href]{color:#ff3333!important;}
table,tr,td,th{border-color:#2a2a3a!important;}
tr{background:transparent!important;}
code{background:#12121a!important;color:#e4e4ef!important;}
pre{background:#12121a!important;}
[class*="search"] input{background:#12121a!important;color:#e4e4ef!important;border-color:#2a2a3a!important;}
[class*="menu-content"]{background:#0a0a0f!important;}
button{color:#e4e4ef!important;}
</style>
</body></html>""")


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
    details = []
    for err in exc.errors():
        field = ".".join(str(loc) for loc in err.get("loc", []) if loc != "body")
        details.append({
            "field": field,
            "message": err.get("msg", ""),
            "type": err.get("type", ""),
        })
    return JSONResponse(
        status_code=422,
        content={"error": "Validation failed", "code": "validation_error", "status": 422, "details": details},
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
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
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

    # Always include remaining and reset headers
    if request.state.rate_limit_remaining is not None:
        response.headers["X-RateLimit-Remaining"] = str(request.state.rate_limit_remaining)
    else:
        # Unauthenticated request: show full limit as remaining
        response.headers["X-RateLimit-Remaining"] = str(rate_limit_max if rate_limit_max is not None else RATE_LIMIT_MAX)

    if request.state.rate_limit_reset is not None:
        response.headers["X-RateLimit-Reset"] = str(request.state.rate_limit_reset)
    else:
        # Calculate next window boundary
        import time as _time
        _window = (int(_time.time()) // RATE_LIMIT_WINDOW + 1) * RATE_LIMIT_WINDOW
        response.headers["X-RateLimit-Reset"] = str(_window)

    return response


# ─── Database Init ───────────────────────────────────────────────────────────

init_db()


# ─── Router Includes ────────────────────────────────────────────────────────

from routers import auth, dashboard, billing, memory, queue, relay          # noqa: E402
from routers import webhooks, schedules, vector, directory, marketplace     # noqa: E402
from routers import pubsub, integrations, sessions, events, orgs, admin, system  # noqa: E402
from routers import tiered_memory, user                                     # noqa: E402
from routers import chat_gateway                                             # noqa: E402
from routers import sse                                                      # noqa: E402
from routers import promo                                                     # noqa: E402

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
app.include_router(user.router)
app.include_router(chat_gateway.router)
app.include_router(sse.router)
app.include_router(promo.router)


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
