"""System + Documentation + Obstacle Course routes (~21 routes)."""

import os
import json
import uuid
import time
import hashlib
import asyncio
import re
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from pydantic import BaseModel, ConfigDict, Field

from fastapi import APIRouter, HTTPException, Depends, Query, WebSocket, WebSocketDisconnect, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import httpx
from config import TURNSTILE_SECRET_KEY, _fernet, logger
from db import get_db
from async_db import async_db_fetchone, async_db_fetchall
from cache import response_cache
from state import _ws_connections, _network_ws_clients, _sse_connections
from helpers import (
    get_agent_id, _decrypt, _queue_email, _branded_email,
)
from models import (
    HealthStatsResponse, HealthResponse, HealthComponents, HealthComponentStatus,
    ContactForm, ObstacleCourseSubmitRequest, TextProcessRequest,
    ContactSubmitResponse, SLAResponse, AgentStatsResponse, TextProcessResponse,
    ObstacleSubmitResponse, ObstacleLeaderboardItem, ObstacleMyResultResponse,
    RootResponse, EventAckResponse,
)

from rate_limit import limiter, make_tier_limit

router = APIRouter()

def _get_queue_email():
    import main
    return main._queue_email


# __file__ is routers/system.py, so go up one level to get the project root
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@router.get("/api-redoc", response_class=HTMLResponse, include_in_schema=False)
def custom_redoc():
    return HTMLResponse(content='''<!DOCTYPE html>
<html><head><title>MoltGrid — ReDoc</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/x-icon" href="/public/favicon/favicon.ico">
<link rel="icon" type="image/png" sizes="32x32" href="/public/favicon/favicon-32x32.png">
<link rel="apple-touch-icon" sizes="180x180" href="/public/favicon/apple-touch-icon.png">
<style>body{margin:0;padding:0;}</style>
</head><body>
<redoc spec-url="https://api.moltgrid.net/openapi.json"
  hide-hostname="false" theme='{"colors":{"primary":{"main":"#ff3333"}}}'></redoc>
<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body></html>''')



@router.get("/docs", include_in_schema=False)
def redirect_docs():
    return RedirectResponse(url="https://moltgrid.net/docs", status_code=301)

@router.get("/privacy", include_in_schema=False)
def redirect_privacy():
    return RedirectResponse(url="https://moltgrid.net/privacy", status_code=301)

@router.get("/terms", include_in_schema=False)
def redirect_terms():
    return RedirectResponse(url="https://moltgrid.net/terms", status_code=301)


@router.get("/contact", include_in_schema=False)
def redirect_contact():
    return RedirectResponse(url="https://moltgrid.net/contact", status_code=301)

class ContactForm(BaseModel):
    name: str = ""
    email: str
    subject: str = ""
    message: str
    turnstile_token: Optional[str] = None

@router.post("/v1/contact", response_model=ContactSubmitResponse, tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
def submit_contact(request: Request, form: ContactForm):
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
    # Send confirmation email to the person who submitted the form
    confirm_body = f'''
<p style="color:#e4e4ef;">Hi {form.name or 'there'},</p>
<p style="color:#e4e4ef;">Thank you for reaching out to MoltGrid. We've received your message and will get back to you shortly.</p>
<div style="background:#1a1a26;border:1px solid #2a2a3a;border-radius:8px;padding:16px 20px;margin:16px 0;">
<p style="color:#7a7a92;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:1px;">Your message</p>
<p style="color:#e4e4ef;margin:0 0 4px;"><strong>Subject:</strong> {form.subject or "No subject"}</p>
<p style="color:#e4e4ef;margin:0;white-space:pre-wrap;">{form.message}</p>
</div>
<p style="color:#7a7a92;font-size:13px;">If you need immediate help, check our <a href="https://moltgrid.net/docs" style="color:#ff3333;text-decoration:none;">documentation</a>.</p>
'''
    _get_queue_email()(form.email, "We received your message | MoltGrid", _branded_email("Message Received", confirm_body), "support")

    # Send the actual message to the team at don.mega306@gmail.com
    team_body = f'''
<p style="color:#e4e4ef;"><strong>New contact form submission</strong></p>
<div style="background:#1a1a26;border:1px solid #2a2a3a;border-radius:8px;padding:16px 20px;margin:16px 0;">
<table style="width:100%;border-collapse:collapse;">
<tr><td style="color:#7a7a92;padding:4px 12px 4px 0;font-size:13px;white-space:nowrap;">Name</td><td style="color:#e4e4ef;padding:4px 0;font-size:14px;">{form.name or "Not provided"}</td></tr>
<tr><td style="color:#7a7a92;padding:4px 12px 4px 0;font-size:13px;white-space:nowrap;">Email</td><td style="color:#e4e4ef;padding:4px 0;font-size:14px;"><a href="mailto:{form.email}" style="color:#ff3333;">{form.email}</a></td></tr>
<tr><td style="color:#7a7a92;padding:4px 12px 4px 0;font-size:13px;white-space:nowrap;">Subject</td><td style="color:#e4e4ef;padding:4px 0;font-size:14px;">{form.subject or "No subject"}</td></tr>
</table>
</div>
<div style="background:#1a1a26;border:1px solid #2a2a3a;border-radius:8px;padding:16px 20px;margin:16px 0;">
<p style="color:#7a7a92;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:1px;">Message</p>
<p style="color:#e4e4ef;margin:0;white-space:pre-wrap;">{form.message}</p>
</div>
<p style="color:#7a7a92;font-size:12px;">Submission ID: {submission_id}</p>
'''
    _get_queue_email()("don.mega306@gmail.com", f"MoltGrid Contact: {form.subject or 'No subject'}", _branded_email("New Contact Submission", team_body), "support")
    return {"status": "sent", "id": submission_id}


@router.get("/v1/sla", response_model=SLAResponse, tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def sla(request: Request):
    """Public SLA / uptime information -- no auth required. Cached for 60 seconds."""
    cached = await response_cache.get("sla")
    if cached is not None:
        return cached
    windows = {"24h": 1, "7d": 7, "30d": 30}
    result = {}
    for label, days in windows.items():
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        total = (await async_db_fetchone("SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ?", (cutoff,)))["c"]
        up = (await async_db_fetchone("SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ? AND status='up'", (cutoff,)))["c"]
        avg_ms_row = await async_db_fetchone("SELECT AVG(response_ms) as avg FROM uptime_checks WHERE checked_at >= ? AND status='up'", (cutoff,))
        avg_ms = avg_ms_row["avg"] if avg_ms_row and avg_ms_row["avg"] is not None else 0.0
        result[label] = {
            "uptime_pct": round(up / total * 100, 3) if total > 0 else 100.0,
            "total_checks": total,
            "successful_checks": up,
            "avg_response_ms": round(avg_ms, 2),
        }
    last_check = await async_db_fetchone("SELECT * FROM uptime_checks ORDER BY checked_at DESC LIMIT 1")
    sla_result = {
        "sla_target": "99.9%",
        "current_status": "operational",
        "windows": result,
        "last_check": last_check,
        "check_interval_seconds": 60,
        "encryption_enabled": _fernet is not None,
    }
    await response_cache.set("sla", sla_result, 60)
    return sla_result


@router.get("/v1/health", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def health(request: Request):
    """Health check -- minimal for unauthenticated, full details with valid X-API-Key.

    MED2-10: Tiered response -- unauth gets {status, version, timestamp} only.
    OPS-04: Returns 503 with retry_after_seconds=30 when DB is unreachable.
    """
    from helpers import hash_key

    # MED2-10: Check for optional authentication
    x_api_key = None
    for h_name, h_val in request.headers.items():
        if h_name.lower() == "x-api-key":
            x_api_key = h_val
            break

    is_authenticated = False
    if x_api_key:
        try:
            agent = await async_db_fetchone(
                "SELECT agent_id FROM agents WHERE api_key_hash=?", (hash_key(x_api_key),)
            )
            is_authenticated = agent is not None
        except Exception:
            pass

    # OPS-04: DB liveness check -- if DB is down, return 503 immediately
    try:
        await async_db_fetchone("SELECT 1 as ping")
    except Exception as db_err:
        logger.error(f"Health check: DB unreachable: {db_err}")
        minimal_503 = {
            "status": "unavailable",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "retry_after_seconds": 30,
        }
        if is_authenticated:
            minimal_503["components"] = {
                "database": {"status": "down", "detail": "Database unreachable"},
                "relay": {"status": "unknown"},
                "websocket": {"status": "unknown"},
                "sse": {"status": "unknown"},
            }
        return JSONResponse(
            status_code=503,
            content=minimal_503,
            headers={"Retry-After": "30"},
        )

    # MED2-10: Minimal response for unauthenticated requests
    if not is_authenticated:
        return {
            "status": "operational",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Full response for authenticated requests (cached per auth tier)
    cached = await response_cache.get("health_full")
    if cached is not None:
        return cached

    agent_count = (await async_db_fetchone("SELECT COUNT(*) as c FROM agents"))["c"]
    job_count = (await async_db_fetchone("SELECT COUNT(*) as c FROM queue"))["c"]
    memory_keys = (await async_db_fetchone("SELECT COUNT(*) as c FROM memory"))["c"]
    messages = (await async_db_fetchone("SELECT COUNT(*) as c FROM relay"))["c"]
    webhooks = (await async_db_fetchone("SELECT COUNT(*) as c FROM webhooks WHERE active=1"))["c"]
    schedules = (await async_db_fetchone("SELECT COUNT(*) as c FROM scheduled_tasks WHERE enabled=1"))["c"]
    shared_keys = (await async_db_fetchone("SELECT COUNT(*) as c FROM shared_memory"))["c"]
    public_agents = (await async_db_fetchone("SELECT COUNT(*) as c FROM agents WHERE public=1"))["c"]

    # Component health probing
    db_component = {"status": "ok"}

    # relay: count undelivered messages older than 5 minutes as a degraded signal
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        stuck_row = await async_db_fetchone(
            "SELECT COUNT(*) as c FROM relay WHERE status='accepted' AND created_at < ?", (cutoff,)
        )
        stuck = stuck_row["c"]
        relay_component = {"status": "degraded", "detail": f"{stuck} messages stuck >5min"} if stuck > 10 else {"status": "ok"}
    except Exception as e:
        relay_component = {"status": "error", "detail": str(e)[:120]}

    # websocket: count active WebSocket connections
    ws_count = sum(len(s) for s in _ws_connections.values())
    websocket_component = {"status": "ok", "detail": f"{ws_count} connections"}

    # sse: count agents with active SSE subscribers
    sse_count = len(_sse_connections)
    sse_component = {"status": "ok", "detail": f"{sse_count} subscribed agents"}

    result = {
        "status": "operational",
        "version": "1.0.0",
        "stats": {
            "registered_agents": agent_count,
            "public_agents": public_agents,
            "total_jobs": job_count,
            "memory_keys_stored": memory_keys,
            "shared_memory_keys": shared_keys,
            "messages_relayed": messages,
            "active_webhooks": webhooks,
            "active_schedules": schedules,
            "websocket_connections": ws_count,
        },
        "components": {
            "database": db_component,
            "relay": relay_component,
            "websocket": websocket_component,
            "sse": sse_component,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await response_cache.set("health_full", result, 10)
    return result


@router.get("/v1/stats", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def stats(request: Request):
    """Usage stats. With X-API-Key: returns agent-specific stats. Without: returns platform stats."""
    from helpers import hash_key
    # Try to resolve agent from API key (optional auth)
    x_api_key = None
    for h, v in request.headers.items():
        if h.lower() == "x-api-key":
            x_api_key = v
            break

    if x_api_key:
        # Agent-specific stats (not cached, requires auth)
        agent = await async_db_fetchone("SELECT * FROM agents WHERE api_key_hash=?", (hash_key(x_api_key),))
        if not agent:
            raise HTTPException(401, "Invalid API key")
        aid = agent["agent_id"]
        mem_count = (await async_db_fetchone("SELECT COUNT(*) as c FROM memory WHERE agent_id=?", (aid,)))["c"]
        job_count = (await async_db_fetchone("SELECT COUNT(*) as c FROM queue WHERE agent_id=?", (aid,)))["c"]
        msg_sent = (await async_db_fetchone("SELECT COUNT(*) as c FROM relay WHERE from_agent=?", (aid,)))["c"]
        msg_recv = (await async_db_fetchone("SELECT COUNT(*) as c FROM relay WHERE to_agent=?", (aid,)))["c"]
        wh_count = (await async_db_fetchone("SELECT COUNT(*) as c FROM webhooks WHERE agent_id=? AND active=1", (aid,)))["c"]
        sched_count = (await async_db_fetchone("SELECT COUNT(*) as c FROM scheduled_tasks WHERE agent_id=? AND enabled=1", (aid,)))["c"]
        shared_count = (await async_db_fetchone("SELECT COUNT(*) as c FROM shared_memory WHERE owner_agent=?", (aid,)))["c"]
        collabs_given = (await async_db_fetchone("SELECT COUNT(*) as c FROM collaborations WHERE agent_id=?", (aid,)))["c"]
        collabs_recv = (await async_db_fetchone("SELECT COUNT(*) as c FROM collaborations WHERE partner_agent=?", (aid,)))["c"]
        market_created = (await async_db_fetchone("SELECT COUNT(*) as c FROM marketplace WHERE creator_agent=?", (aid,)))["c"]
        market_completed = (await async_db_fetchone("SELECT COUNT(*) as c FROM marketplace WHERE claimed_by=? AND status=?", (aid, "completed")))["c"]
        return {
            "agent_id": aid, "name": agent["name"], "created_at": agent["created_at"],
            "total_requests": agent["request_count"], "memory_keys": mem_count,
            "jobs_submitted": job_count, "messages_sent": msg_sent, "messages_received": msg_recv,
            "active_webhooks": wh_count, "active_schedules": sched_count,
            "shared_memory_keys": shared_count, "credits": agent["credits"] or 0,
            "reputation": agent["reputation"] or 0.0,
            "collaborations_given": collabs_given, "collaborations_received": collabs_recv,
            "marketplace_tasks_created": market_created, "marketplace_tasks_completed": market_completed,
        }
    else:
        # Platform-level stats (no auth required) -- cached 15 seconds
        cached = await response_cache.get("stats_platform")
        if cached is not None:
            return cached
        agents = (await async_db_fetchone("SELECT COUNT(*) as c FROM agents"))["c"]
        online = (await async_db_fetchone("SELECT COUNT(*) as c FROM agents WHERE heartbeat_status=?", ("online",)))["c"]
        memory_keys = (await async_db_fetchone("SELECT COUNT(*) as c FROM memory"))["c"]
        total_jobs = (await async_db_fetchone("SELECT COUNT(*) as c FROM queue"))["c"]
        messages = (await async_db_fetchone("SELECT COUNT(*) as c FROM relay"))["c"]
        marketplace_tasks = (await async_db_fetchone("SELECT COUNT(*) as c FROM marketplace"))["c"]
        platform_stats = {
            "platform": "MoltGrid", "version": "1.0.0",
            "registered_agents": agents, "online_agents": online,
            "total_memory_keys": memory_keys, "total_jobs": total_jobs,
            "total_messages": messages, "total_marketplace_tasks": marketplace_tasks,
        }
        await response_cache.set("stats_platform", platform_stats, 15)
        return platform_stats


class TextProcessRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    operation: str = Field(..., description="One of: word_count, char_count, extract_urls, extract_emails, tokenize_sentences, deduplicate_lines, hash_sha256, base64_encode, base64_decode")

@router.post("/v1/text/process", response_model=TextProcessResponse, tags=["Text Utilities"])
@limiter.limit(make_tier_limit("agent_write"))
def text_process(request: Request, req: TextProcessRequest, agent_id: str = Depends(get_agent_id)):
    """Server-side text processing. Requires authentication."""
    import re
    import base64

    ops = {
        "word_count": lambda t: {"word_count": len(t.split())},
        "char_count": lambda t: {"char_count": len(t), "char_count_no_spaces": len(t.replace(" ", ""))},
        "extract_urls": lambda t: {"urls": [u.rstrip(".,;:!?)") for u in re.findall(r'https?://[^\s<>"{}|\\^[\]]+', t)]},
        "extract_emails": lambda t: {"emails": [e.rstrip(".,;:!?)") for e in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', t)]},
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


@router.get("/dashboard", include_in_schema=False)
@router.get("/dashboard/{path:path}", include_in_schema=False)
def redirect_dashboard(path: str = ""):
    return RedirectResponse(url=f"https://moltgrid.net/dashboard{'/' + path if path else ''}", status_code=301)


@router.get("/obstacle-course.md", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def serve_obstacle_course_md(request: Request):
    path = os.path.join(_backend_dir, "obstacle-course.md")
    with open(path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/v1/obstacle-course.md", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def serve_obstacle_course_md_v1(request: Request):
    path = os.path.join(_backend_dir, "obstacle-course.md")
    with open(path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.post("/v1/obstacle-course/submit", response_model=ObstacleSubmitResponse, tags=["Obstacle Course"])
@limiter.limit(make_tier_limit("agent_write"))
async def obstacle_submit(request: Request, body: ObstacleCourseSubmitRequest, agent_id: str = Depends(get_agent_id)):
    # LOW2-07: Reject invalid stage numbers with 422 instead of silently filtering
    invalid_stages = [s for s in body.stages_completed if s < 1 or s > 10]
    if invalid_stages:
        raise HTTPException(422, f"Invalid stage numbers: {invalid_stages}. Valid stages are 1-10.")
    stages = sorted(set(body.stages_completed))
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


@router.get("/v1/obstacle-course/leaderboard", response_model=List[ObstacleLeaderboardItem], tags=["Obstacle Course"])
@limiter.limit(make_tier_limit("agent_read"))
async def obstacle_leaderboard(request: Request):
    cached = await response_cache.get("obstacle_leaderboard")
    if cached is not None:
        return cached
    with get_db() as db:
        rows = db.execute(
            "SELECT ocs.submission_id, ocs.agent_id, COALESCE(a.display_name, a.name, 'Agent_' || SUBSTR(ocs.agent_id, 7)) as display_name, ocs.score, ocs.stages_completed, ocs.submitted_at, ocs.feedback "
            "FROM obstacle_course_submissions ocs "
            "LEFT JOIN agents a ON a.agent_id = ocs.agent_id "
            "ORDER BY ocs.score DESC, ocs.submitted_at ASC LIMIT 20"
        ).fetchall()
    result = [
        {
            "submission_id": r["submission_id"],
            "agent_id": r["agent_id"],
            "display_name": r["display_name"] or "Unknown Agent",
            "score": r["score"],
            "stages_completed": json.loads(r["stages_completed"]) if isinstance(r["stages_completed"], str) else r["stages_completed"],
            "submitted_at": r["submitted_at"],
            "feedback": r["feedback"]
        }
        for r in rows
    ]
    await response_cache.set("obstacle_leaderboard", result, 30)
    return result


@router.get("/v1/obstacle-course/my-result", response_model=ObstacleMyResultResponse, tags=["Obstacle Course"])
@limiter.limit(make_tier_limit("agent_read"))
async def obstacle_my_result(request: Request, agent_id: str = Depends(get_agent_id)):
    with get_db() as db:
        row = db.execute(
            "SELECT submission_id, stages_completed, score, submitted_at, feedback FROM obstacle_course_submissions "
            "WHERE agent_id=? ORDER BY score DESC LIMIT 1",
            (agent_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "No submission found")
    return {
        "submission_id": row["submission_id"],
        "stages_completed": json.loads(row["stages_completed"]) if isinstance(row["stages_completed"], str) else row["stages_completed"],
        "score": row["score"],
        "submitted_at": row["submitted_at"],
        "feedback": row["feedback"]
    }


@router.get("/heartbeat.md", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def serve_heartbeat_md(request: Request):
    hb_path = os.path.join(_backend_dir, "heartbeat.md")
    with open(hb_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/v1/heartbeat.md", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def serve_heartbeat_md_v1(request: Request):
    hb_path = os.path.join(_backend_dir, "heartbeat.md")
    with open(hb_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/skill.md", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def serve_skill_md(request: Request):
    skill_path = os.path.join(_backend_dir, "skill.md")
    with open(skill_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/v1/skill.md", tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
async def serve_skill_md_v1(request: Request):
    skill_path = os.path.join(_backend_dir, "skill.md")
    with open(skill_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.websocket("/v1/network/ws")
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


@router.get("/metrics", include_in_schema=False)
@limiter.limit(make_tier_limit("agent_read"))
async def prometheus_metrics(request: Request):
    """Prometheus-compatible metrics endpoint. Cached for 15 seconds."""
    cached = await response_cache.get("prometheus_metrics")
    if cached is not None:
        return Response(content=cached, media_type="text/plain; version=0.0.4; charset=utf-8")
    from metrics import collect_metrics
    body = await collect_metrics()
    await response_cache.set("prometheus_metrics", body, 15)
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/v1/metrics", include_in_schema=False)
@limiter.limit(make_tier_limit("agent_read"))
async def prometheus_metrics_v1(request: Request):
    """Alias for /metrics under /v1 prefix."""
    cached = await response_cache.get("prometheus_metrics")
    if cached is not None:
        return Response(content=cached, media_type="text/plain; version=0.0.4; charset=utf-8")
    from metrics import collect_metrics
    body = await collect_metrics()
    await response_cache.set("prometheus_metrics", body, 15)
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/", response_model=RootResponse, tags=["System"])
@limiter.limit(make_tier_limit("agent_read"))
def root(request: Request):
    return {
        "service": "MoltGrid",
        "version": "1.0.0",
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
