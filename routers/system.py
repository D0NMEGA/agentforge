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
from fastapi.responses import HTMLResponse, JSONResponse

import httpx
from config import TURNSTILE_SECRET_KEY, _fernet, logger
from db import get_db
from state import _ws_connections, _network_ws_clients
from helpers import (
    get_agent_id, _decrypt, _queue_email, _branded_email,
)
from models import (
    HealthStatsResponse, HealthResponse,
    ContactForm, ObstacleCourseSubmitRequest, TextProcessRequest,
)

router = APIRouter()

def _get_queue_email():
    import main
    return main._queue_email


# __file__ is routers/system.py, so go up one level to get the project root
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_web_dir = os.path.join(os.path.dirname(_backend_dir), "moltgrid-web") if not os.path.exists(os.path.join(_backend_dir, "dashboard.html")) else None

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



@router.get("/docs", response_class=HTMLResponse, tags=["Documentation"], include_in_schema=False)
def docs_page():
    """Serve the comprehensive documentation page."""
    html_path = _find_html("docs.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Documentation page not found")

@router.get("/privacy", response_class=HTMLResponse, tags=["System"], include_in_schema=False)
def privacy_page():
    """Serve the privacy policy page."""
    try:
        with open(_find_html("privacy.html"), "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Privacy policy not found")

@router.get("/terms", response_class=HTMLResponse, tags=["System"], include_in_schema=False)
def terms_page():
    """Serve the terms of service page."""
    try:
        with open(_find_html("terms.html"), "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Terms of service not found")


@router.get("/contact", response_class=HTMLResponse, tags=["System"])
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

@router.post("/v1/contact", tags=["System"])
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
    # Send confirmation email to the person who submitted the form
    confirm_body = f'''
<p style="color:#e4e4ef;">Hi {form.name or 'there'},</p>
<p style="color:#e4e4ef;">Thank you for reaching out to MoltGrid. We've received your message and will get back to you shortly.</p>
<div style="background:#1a1a26;border:1px solid #2a2a3a;border-radius:8px;padding:16px 20px;margin:16px 0;">
<p style="color:#7a7a92;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:1px;">Your message</p>
<p style="color:#e4e4ef;margin:0 0 4px;"><strong>Subject:</strong> {form.subject or "No subject"}</p>
<p style="color:#e4e4ef;margin:0;white-space:pre-wrap;">{form.message}</p>
</div>
<p style="color:#7a7a92;font-size:13px;">If you need immediate help, check our <a href="https://api.moltgrid.net/docs" style="color:#ff3333;text-decoration:none;">documentation</a>.</p>
'''
    _get_queue_email()(form.email, "We received your message — MoltGrid", _branded_email("Message Received", confirm_body))

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
    _get_queue_email()("don.mega306@gmail.com", f"MoltGrid Contact: {form.subject or 'No subject'}", _branded_email("New Contact Submission", team_body))
    return {"status": "sent", "id": submission_id}


@router.get("/v1/sla", tags=["System"])
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


@router.get("/v1/health", response_model=HealthResponse, tags=["System"])
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
        "version": "0.9.0",
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


@router.get("/v1/stats", tags=["System"])
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


class TextProcessRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    operation: str = Field(..., description="One of: word_count, char_count, extract_urls, extract_emails, tokenize_sentences, deduplicate_lines, hash_sha256, base64_encode, base64_decode")

@router.post("/v1/text/process", tags=["Text Utilities"])
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


@router.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
def dashboard_root():
    return _serve_dashboard()

@router.get("/dashboard/{path:path}", response_class=HTMLResponse, tags=["Dashboard"])
def dashboard_catchall(path: str):
    return _serve_dashboard()


@router.get("/obstacle-course.md", tags=["System"])
async def serve_obstacle_course_md():
    path = os.path.join(_backend_dir, "obstacle-course.md")
    with open(path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/v1/obstacle-course.md", tags=["System"])
async def serve_obstacle_course_md_v1():
    path = os.path.join(_backend_dir, "obstacle-course.md")
    with open(path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.post("/v1/obstacle-course/submit", tags=["Obstacle Course"])
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


@router.get("/v1/obstacle-course/leaderboard", tags=["Obstacle Course"])
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


@router.get("/v1/obstacle-course/my-result", tags=["Obstacle Course"])
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


@router.get("/heartbeat.md", tags=["System"])
async def serve_heartbeat_md():
    hb_path = os.path.join(_backend_dir, "heartbeat.md")
    with open(hb_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/v1/heartbeat.md", tags=["System"])
async def serve_heartbeat_md_v1():
    hb_path = os.path.join(_backend_dir, "heartbeat.md")
    with open(hb_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/skill.md", tags=["System"])
async def serve_skill_md():
    skill_path = os.path.join(_backend_dir, "skill.md")
    with open(skill_path) as f:
        content = f.read()
    return Response(content=content, media_type="text/markdown")


@router.get("/v1/skill.md", tags=["System"])
async def serve_skill_md_v1():
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


@router.get("/", tags=["System"])
def root():
    return {
        "service": "MoltGrid",
        "version": "0.9.0",
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
