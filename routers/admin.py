"""Admin routes (20 routes)."""

import os
import json
import time
import hashlib
import secrets
import hmac as _hmac
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt as _bcrypt
from fastapi import APIRouter, HTTPException, Depends, Query, Cookie, Response, Request
from fastapi.responses import HTMLResponse

from config import ADMIN_PASSWORD_HASH, ADMIN_SESSION_TTL, _fernet, logger
from db import get_db
from state import _ws_connections
from helpers import (
    _check_auth_rate_limit, _decrypt, _encrypt, _fire_webhooks,
)
from pydantic import BaseModel
from models import AdminLoginRequest, AdminEmailRequest

from rate_limit import limiter, make_tier_limit
import time as _time

# Progressive lockout: 5 failures per IP -> 429 for 15 minutes
_admin_lockout: dict[str, list[float]] = {}
_ADMIN_LOCKOUT_MAX = 5
_ADMIN_LOCKOUT_WINDOW = 900  # 15 minutes in seconds


def _check_admin_lockout(request):
    """Block admin login if IP has 5+ failures in 15 minutes."""
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
    now = _time.time()
    attempts = _admin_lockout.get(ip, [])
    attempts = [t for t in attempts if now - t < _ADMIN_LOCKOUT_WINDOW]
    _admin_lockout[ip] = attempts
    if len(attempts) >= _ADMIN_LOCKOUT_MAX:
        raise HTTPException(429, "Too many failed login attempts. Try again later.")


def _record_admin_failure(request):
    """Record a failed admin login attempt."""
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
    now = _time.time()
    attempts = _admin_lockout.get(ip, [])
    attempts = [t for t in attempts if now - t < _ADMIN_LOCKOUT_WINDOW]
    attempts.append(now)
    _admin_lockout[ip] = attempts

router = APIRouter()

def _parse_marketplace_row(row):
    d = dict(row)
    d["requirements"] = json.loads(d["requirements"]) if d["requirements"] else []
    d["tags"] = json.loads(d["tags"]) if d["tags"] else []
    if d.get("description"): d["description"] = _decrypt(d["description"])
    if d.get("result"): d["result"] = _decrypt(d["result"])
    return d


# __file__ is routers/admin.py, so go up one level to get the project root
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

@router.post("/admin/api/login", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_login(req: AdminLoginRequest, request: Request, response: Response):
    """Authenticate admin and set session cookie."""
    _check_auth_rate_limit(request)
    _check_admin_lockout(request)
    if not ADMIN_PASSWORD_HASH:
        raise HTTPException(503, "Admin not configured. Set ADMIN_PASSWORD_HASH env var.")
    # Support bcrypt hashes (start with $2) with SHA-256 fallback for backward compat
    if ADMIN_PASSWORD_HASH.startswith("$2"):
        try:
            valid = _bcrypt.checkpw(req.password.encode(), ADMIN_PASSWORD_HASH.encode())
        except (ValueError, TypeError):
            valid = False
        if not valid:
            _record_admin_failure(request)
            raise HTTPException(401, "Invalid credentials")
    else:
        incoming_hash = hashlib.sha256(req.password.encode()).hexdigest()
        if not _hmac.compare_digest(incoming_hash, ADMIN_PASSWORD_HASH):
            _record_admin_failure(request)
            raise HTTPException(401, "Invalid credentials")
    token = secrets.token_urlsafe(48)
    expires_at = time.time() + ADMIN_SESSION_TTL
    with get_db() as db:
        # Clean up expired sessions
        db.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (time.time(),))
        db.execute("INSERT INTO admin_sessions (token, expires_at) VALUES (?, ?)", (token, expires_at))
    response.set_cookie(
        key="admin_token", value=token, httponly=True,
        secure=True, max_age=ADMIN_SESSION_TTL, samesite="lax", path="/",
    )
    return {"status": "authenticated"}

@router.post("/admin/api/logout", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_logout(request: Request, response: Response, admin_token: str = Cookie(None)):
    """Log out admin session."""
    if admin_token:
        with get_db() as db:
            db.execute("DELETE FROM admin_sessions WHERE token=?", (admin_token,))
    response.delete_cookie("admin_token", path="/")
    return {"status": "logged_out"}

@router.get("/admin/api/dashboard", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_dashboard(request: Request, _: bool = Depends(_verify_admin_session)):
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
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "encryption_enabled": _fernet is not None,
    }

@router.get("/admin/api/messages", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_messages(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/webhook-deliveries", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_webhook_deliveries(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/analytics", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_analytics(request: Request, _: bool = Depends(_verify_admin_session)):
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

@router.get("/admin/api/memory", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_memory(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/queue", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_queue(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/webhooks", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_webhooks(request: Request, _: bool = Depends(_verify_admin_session)):
    """Browse all registered webhooks."""
    with get_db() as db:
        rows = db.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
    return {"webhooks": [{**dict(r), "event_types": json.loads(r["event_types"])} for r in rows], "total": len(rows)}

@router.get("/admin/api/schedules", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_schedules(request: Request, _: bool = Depends(_verify_admin_session)):
    """Browse all scheduled tasks."""
    with get_db() as db:
        rows = db.execute("SELECT * FROM scheduled_tasks ORDER BY created_at DESC").fetchall()
    schedules = [dict(r) for r in rows]
    for s in schedules:
        s["payload"] = _decrypt(s["payload"])
    return {"schedules": schedules, "total": len(schedules)}

@router.get("/admin/api/shared-memory", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_shared_memory(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/sla", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_sla(request: Request, _: bool = Depends(_verify_admin_session)):
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

@router.get("/admin/api/agents/{agent_id}", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_agent_detail(request: Request, agent_id: str, _: bool = Depends(_verify_admin_session)):
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

@router.delete("/admin/api/agents/{agent_id}", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_delete_agent(request: Request, agent_id: str, _: bool = Depends(_verify_admin_session)):
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

@router.get("/admin/api/collaborations", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_collaborations(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/marketplace", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_marketplace(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/scenarios", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_scenarios(request: Request, 
    limit: int = Query(100, ge=1, le=500),
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

@router.get("/admin/api/contact", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_contact(request: Request, 
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: bool = Depends(_verify_admin_session),
):
    """Browse contact form submissions."""
    with get_db() as db:
        rows = db.execute("SELECT * FROM contact_submissions ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        total = db.execute("SELECT COUNT(*) as c FROM contact_submissions").fetchone()["c"]
    return {"submissions": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

@router.post("/admin/api/email", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_email(request: Request, req: AdminEmailRequest, _: bool = Depends(_verify_admin_session)):
    """Preview or send a branded email from the admin panel."""
    from helpers import _branded_email, _queue_email, _email_from

    rendered = _branded_email(req.title, req.body_html)

    if req.send:
        _queue_email(req.to_email, req.subject, rendered, req.from_category)
        return {"status": "queued", "preview": rendered, "from": _email_from(req.from_category)}

    return {"status": "preview", "preview": rendered, "from": _email_from(req.from_category)}

@router.get("/admin/api/emails", tags=["Admin"])
@limiter.limit(make_tier_limit("admin"))
def admin_email_history(request: Request, _: bool = Depends(_verify_admin_session)):
    """List recent emails from the queue."""
    with get_db() as db:
        emails = db.execute(
            "SELECT id, to_email, subject, status, from_display, created_at, sent_at "
            "FROM email_queue ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    return {"emails": [dict(e) for e in emails]}

@router.get("/admin/login", response_class=HTMLResponse, tags=["Admin"])
def admin_login_page():
    """Serve the admin login page."""
    html_path = _find_html("admin_login.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Admin login page not found")

@router.get("/admin", response_class=HTMLResponse, tags=["Admin"])
def admin_page():
    """Serve the admin dashboard page."""
    html_path = _find_html("admin.html")
    try:
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(404, "Admin page not found")
