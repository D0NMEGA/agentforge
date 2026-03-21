"""User Dashboard routes (33 routes)."""

import json
import uuid
import io
import csv
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from croniter import croniter
from fastapi import APIRouter, HTTPException, Depends, Query, Response

from config import TIER_LIMITS, logger
from db import get_db
from helpers import (
    get_user_id, _verify_agent_ownership,
    _log_memory_access, _log_audit, _decrypt, _encrypt,
    _get_user_notification_prefs,
)
from models import (
    MemoryVisibilityRequest, MemoryBulkVisibilityRequest,
    TransferRequest, UserScheduleRequest, UserScheduleUpdateRequest,
    WebhookRegisterRequest,
    IntegrationStatusItem, IntegrationStatusResponse,
)

# Import webhook validation
from helpers import _is_safe_url


def _fill_date_series(rows, days, keys, date_key="date"):
    """Fill a sparse date-keyed result set with zeros for missing days.

    Given a list of dicts like [{"date": "2026-03-18", "count": 5}],
    returns a full series from (today - days) to today with 0s for gaps.
    """
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).date()
    all_dates = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    by_date = {r[date_key]: r for r in rows}
    result = []
    for d in all_dates:
        if d in by_date:
            result.append(dict(by_date[d]))
        else:
            entry = {date_key: d}
            for k in keys:
                entry[k] = 0
            result.append(entry)
    return result

router = APIRouter()

# Webhook event types (shared constant)
WEBHOOK_EVENT_TYPES = {"message.received", "message.broadcast", "job.completed", "job.failed", "marketplace.task.claimed", "marketplace.task.delivered", "marketplace.task.completed"}


@router.get("/v1/user/activity", tags=["User Dashboard"])
def user_activity(
    user_id: str = Depends(get_user_id),
    limit: int = Query(20, ge=1, le=100),
    days: int = Query(7, ge=1, le=90),
):
    """Recent activity events across all user's agents."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with get_db() as db:
        agent_rows = db.execute(
            "SELECT agent_id FROM agents WHERE owner_id=?", (str(user_id),)
        ).fetchall()
        agent_ids = [r["agent_id"] if isinstance(r, dict) else r[0] for r in agent_rows]
        if not agent_ids:
            return {"events": []}
        ph = ",".join("?" * len(agent_ids))
        rows = db.execute(
            "SELECT event_id, agent_id, event_type, payload, created_at "
            "FROM agent_events "
            f"WHERE agent_id IN ({ph}) AND created_at >= ? "
            "ORDER BY created_at DESC LIMIT ?",
            agent_ids + [cutoff, limit],
        ).fetchall()
    events = []
    for r in rows:
        try:
            payload = json.loads(r["payload"]) if r.get("payload") else {}
        except (json.JSONDecodeError, TypeError):
            payload = {"raw": str(r.get("payload",""))[:200] if r.get("payload") else ""}
        events.append({
            "event_id": r["event_id"],
            "agent_id": r["agent_id"],
            "event_type": r["event_type"],
            "payload": payload,
            "created_at": r["created_at"],
        })
    return {"events": events}


@router.get("/v1/user/overview", tags=["User Dashboard"])
def user_overview(user_id: str = Depends(get_user_id)):
    """Aggregated account overview: agents, totals, and 30-day charts."""
    import json as _json
    cutoff30 = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    with get_db() as db:
        agents_rows = db.execute(
            "SELECT a.agent_id, a.name, a.heartbeat_status, a.heartbeat_at, a.request_count, "
            "a.credits, a.onboarding_completed, "
            "(SELECT MAX(ocs.score) FROM obstacle_course_submissions ocs WHERE ocs.agent_id = a.agent_id) as obstacle_course_score, "
            "(SELECT CASE WHEN MAX(ocs.score) >= 100 THEN 1 ELSE 0 END FROM obstacle_course_submissions ocs WHERE ocs.agent_id = a.agent_id) as obstacle_course_passed "
            "FROM agents a WHERE a.owner_id=? ORDER BY a.created_at DESC",
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
        msg_rows = db.execute(
            f"SELECT substr(created_at,1,10) as date, COUNT(*) as count FROM relay "
            f"WHERE (from_agent IN ({placeholders}) OR to_agent IN ({placeholders})) AND created_at >= ? "
            f"GROUP BY date ORDER BY date",
            agent_ids + agent_ids + [cutoff30]
        ).fetchall()
        job_rows = db.execute(
            f"SELECT substr(created_at,1,10) as date, "
            f"SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed, "
            f"SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed "
            f"FROM queue WHERE agent_id IN ({placeholders}) AND created_at >= ? "
            f"GROUP BY date ORDER BY date",
            agent_ids + [cutoff30]
        ).fetchall()
    return {
        "total_agents": total_agents, "online_count": online_count, "agents": agents,
        "totals": {"messages_sent": messages_sent, "messages_received": messages_received,
                   "jobs_completed": jobs_completed, "jobs_failed": jobs_failed, "memory_keys": memory_keys},
        "msg_chart": _fill_date_series([dict(r) for r in msg_rows], 30, ["count"]),
        "job_chart": _fill_date_series([dict(r) for r in job_rows], 30, ["completed", "failed"]),
    }


@router.get("/v1/user/agents", tags=["User Dashboard"])
def user_list_agents(user_id: str = Depends(get_user_id)):
    """List all agents owned by this user, with computed stats for dashboard cards."""
    with get_db() as db:
        rows = db.execute(
            "SELECT a.agent_id, a.name, a.description, a.public, a.request_count, "
            "a.last_seen, a.heartbeat_at, a.heartbeat_status, a.created_at, "
            "a.credits, a.onboarding_completed, a.capabilities, a.skills, "
            "(SELECT COUNT(*) FROM memory m WHERE m.agent_id = a.agent_id) as memory_keys, "
            "(SELECT COUNT(*) FROM relay r WHERE r.from_agent = a.agent_id) as messages_sent, "
            "(SELECT COUNT(*) FROM relay r WHERE r.to_agent = a.agent_id) as messages_received, "
            "(SELECT MAX(ocs.score) FROM obstacle_course_submissions ocs WHERE ocs.agent_id = a.agent_id) as obstacle_course_score, "
            "(SELECT CASE WHEN MAX(ocs.score) >= 100 THEN 1 ELSE 0 END FROM obstacle_course_submissions ocs WHERE ocs.agent_id = a.agent_id) as obstacle_course_passed "
            "FROM agents a WHERE a.owner_id = ? ORDER BY a.created_at DESC",
            (user_id,),
        ).fetchall()

        agents = []
        for r in rows:
            d = dict(r)
            # Compute onboarding progress (0-7) for the dashboard card
            aid = d["agent_id"]
            progress = 1  # registration is always done
            if d.get("memory_keys", 0) > 0:
                progress += 1
            if d.get("messages_sent", 0) > 0:
                progress += 1
            has_queue = db.execute("SELECT COUNT(*) as c FROM queue WHERE agent_id=?", (aid,)).fetchone()["c"] > 0
            has_dlq = db.execute("SELECT COUNT(*) as c FROM dead_letter WHERE agent_id=?", (aid,)).fetchone()["c"] > 0
            if has_queue or has_dlq:
                progress += 1
            has_sched = db.execute("SELECT COUNT(*) as c FROM scheduled_tasks WHERE agent_id=?", (aid,)).fetchone()["c"] > 0
            if has_sched or (d.get("request_count") or 0) >= 50:
                progress += 1
            if d.get("description") is not None:
                progress += 1
            if d.get("heartbeat_at") is not None:
                progress += 1

            d["onboarding_progress"] = progress
            d["credits_balance"] = d.get("credits") or 0
            d["messages_count"] = (d.get("messages_sent") or 0) + (d.get("messages_received") or 0)
            d["capabilities"] = json.loads(d["capabilities"]) if d.get("capabilities") else []
            d["skills"] = json.loads(d["skills"]) if d.get("skills") else []
            agents.append(d)

    return {"agents": agents, "count": len(agents)}


@router.get("/v1/user/agents/{agent_id}/activity", tags=["User Dashboard"])
def user_agent_activity(
    agent_id: str,
    user_id: str = Depends(get_user_id),
    type: str = Query("all", description="Filter: all, messages, jobs, memory, schedules, security"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Activity feed for one owned agent."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        events = []
        for r in db.execute(
            "SELECT message_id, 'message_sent' as event_type, to_agent as target, "
            "channel, created_at as timestamp FROM relay WHERE from_agent = ? "
            "ORDER BY created_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))
        for r in db.execute(
            "SELECT message_id, 'message_received' as event_type, from_agent as source, "
            "channel, created_at as timestamp FROM relay WHERE to_agent = ? "
            "ORDER BY created_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))
        for r in db.execute(
            "SELECT job_id, 'job_' || status as event_type, queue_name, "
            "COALESCE(completed_at, started_at, created_at) as timestamp "
            "FROM queue WHERE agent_id = ? ORDER BY created_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))
        for r in db.execute(
            "SELECT key, namespace, 'memory_update' as event_type, "
            "updated_at as timestamp FROM memory WHERE agent_id = ? "
            "ORDER BY updated_at DESC LIMIT 50", (agent_id,)
        ).fetchall():
            events.append(dict(r))
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
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
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
    total = len(events)
    events = events[offset:offset + limit]
    return {"agent_id": agent_id, "events": events, "total": total}


@router.get("/v1/user/agents/{agent_id}/stats", tags=["User Dashboard"])
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
        "agent_id": agent_id, "name": agent["name"], "description": agent["description"],
        "heartbeat_status": agent["heartbeat_status"], "heartbeat_at": agent["heartbeat_at"],
        "request_count": agent["request_count"], "created_at": agent["created_at"],
        "last_seen": agent["last_seen"], "memory_keys": memory_keys,
        "jobs_pending": jobs_pending, "jobs_completed": jobs_completed, "jobs_failed": jobs_failed,
        "messages_sent": msgs_sent, "messages_received": msgs_received, "schedules_active": schedules,
    }



@router.get("/v1/user/agents/{agent_id}/charts", tags=["User Dashboard"])
def user_agent_charts(agent_id: str, days: int = Query(7, ge=1, le=90), user_id: str = Depends(get_user_id)):
    """Per-agent message and job charts for the given time window."""
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        msg_rows = db.execute(
            "SELECT substr(created_at,1,10) as date, "
            "SUM(CASE WHEN from_agent=? THEN 1 ELSE 0 END) as sent, "
            "SUM(CASE WHEN to_agent=? THEN 1 ELSE 0 END) as received "
            "FROM relay WHERE (from_agent=? OR to_agent=?) AND created_at >= ? "
            "GROUP BY date ORDER BY date",
            (agent_id, agent_id, agent_id, agent_id, cutoff)
        ).fetchall()
        job_rows = db.execute(
            "SELECT substr(created_at,1,10) as date, "
            "SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed, "
            "SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed, "
            "SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending "
            "FROM queue WHERE agent_id=? AND created_at >= ? "
            "GROUP BY date ORDER BY date",
            (agent_id, cutoff)
        ).fetchall()
    return {
        "messages": _fill_date_series([dict(r) for r in msg_rows], days, ["sent", "received"]),
        "jobs": _fill_date_series([dict(r) for r in job_rows], days, ["completed", "failed", "pending"]),
    }

@router.patch("/v1/user/agents/{agent_id}", tags=["User Dashboard"])
def user_rename_agent(agent_id: str, body: dict, user_id: str = Depends(get_user_id)):
    """Rename an owned agent."""
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


@router.post("/v1/user/agents/{agent_id}/rotate-key", tags=["User Dashboard"])
def user_rotate_key(agent_id: str, user_id: str = Depends(get_user_id)):
    """Rotate API key for an owned agent."""
    from helpers import hash_key, generate_api_key
    new_key = generate_api_key()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute("UPDATE agents SET api_key_hash=? WHERE agent_id=?", (hash_key(new_key), agent_id))
    _log_audit("apikey.rotate", user_id=user_id, agent_id=agent_id)
    return {
        "status": "rotated", "agent_id": agent_id, "api_key": new_key,
        "rotated_at": datetime.now(timezone.utc).isoformat(),
        "message": "Store your new API key securely. The old key is now invalid.",
    }


@router.delete("/v1/user/agents/{agent_id}", tags=["User Dashboard"])
def user_delete_agent(agent_id: str, user_id: str = Depends(get_user_id)):
    """Delete an owned agent and all its data."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        # Delete webhook_deliveries via webhook IDs (no agent_id column in that table)
        wh_rows = db.execute("SELECT webhook_id FROM webhooks WHERE agent_id=?", (agent_id,)).fetchall()
        wh_ids = [r["webhook_id"] if isinstance(r, dict) else r[0] for r in wh_rows]
        if wh_ids:
            ph = ",".join("?" * len(wh_ids))
            db.execute(f"DELETE FROM webhook_deliveries WHERE webhook_id IN ({ph})", wh_ids)
        # Cascade delete from all tables with agent_id column
        for tbl in ["memory", "queue", "webhooks", "scheduled_tasks",
                     "rate_limits", "vector_memory", "memory_access_log",
                     "sessions", "pubsub_subscriptions", "integrations",
                     "agent_events", "dead_letter", "obstacle_course_submissions"]:
            db.execute(f"DELETE FROM {tbl} WHERE agent_id=?", (agent_id,))
        # Tables with different column names
        db.execute("DELETE FROM shared_memory WHERE owner_agent=?", (agent_id,))
        db.execute("DELETE FROM relay WHERE from_agent=? OR to_agent=?", (agent_id, agent_id))
        db.execute("DELETE FROM collaborations WHERE agent_id=? OR partner_agent=?", (agent_id, agent_id))
        db.execute("DELETE FROM marketplace WHERE creator_agent=?", (agent_id,))
        db.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
    _log_audit("agent.delete", user_id=user_id, agent_id=agent_id)
    return {"status": "deleted", "agent_id": agent_id}


@router.get("/v1/user/usage", tags=["User Dashboard"])
def user_usage(user_id: str = Depends(get_user_id)):
    """Aggregate usage stats for the current billing period."""
    now = datetime.now(timezone.utc)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
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
        agent_ids = [r["agent_id"] for r in db.execute("SELECT agent_id FROM agents WHERE owner_id = ?", (user_id,)).fetchall()]
        total_agents = len(agent_ids)
        if not agent_ids:
            return {"total_api_calls": user["usage_count"], "total_agents": 0, "memory_keys": 0,
                    "jobs_submitted": 0, "messages_sent": 0, "period_start": period_start,
                    "period_end": period_end, "tier": tier, "limits": limits}
        placeholders = ",".join("?" * len(agent_ids))
        memory_keys = db.execute(f"SELECT COUNT(*) as cnt FROM memory WHERE agent_id IN ({placeholders})", agent_ids).fetchone()["cnt"]
        jobs_submitted = db.execute(f"SELECT COUNT(*) as cnt FROM queue WHERE agent_id IN ({placeholders}) AND created_at >= ?", agent_ids + [period_start]).fetchone()["cnt"]
        messages_sent = db.execute(f"SELECT COUNT(*) as cnt FROM relay WHERE from_agent IN ({placeholders}) AND created_at >= ?", agent_ids + [period_start]).fetchone()["cnt"]
    return {"total_api_calls": user["usage_count"], "total_agents": total_agents, "memory_keys": memory_keys,
            "jobs_submitted": jobs_submitted, "messages_sent": messages_sent, "period_start": period_start,
            "period_end": period_end, "tier": tier, "limits": limits}


@router.get("/v1/user/billing", tags=["User Dashboard"])
def user_billing(user_id: str = Depends(get_user_id)):
    """Subscription and billing info."""
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
    tier = user["subscription_tier"] or "free"
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    now = datetime.now(timezone.utc)
    if now.month == 12:
        next_billing = now.replace(year=now.year + 1, month=1, day=1).strftime("%Y-%m-%d")
    else:
        next_billing = now.replace(month=now.month + 1, day=1).strftime("%Y-%m-%d")
    return {"tier": tier, "max_agents": limits["max_agents"], "max_api_calls": limits["max_api_calls"],
            "usage_count": user["usage_count"], "stripe_customer_id": user["stripe_customer_id"],
            "next_billing_date": next_billing}


@router.post("/v1/user/agents/{agent_id}/transfer", tags=["User Dashboard"])
def user_transfer_agent(agent_id: str, req: TransferRequest, user_id: str = Depends(get_user_id)):
    """Transfer agent ownership to another user by email."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        recipient = db.execute("SELECT user_id, subscription_tier FROM users WHERE email = ?", (req.to_email.lower(),)).fetchone()
        if not recipient:
            raise HTTPException(404, "Recipient user not found")
        if recipient["user_id"] == user_id:
            raise HTTPException(400, "Cannot transfer to yourself")
        r_tier = recipient["subscription_tier"] or "free"
        r_limit = TIER_LIMITS.get(r_tier, TIER_LIMITS["free"])["max_agents"]
        r_count = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE owner_id = ?", (recipient["user_id"],)).fetchone()["cnt"]
        if r_limit is not None and r_count >= r_limit:
            raise HTTPException(403, f"Recipient has reached their agent limit ({r_limit})")
        db.execute("UPDATE agents SET owner_id = ? WHERE agent_id = ?", (recipient["user_id"], agent_id))
    return {"agent_id": agent_id, "transferred_to": req.to_email.lower(), "message": "Transfer complete"}


@router.delete("/v1/user/account", tags=["User Dashboard"])
def user_delete_account(user_id: str = Depends(get_user_id)):
    """Soft-delete user account."""
    with get_db() as db:
        db.execute("UPDATE users SET subscription_tier = 'deleted', max_agents = 0, max_api_calls = 0 WHERE user_id = ?", (user_id,))
        db.execute("UPDATE agents SET owner_id = NULL WHERE owner_id = ?", (user_id,))
    return {"user_id": user_id, "message": "Account deactivated. Agents unlinked."}


@router.post("/v1/user/account/hard-delete", tags=["User Dashboard"])
def user_hard_delete_account(user_id: str = Depends(get_user_id)):
    """GDPR right to erasure."""
    with get_db() as db:
        agent_rows = db.execute("SELECT agent_id FROM agents WHERE owner_id=?", (user_id,)).fetchall()
        for row in agent_rows:
            aid = row["agent_id"]
            for tbl in ["memory", "vector_memory", "queue", "webhooks", "scheduled_tasks",
                         "shared_memory", "rate_limits", "memory_access_log"]:
                db.execute(f"DELETE FROM {tbl} WHERE agent_id=?", (aid,))
            db.execute("DELETE FROM relay WHERE from_agent=? OR to_agent=?", (aid, aid))
            db.execute("DELETE FROM collaborations WHERE agent_id=? OR partner_agent=?", (aid, aid))
            db.execute("DELETE FROM marketplace WHERE creator_agent=?", (aid,))
            db.execute("DELETE FROM agents WHERE agent_id=?", (aid,))
        db.execute("DELETE FROM users WHERE user_id=?", (user_id,))
    _log_audit("account.hard_delete", user_id=user_id)
    return {"status": "deleted", "message": "All data permanently erased per GDPR Article 17."}


@router.get("/v1/user/data-export", tags=["User Dashboard"])
def user_data_export(user_id: str = Depends(get_user_id)):
    """GDPR right to data portability."""
    with get_db() as db:
        user = db.execute("SELECT user_id, email, display_name, subscription_tier, created_at FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        agents = db.execute("SELECT agent_id, name, display_name, status, created_at FROM agents WHERE owner_id=?", (user_id,)).fetchall()
        export = {"user": dict(user), "agents": [], "exported_at": datetime.utcnow().isoformat() + "Z"}
        for agent in agents:
            aid = agent["agent_id"]
            memories = db.execute("SELECT key, namespace, value, visibility, created_at, updated_at FROM memory WHERE agent_id=?", (aid,)).fetchall()
            vectors = db.execute("SELECT key, namespace, text, metadata, created_at, updated_at FROM vector_memory WHERE agent_id=?", (aid,)).fetchall()
            messages = db.execute("SELECT from_agent, to_agent, channel, payload, created_at FROM relay WHERE from_agent=? OR to_agent=?", (aid, aid)).fetchall()
            jobs = db.execute("SELECT job_id, queue_name, payload, status, created_at FROM queue WHERE agent_id=?", (aid,)).fetchall()
            export["agents"].append({"agent": dict(agent), "memory": [dict(m) for m in memories],
                                     "vector_memory": [dict(v) for v in vectors],
                                     "messages": [dict(m) for m in messages], "jobs": [dict(j) for j in jobs]})
    _log_audit("data.export", user_id=user_id)
    return export


@router.get("/v1/user/agents/{agent_id}/messages-list", tags=["User Dashboard"])
def user_messages_list(agent_id: str, offset: int = 0, limit: int = 20, direction: str = "all", search: str = "", user_id: str = Depends(get_user_id)):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        if direction == "sent":
            cond = "from_agent = ?"; params = [agent_id]
        elif direction == "received":
            cond = "to_agent = ?"; params = [agent_id]
        else:
            cond = "(from_agent = ? OR to_agent = ?)"; params = [agent_id, agent_id]
        total = db.execute(f"SELECT COUNT(*) as c FROM relay WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(f"SELECT message_id, from_agent, to_agent, channel, created_at FROM relay WHERE {cond} ORDER BY created_at DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for col, aid in [("from_name", d["from_agent"]), ("to_name", d["to_agent"])]:
                a = db.execute("SELECT name FROM agents WHERE agent_id=?", (aid,)).fetchone()
                d[col] = a["name"] if a and a["name"] else aid
            result.append(d)
    return {"messages": result, "total": total, "offset": offset, "limit": limit}


@router.get("/v1/user/agents/{agent_id}/messages/{message_id}", tags=["User Dashboard"])
def user_message_detail(agent_id: str, message_id: str, user_id: str = Depends(get_user_id)):
    """Get full detail for a single relay message."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        row = db.execute("SELECT message_id, from_agent, to_agent, channel, payload, created_at, read_at FROM relay WHERE message_id=? AND (from_agent=? OR to_agent=?)", (message_id, agent_id, agent_id)).fetchone()
        if not row:
            raise HTTPException(404, "Message not found")
        d = dict(row)
        d["payload"] = _decrypt(d["payload"])
        for col, aid in [("from_name", d["from_agent"]), ("to_name", d["to_agent"])]:
            a = db.execute("SELECT name FROM agents WHERE agent_id=?", (aid,)).fetchone()
            d[col] = a["name"] if a and a["name"] else aid
    return d


@router.get("/v1/user/agents/{agent_id}/memory-list", tags=["User Dashboard"])
def user_memory_list(agent_id: str, offset: int = 0, limit: int = 30, namespace: str = "", search: str = "", visibility: str = "", user_id: str = Depends(get_user_id)):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        cond = "agent_id = ?"; params = [agent_id]
        if namespace: cond += " AND namespace = ?"; params.append(namespace)
        if search: cond += " AND key LIKE ?"; params.append(f"%{search}%")
        if visibility in ("private", "public", "shared"): cond += " AND COALESCE(visibility,'private') = ?"; params.append(visibility)
        total = db.execute(f"SELECT COUNT(*) as c FROM memory WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(f"SELECT namespace, key, created_at, updated_at, expires_at, COALESCE(visibility,'private') as visibility, shared_agents FROM memory WHERE {cond} ORDER BY updated_at DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
        ns_rows = db.execute("SELECT DISTINCT namespace FROM memory WHERE agent_id=? ORDER BY namespace", (agent_id,)).fetchall()
    return {"keys": [dict(r) for r in rows], "total": total, "offset": offset, "limit": limit, "namespaces": [r["namespace"] for r in ns_rows]}


@router.get("/v1/user/agents/{agent_id}/memory-entry", tags=["User Dashboard"])
def user_memory_get(agent_id: str, namespace: str = "default", key: str = "", user_id: str = Depends(get_user_id)):
    """Fetch a single memory entry including its value and visibility metadata."""
    if not key: raise HTTPException(400, "key is required")
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        row = db.execute("SELECT namespace, key, value, created_at, updated_at, expires_at, COALESCE(visibility,'private') as visibility, shared_agents FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)", (agent_id, namespace, key, now)).fetchone()
    if not row: raise HTTPException(404, "Memory key not found or expired")
    d = dict(row); d["value"] = _decrypt(d["value"]); d["shared_agents"] = json.loads(d["shared_agents"] or "[]")
    return d


@router.patch("/v1/user/agents/{agent_id}/memory-entry/visibility", tags=["User Dashboard"])
def user_memory_set_visibility(agent_id: str, req: MemoryVisibilityRequest, user_id: str = Depends(get_user_id)):
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        old = db.execute("SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, req.namespace, req.key)).fetchone()
        if not old: raise HTTPException(404, "Memory key not found")
        db.execute("UPDATE memory SET visibility=?, shared_agents=? WHERE agent_id=? AND namespace=? AND key=?", (vis, sa_json, agent_id, req.namespace, req.key))
    _log_memory_access("visibility_changed", agent_id, req.namespace, req.key, actor_user_id=user_id, old_visibility=old["visibility"] or "private", new_visibility=vis)
    return {"status": "updated", "key": req.key, "namespace": req.namespace, "visibility": vis}


@router.post("/v1/user/agents/{agent_id}/memory-bulk-visibility", tags=["User Dashboard"])
def user_memory_bulk_visibility(agent_id: str, req: MemoryBulkVisibilityRequest, user_id: str = Depends(get_user_id)):
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    updated = 0; log_entries = []
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        for entry in req.entries[:200]:
            ns = entry.get("namespace", "default"); k = entry.get("key", "")
            if not k: continue
            old = db.execute("SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, ns, k)).fetchone()
            if not old: continue
            db.execute("UPDATE memory SET visibility=?, shared_agents=? WHERE agent_id=? AND namespace=? AND key=?", (vis, sa_json, agent_id, ns, k))
            log_entries.append((ns, k, old["visibility"] or "private")); updated += 1
    for ns, k, old_vis in log_entries:
        _log_memory_access("visibility_changed", agent_id, ns, k, actor_user_id=user_id, old_visibility=old_vis, new_visibility=vis)
    return {"status": "updated", "count": updated, "visibility": vis}


@router.get("/v1/user/agents/{agent_id}/memory-access-log", tags=["User Dashboard"])
def user_memory_access_log(agent_id: str, namespace: str = "", key: str = "", offset: int = 0, limit: int = 50, user_id: str = Depends(get_user_id)):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        cond = "agent_id = ?"; params = [agent_id]
        if namespace: cond += " AND namespace = ?"; params.append(namespace)
        if key: cond += " AND key = ?"; params.append(key)
        total = db.execute(f"SELECT COUNT(*) as c FROM memory_access_log WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(f"SELECT id, namespace, key, action, actor_agent_id, actor_user_id, old_visibility, new_visibility, authorized, created_at FROM memory_access_log WHERE {cond} ORDER BY created_at DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
    return {"logs": [dict(r) for r in rows], "total": total, "offset": offset}


@router.delete("/v1/user/agents/{agent_id}/memory-entry", tags=["User Dashboard"])
def user_memory_delete(agent_id: str, namespace: str = "default", key: str = "", user_id: str = Depends(get_user_id)):
    if not key: raise HTTPException(400, "key is required")
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        deleted = db.execute("DELETE FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, namespace, key)).rowcount
    if not deleted: raise HTTPException(404, "Memory key not found")
    _log_memory_access("delete", agent_id, namespace, key, actor_user_id=user_id)
    return {"status": "deleted"}


@router.get("/v1/user/agents/{agent_id}/integrations", tags=["User Dashboard"])
def user_integration_list(agent_id: str, user_id: str = Depends(get_user_id)):
    """List platform integrations for an owned agent (dashboard)."""
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        rows = db.execute("SELECT id, platform, config, status, created_at FROM integrations WHERE agent_id=? ORDER BY created_at DESC", (agent_id,)).fetchall()
    integrations = []
    for r in rows:
        item = dict(r)
        if item.get("config"):
            try: item["config"] = json.loads(item["config"])
            except Exception: pass
        integrations.append(item)
    return {"agent_id": agent_id, "integrations": integrations}


@router.get("/v1/user/integrations/status", response_model=IntegrationStatusResponse, tags=["User Dashboard"])
def user_integrations_status(agent_id: Optional[str] = None, user_id: str = Depends(get_user_id)):
    """Return integration status with event counts."""
    with get_db() as db:
        if agent_id:
            _verify_agent_ownership(db, agent_id, user_id)
            rows = db.execute("SELECT i.id, i.agent_id, i.platform, i.status, i.created_at FROM integrations i JOIN agents a ON i.agent_id = a.agent_id WHERE a.owner_id = ? AND i.agent_id = ? ORDER BY i.created_at DESC", (user_id, agent_id)).fetchall()
        else:
            rows = db.execute("SELECT i.id, i.agent_id, i.platform, i.status, i.created_at FROM integrations i JOIN agents a ON i.agent_id = a.agent_id WHERE a.owner_id = ? ORDER BY i.created_at DESC", (user_id,)).fetchall()
        items = []
        for r in rows:
            count_row = db.execute("SELECT COUNT(*) as c FROM analytics_events WHERE agent_id = ? AND source != 'moltgrid_api'", (r["agent_id"],)).fetchone()
            items.append(IntegrationStatusItem(integration_id=r["id"], agent_id=r["agent_id"], platform=r["platform"], status=r["status"], last_sync_at=r["created_at"], event_count=count_row["c"] if count_row else 0))
    return IntegrationStatusResponse(integrations=items)


@router.get("/v1/user/agents/{agent_id}/jobs-list", tags=["User Dashboard"])
def user_jobs_list(agent_id: str, offset: int = 0, limit: int = 20, status: str = "all", user_id: str = Depends(get_user_id)):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        cond = "agent_id = ?"; params = [agent_id]
        if status != "all": cond += " AND status = ?"; params.append(status)
        total = db.execute(f"SELECT COUNT(*) as c FROM queue WHERE {cond}", params).fetchone()["c"]
        rows = db.execute(f"SELECT job_id, queue_name, status, priority, created_at, started_at, completed_at, failed_at, fail_reason, attempt_count, max_attempts FROM queue WHERE {cond} ORDER BY created_at DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
    return {"jobs": [dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.get("/v1/user/agents/{agent_id}/schedules", tags=["User Dashboard"])
def user_schedules_list(agent_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        rows = db.execute("SELECT task_id, cron_expr, queue_name, priority, enabled, last_run_at, next_run_at, run_count, created_at FROM scheduled_tasks WHERE agent_id=? ORDER BY created_at DESC", (agent_id,)).fetchall()
    return {"schedules": [dict(r) for r in rows]}


@router.post("/v1/user/agents/{agent_id}/schedules", tags=["User Dashboard"])
def user_schedule_create(agent_id: str, req: UserScheduleRequest, user_id: str = Depends(get_user_id)):
    try:
        cron = croniter(req.cron_expr, datetime.now(timezone.utc)); next_run = cron.get_next(datetime).isoformat()
    except (ValueError, KeyError) as e:
        raise HTTPException(400, f"Invalid cron expression: {e}")
    task_id = f"task_{uuid.uuid4().hex[:16]}"; now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute("INSERT INTO scheduled_tasks (task_id, agent_id, cron_expr, queue_name, payload, priority, enabled, created_at, next_run_at, run_count) VALUES (?,?,?,?,?,?,1,?,?,0)", (task_id, agent_id, req.cron_expr, req.queue_name, _encrypt(req.payload), req.priority, now, next_run))
    _log_audit("schedule.create", user_id=user_id, agent_id=agent_id, details=task_id)
    return {"task_id": task_id, "cron_expr": req.cron_expr, "next_run_at": next_run, "enabled": True}


@router.patch("/v1/user/agents/{agent_id}/schedules/{task_id}", tags=["User Dashboard"])
def user_schedule_update(agent_id: str, task_id: str, req: UserScheduleUpdateRequest, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        row = db.execute("SELECT * FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)).fetchone()
        if not row: raise HTTPException(404, "Schedule not found")
        updates = []; params = []
        if req.enabled is not None: updates.append("enabled=?"); params.append(1 if req.enabled else 0)
        if req.cron_expr is not None:
            try:
                cron = croniter(req.cron_expr, datetime.now(timezone.utc)); next_run = cron.get_next(datetime).isoformat()
            except (ValueError, KeyError) as e:
                raise HTTPException(400, f"Invalid cron: {e}")
            updates.append("cron_expr=?"); params.append(req.cron_expr)
            updates.append("next_run_at=?"); params.append(next_run)
        if not updates: raise HTTPException(400, "Nothing to update")
        db.execute(f"UPDATE scheduled_tasks SET {', '.join(updates)} WHERE task_id=?", params + [task_id])
        row = db.execute("SELECT * FROM scheduled_tasks WHERE task_id=?", (task_id,)).fetchone()
    return dict(row)


@router.delete("/v1/user/agents/{agent_id}/schedules/{task_id}", tags=["User Dashboard"])
def user_schedule_delete(agent_id: str, task_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        deleted = db.execute("DELETE FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)).rowcount
    if not deleted: raise HTTPException(404, "Schedule not found")
    _log_audit("schedule.delete", user_id=user_id, agent_id=agent_id, details=task_id)
    return {"status": "deleted"}


@router.get("/v1/user/agents/{agent_id}/webhooks", tags=["User Dashboard"])
def user_webhooks_list(agent_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        rows = db.execute("SELECT webhook_id, url, event_types, active, created_at FROM webhooks WHERE agent_id=? ORDER BY created_at DESC", (agent_id,)).fetchall()
    return {"webhooks": [dict(r) for r in rows]}


@router.post("/v1/user/agents/{agent_id}/webhooks", tags=["User Dashboard"])
def user_webhook_create(agent_id: str, req: WebhookRegisterRequest, user_id: str = Depends(get_user_id)):
    if not _is_safe_url(req.url): raise HTTPException(400, "Webhook URL points to a private/internal address")
    for et in req.event_types:
        if et not in WEBHOOK_EVENT_TYPES: raise HTTPException(400, f"Invalid event type: {et}")
    webhook_id = f"wh_{uuid.uuid4().hex[:16]}"; now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        db.execute("INSERT INTO webhooks (webhook_id, agent_id, url, event_types, secret, created_at, active) VALUES (?,?,?,?,?,?,1)", (webhook_id, agent_id, req.url, json.dumps(req.event_types), req.secret, now))
    _log_audit("webhook.create", user_id=user_id, agent_id=agent_id, details=webhook_id)
    return {"webhook_id": webhook_id, "url": req.url, "event_types": req.event_types, "active": True}


@router.delete("/v1/user/agents/{agent_id}/webhooks/{webhook_id}", tags=["User Dashboard"])
def user_webhook_delete(agent_id: str, webhook_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        deleted = db.execute("DELETE FROM webhooks WHERE webhook_id=? AND agent_id=?", (webhook_id, agent_id)).rowcount
    if not deleted: raise HTTPException(404, "Webhook not found")
    _log_audit("webhook.delete", user_id=user_id, agent_id=agent_id, details=webhook_id)
    return {"status": "deleted"}


@router.get("/v1/user/audit-log/export", tags=["User Dashboard"])
def user_audit_log_export(action: Optional[str] = None, from_date: Optional[str] = None, to_date: Optional[str] = None, user_id: str = Depends(get_user_id)):
    """Export audit log entries as CSV."""
    base = "SELECT log_id, action, agent_id, details, ip_address, created_at FROM audit_logs WHERE user_id = ?"
    params: list = [user_id]
    if action: base += " AND action = ?"; params.append(action)
    if from_date: base += " AND created_at >= ?"; params.append(from_date)
    if to_date: base += " AND created_at <= ?"; params.append(to_date)
    base += " ORDER BY created_at DESC"
    with get_db() as db:
        rows = db.execute(base, params).fetchall()
    buf = io.StringIO(); writer = csv.writer(buf)
    writer.writerow(["timestamp", "action", "agent_id", "details", "ip_address"])
    for row in rows:
        writer.writerow([row["created_at"], row["action"], row["agent_id"] or "", row["details"] or "", row["ip_address"] or ""])
    return Response(content=buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit-log.csv"})


@router.get("/v1/user/audit-log", tags=["User Dashboard"])
def user_audit_log(action: Optional[str] = None, from_date: Optional[str] = None, to_date: Optional[str] = None, limit: int = 50, offset: int = 0, user_id: str = Depends(get_user_id)):
    """Retrieve audit log entries for the authenticated user."""
    base = "SELECT log_id, action, agent_id, details, ip_address, created_at FROM audit_logs WHERE user_id = ?"
    count_base = "SELECT COUNT(*) as cnt FROM audit_logs WHERE user_id = ?"
    params: list = [user_id]; count_params: list = [user_id]
    if action: base += " AND action = ?"; count_base += " AND action = ?"; params.append(action); count_params.append(action)
    if from_date: base += " AND created_at >= ?"; count_base += " AND created_at >= ?"; params.append(from_date); count_params.append(from_date)
    if to_date: base += " AND created_at <= ?"; count_base += " AND created_at <= ?"; params.append(to_date); count_params.append(to_date)
    capped_limit = min(limit, 200)
    base += " ORDER BY created_at DESC LIMIT ? OFFSET ?"; params.extend([capped_limit, offset])
    with get_db() as db:
        rows = db.execute(base, params).fetchall()
        total = db.execute(count_base, count_params).fetchone()["cnt"]
    return {"entries": [dict(r) for r in rows], "total": total, "limit": capped_limit, "offset": offset}

