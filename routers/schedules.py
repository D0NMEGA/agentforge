"""Schedules routes (5 routes)."""

import json
import uuid
from datetime import datetime, timezone

from croniter import croniter
from fastapi import APIRouter, HTTPException, Depends, Query, Request

from config import MAX_QUEUE_PAYLOAD_SIZE
from db import get_db
from helpers import get_agent_id, _encrypt, _decrypt
from models import ScheduledTaskRequest, ScheduleUpdateRequest, ScheduledTaskResponse, ScheduleListResponse

from rate_limit import limiter, make_tier_limit

router = APIRouter()

@router.post("/v1/schedules", response_model=ScheduledTaskResponse, tags=["Schedules"])
@limiter.limit(make_tier_limit("agent_write"))
def schedule_create(request: Request, req: ScheduledTaskRequest, agent_id: str = Depends(get_agent_id)):
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

@router.get("/v1/schedules", response_model=ScheduleListResponse, tags=["Schedules"])
@limiter.limit(make_tier_limit("agent_read"))
def schedule_list(request: Request, agent_id: str = Depends(get_agent_id)):
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

@router.get("/v1/schedules/{task_id}", tags=["Schedules"])
@limiter.limit(make_tier_limit("agent_read"))
def schedule_get(request: Request, task_id: str, agent_id: str = Depends(get_agent_id)):
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

@router.patch("/v1/schedules/{task_id}", tags=["Schedules"])
@limiter.limit(make_tier_limit("agent_write"))
def schedule_update(request: Request, task_id: str, req: ScheduleUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update a scheduled task. Supports enabling/disabling and updating fields."""
    with get_db() as db:
        row = db.execute(
            "SELECT cron_expr, enabled FROM scheduled_tasks WHERE task_id=? AND agent_id=?",
            (task_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Scheduled task not found")

        updates = []
        params = []

        if req.cron_expr is not None:
            try:
                croniter(req.cron_expr, datetime.now(timezone.utc))
            except (ValueError, KeyError) as e:
                raise HTTPException(400, f"Invalid cron expression: {e}")
            updates.append("cron_expr=?")
            params.append(req.cron_expr)

        if req.queue_name is not None:
            updates.append("queue_name=?")
            params.append(req.queue_name)

        if req.priority is not None:
            updates.append("priority=?")
            params.append(req.priority)

        if req.enabled is not None:
            updates.append("enabled=?")
            params.append(int(req.enabled))
            # If re-enabling, recalculate next_run
            if req.enabled:
                cron_expr = req.cron_expr if req.cron_expr is not None else row["cron_expr"]
                cron = croniter(cron_expr, datetime.now(timezone.utc))
                next_run = cron.get_next(datetime).isoformat()
                updates.append("next_run_at=?")
                params.append(next_run)

        if not updates:
            raise HTTPException(400, "No fields to update")

        params.extend([task_id, agent_id])
        db.execute(
            f"UPDATE scheduled_tasks SET {', '.join(updates)} WHERE task_id=? AND agent_id=?",
            params
        )

    enabled_val = req.enabled if req.enabled is not None else bool(row["enabled"])
    return {"task_id": task_id, "enabled": enabled_val}

@router.delete("/v1/schedules/{task_id}", tags=["Schedules"])
@limiter.limit(make_tier_limit("agent_write"))
def schedule_delete(request: Request, task_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a scheduled task."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Scheduled task not found")
    return {"status": "deleted", "task_id": task_id}
