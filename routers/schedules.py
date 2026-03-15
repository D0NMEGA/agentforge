"""Schedules routes (5 routes)."""

import json
import uuid
from datetime import datetime, timezone

from croniter import croniter
from fastapi import APIRouter, HTTPException, Depends, Query

from config import MAX_QUEUE_PAYLOAD_SIZE
from db import get_db
from helpers import get_agent_id, _encrypt, _decrypt
from models import ScheduledTaskRequest, ScheduledTaskResponse, ScheduleListResponse

router = APIRouter()

@router.post("/v1/schedules", response_model=ScheduledTaskResponse, tags=["Schedules"])
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

@router.get("/v1/schedules", response_model=ScheduleListResponse, tags=["Schedules"])
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

@router.get("/v1/schedules/{task_id}", tags=["Schedules"])
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

@router.patch("/v1/schedules/{task_id}", tags=["Schedules"])
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

@router.delete("/v1/schedules/{task_id}", tags=["Schedules"])
def schedule_delete(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a scheduled task."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Scheduled task not found")
    return {"status": "deleted", "task_id": task_id}
