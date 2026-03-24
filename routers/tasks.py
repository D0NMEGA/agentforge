"""Task Object routes (6 routes) -- Phase 44.

Provides atomic task claiming via UPDATE WHERE status='pending' AND claimed_by IS NULL
(WAL-mode single-writer guarantee on SQLite, SKIP LOCKED equivalent on PostgreSQL path).
"""

import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query

from config import logger
from db import get_db
from helpers import get_agent_id, _queue_agent_event, publish_event
from models import (
    TaskCreateRequest,
    TaskUpdateRequest,
    TaskDependencyRequest,
    TaskResponse,
    TaskListResponse,
    TaskClaimResponse,
    TaskHistoryEntry,
)

router = APIRouter()

# ─── State Machine ─────────────────────────────────────────────────────────────

VALID_STATUSES = {"pending", "running", "completed", "failed", "waiting_input", "cancelled", "rejected"}

VALID_TRANSITIONS = {
    "pending": {"running", "cancelled", "rejected"},
    "running": {"completed", "failed", "waiting_input"},
    "waiting_input": {"running", "cancelled"},
    "failed": {"pending"},
}

LEASE_DURATION_SECONDS = 300  # 5-minute lease


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _parse_task_row(row) -> TaskResponse:
    """Convert a DB row dict into a TaskResponse, parsing history JSON."""
    history_raw = row["history"] if row["history"] else "[]"
    try:
        history_list = json.loads(history_raw)
    except (json.JSONDecodeError, TypeError):
        history_list = []
    history = [TaskHistoryEntry(**h) for h in history_list]

    metadata_raw = row["metadata"]
    try:
        metadata = json.loads(metadata_raw) if metadata_raw else None
    except (json.JSONDecodeError, TypeError):
        metadata = None

    return TaskResponse(
        task_id=row["task_id"],
        creator_agent=row["creator_agent"],
        title=row["title"],
        description=row["description"],
        status=row["status"],
        priority=row["priority"] if row["priority"] is not None else 0,
        claimed_by=row["claimed_by"],
        claimed_at=row["claimed_at"],
        lease_expires_at=row["lease_expires_at"],
        completed_at=row["completed_at"],
        result=row["result"],
        metadata=metadata,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        history=history,
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/v1/tasks", response_model=TaskResponse)
def task_create(body: TaskCreateRequest, agent_id: str = Depends(get_agent_id)):
    """Create a new task. Status starts as 'pending'."""
    task_id = f"task_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    history = [{"status": "pending", "actor": agent_id, "timestamp": now}]
    metadata_json = json.dumps(body.metadata) if body.metadata is not None else None

    with get_db() as db:
        db.execute(
            "INSERT INTO agent_tasks "
            "(task_id, creator_agent, title, description, status, priority, metadata, created_at, updated_at, history) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                task_id, agent_id, body.title, body.description,
                "pending", body.priority, metadata_json,
                now, now, json.dumps(history),
            ),
        )
        row = db.execute(
            "SELECT * FROM agent_tasks WHERE task_id=?", (task_id,)
        ).fetchone()

    _queue_agent_event(agent_id, "task_created", {"task_id": task_id, "title": body.title})
    # EVT-03: Auto-publish task.created lifecycle event OUTSIDE get_db block
    publish_event("task.created", {
        "task_id": task_id, "title": body.title, "creator_agent": agent_id, "status": "pending",
    }, source_agent=agent_id)
    return _parse_task_row(row)


@router.get("/v1/tasks", response_model=TaskListResponse)
def task_list(
    status: Optional[str] = Query(None),
    creator: Optional[str] = Query(None),
    claimed_by: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    agent_id: str = Depends(get_agent_id),
):
    """List tasks with optional filters."""
    clauses = []
    params = []
    if status:
        clauses.append("status=?")
        params.append(status)
    if creator:
        clauses.append("creator_agent=?")
        params.append(creator)
    if claimed_by:
        clauses.append("claimed_by=?")
        params.append(claimed_by)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params_with_limit = params + [limit, offset]

    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM agent_tasks {where} ORDER BY priority DESC, created_at ASC LIMIT ? OFFSET ?",
            params_with_limit,
        ).fetchall()

    tasks = [_parse_task_row(r) for r in rows]
    return TaskListResponse(tasks=tasks, count=len(tasks))


@router.get("/v1/tasks/{task_id}", response_model=TaskResponse)
def task_get(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Get a single task by ID."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM agent_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Task not found")
    return _parse_task_row(row)


@router.post("/v1/tasks/{task_id}/claim", response_model=TaskClaimResponse)
def task_claim(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Atomically claim a pending task.

    Uses UPDATE WHERE status='pending' AND claimed_by IS NULL. SQLite WAL mode
    guarantees single-writer atomicity, so only one concurrent UPDATE can succeed.
    """
    now = datetime.now(timezone.utc).isoformat()
    lease_expiry = (datetime.now(timezone.utc) + timedelta(seconds=LEASE_DURATION_SECONDS)).isoformat()

    with get_db() as db:
        # Verify task exists first
        existing = db.execute(
            "SELECT task_id, status FROM agent_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Task not found")

        # Check all dependencies are completed before allowing claim
        unmet_deps = db.execute(
            "SELECT d.depends_on, t.status FROM task_dependencies d "
            "JOIN agent_tasks t ON d.depends_on = t.task_id "
            "WHERE d.task_id=? AND t.status != 'completed'",
            (task_id,),
        ).fetchall()
        if unmet_deps:
            raise HTTPException(status_code=409, detail="Task has unmet dependencies")

        # Fetch current history for appending
        row_pre = db.execute(
            "SELECT history FROM agent_tasks WHERE task_id=? AND status='pending' AND claimed_by IS NULL",
            (task_id,),
        ).fetchone()
        if not row_pre:
            raise HTTPException(status_code=409, detail="Task already claimed or not available")

        history = json.loads(row_pre["history"])
        history.append({"status": "running", "actor": agent_id, "timestamp": now})

        # Atomic claim: UPDATE only if still pending and unclaimed
        result = db.execute(
            "UPDATE agent_tasks SET status='running', claimed_by=?, claimed_at=?, "
            "lease_expires_at=?, updated_at=?, history=? "
            "WHERE task_id=? AND status='pending' AND claimed_by IS NULL",
            (agent_id, now, lease_expiry, now, json.dumps(history), task_id),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=409, detail="Task already claimed or not available")

    _queue_agent_event(agent_id, "task_claimed", {"task_id": task_id, "claimed_by": agent_id})
    # EVT-03: Auto-publish task.status_changed lifecycle event OUTSIDE get_db block
    publish_event("task.status_changed", {
        "task_id": task_id, "status": "running", "actor": agent_id,
    }, source_agent=agent_id)
    return TaskClaimResponse(
        task_id=task_id,
        status="running",
        claimed_by=agent_id,
        lease_expires_at=lease_expiry,
    )


@router.patch("/v1/tasks/{task_id}", response_model=TaskResponse)
def task_update(task_id: str, body: TaskUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update task status. Validates state machine transitions.

    Only claimed_by agent can transition running tasks. Creator can cancel/reject pending tasks.
    """
    new_status = body.status
    if new_status not in VALID_STATUSES:
        raise HTTPException(status_code=409, detail=f"Unknown status '{new_status}'")

    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM agent_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")

        current_status = row["status"]

        # Validate transition
        allowed = VALID_TRANSITIONS.get(current_status, set())
        if new_status not in allowed:
            raise HTTPException(
                status_code=409,
                detail=f"Invalid transition: {current_status} -> {new_status}",
            )

        # Authorization: claimed_by agent for running/waiting_input transitions
        # Creator can cancel/reject pending tasks
        if current_status == "pending" and new_status in ("cancelled", "rejected"):
            if row["creator_agent"] != agent_id:
                raise HTTPException(status_code=403, detail="Only creator can cancel or reject pending tasks")
        else:
            if row["claimed_by"] != agent_id:
                raise HTTPException(status_code=403, detail="Only claiming agent can update task status")

        # Append to history
        history = json.loads(row["history"] if row["history"] else "[]")
        history.append({"status": new_status, "actor": agent_id, "timestamp": now})

        # Set completed_at if terminal
        completed_at = now if new_status == "completed" else row["completed_at"]

        db.execute(
            "UPDATE agent_tasks SET status=?, result=?, updated_at=?, history=?, completed_at=? "
            "WHERE task_id=?",
            (new_status, body.result or row["result"], now, json.dumps(history), completed_at, task_id),
        )
        updated_row = db.execute(
            "SELECT * FROM agent_tasks WHERE task_id=?", (task_id,)
        ).fetchone()

    _queue_agent_event(agent_id, "task_status_changed", {
        "task_id": task_id, "from": current_status, "to": new_status
    })
    # EVT-03: Auto-publish task.status_changed lifecycle event OUTSIDE get_db block
    publish_event("task.status_changed", {
        "task_id": task_id, "status": new_status, "actor": agent_id,
    }, source_agent=agent_id)
    return _parse_task_row(updated_row)


@router.post("/v1/tasks/{task_id}/dependencies")
def task_add_dependency(task_id: str, body: TaskDependencyRequest, agent_id: str = Depends(get_agent_id)):
    """Add a dependency edge: task_id must not be claimed until depends_on is completed."""
    with get_db() as db:
        # Verify both tasks exist
        task = db.execute(
            "SELECT task_id FROM agent_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        dep = db.execute(
            "SELECT task_id FROM agent_tasks WHERE task_id=?", (body.depends_on,)
        ).fetchone()
        if not dep:
            raise HTTPException(status_code=404, detail=f"Dependency task '{body.depends_on}' not found")

        # Insert dependency (ignore if already exists)
        try:
            db.execute(
                "INSERT OR IGNORE INTO task_dependencies (task_id, depends_on) VALUES (?,?)",
                (task_id, body.depends_on),
            )
        except Exception:
            pass  # Already exists or constraint error -- idempotent

    return {"status": "ok", "task_id": task_id, "depends_on": body.depends_on}
