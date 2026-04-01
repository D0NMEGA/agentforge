"""Queue routes (8 routes)."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query, Request

from config import MAX_QUEUE_PAYLOAD_SIZE
from db import get_db, DB_BACKEND
from helpers import get_agent_id, _encrypt, _decrypt, _track_event, _fire_webhooks, _queue_agent_event
from models import QueueSubmitRequest, QueueJobResponse, QueueListResponse, QueueFailRequest, QueueCompleteRequest, QueueBatchRequest, QueueBatchResponse, QueueBatchResultItem

from rate_limit import limiter, make_tier_limit

router = APIRouter()

@router.post("/v1/queue/submit", tags=["Queue"])
@limiter.limit(make_tier_limit("agent_write"))
def queue_submit(request: Request, req: QueueSubmitRequest, agent_id: str = Depends(get_agent_id)):
    job_id = f"job_{uuid.uuid4().hex[:16]}"; now = datetime.now(timezone.utc).isoformat()
    payload_str = json.dumps(req.payload) if isinstance(req.payload, dict) else req.payload
    if len(payload_str.encode("utf-8")) > MAX_QUEUE_PAYLOAD_SIZE:
        raise HTTPException(422, f"Payload exceeds maximum size of {MAX_QUEUE_PAYLOAD_SIZE} bytes")
    with get_db() as db:
        is_first = db.execute("SELECT COUNT(*) as c FROM queue WHERE agent_id=?", (agent_id,)).fetchone()["c"] == 0
        db.execute("INSERT INTO queue (job_id, agent_id, queue_name, payload, priority, created_at, max_attempts, retry_delay_seconds) VALUES (?,?,?,?,?,?,?,?)", (job_id, agent_id, req.queue_name, _encrypt(payload_str), req.priority, now, req.max_attempts, req.retry_delay_seconds))
    if is_first: _track_event("agent.first_job", agent_id=agent_id)
    return {"job_id": job_id, "status": "pending", "queue_name": req.queue_name, "max_attempts": req.max_attempts}


@router.post("/v1/queue/batch", tags=["Queue"], response_model=QueueBatchResponse)
@limiter.limit(make_tier_limit("agent_write"))
def queue_batch(request: Request, req: QueueBatchRequest, agent_id: str = Depends(get_agent_id)):
    results = []
    succeeded = 0
    failed = 0

    with get_db() as db:
        for item in req.items:
            try:
                job_id = f"job_{uuid.uuid4().hex[:16]}"
                now = datetime.now(timezone.utc).isoformat()
                payload_str = json.dumps(item.payload) if isinstance(item.payload, dict) else item.payload
                if len(payload_str.encode("utf-8")) > MAX_QUEUE_PAYLOAD_SIZE:
                    raise ValueError(f"Payload exceeds maximum size of {MAX_QUEUE_PAYLOAD_SIZE} bytes")
                db.execute(
                    "INSERT INTO queue (job_id, agent_id, queue_name, payload, priority, created_at, max_attempts, retry_delay_seconds) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (job_id, agent_id, item.queue_name, _encrypt(payload_str), item.priority, now, item.max_attempts, item.retry_delay_seconds)
                )
                results.append(QueueBatchResultItem(job_id=job_id, success=True, status="pending", queue_name=item.queue_name))
                succeeded += 1
            except Exception as e:
                results.append(QueueBatchResultItem(success=False, status="error", error=str(e)))
                failed += 1

    return QueueBatchResponse(results=results, total=len(req.items), succeeded=succeeded, failed=failed)


@router.get("/v1/queue/dead_letter", tags=["Queue"])
@limiter.limit(make_tier_limit("agent_read"))
def queue_dead_letter_list(request: Request, queue_name: Optional[str] = None, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), agent_id: str = Depends(get_agent_id)):
    with get_db() as db:
        if queue_name:
            rows = db.execute("SELECT job_id, queue_name, priority, attempt_count, max_attempts, fail_reason, created_at, failed_at, moved_at FROM dead_letter WHERE agent_id=? AND queue_name=? ORDER BY moved_at DESC LIMIT ? OFFSET ?", (agent_id, queue_name, limit, offset)).fetchall()
        else:
            rows = db.execute("SELECT job_id, queue_name, priority, attempt_count, max_attempts, fail_reason, created_at, failed_at, moved_at FROM dead_letter WHERE agent_id=? ORDER BY moved_at DESC LIMIT ? OFFSET ?", (agent_id, limit, offset)).fetchall()
    return {"jobs": [dict(r) for r in rows], "count": len(rows)}

@router.get("/v1/queue/{job_id}", response_model=QueueJobResponse, tags=["Queue"])
@limiter.limit(make_tier_limit("agent_read"))
def queue_status(request: Request, job_id: str, agent_id: str = Depends(get_agent_id)):
    with get_db() as db:
        row = db.execute("SELECT * FROM queue WHERE job_id=? AND agent_id=?", (job_id, agent_id)).fetchone()
        if not row: raise HTTPException(404, "Job not found")
        d = dict(row); d["payload"] = _decrypt(d["payload"])
        if d.get("result"): d["result"] = _decrypt(d["result"])
        return QueueJobResponse(**d)

@router.post("/v1/queue/claim", tags=["Queue"])
@limiter.limit(make_tier_limit("agent_write"))
def queue_claim(request: Request, queue_name: str = Query("default"), agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc).isoformat()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=86400)).strftime("%Y-%m-%dT%H:%M:%S")
    with get_db() as db:
        if DB_BACKEND in ("postgres", "dual"):
            # PostgreSQL: atomic claim via FOR UPDATE SKIP LOCKED
            row = db.execute(
                "UPDATE queue SET status='processing', claimed_by=?, started_at=? "
                "WHERE job_id = ("
                "  SELECT job_id FROM queue "
                "  WHERE queue_name=? AND status='pending' "
                "  AND (next_retry_at IS NULL OR next_retry_at <= ?) "
                "  AND created_at >= ? "
                "  ORDER BY priority DESC, created_at ASC "
                "  LIMIT 1 "
                "  FOR UPDATE SKIP LOCKED"
                ") RETURNING job_id, payload, priority",
                (agent_id, now, queue_name, now, cutoff)
            ).fetchone()
        else:
            # SQLite: atomic UPDATE WHERE status='pending' with rowcount check
            row = db.execute(
                "SELECT job_id, payload, priority FROM queue "
                "WHERE queue_name=? AND status='pending' "
                "AND (next_retry_at IS NULL OR next_retry_at <= ?) "
                "AND created_at >= ? "
                "ORDER BY priority DESC, created_at ASC LIMIT 1",
                (queue_name, now, cutoff)
            ).fetchone()
            if row:
                result = db.execute(
                    "UPDATE queue SET status='processing', claimed_by=?, started_at=? "
                    "WHERE job_id=? AND status='pending'",
                    (agent_id, now, row["job_id"])
                )
                if result.rowcount == 0:
                    row = None  # Lost the race -- another agent claimed it

        if not row:
            return {"status": "empty", "queue_name": queue_name}
        return {
            "job_id": row["job_id"],
            "payload": _decrypt(row["payload"]),
            "priority": row["priority"],
            "claimed_by": agent_id,
        }

@router.post("/v1/queue/{job_id}/complete", tags=["Queue"])
@limiter.limit(make_tier_limit("agent_write"))
def queue_complete(request: Request, job_id: str, body: Optional[QueueCompleteRequest] = None, agent_id: str = Depends(get_agent_id)):
    result = ""
    if body and body.result is not None:
        result = json.dumps(body.result) if isinstance(body.result, dict) else body.result
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        job_row = db.execute("SELECT agent_id, queue_name, claimed_by FROM queue WHERE job_id=? AND status='processing'", (job_id,)).fetchone()
        if not job_row: raise HTTPException(404, "Job not found or not in processing state")
        if job_row["claimed_by"] and job_row["claimed_by"] != agent_id:
            raise HTTPException(403, "Not authorized -- job claimed by another agent")
        db.execute("UPDATE queue SET status='completed', completed_at=?, result=? WHERE job_id=?", (now, _encrypt(result) if result else result, job_id))
    _fire_webhooks(job_row["agent_id"], "job.completed", {"job_id": job_id, "queue_name": job_row["queue_name"], "result": result, "completed_at": now})
    _queue_agent_event(agent_id, "job_completed", {"job_id": job_id, "queue_name": job_row["queue_name"]})
    return {"job_id": job_id, "status": "completed"}

@router.get("/v1/queue", response_model=QueueListResponse, tags=["Queue"])
@limiter.limit(make_tier_limit("agent_read"))
def queue_list(request: Request, queue_name: str = "default", status: Optional[str] = None, limit: int = Query(20, ge=1, le=100), agent_id: str = Depends(get_agent_id)):
    with get_db() as db:
        if status:
            rows = db.execute("SELECT job_id, status, priority, created_at, completed_at FROM queue WHERE agent_id=? AND queue_name=? AND status=? ORDER BY created_at DESC LIMIT ?", (agent_id, queue_name, status, limit)).fetchall()
        else:
            rows = db.execute("SELECT job_id, status, priority, created_at, completed_at FROM queue WHERE agent_id=? AND queue_name=? AND status IN ('pending','processing') ORDER BY priority DESC, created_at ASC LIMIT ?", (agent_id, queue_name, limit)).fetchall()
    return {"queue_name": queue_name, "jobs": [dict(r) for r in rows], "count": len(rows)}

@router.post("/v1/queue/{job_id}/fail", tags=["Queue"])
@limiter.limit(make_tier_limit("agent_write"))
def queue_fail(request: Request, job_id: str, req: QueueFailRequest, agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc); now_iso = now.isoformat(); fire_webhook_data = None
    with get_db() as db:
        row = db.execute("SELECT * FROM queue WHERE job_id=? AND status='processing'", (job_id,)).fetchone()
        if not row: raise HTTPException(404, "Job not found or not in processing state")
        if row["claimed_by"] and row["claimed_by"] != agent_id:
            raise HTTPException(403, "Not authorized -- job claimed by another agent")
        attempt = (row["attempt_count"] or 0) + 1; max_att = row["max_attempts"] or 1; delay = row["retry_delay_seconds"] or 0
        if attempt >= max_att:
            db.execute("INSERT INTO dead_letter (job_id, agent_id, queue_name, payload, status, priority, created_at, started_at, completed_at, result, max_attempts, attempt_count, retry_delay_seconds, failed_at, fail_reason, moved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (row["job_id"], row["agent_id"], row["queue_name"], row["payload"], "failed", row["priority"], row["created_at"], row["started_at"], row["completed_at"], row["result"], max_att, attempt, delay, now_iso, req.reason, now_iso))
            db.execute("DELETE FROM queue WHERE job_id=?", (job_id,))
            fire_webhook_data = (row["agent_id"], row["queue_name"])
            result = {"job_id": job_id, "status": "dead_lettered", "attempts": attempt, "max_attempts": max_att}
        else:
            next_retry = (now + timedelta(seconds=delay)).isoformat() if delay > 0 else None
            db.execute("UPDATE queue SET status='pending', started_at=NULL, attempt_count=?, failed_at=?, fail_reason=?, next_retry_at=? WHERE job_id=?", (attempt, now_iso, req.reason, next_retry, job_id))
            result = {"job_id": job_id, "status": "pending_retry", "attempts": attempt, "max_attempts": max_att, "next_retry_at": next_retry}
    if fire_webhook_data:
        _fire_webhooks(fire_webhook_data[0], "job.failed", {"job_id": job_id, "queue_name": fire_webhook_data[1], "reason": req.reason, "attempts": attempt, "dead_lettered": True})
    return result

@router.post("/v1/queue/{job_id}/replay", tags=["Queue"])
@limiter.limit(make_tier_limit("agent_write"))
def queue_replay(request: Request, job_id: str, agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT * FROM dead_letter WHERE job_id=? AND agent_id=?", (job_id, agent_id)).fetchone()
        if not row: raise HTTPException(404, "Dead-letter job not found")
        db.execute("INSERT INTO queue (job_id, agent_id, queue_name, payload, status, priority, created_at, max_attempts, attempt_count, retry_delay_seconds) VALUES (?,?,?,?,?,?,?,?,?,?)", (row["job_id"], row["agent_id"], row["queue_name"], row["payload"], "pending", row["priority"], now, row["max_attempts"], 0, row["retry_delay_seconds"]))
        db.execute("DELETE FROM dead_letter WHERE job_id=?", (job_id,))
    return {"job_id": job_id, "status": "pending", "replayed_at": now}
