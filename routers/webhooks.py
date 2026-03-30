"""Webhooks routes (4 routes)."""

import json
import uuid
import hashlib
import hmac as _hmac
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, HTTPException, Depends, Request

from db import get_db
from helpers import get_agent_id, _is_safe_url, _run_webhook_delivery_tick, _check_auth_rate_limit, _encrypt, _decrypt
from models import WebhookRegisterRequest, WebhookResponse, WebhookListResponse, WebhookDeleteResponse, WebhookTestResponse

from rate_limit import limiter, make_tier_limit

router = APIRouter()

WEBHOOK_EVENT_TYPES = {"message.received", "message.broadcast", "job.completed", "job.failed", "marketplace.task.claimed", "marketplace.task.delivered", "marketplace.task.completed"}
WEBHOOK_TIMEOUT = 5.0

@router.post("/v1/webhooks", response_model=WebhookResponse, tags=["Webhooks"])
@limiter.limit(make_tier_limit("agent_write"))
def webhook_register(request: Request, req: WebhookRegisterRequest, agent_id: str = Depends(get_agent_id)):
    """Register a webhook callback URL for event notifications."""
    is_safe, reason = _is_safe_url(req.url)
    if not is_safe:
        raise HTTPException(400, reason)
    for et in req.event_types:
        if et not in WEBHOOK_EVENT_TYPES:
            raise HTTPException(400, f"Invalid event type '{et}'. Valid: {sorted(WEBHOOK_EVENT_TYPES)}")

    webhook_id = f"wh_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO webhooks (webhook_id, agent_id, url, event_types, secret, created_at) VALUES (?,?,?,?,?,?)",
            (webhook_id, agent_id, req.url, json.dumps(req.event_types), _encrypt(req.secret) if req.secret else None, now)
        )
    return WebhookResponse(
        webhook_id=webhook_id, url=req.url,
        event_types=req.event_types, active=True, created_at=now
    )

@router.get("/v1/webhooks", tags=["Webhooks"], response_model=WebhookListResponse)
@limiter.limit(make_tier_limit("agent_read"))
def webhook_list(request: Request, agent_id: str = Depends(get_agent_id)):
    """List your registered webhooks."""
    with get_db() as db:
        rows = db.execute(
            "SELECT webhook_id, url, event_types, active, created_at FROM webhooks WHERE agent_id=?",
            (agent_id,)
        ).fetchall()
    return {
        "webhooks": [
            {**dict(r), "event_types": json.loads(r["event_types"]), "active": bool(r["active"])}
            for r in rows
        ],
        "count": len(rows),
    }

@router.delete("/v1/webhooks/{webhook_id}", tags=["Webhooks"], response_model=WebhookDeleteResponse)
@limiter.limit(make_tier_limit("agent_write"))
def webhook_delete(request: Request, webhook_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a webhook."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM webhooks WHERE webhook_id=? AND agent_id=?", (webhook_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Webhook not found")
    return {"status": "deleted", "webhook_id": webhook_id}


@router.post("/v1/webhooks/{webhook_id}/test", tags=["Webhooks"], response_model=WebhookTestResponse)
@limiter.limit(make_tier_limit("agent_write"))
def webhook_test(webhook_id: str, request: Request, agent_id: str = Depends(get_agent_id)):
    """Fire a test ping to the webhook URL to verify it is reachable."""
    now = datetime.now(timezone.utc).isoformat()
    delivery_id = f"whd_{uuid.uuid4().hex[:16]}"
    test_payload = json.dumps({
        "event": "webhook.test",
        "webhook_id": webhook_id,
        "timestamp": now,
    })
    with get_db() as db:
        hook = db.execute(
            "SELECT webhook_id, url FROM webhooks WHERE webhook_id = ? AND agent_id = ?",
            (webhook_id, agent_id)
        ).fetchone()
        if not hook:
            raise HTTPException(404, "Webhook not found or not owned by you")
        db.execute(
            "INSERT INTO webhook_deliveries "
            "(delivery_id, webhook_id, event_type, payload, status, attempt_count, max_attempts, next_retry_at, created_at) "
            "VALUES (?, ?, 'webhook.test', ?, 'pending', 0, 1, ?, ?)",
            (delivery_id, webhook_id, test_payload, now, now)
        )
    # Attempt delivery synchronously (single attempt only for test pings)
    try:
        _run_webhook_delivery_tick()
    except Exception:
        pass
    with get_db() as db:
        result = db.execute(
            "SELECT status, last_error FROM webhook_deliveries WHERE delivery_id = ?",
            (delivery_id,)
        ).fetchone()
    return {
        "delivery_id": delivery_id,
        "status": result["status"] if result else "unknown",
        "error": result["last_error"] if result else None,
    }


@router.post("/v1/agents/{agent_id}/webhooks/openclaw", tags=["Webhooks"])
@limiter.limit(make_tier_limit("agent_write"))
async def receive_openclaw_event(agent_id: str, request: Request):
    """Receive an OpenClaw event and enqueue it for the agent."""
    _check_auth_rate_limit(request)
    body = await request.body()
    signature = request.headers.get("X-OpenClaw-Signature", "")

    if not signature:
        raise HTTPException(401, "Missing X-OpenClaw-Signature header")

    with get_db() as db:
        agent = db.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(404, "Agent not found")

        webhook = db.execute(
            "SELECT secret FROM webhooks WHERE agent_id = ? AND event_types = 'openclaw.*' AND active = 1",
            (agent_id,)
        ).fetchone()
        if not webhook or not webhook["secret"]:
            raise HTTPException(404, "No active OpenClaw webhook for this agent")

        # Verify HMAC signature — secret stored encrypted at rest
        secret = _decrypt(webhook["secret"]) if webhook["secret"] else ""
        expected = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(signature, expected):
            raise HTTPException(401, "Invalid signature")

        # Parse body
        try:
            payload = json.loads(body)
        except Exception:
            raise HTTPException(422, "Invalid JSON body")

        # Enqueue as a job
        job_id = f"job_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO queue (job_id, agent_id, queue_name, payload, status, priority, created_at) VALUES (?,?,?,?,?,?,?)",
            (job_id, agent_id, "openclaw", json.dumps(payload), "pending", 5, now)
        )

    return {"status": "accepted", "job_id": job_id}
