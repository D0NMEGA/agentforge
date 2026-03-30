"""Pub/Sub routes (5 routes)."""

import fnmatch
import json
import re
import uuid
import asyncio
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Query, Request

from db import get_db
from state import _ws_connections
from helpers import get_agent_id, _encrypt, _fire_webhooks, publish_event
from models import (
    PubSubSubscribeRequest, PubSubPublishRequest,
    PubSubSubscribeResponse, PubSubUnsubscribeResponse,
    PubSubSubscriptionsResponse, PubSubPublishResponse, PubSubChannelsResponse,
)

from rate_limit import limiter, make_tier_limit

router = APIRouter()

# Wildcard channel pattern validator: alphanumeric, dots, asterisks, hyphens, underscores
_CHANNEL_PATTERN_RE = re.compile(r'^[\w.\-*]+$')

# Max subscriptions per agent
_MAX_SUBSCRIPTIONS = 50
# Max publish events per agent per minute
_MAX_PUBLISHES_PER_MINUTE = 100

@router.post("/v1/pubsub/subscribe", tags=["Pub/Sub"], response_model=PubSubSubscribeResponse)
@limiter.limit(make_tier_limit("agent_write"))
def pubsub_subscribe(request: Request, req: PubSubSubscribeRequest, agent_id: str = Depends(get_agent_id)):
    """Subscribe to a broadcast channel. Supports wildcard patterns (e.g. 'task.*')."""
    # Validate channel/pattern format
    if not _CHANNEL_PATTERN_RE.match(req.channel):
        raise HTTPException(400, "Invalid channel pattern. Use alphanumeric, dots, hyphens, underscores, asterisks.")

    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        # EVT-05: enforce 50 subscription max
        count = db.execute(
            "SELECT COUNT(*) as cnt FROM pubsub_subscriptions WHERE agent_id=?",
            (agent_id,)
        ).fetchone()
        current_count = count["cnt"] if count else 0

        existing = db.execute(
            "SELECT id FROM pubsub_subscriptions WHERE agent_id=? AND channel=?",
            (agent_id, req.channel)
        ).fetchone()
        if existing:
            return {"channel": req.channel, "status": "already_subscribed"}

        if current_count >= _MAX_SUBSCRIPTIONS:
            raise HTTPException(429, f"Subscription limit reached ({_MAX_SUBSCRIPTIONS} max per agent).")

        db.execute(
            "INSERT INTO pubsub_subscriptions (agent_id, channel, subscribed_at) VALUES (?,?,?)",
            (agent_id, req.channel, now)
        )
    return {"channel": req.channel, "status": "subscribed", "subscribed_at": now}

@router.post("/v1/pubsub/unsubscribe", tags=["Pub/Sub"], response_model=PubSubUnsubscribeResponse)
@limiter.limit(make_tier_limit("agent_write"))
def pubsub_unsubscribe(request: Request, req: PubSubSubscribeRequest, agent_id: str = Depends(get_agent_id)):
    """Unsubscribe from a broadcast channel. Idempotent -- returns 200 even if not subscribed."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM pubsub_subscriptions WHERE agent_id=? AND channel=?",
            (agent_id, req.channel)
        )
        # LOW2-08: Idempotent unsubscribe -- return 200 with "not_subscribed" instead of 404
        if r.rowcount == 0:
            return {"channel": req.channel, "status": "not_subscribed"}
    return {"channel": req.channel, "status": "unsubscribed"}

@router.get("/v1/pubsub/subscriptions", tags=["Pub/Sub"], response_model=PubSubSubscriptionsResponse)
@limiter.limit(make_tier_limit("agent_read"))
def pubsub_list_subscriptions(request: Request, agent_id: str = Depends(get_agent_id)):
    """List all channels this agent is subscribed to."""
    with get_db() as db:
        rows = db.execute(
            "SELECT channel, subscribed_at FROM pubsub_subscriptions WHERE agent_id=? ORDER BY subscribed_at",
            (agent_id,)
        ).fetchall()
    return {"subscriptions": [dict(r) for r in rows], "count": len(rows)}

@router.post("/v1/pubsub/publish", tags=["Pub/Sub"], response_model=PubSubPublishResponse)
@limiter.limit(make_tier_limit("agent_write"))
async def pubsub_publish(request: Request, req: PubSubPublishRequest, agent_id: str = Depends(get_agent_id)):
    """Publish an event to all subscribers matching the channel pattern."""
    # EVT-05: enforce 100 publishes/minute rate limit
    import helpers as _helpers_mod
    now_epoch = time.time()
    publish_history = _helpers_mod._pubsub_publish_counts.get(agent_id, [])
    publish_history = [t for t in publish_history if now_epoch - t < 60]
    if len(publish_history) >= _MAX_PUBLISHES_PER_MINUTE:
        raise HTTPException(429, f"Publish rate limit reached ({_MAX_PUBLISHES_PER_MINUTE} per minute).")
    publish_history.append(now_epoch)
    _helpers_mod._pubsub_publish_counts[agent_id] = publish_history

    now = datetime.now(timezone.utc).isoformat()
    message_id = f"ps_{uuid.uuid4().hex[:12]}"

    # PUB-01: Use fnmatch for wildcard matching (mirrors helpers.py publish_event)
    with get_db() as db:
        rows = db.execute(
            "SELECT agent_id, channel FROM pubsub_subscriptions"
        ).fetchall()
    subscriber_ids = []
    for r in rows:
        pattern = r["channel"]
        if fnmatch.fnmatch(req.channel, pattern):
            subscriber_ids.append(r["agent_id"])

    # PUB-02: Count ALL matching subscribers (including self) for notified count
    all_matched_count = len(subscriber_ids)
    # Store a relay message for each subscriber (except the publisher)
    recipients = [sid for sid in subscriber_ids if sid != agent_id]
    with get_db() as db:
        for sid in recipients:
            db.execute(
                "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
                (f"{message_id}_{sid[:8]}", agent_id, sid, f"pubsub:{req.channel}", _encrypt(req.payload), now)
            )

    # Push to WebSocket connections for each subscriber
    broadcast_data = {
        "event": "message.broadcast", "message_id": message_id,
        "from_agent": agent_id, "channel": req.channel,
        "payload": req.payload, "created_at": now,
    }
    async def _ws_broadcast():
        for sid in recipients:
            if sid in _ws_connections:
                dead = set()
                for peer in _ws_connections[sid]:
                    try:
                        await peer.send_json(broadcast_data)
                    except Exception:
                        dead.add(peer)
                _ws_connections[sid] -= dead
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_ws_broadcast())
    except RuntimeError:
        pass

    # Fire webhook notifications for each subscriber
    for sid in recipients:
        _fire_webhooks(sid, "message.broadcast", {
            "message_id": message_id, "from_agent": agent_id,
            "channel": req.channel, "payload": req.payload,
        })

    # EVT-04: Use central publish_event for SSE fan-out via wildcard pattern matching
    publish_event(req.channel, {
        "message_id": message_id, "from_agent": agent_id,
        "channel": req.channel, "payload": req.payload, "created_at": now,
    }, source_agent=agent_id)

    return {
        "message_id": message_id, "channel": req.channel,
        "subscribers_notified": all_matched_count, "created_at": now,
    }

@router.get("/v1/pubsub/channels", tags=["Pub/Sub"], response_model=PubSubChannelsResponse)
@limiter.limit(make_tier_limit("agent_read"))
def pubsub_list_channels(request: Request, agent_id: str = Depends(get_agent_id)):
    """List all active pub/sub channels with subscriber counts."""
    with get_db() as db:
        rows = db.execute(
            "SELECT channel, COUNT(*) as subscriber_count FROM pubsub_subscriptions GROUP BY channel ORDER BY subscriber_count DESC"
        ).fetchall()
    return {"channels": [dict(r) for r in rows], "count": len(rows)}
