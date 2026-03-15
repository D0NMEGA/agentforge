"""Pub/Sub routes (5 routes)."""

import json
import uuid
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Query

from db import get_db
from state import _ws_connections
from helpers import get_agent_id, _encrypt, _fire_webhooks
from models import (
    PubSubSubscribeRequest, PubSubPublishRequest,
    PubSubSubscribeResponse, PubSubUnsubscribeResponse,
    PubSubSubscriptionsResponse, PubSubPublishResponse, PubSubChannelsResponse,
)

router = APIRouter()

@router.post("/v1/pubsub/subscribe", tags=["Pub/Sub"], response_model=PubSubSubscribeResponse)
def pubsub_subscribe(req: PubSubSubscribeRequest, agent_id: str = Depends(get_agent_id)):
    """Subscribe to a broadcast channel."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM pubsub_subscriptions WHERE agent_id=? AND channel=?",
            (agent_id, req.channel)
        ).fetchone()
        if existing:
            return {"channel": req.channel, "status": "already_subscribed"}
        db.execute(
            "INSERT INTO pubsub_subscriptions (agent_id, channel, subscribed_at) VALUES (?,?,?)",
            (agent_id, req.channel, now)
        )
    return {"channel": req.channel, "status": "subscribed", "subscribed_at": now}

@router.post("/v1/pubsub/unsubscribe", tags=["Pub/Sub"], response_model=PubSubUnsubscribeResponse)
def pubsub_unsubscribe(req: PubSubSubscribeRequest, agent_id: str = Depends(get_agent_id)):
    """Unsubscribe from a broadcast channel."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM pubsub_subscriptions WHERE agent_id=? AND channel=?",
            (agent_id, req.channel)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Not subscribed to this channel")
    return {"channel": req.channel, "status": "unsubscribed"}

@router.get("/v1/pubsub/subscriptions", tags=["Pub/Sub"], response_model=PubSubSubscriptionsResponse)
def pubsub_list_subscriptions(agent_id: str = Depends(get_agent_id)):
    """List all channels this agent is subscribed to."""
    with get_db() as db:
        rows = db.execute(
            "SELECT channel, subscribed_at FROM pubsub_subscriptions WHERE agent_id=? ORDER BY subscribed_at",
            (agent_id,)
        ).fetchall()
    return {"subscriptions": [dict(r) for r in rows], "count": len(rows)}

@router.post("/v1/pubsub/publish", tags=["Pub/Sub"], response_model=PubSubPublishResponse)
async def pubsub_publish(req: PubSubPublishRequest, agent_id: str = Depends(get_agent_id)):
    """Publish a message to all subscribers of a channel."""
    now = datetime.now(timezone.utc).isoformat()
    message_id = f"ps_{uuid.uuid4().hex[:12]}"

    with get_db() as db:
        rows = db.execute(
            "SELECT agent_id FROM pubsub_subscriptions WHERE channel=?",
            (req.channel,)
        ).fetchall()
    subscriber_ids = [r["agent_id"] for r in rows]

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

    return {
        "message_id": message_id, "channel": req.channel,
        "subscribers_notified": len(recipients), "created_at": now,
    }

@router.get("/v1/pubsub/channels", tags=["Pub/Sub"], response_model=PubSubChannelsResponse)
def pubsub_list_channels(agent_id: str = Depends(get_agent_id)):
    """List all active pub/sub channels with subscriber counts."""
    with get_db() as db:
        rows = db.execute(
            "SELECT channel, COUNT(*) as subscriber_count FROM pubsub_subscriptions GROUP BY channel ORDER BY subscriber_count DESC"
        ).fetchall()
    return {"channels": [dict(r) for r in rows], "count": len(rows)}
