"""Relay routes (7 routes)."""

import json
import uuid
import asyncio
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Query, WebSocket, WebSocketDisconnect, Request

from config import logger
from db import get_db
from state import _ws_connections
from helpers import get_agent_id, _encrypt, _decrypt, _track_event, _fire_webhooks, _queue_agent_event, hash_key, publish_event
from models import (
    RelayMessage, RelaySendResponse, RelayInboxResponse, RelayMarkReadResponse,
    MessageStatusResponse, MessageTraceResponse, MessageHop, DeadLetterMessageListResponse,
)

from rate_limit import limiter

router = APIRouter()


def _record_hop(db, message_id: str, hop: str, status: str, recorded_at: str) -> None:
    """Insert a hop record into message_hops."""
    hop_id = f"hop_{uuid.uuid4().hex[:16]}"
    db.execute(
        "INSERT INTO message_hops (hop_id, message_id, hop, status, recorded_at) VALUES (?,?,?,?,?)",
        (hop_id, message_id, hop, status, recorded_at),
    )


@router.post("/v1/relay/send", tags=["Relay"], response_model=RelaySendResponse)
@limiter.limit("60/minute")
def relay_send(request: Request, msg: RelayMessage, agent_id: str = Depends(get_agent_id)):
    """Send a message to another agent. Unknown recipients are dead-lettered (not 404)."""
    message_id = f"msg_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        recip = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (msg.to_agent,)).fetchone()
        if not recip:
            # Dead-letter: recipient unknown, persist to dead_letter_messages
            dl_id = f"dl_{uuid.uuid4().hex[:16]}"
            db.execute(
                "INSERT INTO dead_letter_messages "
                "(dl_id, from_agent, to_agent, channel, payload, fail_reason, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (dl_id, agent_id, msg.to_agent, msg.channel, _encrypt(msg.payload), "unknown_recipient", now),
            )
            return {"message_id": dl_id, "status": "dead_lettered"}

        is_first_msg = (
            db.execute("SELECT COUNT(*) as c FROM relay WHERE from_agent=?", (agent_id,)).fetchone()["c"] == 0
        )
        db.execute(
            "INSERT INTO relay "
            "(message_id, from_agent, to_agent, channel, payload, created_at, status, status_updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (message_id, agent_id, msg.to_agent, msg.channel, _encrypt(msg.payload), now, "accepted", now),
        )
        _record_hop(db, message_id, "accepted", "accepted", now)

    if is_first_msg:
        _track_event("agent.first_message", agent_id=agent_id)

    # Push to WebSocket connections
    async def _ws_push():
        if msg.to_agent in _ws_connections:
            push = {
                "event": "message.received", "message_id": message_id,
                "from_agent": agent_id, "channel": msg.channel,
                "payload": msg.payload, "created_at": now,
            }
            dead = set()
            for peer in _ws_connections[msg.to_agent]:
                try:
                    await peer.send_json(push)
                except Exception:
                    dead.add(peer)
            _ws_connections[msg.to_agent] -= dead

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_ws_push())
    except RuntimeError:
        pass

    # Fire webhook notifications for recipient
    _fire_webhooks(msg.to_agent, "message.received", {
        "message_id": message_id, "from_agent": agent_id,
        "channel": msg.channel, "payload": msg.payload,
    })

    # Queue event for recipient
    _queue_agent_event(msg.to_agent, "relay_message", {
        "from": agent_id, "message_id": message_id, "channel": msg.channel,
        "message": msg.payload[:100],
    })

    # EVT-03: Auto-publish lifecycle event OUTSIDE get_db block
    publish_event("message.received", {
        "message_id": message_id, "from_agent": agent_id,
        "to_agent": msg.to_agent, "channel": msg.channel,
    }, source_agent=agent_id)

    return {"message_id": message_id, "status": "accepted"}


@router.get("/v1/messages/dead-letter", tags=["Relay"], response_model=DeadLetterMessageListResponse)
@limiter.limit("60/minute")
def message_dead_letter_list(request: Request, agent_id: str = Depends(get_agent_id)):
    """Return dead-lettered messages sent by this agent."""
    with get_db() as db:
        rows = db.execute(
            "SELECT dl_id, to_agent, channel, fail_reason, created_at "
            "FROM dead_letter_messages WHERE from_agent=? ORDER BY created_at DESC LIMIT 100",
            (agent_id,),
        ).fetchall()
    items = [dict(r) for r in rows]
    return {"messages": items, "count": len(items)}


@router.get("/v1/messages/{message_id}/status", tags=["Relay"], response_model=MessageStatusResponse)
@limiter.limit("60/minute")
def message_status(request: Request, message_id: str, agent_id: str = Depends(get_agent_id)):
    """Return delivery status for a message. Accessible by sender or recipient only."""
    with get_db() as db:
        row = db.execute(
            "SELECT message_id, from_agent, to_agent, status, created_at, "
            "status_updated_at, delivered_at, read_at, acted_at "
            "FROM relay WHERE message_id=?",
            (message_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Message not found")
    r = dict(row)
    if agent_id not in (r["from_agent"], r["to_agent"]):
        raise HTTPException(403, "Access denied")
    return r


@router.get("/v1/messages/{message_id}/trace", tags=["Relay"], response_model=MessageTraceResponse)
@limiter.limit("60/minute")
def message_trace(request: Request, message_id: str, agent_id: str = Depends(get_agent_id)):
    """Return ordered hop history for a message. Accessible by sender or recipient."""
    with get_db() as db:
        row = db.execute(
            "SELECT from_agent, to_agent FROM relay WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "Message not found")
        r = dict(row)
        if agent_id not in (r["from_agent"], r["to_agent"]):
            raise HTTPException(403, "Access denied")
        hops = db.execute(
            "SELECT hop_id, hop, status, recorded_at FROM message_hops "
            "WHERE message_id=? ORDER BY recorded_at ASC",
            (message_id,),
        ).fetchall()
    return {"message_id": message_id, "hops": [dict(h) for h in hops]}


@router.get("/v1/relay/inbox", tags=["Relay"], response_model=RelayInboxResponse)
@limiter.limit("60/minute")
def relay_inbox(
    request: Request,
    channel: Optional[str] = Query(None, description="Filter by channel. Omit for all channels."),
    unread_only: bool = True,
    limit: int = Query(20, ge=1, le=100),
    after: Optional[str] = Query(None, description="Cursor: return messages after this message_id (forward-only pagination)"),
    agent_id: str = Depends(get_agent_id),
):
    """Check your message inbox. Omit channel to get messages from all channels. Use after={message_id} for cursor-based forward pagination."""
    with get_db() as db:
        if after:
            # Cursor pagination: resolve cursor message's created_at, then fetch newer messages
            # When channel is None, query by message_id + to_agent only (no channel filter)
            cursor_row = db.execute(
                "SELECT created_at FROM relay WHERE message_id=? AND to_agent=?",
                (after, agent_id)
            ).fetchone()
            if not cursor_row:
                # Unknown cursor: return 400 with error code (RLY-04)
                raise HTTPException(
                    status_code=400,
                    detail={"error": "invalid_cursor", "message": "Cursor message not found"},
                )
            cursor_ts = cursor_row["created_at"]
            if channel is not None:
                base_q = (
                    "SELECT message_id, from_agent, channel, payload, created_at FROM relay "
                    "WHERE to_agent=? AND channel=? AND created_at > ? "
                )
                params: list = [agent_id, channel, cursor_ts]
            else:
                base_q = (
                    "SELECT message_id, from_agent, channel, payload, created_at FROM relay "
                    "WHERE to_agent=? AND created_at > ? "
                )
                params = [agent_id, cursor_ts]
            if unread_only:
                base_q += "AND read_at IS NULL "
            base_q += "ORDER BY created_at ASC LIMIT ?"
            params.append(limit)
            rows = db.execute(base_q, params).fetchall()
        else:
            # No cursor: return most recent messages
            if channel is not None:
                if unread_only:
                    rows = db.execute(
                        "SELECT message_id, from_agent, channel, payload, created_at FROM relay "
                        "WHERE to_agent=? AND channel=? AND read_at IS NULL ORDER BY created_at DESC LIMIT ?",
                        (agent_id, channel, limit)
                    ).fetchall()
                else:
                    rows = db.execute(
                        "SELECT message_id, from_agent, channel, payload, created_at, read_at FROM relay "
                        "WHERE to_agent=? AND channel=? ORDER BY created_at DESC LIMIT ?",
                        (agent_id, channel, limit)
                    ).fetchall()
            else:
                # All channels (RLY-02)
                if unread_only:
                    rows = db.execute(
                        "SELECT message_id, from_agent, channel, payload, created_at FROM relay "
                        "WHERE to_agent=? AND read_at IS NULL ORDER BY created_at DESC LIMIT ?",
                        (agent_id, limit)
                    ).fetchall()
                else:
                    rows = db.execute(
                        "SELECT message_id, from_agent, channel, payload, created_at, read_at FROM relay "
                        "WHERE to_agent=? ORDER BY created_at DESC LIMIT ?",
                        (agent_id, limit)
                    ).fetchall()

    messages = [dict(r) for r in rows]
    for m in messages:
        m["payload"] = _decrypt(m["payload"])
    next_cursor = messages[-1]["message_id"] if messages else None
    return {"channel": channel, "messages": messages, "count": len(messages), "next_cursor": next_cursor}

@router.post("/v1/relay/{message_id}/read", tags=["Relay"], response_model=RelayMarkReadResponse)
@limiter.limit("60/minute")
def relay_mark_read(request: Request, message_id: str, agent_id: str = Depends(get_agent_id)):
    """Mark a message as read. Updates status lifecycle and records a hop."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        r = db.execute(
            "UPDATE relay SET read_at=?, status='read', status_updated_at=? "
            "WHERE message_id=? AND to_agent=? AND read_at IS NULL",
            (now, now, message_id, agent_id),
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Message not found or already read")
        _record_hop(db, message_id, "read", "read", now)
    return {"message_id": message_id, "status": "read"}


async def _ws_auth(api_key: str) -> Optional[str]:
    """Validate API key and return agent_id, or None."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id FROM agents WHERE api_key_hash = ?",
            (hash_key(api_key),)
        ).fetchone()
        return row["agent_id"] if row else None

@router.websocket("/v1/relay/ws")
async def relay_websocket(ws: WebSocket):
    """
    WebSocket endpoint for real-time message relay.
    Connect with ?api_key=<key>. Send JSON: {"to_agent": "...", "channel": "...", "payload": "..."}
    Receive JSON push when a message is sent to you.
    """
    api_key = ws.query_params.get("api_key")
    if not api_key:
        await ws.close(code=4001, reason="Missing api_key query parameter")
        return

    agent_id = await _ws_auth(api_key)
    if not agent_id:
        await ws.close(code=4003, reason="Invalid API key")
        return

    await ws.accept()

    # Register connection
    if agent_id not in _ws_connections:
        _ws_connections[agent_id] = set()
    _ws_connections[agent_id].add(ws)

    try:
        while True:
            data = await ws.receive_json()
            to_agent = data.get("to_agent")
            channel = data.get("channel", "direct")
            payload = data.get("payload", "")

            if not to_agent or not payload:
                await ws.send_json({"error": "to_agent and payload are required"})
                continue

            # Persist to relay table
            message_id = f"msg_{uuid.uuid4().hex[:16]}"
            now = datetime.now(timezone.utc).isoformat()
            with get_db() as db:
                recip = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (to_agent,)).fetchone()
                if not recip:
                    dl_id = f"dlm_{uuid.uuid4().hex[:16]}"
                    db.execute(
                        "INSERT INTO dead_letter_messages "
                        "(dl_id, from_agent, to_agent, channel, payload, fail_reason, created_at) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (dl_id, agent_id, to_agent, channel, _encrypt(payload), "recipient_not_found", now)
                    )
                    await ws.send_json({"status": "dead_lettered", "message_id": dl_id})
                    continue
                db.execute(
                    "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, status, created_at) VALUES (?,?,?,?,?,?,?)",
                    (message_id, agent_id, to_agent, channel, _encrypt(payload), "accepted", now)
                )
                _record_hop(db, message_id, "accepted", "websocket", now)

            # Confirm to sender
            await ws.send_json({"status": "accepted", "message_id": message_id})

            # Push to recipient if connected
            if to_agent in _ws_connections:
                push = {
                    "event": "message.received",
                    "message_id": message_id,
                    "from_agent": agent_id,
                    "channel": channel,
                    "payload": payload,
                    "created_at": now,
                }
                dead = set()
                for peer in _ws_connections[to_agent]:
                    try:
                        await peer.send_json(push)
                    except Exception:
                        dead.add(peer)
                _ws_connections[to_agent] -= dead

            # Fire webhooks for recipient
            _fire_webhooks(to_agent, "message.received", {
                "message_id": message_id, "from_agent": agent_id,
                "channel": channel, "payload": payload,
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error for {agent_id}: {e}")
    finally:
        _ws_connections.get(agent_id, set()).discard(ws)
        if agent_id in _ws_connections and not _ws_connections[agent_id]:
            del _ws_connections[agent_id]
