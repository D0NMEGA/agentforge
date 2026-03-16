"""Events routes (4 routes)."""

import json
import time
import hashlib
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Query, WebSocket, WebSocketDisconnect, Response

from db import get_db
from helpers import get_agent_id
from models import EventAckRequest, EventAckResponse, EventStreamItem

router = APIRouter()

@router.get("/v1/events/stream", response_model=EventStreamItem, tags=["Events"])
async def events_stream(agent_id: str = Depends(get_agent_id)):
    """Long-poll: waits up to 30s for first unacked event. Returns event or 204."""
    import asyncio
    deadline = time.time() + 30
    while time.time() < deadline:
        with get_db() as db:
            row = db.execute(
                "SELECT event_id, event_type, payload, created_at FROM agent_events "
                "WHERE agent_id=? AND acknowledged=0 ORDER BY created_at ASC LIMIT 1",
                (agent_id,)
            ).fetchone()
        if row:
            return {
                "event_id": row[0],
                "event_type": row[1],
                "payload": json.loads(row[2]),
                "created_at": row[3]
            }
        await asyncio.sleep(0.5)
    return Response(status_code=204)


@router.get("/v1/events", tags=["Events"])
async def events_poll(agent_id: str = Depends(get_agent_id)):
    """Return up to 20 unacknowledged events for agent."""
    with get_db() as db:
        rows = db.execute(
            "SELECT event_id, event_type, payload, created_at FROM agent_events "
            "WHERE agent_id=? AND acknowledged=0 ORDER BY created_at ASC LIMIT 20",
            (agent_id,)
        ).fetchall()
    return [{"event_id": r[0], "event_type": r[1], "payload": json.loads(r[2]), "created_at": r[3]} for r in rows]


@router.post("/v1/events/ack", response_model=EventAckResponse, tags=["Events"])
async def events_ack(body: EventAckRequest, agent_id: str = Depends(get_agent_id)):
    """Mark event_ids as acknowledged."""
    if not body.event_ids:
        return {"acknowledged": 0}
    with get_db() as db:
        placeholders = ",".join("?" * len(body.event_ids))
        db.execute(
            f"UPDATE agent_events SET acknowledged=1 WHERE agent_id=? AND event_id IN ({placeholders})",
            [agent_id] + body.event_ids
        )
        db.commit()
    return {"acknowledged": len(body.event_ids)}



@router.websocket("/v1/events/ws")
async def events_ws(websocket: WebSocket, api_key: str = Query(None)):
    """Real-time event stream via WebSocket. Auth via ?api_key=af_... query param."""
    import asyncio, hashlib, time as _time

    if not api_key:
        await websocket.close(code=4001)
        return
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    with get_db() as db:
        row = db.execute("SELECT agent_id FROM agents WHERE api_key_hash=?", (key_hash,)).fetchone()
    if not row:
        await websocket.close(code=4001)
        return
    agent_id = row[0]

    await websocket.accept()
    await websocket.send_json({"type": "connected", "agent_id": agent_id})

    last_ping = _time.time()

    try:
        while True:
            if _time.time() - last_ping >= 30:
                await websocket.send_json({"type": "ping"})
                last_ping = _time.time()

            with get_db() as db:
                ws_rows = db.execute(
                    "SELECT event_id, event_type, payload, created_at FROM agent_events "
                    "WHERE agent_id=? AND acknowledged=0 ORDER BY created_at ASC LIMIT 5",
                    (agent_id,)
                ).fetchall()

            for ws_row in ws_rows:
                event = {
                    "type": "event",
                    "event_id": ws_row[0],
                    "event_type": ws_row[1],
                    "payload": json.loads(ws_row[2]),
                    "created_at": ws_row[3]
                }
                await websocket.send_json(event)

            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=0.1)
                if msg.get("type") == "pong":
                    pass
                elif msg.get("type") == "ack" and msg.get("event_ids"):
                    eids = msg["event_ids"]
                    placeholders = ",".join("?" * len(eids))
                    with get_db() as db:
                        db.execute(
                            f"UPDATE agent_events SET acknowledged=1 WHERE agent_id=? AND event_id IN ({placeholders})",
                            [agent_id] + eids
                        )
                        db.commit()
            except asyncio.TimeoutError:
                pass

            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        from config import logger
        logger.warning("events_ws error: %s", type(e).__name__)


@router.websocket("/v1/user/events/ws")
async def user_events_ws(websocket: WebSocket, token: str = Query(None)):
    """User-scoped event stream via WebSocket. Aggregates events from ALL agents owned by the user.
    Auth via ?token=<JWT> query param or mg_token cookie."""
    import jwt, time as _time
    from config import JWT_SECRET

    # Resolve token from query param or cookie
    ws_token = token
    if not ws_token:
        ws_token = websocket.cookies.get("mg_token")
    if not ws_token:
        await websocket.close(code=4001)
        return

    # Decode JWT and extract user_id
    try:
        payload = jwt.decode(ws_token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get("user_id") or payload.get("sub")
        if not user_id:
            await websocket.close(code=4001)
            return
    except jwt.ExpiredSignatureError:
        await websocket.close(code=4001)
        return
    except jwt.InvalidTokenError:
        await websocket.close(code=4001)
        return

    # Look up all agent_ids for this user
    with get_db() as db:
        agent_rows = db.execute(
            "SELECT agent_id FROM agents WHERE user_id=?", (str(user_id),)
        ).fetchall()
    agent_ids = [r[0] for r in agent_rows]

    await websocket.accept()
    await websocket.send_json({
        "type": "connected",
        "user_id": str(user_id),
        "agent_count": len(agent_ids),
    })

    last_ping = _time.time()

    try:
        while True:
            # Ping every 30s
            if _time.time() - last_ping >= 30:
                await websocket.send_json({"type": "ping"})
                last_ping = _time.time()

            # Refresh agent list (user may register new agents)
            with get_db() as db:
                agent_rows = db.execute(
                    "SELECT agent_id FROM agents WHERE user_id=?", (str(user_id),)
                ).fetchall()
            agent_ids = [r[0] for r in agent_rows]

            # Query unacknowledged events across all user's agents
            if agent_ids:
                placeholders = ",".join("?" * len(agent_ids))
                with get_db() as db:
                    ws_rows = db.execute(
                        "SELECT event_id, agent_id, event_type, payload, created_at "
                        "FROM agent_events "
                        f"WHERE agent_id IN ({placeholders}) AND acknowledged=0 "
                        "ORDER BY created_at ASC LIMIT 10",
                        agent_ids,
                    ).fetchall()

                for ws_row in ws_rows:
                    event = {
                        "type": "event",
                        "event_id": ws_row[0],
                        "agent_id": ws_row[1],
                        "event_type": ws_row[2],
                        "payload": json.loads(ws_row[3]),
                        "created_at": ws_row[4],
                    }
                    await websocket.send_json(event)

            # Listen for client messages (ack, pong)
            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=0.1)
                if msg.get("type") == "pong":
                    pass
                elif msg.get("type") == "ack" and msg.get("event_ids"):
                    eids = msg["event_ids"]
                    # Validate: must be a list of strings, max 50 items
                    if not isinstance(eids, list) or len(eids) > 50:
                        continue
                    eids = [str(e) for e in eids if isinstance(e, (str, int))][:50]
                    if not eids or not agent_ids:
                        continue
                    # Ownership check: only ack events belonging to this user's agents
                    eid_ph = ",".join("?" * len(eids))
                    aid_ph = ",".join("?" * len(agent_ids))
                    with get_db() as db:
                        db.execute(
                            "UPDATE agent_events SET acknowledged=1 "
                            f"WHERE event_id IN ({eid_ph}) AND agent_id IN ({aid_ph})",
                            eids + agent_ids,
                        )
                        db.commit()
            except asyncio.TimeoutError:
                pass

            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        from config import logger
        logger.warning("events_ws error: %s", type(e).__name__)
