"""Events routes (4 routes)."""

import json
import time
import hashlib
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Query, WebSocket, WebSocketDisconnect, Response

from db import get_db
from helpers import get_agent_id
from models import EventAckRequest

router = APIRouter()

@router.get("/v1/events/stream", tags=["Events"])
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


@router.post("/v1/events/ack", tags=["Events"])
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
    except Exception:
        pass
