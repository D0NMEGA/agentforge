"""SSE push stream routes (1 route). Phase 43."""

import json
import asyncio
from fastapi import APIRouter, HTTPException, Request, Depends

from sse_starlette import EventSourceResponse, ServerSentEvent

from db import get_db
from helpers import get_agent_id
from state import _sse_connections

router = APIRouter()


@router.get("/v1/agents/{agent_id_path}/events", tags=["Events"])
async def agent_sse_stream(
    request: Request,
    agent_id_path: str,
    auth_agent_id: str = Depends(get_agent_id),
):
    """SSE push stream for agent events. Delivers relay messages, job assignments,
    and memory changes in real-time. Reconnect with Last-Event-ID to replay missed events.

    Auth: X-API-Key header (same as all /v1/ endpoints).
    Agents can only subscribe to their own stream.

    Note: With 4 Uvicorn workers, SSE fan-out is intra-worker only. Use Last-Event-ID
    reconnect for guaranteed delivery. Cross-worker delivery requires Redis pub/sub
    (future enhancement).
    """
    if auth_agent_id != agent_id_path:
        raise HTTPException(403, "Cannot subscribe to another agent's SSE stream")

    last_event_id = request.headers.get("last-event-id")

    async def generator():
        # Phase 1: Replay missed events since last_event_id
        if last_event_id:
            with get_db() as db:
                cursor_row = db.execute(
                    "SELECT created_at FROM agent_events WHERE event_id=? AND agent_id=?",
                    (last_event_id, auth_agent_id)
                ).fetchone()
                if cursor_row:
                    missed = db.execute(
                        "SELECT event_id, event_type, payload, created_at "
                        "FROM agent_events "
                        "WHERE agent_id=? AND created_at > ? "
                        "ORDER BY created_at ASC LIMIT 100",
                        (auth_agent_id, cursor_row["created_at"])
                    ).fetchall()
                    for m in missed:
                        payload_data = m["payload"]
                        if isinstance(payload_data, str):
                            try:
                                payload_data = json.loads(payload_data)
                            except Exception:
                                pass
                        yield ServerSentEvent(
                            data=json.dumps({
                                "event_type": m["event_type"],
                                "payload": payload_data,
                                "created_at": m["created_at"],
                            }),
                            id=m["event_id"],
                            event="agent_event",
                        )

        # Phase 2: Register asyncio.Queue for live push events
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        _sse_connections.setdefault(auth_agent_id, set()).add(q)

        try:
            while True:
                # Check disconnect first (short poll to respond quickly)
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=0.25)
                    yield ServerSentEvent(
                        data=json.dumps(event["payload"]),
                        id=event["event_id"],
                        event=event["event_type"],
                    )
                except asyncio.TimeoutError:
                    pass  # keepalive ping handled automatically by EventSourceResponse(ping=15)
        finally:
            _sse_connections.get(auth_agent_id, set()).discard(q)
            if auth_agent_id in _sse_connections and not _sse_connections[auth_agent_id]:
                del _sse_connections[auth_agent_id]

    return EventSourceResponse(generator(), ping=15, headers={"X-Accel-Buffering": "no"})
