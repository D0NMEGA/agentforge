"""Sessions routes (6 routes)."""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends

from db import get_db
from helpers import get_agent_id
from models import (
    SessionCreateRequest, SessionAppendRequest,
    SessionCreateResponse, SessionListResponse, SessionAppendResponse,
    SessionSummarizeResponse, SessionDeleteResponse,
)

router = APIRouter()


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return max(1, len(text) // 4)


def _auto_summarize(messages: list) -> list:
    """MVP auto-summarization: keep system msgs + last 10, summarize the rest."""
    system_msgs = [m for m in messages if m.get("role") == "system"]
    non_system = [m for m in messages if m.get("role") != "system"]

    if len(non_system) <= 10:
        return messages

    keep = non_system[-10:]
    trimmed = non_system[:-10]

    # Build summary: first message + count + last 5 of trimmed block
    parts = []
    if trimmed:
        parts.append(trimmed[0].get("content", "")[:200])
    if len(trimmed) > 5:
        parts.append(f"... [{len(trimmed)} messages trimmed] ...")
        for m in trimmed[-5:]:
            parts.append(f"{m.get('role', 'user')}: {m.get('content', '')[:100]}")
    elif len(trimmed) > 1:
        parts.append(f"... [{len(trimmed)} messages trimmed] ...")

    summary_text = "Summary of previous conversation: " + "\n".join(parts)
    summary_msg = {"role": "system", "content": summary_text}

    return system_msgs + [summary_msg] + keep


@router.post("/v1/sessions", response_model=SessionCreateResponse, tags=["Sessions"])
def session_create(req: SessionCreateRequest, agent_id: str = Depends(get_agent_id)):
    """Create a new conversation session."""
    now = datetime.now(timezone.utc).isoformat()
    session_id = f"sess_{uuid.uuid4().hex[:16]}"
    title = req.title or f"Session {now[:10]}"

    with get_db() as db:
        db.execute("""
            INSERT INTO sessions (session_id, agent_id, title, messages, metadata, token_count, max_tokens, created_at, updated_at)
            VALUES (?, ?, ?, '[]', ?, 0, ?, ?, ?)
        """, (session_id, agent_id, title, json.dumps(req.metadata) if req.metadata else None, req.max_tokens, now, now))

    return {"session_id": session_id, "title": title, "created_at": now}


@router.get("/v1/sessions", response_model=SessionListResponse, tags=["Sessions"])
def session_list(agent_id: str = Depends(get_agent_id)):
    """List all sessions for this agent."""
    with get_db() as db:
        rows = db.execute(
            "SELECT session_id, title, token_count, max_tokens, created_at, updated_at FROM sessions WHERE agent_id=? ORDER BY updated_at DESC",
            (agent_id,)
        ).fetchall()
    return {"sessions": [dict(r) for r in rows]}


@router.get("/v1/sessions/{session_id}", tags=["Sessions"])
def session_get(session_id: str, agent_id: str = Depends(get_agent_id)):
    """Get a session with its full message history."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Session not found")
    d = dict(row)
    d["messages"] = json.loads(d["messages"])
    if d.get("metadata") and isinstance(d["metadata"], str):
        try:
            d["metadata"] = json.loads(d["metadata"])
        except (json.JSONDecodeError, TypeError):
            pass
    return d


@router.post("/v1/sessions/{session_id}/messages", response_model=SessionAppendResponse, tags=["Sessions"])
def session_append(session_id: str, req: SessionAppendRequest, agent_id: str = Depends(get_agent_id)):
    """Append a message to a session. Auto-summarizes if near token limit."""
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        row = db.execute(
            "SELECT messages, token_count, max_tokens FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        messages = json.loads(row["messages"])
        token_count = row["token_count"]
        max_tokens = row["max_tokens"]

        role = "assistant" if req.role == "agent" else req.role
        new_msg = {"role": role, "content": req.content}
        messages.append(new_msg)
        token_count += _estimate_tokens(req.content)

        summarized = False
        if token_count > max_tokens * 0.9:
            messages = _auto_summarize(messages)
            token_count = sum(_estimate_tokens(m.get("content", "")) for m in messages)
            summarized = True

        db.execute(
            "UPDATE sessions SET messages=?, token_count=?, updated_at=? WHERE session_id=? AND agent_id=?",
            (json.dumps(messages), token_count, now, session_id, agent_id)
        )

    return {
        "status": "appended",
        "message_count": len(messages),
        "token_count": token_count,
        "summarized": summarized,
    }


@router.post("/v1/sessions/{session_id}/summarize", response_model=SessionSummarizeResponse, tags=["Sessions"])
def session_summarize(session_id: str, agent_id: str = Depends(get_agent_id)):
    """Force-summarize a session: collapse history to summary + recent 10 messages."""
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        row = db.execute(
            "SELECT messages FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        messages = json.loads(row["messages"])
        original_count = len(messages)
        messages = _auto_summarize(messages)
        token_count = sum(_estimate_tokens(m.get("content", "")) for m in messages)

        db.execute(
            "UPDATE sessions SET messages=?, token_count=?, updated_at=? WHERE session_id=? AND agent_id=?",
            (json.dumps(messages), token_count, now, session_id, agent_id)
        )

    return {
        "status": "summarized",
        "original_message_count": original_count,
        "new_message_count": len(messages),
        "token_count": token_count,
    }


@router.delete("/v1/sessions/{session_id}", response_model=SessionDeleteResponse, tags=["Sessions"])
def session_delete(session_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a session."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM sessions WHERE session_id=? AND agent_id=?",
            (session_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Session not found")
    return {"status": "deleted", "session_id": session_id}
