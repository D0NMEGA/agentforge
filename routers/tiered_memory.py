"""Tiered Memory routes (3 routes) -- composition layer over sessions, memory, and vector_memory."""

import json
import uuid
from datetime import datetime, timezone

import numpy as np
from fastapi import APIRouter, HTTPException, Depends, Request

from db import get_db
from helpers import get_agent_id, _embed_text, _log_memory_access, _encrypt, _decrypt
from routers.sessions import _auto_summarize, _estimate_tokens
from models import (
    TieredStoreEventRequest, TieredStoreEventResponse,
    TieredRecallRequest, TieredRecallResponse,
    TieredSummarizeResponse,
)

from rate_limit import limiter, make_tier_limit

router = APIRouter(tags=["tiered-memory"])


def _cosine_similarity(vec1, vec2):
    """Cosine similarity between two L2-normalized vectors."""
    return float(np.dot(vec1, vec2))


@router.post("/v1/tiered/store_event", response_model=TieredStoreEventResponse)
@limiter.limit(make_tier_limit("agent_write"))
def tiered_store_event(request: Request, req: TieredStoreEventRequest, agent_id: str = Depends(get_agent_id)):
    """Append an event to the session buffer (Tier 1). Optionally persist to mid-term notes (Tier 2)."""
    if req.persist and not req.note_key:
        raise HTTPException(422, "note_key is required when persist=True")

    now = datetime.now(timezone.utc).isoformat()

    # Prepare content string
    content = json.dumps(req.data) if isinstance(req.data, dict) else str(req.data)

    with get_db() as db:
        # Validate session exists and belongs to agent
        row = db.execute(
            "SELECT messages, token_count, max_tokens FROM sessions WHERE session_id=? AND agent_id=?",
            (req.session_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        messages = json.loads(row["messages"])
        token_count = row["token_count"]

        # Append new event as a message
        new_msg = {"role": req.role, "content": content}
        messages.append(new_msg)
        token_count += _estimate_tokens(content)

        # Auto-summarize if near token limit
        max_tokens = row["max_tokens"]
        if token_count > max_tokens * 0.9:
            messages = _auto_summarize(messages)
            token_count = sum(_estimate_tokens(m.get("content", "")) for m in messages)

        db.execute(
            "UPDATE sessions SET messages=?, token_count=?, updated_at=? WHERE session_id=? AND agent_id=?",
            (json.dumps(messages), token_count, now, req.session_id, agent_id)
        )

        # Optionally persist to mid-term memory (Tier 2)
        # SEC-01: Use auth-scoped namespace to match the GET /v1/memory/{key} auto-scoping
        persisted = False
        if req.persist and req.note_key:
            enc_value = _encrypt(content)
            scoped_ns = f"agent:{agent_id}"
            db.execute("""
                INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, visibility)
                VALUES (?, ?, ?, ?, ?, ?, 'private')
                ON CONFLICT(agent_id, namespace, key)
                DO UPDATE SET value=?, updated_at=?
            """, (agent_id, scoped_ns, req.note_key, enc_value, now, now,
                  enc_value, now))
            persisted = True

    # Log memory access OUTSIDE the get_db() block
    _log_memory_access("tiered_store_event", agent_id, "session", req.session_id, actor_agent_id=agent_id)

    return {
        "status": "stored",
        "session_id": req.session_id,
        "message_count": len(messages),
        "token_count": token_count,
        "persisted": persisted,
        "note_key": req.note_key if persisted else None,
    }


@router.post("/v1/tiered/recall", response_model=TieredRecallResponse)
@limiter.limit(make_tier_limit("agent_write"))
def tiered_recall(request: Request, req: TieredRecallRequest, agent_id: str = Depends(get_agent_id)):
    """Search across mid-term memory (Tier 2) and long-term vector store (Tier 3)."""
    results = []

    with get_db() as db:
        # Tier 3: Long-term vector search
        if "long" in req.tiers:
            rows = db.execute(
                "SELECT id, key, text, embedding, metadata, importance, access_count "
                "FROM vector_memory WHERE agent_id=? AND namespace=?",
                (agent_id, req.namespace)
            ).fetchall()

            if rows:
                query_embedding = _embed_text(req.query)
                for row in rows:
                    vec_embedding = np.frombuffer(row["embedding"], dtype=np.float32)
                    similarity = _cosine_similarity(query_embedding, vec_embedding)
                    if similarity >= req.min_similarity:
                        results.append({
                            "tier": "long",
                            "key": row["key"],
                            "text": row["text"],
                            "score": round(similarity, 6),
                            "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
                        })

        # Tier 2: Mid-term memory fuzzy search
        if "mid" in req.tiers:
            mid_rows = db.execute(
                "SELECT key, value FROM memory WHERE agent_id=? AND namespace IN ('default', 'notes')",
                (agent_id,)
            ).fetchall()

            query_words = req.query.lower().split()
            for row in mid_rows:
                val = row["value"] or ""
                # Try to decrypt if encrypted
                val = _decrypt(val)
                val_lower = val.lower()
                key_lower = row["key"].lower()
                # Fuzzy match: check if any query word appears in key or value
                matches = sum(1 for w in query_words if w in val_lower or w in key_lower)
                if matches > 0:
                    score = min(0.5 * (matches / max(len(query_words), 1)), 0.99)
                    results.append({
                        "tier": "mid",
                        "key": row["key"],
                        "text": val,
                        "score": round(score, 6),
                        "metadata": None,
                    })

    # Sort by score descending, take top k
    results.sort(key=lambda x: x["score"], reverse=True)
    results = results[:req.k]

    return {
        "results": results,
        "count": len(results),
        "query": req.query,
    }


@router.post("/v1/tiered/summarize/{session_id}", response_model=TieredSummarizeResponse)
@limiter.limit(make_tier_limit("agent_write"))
def tiered_summarize(request: Request, session_id: str, agent_id: str = Depends(get_agent_id)):
    """Summarize a session and promote the summary to the long-term vector store (Tier 3)."""
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

        # Extract summary text from the injected system message
        summary_msg = next(
            (m for m in messages if m.get("role") == "system"
             and m.get("content", "").startswith("Summary of previous conversation:")),
            None
        )
        summary_text = summary_msg["content"] if summary_msg else ""

        promoted = False
        vec_key = f"session_summary_{session_id}"

        if summary_text:
            embedding = _embed_text(summary_text)
            embedding_blob = embedding.tobytes()
            vec_id = f"vec_{uuid.uuid4().hex[:16]}"
            metadata = json.dumps({"source": "session", "session_id": session_id})

            db.execute("""
                INSERT INTO vector_memory
                    (id, agent_id, namespace, key, text, embedding, metadata, importance, created_at, updated_at)
                VALUES (?, ?, 'long_term', ?, ?, ?, ?, 0.7, ?, ?)
                ON CONFLICT(agent_id, namespace, key)
                DO UPDATE SET text=?, embedding=?, metadata=?, updated_at=?
            """, (vec_id, agent_id, vec_key, summary_text, embedding_blob, metadata, now, now,
                  summary_text, embedding_blob, metadata, now))
            promoted = True

    # Log OUTSIDE the get_db() block
    _log_memory_access("tiered_summarize", agent_id, "long_term", vec_key, actor_agent_id=agent_id)

    return {
        "status": "summarized",
        "session_id": session_id,
        "original_message_count": original_count,
        "new_message_count": len(messages),
        "token_count": token_count,
        "summary_text": summary_text,
        "promoted": promoted,
        "vector_key": vec_key,
        "vector_namespace": "long_term",
    }
