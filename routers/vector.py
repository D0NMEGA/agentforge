"""Vector Memory + Shared Memory routes (10 routes)."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, Field

import numpy as np
from fastapi import APIRouter, HTTPException, Depends, Query

from config import MAX_MEMORY_VALUE_SIZE
from db import get_db
from helpers import get_agent_id, _encrypt, _decrypt, _get_embed_model, _embed_text
from models import (
    VectorUpsertRequest, VectorSearchRequest, SharedMemorySetRequest,
    VectorUpsertResponse, VectorSearchResponse, VectorGetResponse,
    VectorDeleteResponse, VectorListResponse,
    SharedMemorySetResponse, SharedMemoryListResponse,
    SharedMemoryDeleteResponse, SharedMemoryNamespacesResponse,
)

router = APIRouter()

def _cosine_similarity(vec1, vec2):
    return float(np.dot(vec1, vec2))

@router.post("/v1/vector/upsert", response_model=VectorUpsertResponse, tags=["Vector Memory"])
def vector_upsert(req: VectorUpsertRequest, agent_id: str = Depends(get_agent_id)):
    """Store text with its embedding vector. Updates if key exists (UPSERT).

    Uses 'all-MiniLM-L6-v2' model (384 dimensions). Cosine similarity search.
    """
    # Generate embedding
    embedding = _embed_text(req.text)
    embedding_blob = embedding.tobytes()

    vec_id = f"vec_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    metadata_json = json.dumps(req.metadata) if req.metadata else None

    with get_db() as db:
        # UPSERT: replace if (agent_id, namespace, key) exists
        db.execute("""
            INSERT INTO vector_memory (id, agent_id, namespace, key, text, embedding, metadata, importance, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, namespace, key)
            DO UPDATE SET text=?, embedding=?, metadata=?, importance=?, updated_at=?
        """, (vec_id, agent_id, req.namespace, req.key, req.text, embedding_blob, metadata_json, req.importance, now, now,
              req.text, embedding_blob, metadata_json, req.importance, now))

    return {
        "key": req.key,
        "namespace": req.namespace,
        "dimensions": len(embedding),
        "status": "upserted"
    }

@router.post("/v1/vector/search", response_model=VectorSearchResponse, tags=["Vector Memory"])
def vector_search(req: VectorSearchRequest, agent_id: str = Depends(get_agent_id)):
    """Semantic search with optional composite scoring.

    Scoring modes:
    - 'cosine': Pure cosine similarity (default, backward-compatible)
    - 'composite': 0.4*recency + 0.2*importance + 0.4*cosine

    NOTE: Uses brute-force search. Fine for ~10K vectors per agent.
    """
    query_embedding = _embed_text(req.query)
    now_ts = datetime.now(timezone.utc)

    with get_db() as db:
        rows = db.execute(
            "SELECT key, text, embedding, metadata, importance, access_count, updated_at "
            "FROM vector_memory WHERE agent_id=? AND namespace=?",
            (agent_id, req.namespace)
        ).fetchall()

        results = []
        for row in rows:
            vec_embedding = np.frombuffer(row["embedding"], dtype=np.float32)
            similarity = _cosine_similarity(query_embedding, vec_embedding)

            if similarity < req.min_similarity:
                continue

            if req.scoring == "composite":
                # Recency: exponential decay, half-life = 7 days
                try:
                    updated = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    updated = now_ts
                age_days = max((now_ts - updated).total_seconds() / 86400.0, 0.0)
                recency = 2.0 ** (-age_days / 7.0)  # 1.0 at t=0, 0.5 at 7 days, 0.25 at 14 days

                importance = float(row["importance"]) if row["importance"] is not None else 0.5
                score = 0.4 * recency + 0.2 * importance + 0.4 * similarity
            else:
                score = similarity

            results.append({
                "key": row["key"],
                "text": row["text"],
                "score": round(score, 6),
                "similarity": round(similarity, 6),
                "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
            })

        results.sort(key=lambda x: x["score"], reverse=True)
        results = results[:req.limit]

        # Increment access_count for returned results
        for r in results:
            db.execute(
                "UPDATE vector_memory SET access_count = access_count + 1 WHERE agent_id=? AND namespace=? AND key=?",
                (agent_id, req.namespace, r["key"])
            )

    return {"results": results, "count": len(results), "scoring": req.scoring}

@router.get("/v1/vector/{key}", response_model=VectorGetResponse, tags=["Vector Memory"])
def vector_get(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Get a specific vector entry by key."""
    with get_db() as db:
        row = db.execute(
            "SELECT key, text, metadata, created_at, updated_at FROM vector_memory "
            "WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Vector entry '{key}' not found in namespace '{namespace}'")

    return {
        "key": row["key"],
        "text": row["text"],
        "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"]
    }

@router.delete("/v1/vector/{key}", response_model=VectorDeleteResponse, tags=["Vector Memory"])
def vector_delete(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Delete a vector entry."""
    with get_db() as db:
        result = db.execute(
            "DELETE FROM vector_memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        )
        if result.rowcount == 0:
            raise HTTPException(404, f"Vector entry '{key}' not found in namespace '{namespace}'")

    return {"status": "deleted", "key": key, "namespace": namespace}

@router.get("/v1/vector", response_model=VectorListResponse, tags=["Vector Memory"])
def vector_list(namespace: str = "default", limit: int = Query(100, le=1000), agent_id: str = Depends(get_agent_id)):
    """List all vector keys in a namespace (without embeddings for efficiency)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT key, created_at FROM vector_memory WHERE agent_id=? AND namespace=? ORDER BY created_at DESC LIMIT ?",
            (agent_id, namespace, limit)
        ).fetchall()

    return {
        "keys": [{"key": r["key"], "created_at": r["created_at"]} for r in rows],
        "count": len(rows),
        "namespace": namespace
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED / PUBLIC MEMORY NAMESPACES
# ═══════════════════════════════════════════════════════════════════════════════

class SharedMemorySetRequest(BaseModel):
    namespace: str = Field(..., max_length=64, description="Public namespace name")
    key: str = Field(..., max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    description: Optional[str] = Field(None, max_length=256, description="Human-readable description of this entry")
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000)

@router.post("/v1/shared-memory", response_model=SharedMemorySetResponse, tags=["Shared Memory"])
def shared_memory_set(req: SharedMemorySetRequest, agent_id: str = Depends(get_agent_id)):
    """Publish a key-value pair to a shared namespace that other agents can read."""
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()

    enc_value = _encrypt(req.value)
    with get_db() as db:
        db.execute("""
            INSERT INTO shared_memory (owner_agent, namespace, key, value, description, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_agent, namespace, key)
            DO UPDATE SET value=?, description=?, updated_at=?, expires_at=?
        """, (agent_id, req.namespace, req.key, enc_value, req.description,
              now.isoformat(), now.isoformat(), expires,
              enc_value, req.description, now.isoformat(), expires))
    return {"status": "published", "namespace": req.namespace, "key": req.key}

@router.get("/v1/shared-memory/{namespace}", response_model=SharedMemoryListResponse, tags=["Shared Memory"])
def shared_memory_list(
    namespace: str,
    prefix: str = "",
    limit: int = Query(50, le=200),
    agent_id: str = Depends(get_agent_id),
):
    """List keys in a shared namespace (readable by any agent)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT owner_agent, key, description, LENGTH(value) as size_bytes, updated_at, expires_at "
            "FROM shared_memory WHERE namespace=? AND key LIKE ? "
            "AND (expires_at IS NULL OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?",
            (namespace, f"{prefix}%", now, limit)
        ).fetchall()
    return {"namespace": namespace, "entries": [dict(r) for r in rows], "count": len(rows)}

@router.get("/v1/shared-memory/{namespace}/{key}", tags=["Shared Memory"])
def shared_memory_get(namespace: str, key: str, agent_id: str = Depends(get_agent_id)):
    """Read a value from a shared namespace (any agent can read)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM shared_memory WHERE namespace=? AND key=? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (namespace, key, now)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Key not found or expired")
    d = dict(row)
    d["value"] = _decrypt(d["value"])
    return d

@router.delete("/v1/shared-memory/{namespace}/{key}", response_model=SharedMemoryDeleteResponse, tags=["Shared Memory"])
def shared_memory_delete(namespace: str, key: str, agent_id: str = Depends(get_agent_id)):
    """Delete a key from a shared namespace (only the owner can delete)."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM shared_memory WHERE owner_agent=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found or you are not the owner")
    return {"status": "deleted", "namespace": namespace, "key": key}

@router.get("/v1/shared-memory", response_model=SharedMemoryNamespacesResponse, tags=["Shared Memory"])
def shared_memory_namespaces(agent_id: str = Depends(get_agent_id)):
    """List all shared namespaces with entry counts."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT namespace, COUNT(*) as entry_count, COUNT(DISTINCT owner_agent) as contributor_count "
            "FROM shared_memory WHERE (expires_at IS NULL OR expires_at > ?) "
            "GROUP BY namespace ORDER BY entry_count DESC",
            (now,)
        ).fetchall()
    return {"namespaces": [dict(r) for r in rows], "count": len(rows)}
