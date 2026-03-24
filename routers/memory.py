"""Memory routes (8 routes) -- CAS, auto-scoping, history, meta, TTL."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query, Request, Header
from fastapi.responses import Response

from config import MAX_MEMORY_VALUE_SIZE
from db import get_db
from rate_limit import limiter
from helpers import (
    get_agent_id, _encrypt, _decrypt,
    _log_memory_access, _check_memory_visibility, _track_event,
    _queue_agent_event, _resolve_namespace, publish_event,
)
from models import (
    MemorySetRequest, MemoryGetResponse, MemoryListResponse,
    MemoryVisibilityRequest, MemoryCrossAgentReadResponse,
    MemorySetResponse, MemoryDeleteResponse, MemoryVisibilityResponse,
    MemoryMetaResponse, MemoryHistoryEntry, MemoryHistoryResponse,
)

import re as _re

_VALID_KEY_PATTERN = _re.compile(r'^[a-zA-Z0-9_\-\.:]{1,256}$')

def _validate_key(key: str):
    """Reject path traversal and special chars in memory keys."""
    if not _VALID_KEY_PATTERN.match(key):
        raise HTTPException(422, "Key must be 1-256 characters: letters, digits, underscore, hyphen, dot only")
    if '..' in key:
        raise HTTPException(422, "Key must not contain path traversal sequences")


router = APIRouter()


@router.get("/v1/agents/{target_agent_id}/memory/{key}", tags=["Memory"], response_model=MemoryCrossAgentReadResponse)
@limiter.limit("60/minute")
def memory_get_cross_agent(request: Request, target_agent_id: str, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc).isoformat()
    resolved_ns = _resolve_namespace(namespace, target_agent_id)
    with get_db() as db:
        row = db.execute("SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)", (target_agent_id, resolved_ns, key, now)).fetchone()
        if not row:
            raise HTTPException(404, "Key not found")
        allowed = _check_memory_visibility(db, target_agent_id, resolved_ns, key, agent_id)
        d = dict(row) if allowed else None
    _log_memory_access("cross_agent_read", target_agent_id, resolved_ns, key, actor_agent_id=agent_id, authorized=1 if allowed else 0)
    if not allowed:
        raise HTTPException(403, "Access denied: memory entry is private or not shared with you")
    d["value"] = _decrypt(d["value"])
    d.pop("shared_agents", None)
    return {"key": d["key"], "value": d["value"], "namespace": d["namespace"], "visibility": d.get("visibility") or "private", "updated_at": d["updated_at"], "expires_at": d.get("expires_at")}


@router.patch("/v1/memory/{key}/visibility", tags=["Memory"], response_model=MemoryVisibilityResponse)
@limiter.limit("60/minute")
def memory_set_visibility(request: Request, key: str, req: MemoryVisibilityRequest, namespace: str = Query(None), agent_id: str = Depends(get_agent_id)):
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    resolved_ns = _resolve_namespace(req.namespace, agent_id)
    with get_db() as db:
        old = db.execute("SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, resolved_ns, key)).fetchone()
        if not old:
            raise HTTPException(404, "Key not found")
        db.execute("UPDATE memory SET visibility=?, shared_agents=? WHERE agent_id=? AND namespace=? AND key=?", (vis, sa_json, agent_id, resolved_ns, key))
    _log_memory_access("visibility_changed", agent_id, resolved_ns, key, actor_agent_id=agent_id, old_visibility=old["visibility"] or "private", new_visibility=vis)
    return {"status": "updated", "key": key, "visibility": vis}


# MEM-06 / MEM-05: /history and /meta MUST be registered BEFORE generic /{key} GET
# to prevent FastAPI matching "history" or "meta" as key values.

@router.get("/v1/memory/{key}/history", tags=["Memory"], response_model=MemoryHistoryResponse)
@limiter.limit("60/minute")
def memory_history(request: Request, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """MEM-06: Return version history for a memory key."""
    resolved_ns = _resolve_namespace(namespace, agent_id)
    with get_db() as db:
        # Verify the key exists first
        exists = db.execute(
            "SELECT 1 FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, resolved_ns, key)
        ).fetchone()
        if not exists:
            raise HTTPException(404, "Key not found")
        rows = db.execute(
            "SELECT version, value, changed_by, changed_at FROM memory_history "
            "WHERE agent_id=? AND namespace=? AND key=? ORDER BY version DESC",
            (agent_id, resolved_ns, key)
        ).fetchall()
    history = []
    for row in rows:
        d = dict(row)
        d["value"] = _decrypt(d["value"])
        history.append(MemoryHistoryEntry(**d))
    return MemoryHistoryResponse(key=key, namespace=resolved_ns, history=history, count=len(history))


@router.get("/v1/memory/{key}/meta", tags=["Memory"], response_model=MemoryMetaResponse)
@limiter.limit("60/minute")
def memory_meta(request: Request, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """MEM-05: Return metadata for a memory key (writer, version, timestamps, namespace)."""
    resolved_ns = _resolve_namespace(namespace, agent_id)
    with get_db() as db:
        row = db.execute(
            "SELECT key, namespace, agent_id, version, created_at, updated_at, expires_at "
            "FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, resolved_ns, key)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Key not found")
    d = dict(row)
    return MemoryMetaResponse(
        key=d["key"],
        namespace=d["namespace"],
        writer=d["agent_id"],
        version=d.get("version") or 1,
        created_at=d["created_at"],
        updated_at=d["updated_at"],
        expires_at=d.get("expires_at"),
    )


@router.post("/v1/memory", tags=["Memory"], response_model=MemorySetResponse)
@limiter.limit("60/minute")
def memory_set(request: Request, req: MemorySetRequest, if_match: Optional[str] = Header(None, alias="If-Match"), agent_id: str = Depends(get_agent_id)):
    _validate_key(req.key)
    if "\x00" in req.value:
        raise HTTPException(422, "Null bytes not allowed in values")
    resolved_ns = _resolve_namespace(req.namespace, agent_id)
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()
    enc_value = _encrypt(req.value)
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    new_version = 1
    with get_db() as db:
        is_first = db.execute("SELECT COUNT(*) as c FROM memory WHERE agent_id=?", (agent_id,)).fetchone()["c"] == 0
        # Check current version for CAS
        existing = db.execute(
            "SELECT version FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, resolved_ns, req.key)
        ).fetchone()
        current_version = (existing["version"] or 1) if existing else 0
        # MEM-02: If-Match CAS check
        if if_match is not None and existing is not None:
            try:
                expected_version = int(if_match)
            except (ValueError, TypeError):
                raise HTTPException(400, "If-Match header must be an integer version number")
            if expected_version != current_version:
                raise HTTPException(409, f"Version conflict: current version is {current_version}, If-Match sent {expected_version}")
        # Increment version on every write (insert = 1, update = current+1)
        new_version = current_version + 1 if existing else 1
        db.execute("""
            INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, expires_at, visibility, shared_agents, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, namespace, key)
            DO UPDATE SET value=?, updated_at=?, expires_at=?, visibility=?, shared_agents=?, version=?
        """, (agent_id, resolved_ns, req.key, enc_value, now.isoformat(), now.isoformat(), expires, vis, sa_json, new_version,
              enc_value, now.isoformat(), expires, vis, sa_json, new_version))
        # MEM-04: Append to memory_history
        history_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO memory_history (id, agent_id, namespace, key, value, version, changed_by, changed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (history_id, agent_id, resolved_ns, req.key, enc_value, new_version, agent_id, now.isoformat())
        )
    _log_memory_access("write", agent_id, resolved_ns, req.key, actor_agent_id=agent_id)
    _queue_agent_event(agent_id, "memory_changed", {"key": req.key, "namespace": resolved_ns, "version": new_version})
    # EVT-03: Auto-publish memory.changed lifecycle event OUTSIDE get_db block
    publish_event("memory.changed", {
        "agent_id": agent_id, "namespace": resolved_ns, "key": req.key, "action": "write",
    }, source_agent=agent_id)
    if is_first:
        _track_event("agent.first_memory", agent_id=agent_id)
    # Build response with ETag header
    response_data = {"status": "stored", "key": req.key, "namespace": resolved_ns, "visibility": vis}
    # FastAPI will serialize the response model; we add ETag via Response injection pattern below
    # We use a workaround: store version in a header via JSONResponse
    from fastapi.responses import JSONResponse
    resp = JSONResponse(content=response_data, status_code=200)
    resp.headers["ETag"] = str(new_version)
    return resp


@router.get("/v1/memory/{key}", response_model=MemoryGetResponse, tags=["Memory"])
@limiter.limit("60/minute")
def memory_get(request: Request, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    resolved_ns = _resolve_namespace(namespace, agent_id)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)", (agent_id, resolved_ns, key, now)).fetchone()
        if not row:
            raise HTTPException(404, "Key not found or expired")
        d = dict(row)
        d["value"] = _decrypt(d["value"])
        version = d.get("version") or 1
        d["namespace"] = resolved_ns
    _log_memory_access("read", agent_id, resolved_ns, key, actor_agent_id=agent_id)
    from fastapi.responses import JSONResponse
    response_data = {
        "key": d["key"],
        "value": d["value"],
        "namespace": d["namespace"],
        "updated_at": d["updated_at"],
        "expires_at": d.get("expires_at"),
    }
    resp = JSONResponse(content=response_data, status_code=200)
    resp.headers["ETag"] = str(version)
    return resp


@router.delete("/v1/memory/{key}", tags=["Memory"], response_model=MemoryDeleteResponse)
@limiter.limit("60/minute")
def memory_delete(request: Request, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    resolved_ns = _resolve_namespace(namespace, agent_id)
    with get_db() as db:
        r = db.execute("DELETE FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, resolved_ns, key))
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found")
    _log_memory_access("delete", agent_id, resolved_ns, key, actor_agent_id=agent_id)
    return {"status": "deleted", "key": key}


@router.get("/v1/memory", response_model=MemoryListResponse, tags=["Memory"])
@limiter.limit("60/minute")
def memory_list(request: Request, namespace: str = "default", prefix: str = "", limit: int = Query(50, le=200), agent_id: str = Depends(get_agent_id)):
    resolved_ns = _resolve_namespace(namespace, agent_id)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute("SELECT key, LENGTH(value) as size_bytes, updated_at, expires_at FROM memory WHERE agent_id=? AND namespace=? AND key LIKE ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?", (agent_id, resolved_ns, f"{prefix}%", now, limit)).fetchall()
    return {"namespace": resolved_ns, "keys": [dict(r) for r in rows], "count": len(rows)}
