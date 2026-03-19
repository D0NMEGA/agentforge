"""Memory routes (6 routes)."""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query

from config import MAX_MEMORY_VALUE_SIZE
from db import get_db
from helpers import (
    get_agent_id, _encrypt, _decrypt,
    _log_memory_access, _check_memory_visibility, _track_event,
)
from models import (
    MemorySetRequest, MemoryGetResponse, MemoryListResponse,
    MemoryVisibilityRequest, MemoryCrossAgentReadResponse,
    MemorySetResponse, MemoryDeleteResponse, MemoryVisibilityResponse,
)

router = APIRouter()


@router.get("/v1/agents/{target_agent_id}/memory/{key}", tags=["Memory"], response_model=MemoryCrossAgentReadResponse)
def memory_get_cross_agent(target_agent_id: str, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)", (target_agent_id, namespace, key, now)).fetchone()
        if not row:
            raise HTTPException(404, "Key not found")
        allowed = _check_memory_visibility(db, target_agent_id, namespace, key, agent_id)
        d = dict(row) if allowed else None
    _log_memory_access("cross_agent_read", target_agent_id, namespace, key, actor_agent_id=agent_id, authorized=1 if allowed else 0)
    if not allowed:
        raise HTTPException(403, "Access denied: memory entry is private or not shared with you")
    d["value"] = _decrypt(d["value"])
    d.pop("shared_agents", None)
    return {"key": d["key"], "value": d["value"], "namespace": d["namespace"], "visibility": d.get("visibility") or "private", "updated_at": d["updated_at"], "expires_at": d.get("expires_at")}


@router.patch("/v1/memory/{key}/visibility", tags=["Memory"], response_model=MemoryVisibilityResponse)
def memory_set_visibility(key: str, req: MemoryVisibilityRequest, namespace: str = Query(None), agent_id: str = Depends(get_agent_id)):
    # Accept namespace from query param or body (body takes precedence)
    if namespace and req.namespace == "default":
        req.namespace = namespace
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    with get_db() as db:
        old = db.execute("SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, req.namespace, key)).fetchone()
        if not old:
            raise HTTPException(404, "Key not found")
        db.execute("UPDATE memory SET visibility=?, shared_agents=? WHERE agent_id=? AND namespace=? AND key=?", (vis, sa_json, agent_id, req.namespace, key))
    _log_memory_access("visibility_changed", agent_id, req.namespace, key, actor_agent_id=agent_id, old_visibility=old["visibility"] or "private", new_visibility=vis)
    return {"status": "updated", "key": key, "visibility": vis}


@router.post("/v1/memory", tags=["Memory"], response_model=MemorySetResponse)
def memory_set(req: MemorySetRequest, agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()
    enc_value = _encrypt(req.value)
    # Accept namespace from query param or body (body takes precedence)
    if namespace and req.namespace == "default":
        req.namespace = namespace
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    with get_db() as db:
        is_first = db.execute("SELECT COUNT(*) as c FROM memory WHERE agent_id=?", (agent_id,)).fetchone()["c"] == 0
        db.execute("""
            INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, expires_at, visibility, shared_agents)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, namespace, key)
            DO UPDATE SET value=?, updated_at=?, expires_at=?, visibility=?, shared_agents=?
        """, (agent_id, req.namespace, req.key, enc_value, now.isoformat(), now.isoformat(), expires, vis, sa_json,
              enc_value, now.isoformat(), expires, vis, sa_json))
    _log_memory_access("write", agent_id, req.namespace, req.key, actor_agent_id=agent_id)
    if is_first:
        _track_event("agent.first_memory", agent_id=agent_id)
    return {"status": "stored", "key": req.key, "namespace": req.namespace, "visibility": vis}

@router.get("/v1/memory/{key}", response_model=MemoryGetResponse, tags=["Memory"])
def memory_get(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)", (agent_id, namespace, key, now)).fetchone()
        if not row:
            raise HTTPException(404, "Key not found or expired")
        d = dict(row)
        d["value"] = _decrypt(d["value"])
    _log_memory_access("read", agent_id, namespace, key, actor_agent_id=agent_id)
    return MemoryGetResponse(**d)

@router.delete("/v1/memory/{key}", tags=["Memory"], response_model=MemoryDeleteResponse)
def memory_delete(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    with get_db() as db:
        r = db.execute("DELETE FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, namespace, key))
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found")
    _log_memory_access("delete", agent_id, namespace, key, actor_agent_id=agent_id)
    return {"status": "deleted", "key": key}

@router.get("/v1/memory", response_model=MemoryListResponse, tags=["Memory"])
def memory_list(namespace: str = "default", prefix: str = "", limit: int = Query(50, le=200), agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute("SELECT key, LENGTH(value) as size_bytes, updated_at, expires_at FROM memory WHERE agent_id=? AND namespace=? AND key LIKE ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?", (agent_id, namespace, f"{prefix}%", now, limit)).fetchall()
    return {"namespace": namespace, "keys": [dict(r) for r in rows], "count": len(rows)}
