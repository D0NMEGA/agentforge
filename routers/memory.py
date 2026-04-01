"""Memory routes (8 routes) -- CAS, auto-scoping, history, meta, TTL."""

import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query, Request, Header
from fastapi.responses import Response

from config import MAX_MEMORY_VALUE_SIZE
from db import get_db
from rate_limit import limiter, make_tier_limit
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
    MemoryBatchRequest, MemoryBatchResponse, MemoryBatchResultItem,
)

import re as _re

_VALID_KEY_PATTERN = _re.compile(r'^[a-zA-Z0-9_\-\.:]{1,256}$')

def _validate_key(key: str):
    """Reject path traversal and special chars in memory keys."""
    if not _VALID_KEY_PATTERN.match(key):
        raise HTTPException(422, "Key must be 1-256 characters: letters, digits, underscore, hyphen, dot only")
    if '..' in key:
        raise HTTPException(422, "Key must not contain path traversal sequences")
    if key.startswith("__internal__"):
        raise HTTPException(403, "Reserved key prefix")


router = APIRouter()


@router.get("/v1/agents/{target_agent_id}/memory/{key}", tags=["Memory"], response_model=MemoryCrossAgentReadResponse)
@limiter.limit(make_tier_limit("agent_read"))
def memory_get_cross_agent(request: Request, target_agent_id: str, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    now = datetime.now(timezone.utc).isoformat()
    # SEC-01: Always derive target namespace from target_agent_id auth identity, never from user input
    target_ns = f"agent:{target_agent_id}"

    # SEC-03: Self-read path -- caller reading their own data via cross-agent endpoint
    if hmac.compare_digest(agent_id, target_agent_id):
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)",
                (target_agent_id, target_ns, key, now)
            ).fetchone()
            d = dict(row) if row else None
        _log_memory_access("self_read", target_agent_id, target_ns, key, actor_agent_id=agent_id, authorized=1 if d else 0)
        if not d:
            raise HTTPException(404, "Key not found")
        d["value"] = _decrypt(d["value"])
        d.pop("shared_agents", None)
        return {"key": d["key"], "value": d["value"], "namespace": d["namespace"], "visibility": d.get("visibility") or "private", "updated_at": d["updated_at"], "expires_at": d.get("expires_at")}

    # Cross-agent path: check visibility, return 404 for both not-found and unauthorized (SEC-02)
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)",
            (target_agent_id, target_ns, key, now)
        ).fetchone()
        if not row:
            _log_memory_access("cross_agent_read", target_agent_id, target_ns, key, actor_agent_id=agent_id, authorized=0)
            raise HTTPException(404, "Key not found")
        allowed = _check_memory_visibility(db, target_agent_id, target_ns, key, agent_id)
        d = dict(row) if allowed else None
    _log_memory_access("cross_agent_read", target_agent_id, target_ns, key, actor_agent_id=agent_id, authorized=1 if allowed else 0)
    if not allowed:
        # SEC-02: Return 404 (not 403) to avoid leaking key existence to unauthorized callers
        raise HTTPException(404, "Key not found")
    d["value"] = _decrypt(d["value"])
    d.pop("shared_agents", None)
    return {"key": d["key"], "value": d["value"], "namespace": d["namespace"], "visibility": d.get("visibility") or "private", "updated_at": d["updated_at"], "expires_at": d.get("expires_at")}


@router.patch("/v1/memory/{key}/visibility", tags=["Memory"], response_model=MemoryVisibilityResponse)
@limiter.limit(make_tier_limit("agent_write"))
def memory_set_visibility(request: Request, key: str, req: MemoryVisibilityRequest, namespace: str = Query(None), agent_id: str = Depends(get_agent_id)):
    vis = req.visibility  # Validated by Pydantic Literal["private","public","shared"]
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    # SEC-05: Always scope to caller's auth-derived namespace (req.namespace no longer exists after SEC-01 fix)
    resolved_ns = _resolve_namespace("", agent_id)
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
@limiter.limit(make_tier_limit("agent_read"))
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
@limiter.limit(make_tier_limit("agent_read"))
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
@limiter.limit(make_tier_limit("agent_write"))
def memory_set(request: Request, req: MemorySetRequest, if_match: Optional[str] = Header(None, alias="If-Match"), agent_id: str = Depends(get_agent_id)):
    _validate_key(req.key)
    if "\x00" in req.value:
        raise HTTPException(422, "Null bytes not allowed in values")
    # SEC-01: namespace is auth-derived, not user-supplied (req.namespace removed from model)
    resolved_ns = _resolve_namespace("", agent_id)
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


@router.post("/v1/memory/batch", tags=["Memory"], response_model=MemoryBatchResponse)
@limiter.limit(make_tier_limit("agent_write"))
def memory_batch(request: Request, req: MemoryBatchRequest, agent_id: str = Depends(get_agent_id)):
    results = []
    succeeded = 0
    failed = 0
    log_items = []  # collect (namespace, key) for logging OUTSIDE get_db()

    with get_db() as db:
        for item in req.items:
            try:
                _validate_key(item.key)
                if "\x00" in item.value:
                    raise ValueError("Null bytes not allowed in values")
                resolved_ns = _resolve_namespace("", agent_id)
                now = datetime.now(timezone.utc)
                expires = None
                if item.ttl_seconds:
                    expires = (now + timedelta(seconds=item.ttl_seconds)).isoformat()
                enc_value = _encrypt(item.value)
                vis = item.visibility if item.visibility in ("private", "public", "shared") else "private"
                sa_json = json.dumps(item.shared_agents) if item.shared_agents else None

                existing = db.execute(
                    "SELECT version FROM memory WHERE agent_id=? AND namespace=? AND key=?",
                    (agent_id, resolved_ns, item.key)
                ).fetchone()
                current_version = (existing["version"] or 1) if existing else 0
                new_version = current_version + 1 if existing else 1

                db.execute("""
                    INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, expires_at, visibility, shared_agents, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(agent_id, namespace, key)
                    DO UPDATE SET value=?, updated_at=?, expires_at=?, visibility=?, shared_agents=?, version=?
                """, (agent_id, resolved_ns, item.key, enc_value, now.isoformat(), now.isoformat(), expires, vis, sa_json, new_version,
                      enc_value, now.isoformat(), expires, vis, sa_json, new_version))

                history_id = str(uuid.uuid4())
                db.execute(
                    "INSERT INTO memory_history (id, agent_id, namespace, key, value, version, changed_by, changed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (history_id, agent_id, resolved_ns, item.key, enc_value, new_version, agent_id, now.isoformat())
                )

                results.append(MemoryBatchResultItem(key=item.key, success=True, status="stored"))
                log_items.append((resolved_ns, item.key, new_version))
                succeeded += 1
            except Exception as e:
                results.append(MemoryBatchResultItem(key=item.key, success=False, status="error", error=str(e)))
                failed += 1

    # Log memory access OUTSIDE get_db() block per CLAUDE.md requirement
    for ns, key, ver in log_items:
        _log_memory_access("write", agent_id, ns, key, actor_agent_id=agent_id)
        _queue_agent_event(agent_id, "memory_changed", {"key": key, "namespace": ns, "version": ver})
        publish_event("memory.changed", {
            "agent_id": agent_id, "namespace": ns, "key": key, "action": "write",
        }, source_agent=agent_id)

    return MemoryBatchResponse(results=results, total=len(req.items), succeeded=succeeded, failed=failed)


@router.get("/v1/memory/{key}", response_model=MemoryGetResponse, tags=["Memory"])
@limiter.limit(make_tier_limit("agent_read"))
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
@limiter.limit(make_tier_limit("agent_write"))
def memory_delete(request: Request, key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    resolved_ns = _resolve_namespace(namespace, agent_id)
    with get_db() as db:
        r = db.execute("DELETE FROM memory WHERE agent_id=? AND namespace=? AND key=?", (agent_id, resolved_ns, key))
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found")
    _log_memory_access("delete", agent_id, resolved_ns, key, actor_agent_id=agent_id)
    return {"status": "deleted", "key": key}


@router.get("/v1/memory", response_model=MemoryListResponse, tags=["Memory"])
@limiter.limit(make_tier_limit("agent_read"))
def memory_list(request: Request, namespace: str = "default", prefix: str = "", limit: int = Query(50, ge=1, le=200), agent_id: str = Depends(get_agent_id)):
    resolved_ns = _resolve_namespace(namespace, agent_id)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute("SELECT key, LENGTH(value) as size_bytes, updated_at, expires_at FROM memory WHERE agent_id=? AND namespace=? AND key LIKE ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?", (agent_id, resolved_ns, f"{prefix}%", now, limit)).fetchall()
    return {"namespace": resolved_ns, "keys": [dict(r) for r in rows], "count": len(rows)}
