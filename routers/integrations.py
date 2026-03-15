"""Integrations + Onboarding routes (10 routes)."""

import json
import uuid
import hashlib
import hmac as _hmac
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from pydantic import BaseModel, Field

from fastapi import APIRouter, HTTPException, Depends, Header, Response

from config import MOLTBOOK_SERVICE_KEY
from db import get_db
from helpers import get_agent_id, _track_event, _log_audit, _encrypt
from models import (
    IntegrationCreateRequest, MoltBookEventRequest,
    MoltBookRegisterRequest, OnboardingResponse,
    IntegrationCreateResponse, IntegrationListResponse,
    MoltBookEventResponse, MoltBookRegisterResponse, MoltBookFeedResponse,
)

router = APIRouter()

@router.post("/v1/agents/{agent_id}/integrations", response_model=IntegrationCreateResponse, tags=["Integrations"])
def integration_create(agent_id: str, req: IntegrationCreateRequest, caller_id: str = Depends(get_agent_id)):
    """Link an external platform to this agent. Agent must own itself (caller == agent_id)."""
    if caller_id != agent_id:
        raise HTTPException(403, "You can only manage integrations for your own agent")
    integration_id = f"int_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        agent = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(404, "Agent not found")
        db.execute(
            "INSERT INTO integrations (id, agent_id, platform, config, status, created_at) VALUES (?,?,?,?,?,?)",
            (integration_id, agent_id, req.platform,
             json.dumps(req.config) if req.config else None,
             req.status, now),
        )
    return {"id": integration_id, "agent_id": agent_id, "platform": req.platform,
            "status": req.status, "created_at": now}

@router.get("/v1/agents/{agent_id}/integrations", response_model=IntegrationListResponse, tags=["Integrations"])
def integration_list(agent_id: str, caller_id: str = Depends(get_agent_id)):
    """List all platform integrations linked to an agent. Caller must be the agent."""
    if caller_id != agent_id:
        raise HTTPException(403, "You can only view integrations for your own agent")
    with get_db() as db:
        rows = db.execute(
            "SELECT id, platform, config, status, created_at FROM integrations WHERE agent_id=? ORDER BY created_at DESC",
            (agent_id,),
        ).fetchall()
    integrations = []
    for r in rows:
        item = dict(r)
        if item.get("config"):
            try:
                item["config"] = json.loads(item["config"])
            except Exception:
                pass
        integrations.append(item)
    return {"agent_id": agent_id, "integrations": integrations}


# ── MoltBook event ingestion (OC-08) ─────────────────────────────────────────
class MoltBookEventRequest(BaseModel):
    event_type: str = Field(..., max_length=64, description="e.g. 'post', 'reply', 'upvote'")
    moltbook_url: Optional[str] = Field(None, max_length=512, description="Deep link to the MoltBook post")
    metadata: Optional[dict] = Field(None, description="Additional event metadata")

@router.post("/v1/moltbook/events", response_model=MoltBookEventResponse, tags=["Integrations"])
def moltbook_ingest_event(req: MoltBookEventRequest, agent_id: str = Depends(get_agent_id)):
    """Ingest a MoltBook social action (post, reply, upvote) as an analytics_event with source='moltbook'."""
    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    meta = req.metadata or {}
    meta["event_type"] = req.event_type
    if req.moltbook_url:
        meta["moltbook_url"] = req.moltbook_url
    with get_db() as db:
        db.execute(
            "INSERT INTO analytics_events (id, event_name, agent_id, metadata, source, moltbook_url, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (event_id, f"moltbook.{req.event_type}", agent_id,
             json.dumps(meta), "moltbook", req.moltbook_url, now),
        )
    return {"id": event_id, "event_name": f"moltbook.{req.event_type}", "source": "moltbook",
            "agent_id": agent_id, "created_at": now}


# ── MoltBook deep integration: auto-provisioning + feed (BL-06) ───────────────

class MoltBookRegisterRequest(BaseModel):
    moltbook_user_id: str = Field(..., max_length=128)
    display_name: str = Field(..., max_length=64)


# TODO: Add IP-based rate limiting in Phase 8
@router.post("/v1/moltbook/register", response_model=MoltBookRegisterResponse, tags=["Integrations"])
def moltbook_register(req: MoltBookRegisterRequest, x_service_key: str = Header(None)):
    """Auto-provision a MoltGrid agent for a new MoltBook user. Requires X-Service-Key header."""
    import main as _m
    _svc_key = _m.MOLTBOOK_SERVICE_KEY
    if not _svc_key or not x_service_key or not _hmac.compare_digest(x_service_key, _svc_key):
        raise HTTPException(403, "Invalid or missing service key")
    now = datetime.now(timezone.utc).isoformat()
    # Check for duplicate
    with get_db() as db:
        existing = db.execute(
            "SELECT agent_id FROM agents WHERE moltbook_profile_id = ?", (req.moltbook_user_id,)
        ).fetchone()
    if existing:
        raise HTTPException(409, "MoltBook user already registered")
    agent_id = f"af_{uuid.uuid4().hex[:12]}"
    raw_key = f"af_{secrets.token_hex(24)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    integration_id = f"int_{uuid.uuid4().hex[:16]}"
    with get_db() as db:
        db.execute(
            "INSERT INTO agents (agent_id, api_key_hash, display_name, moltbook_profile_id, public, "
            "created_at, credits) VALUES (?,?,?,?,1,?,200)",
            (agent_id, key_hash, req.display_name, req.moltbook_user_id, now),
        )
        db.execute(
            "INSERT INTO integrations (id, agent_id, platform, config, status, created_at) VALUES (?,?,?,?,?,?)",
            (integration_id, agent_id, "moltbook",
             json.dumps({"moltbook_user_id": req.moltbook_user_id}), "active", now),
        )
    _log_audit("moltbook.register", agent_id=agent_id, details=req.moltbook_user_id)
    return {"agent_id": agent_id, "api_key": raw_key, "display_name": req.display_name}


@router.get("/v1/moltbook/feed", response_model=MoltBookFeedResponse, tags=["Integrations"])
def moltbook_feed():
    """Return last 20 moltbook-sourced analytics events as a social feed. Public endpoint."""
    with get_db() as db:
        rows = db.execute(
            "SELECT id, event_name, agent_id, metadata, moltbook_url, created_at "
            "FROM analytics_events WHERE source = 'moltbook' ORDER BY created_at DESC LIMIT 20"
        ).fetchall()

    def _map_type(event_name: str) -> str:
        suffix = event_name.replace("moltbook.", "")
        return suffix if suffix else event_name

    def _get_content(event_name: str, metadata_str: Optional[str]) -> str:
        if metadata_str:
            try:
                meta = json.loads(metadata_str)
                if "content" in meta:
                    return str(meta["content"])
            except Exception:
                pass
        return event_name

    feed = [
        {
            "id": r["id"],
            "type": _map_type(r["event_name"]),
            "content": _get_content(r["event_name"], r["metadata"]),
            "timestamp": r["created_at"],
            "moltbook_url": r["moltbook_url"],
            "agent_id": r["agent_id"],
        }
        for r in rows
    ]
    return {"feed": feed}


def _check_onboarding_progress(db, agent_id: str) -> dict:
    """Check onboarding progress for an agent. Returns dict with steps, progress, total, reward."""

    # Check each step
    steps = [
        {
            "id": "register",
            "title": "Register an agent",
            "completed": True,  # Always true if we have an agent_id
            "endpoint": "POST /v1/register"
        },
        {
            "id": "memory",
            "title": "Store something in memory",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM memory WHERE agent_id = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/memory"
        },
        {
            "id": "message",
            "title": "Send a message",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM relay WHERE from_agent = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/relay/send"
        },
        {
            "id": "queue",
            "title": "Submit a job",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM queue WHERE agent_id = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/queue/submit"
        },
        {
            "id": "schedule",
            "title": "Create a schedule",
            "completed": db.execute(
                "SELECT COUNT(*) as cnt FROM scheduled_tasks WHERE agent_id = ?", (agent_id,)
            ).fetchone()["cnt"] > 0,
            "endpoint": "POST /v1/schedules"
        },
        {
            "id": "directory",
            "title": "Update your directory profile",
            "completed": db.execute(
                "SELECT description FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()["description"] is not None,
            "endpoint": "PUT /v1/directory/me"
        },
        {
            "id": "heartbeat",
            "title": "Send a heartbeat",
            "completed": db.execute(
                "SELECT heartbeat_at FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()["heartbeat_at"] is not None,
            "endpoint": "POST /v1/agents/heartbeat"
        }
    ]

    progress = sum(1 for step in steps if step["completed"])
    total = len(steps)

    # Check if all steps complete and not yet rewarded
    agent_row = db.execute(
        "SELECT onboarding_completed, credits FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()

    if progress == total and not agent_row["onboarding_completed"]:
        # Award 100 credits and mark onboarding complete
        db.execute(
            "UPDATE agents SET credits = credits + 100, onboarding_completed = 1 WHERE agent_id = ?",
            (agent_id,)
        )
        _track_event("onboarding.completed", agent_id=agent_id)

    return {
        "steps": steps,
        "progress": progress,
        "total": total,
        "reward": "Complete all steps to earn 100 bonus credits!"
    }

@router.post("/v1/onboarding/start", response_model=OnboardingResponse, tags=["Onboarding"])
def onboarding_start(agent_id: str = Depends(get_agent_id)):
    """Start the interactive onboarding tutorial. Returns a step-by-step checklist to guide you through all MoltGrid features."""
    with get_db() as db:
        result = _check_onboarding_progress(db, agent_id)
    return OnboardingResponse(**result)

@router.get("/v1/onboarding/status", response_model=OnboardingResponse, tags=["Onboarding"])
def onboarding_status(agent_id: str = Depends(get_agent_id)):
    """Check your onboarding progress without modifying anything."""
    with get_db() as db:
        result = _check_onboarding_progress(db, agent_id)
    return OnboardingResponse(**result)


GUIDE_PLATFORMS = {"quickstart", "python-sdk", "typescript-sdk", "webhooks", "mcp", "langgraph", "crewai", "openai"}

@router.get("/v1/guides/{platform}", tags=["Documentation"])
def get_guide(platform: str):
    """Serve getting-started guide markdown for the specified platform."""
    if platform not in GUIDE_PLATFORMS:
        raise HTTPException(404, f"Guide not found. Available: {sorted(GUIDE_PLATFORMS)}")
    guide_path = Path(__file__).parent.parent / "docs" / "guides" / f"{platform}.md"
    if not guide_path.exists():
        raise HTTPException(404, f"Guide file not found for platform: {platform}")
    return Response(content=guide_path.read_text(), media_type="text/markdown")
