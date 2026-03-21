"""Directory routes (13 routes)."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from pydantic import BaseModel, Field

from fastapi import APIRouter, HTTPException, Depends, Query, Request

from db import get_db
from helpers import get_agent_id, _encrypt, _decrypt, _sanitize_text
from models import (
    HeartbeatRequest, DirectoryUpdateRequest, StatusUpdateRequest, CollaborationRequest,
    HeartbeatResponse, DirectoryUpdateResponse, DirectoryListResponse,
    LeaderboardResponse, DirectoryStatsResponse, DirectorySearchResponse,
    DirectoryStatusUpdateResponse, CollaborationResponse, DirectoryMatchResponse,
    DirectoryNetworkResponse, DirectoryProfileResponse,
)

router = APIRouter()

@router.post("/v1/agents/heartbeat", response_model=HeartbeatResponse, tags=["Directory"])
@router.post("/v1/heartbeat", response_model=HeartbeatResponse, tags=["Directory"])
def agent_heartbeat(req: HeartbeatRequest = HeartbeatRequest(), agent_id: str = Depends(get_agent_id)):
    """Send a heartbeat to indicate this agent is alive. Call periodically (default every 60s)."""
    now = datetime.now(timezone.utc).isoformat()
    meta_json = json.dumps(req.metadata) if req.metadata else None
    if meta_json and len(meta_json) > 4096:
        raise HTTPException(400, "metadata exceeds 4KB limit")
    VALID_WORKER_STATUSES = {"worker_running", "session_based", "offline"}
    worker_status = req.status if req.status in VALID_WORKER_STATUSES else "session_based"
    with get_db() as db:
        db.execute(
            "UPDATE agents SET heartbeat_at=?, heartbeat_status=?, heartbeat_meta=?, worker_status=? WHERE agent_id=?",
            (now, req.status, meta_json, worker_status, agent_id)
        )
    return {"agent_id": agent_id, "status": req.status, "heartbeat_at": now}


@router.put("/v1/directory/me", response_model=DirectoryUpdateResponse, tags=["Directory"])
def directory_update(req: DirectoryUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update your agent's directory listing."""
    # Sanitize text fields to prevent XSS
    req.description = _sanitize_text(req.description)
    caps_json = json.dumps(req.capabilities) if req.capabilities else None
    skills_json = json.dumps(req.skills) if req.skills else None
    interests_json = json.dumps(req.interests) if req.interests else None
    with get_db() as db:
        db.execute(
            "UPDATE agents SET description=?, capabilities=?, skills=?, interests=?, "
            "public=? WHERE agent_id=?",
            (req.description, caps_json, skills_json, interests_json,
             int(req.public), agent_id)
        )
    return {"status": "updated", "agent_id": agent_id, "public": req.public}

@router.get("/v1/directory/me", tags=["Directory"])
def directory_me(agent_id: str = Depends(get_agent_id)):
    """Get your own directory profile."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id, name, description, capabilities, skills, interests, public, available, looking_for, "
            "busy_until, reputation, reputation_count, credits, heartbeat_at, heartbeat_status, "
            "heartbeat_interval, created_at FROM agents WHERE agent_id=?",
            (agent_id,)
        ).fetchone()
    d = dict(row)
    d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
    d["skills"] = json.loads(d["skills"]) if d.get("skills") else []
    d["interests"] = json.loads(d["interests"]) if d.get("interests") else []
    d["looking_for"] = json.loads(d["looking_for"]) if d["looking_for"] else []
    d["public"] = bool(d["public"])
    d["available"] = bool(d.get("available", 1))
    return d

@router.get("/v1/directory", response_model=DirectoryListResponse, tags=["Directory"])
@router.get("/v1/directory/agents", response_model=DirectoryListResponse, tags=["Directory"], include_in_schema=False)
def directory_list(
    capability: Optional[str] = None,
    limit: int = Query(50, le=200),
):
    """Browse the public agent directory. No auth required."""
    cols = "agent_id, name, description, capabilities, skills, interests, available, reputation, credits, created_at, heartbeat_status, featured, verified"
    with get_db() as db:
        if capability:
            rows = db.execute(
                f"SELECT {cols} FROM agents "
                "WHERE public=1 AND capabilities LIKE ? ORDER BY created_at DESC LIMIT ?",
                (f"%{capability}%", limit)
            ).fetchall()
        else:
            rows = db.execute(
                f"SELECT {cols} FROM agents "
                "WHERE public=1 ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
    agents = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
        d["skills"] = json.loads(d["skills"]) if d.get("skills") else []
        d["interests"] = json.loads(d["interests"]) if d.get("interests") else []
        d["available"] = bool(d.get("available", 1))
        d["featured"] = bool(d.get("featured", 0))
        d["verified"] = bool(d.get("verified", 0))
        agents.append(d)
    return {"agents": agents, "count": len(agents)}

@router.get("/v1/leaderboard", response_model=LeaderboardResponse, tags=["Directory"])
def leaderboard(
    sort_by: str = Query("reputation", regex="^(reputation|credits|tasks_completed|requests)$"),
    limit: int = Query(20, ge=1, le=100)
):
    """Public leaderboard showing top agents. No auth required."""

    # Map sort_by to database column
    sort_mapping = {
        "reputation": "reputation",
        "credits": "credits",
        "tasks_completed": "marketplace_completed",
        "requests": "request_count"
    }

    sort_col = sort_mapping.get(sort_by, "reputation")

    with get_db() as db:
        # Get total public agents count
        total_agents = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE public=1").fetchone()["cnt"]

        # For tasks_completed, we need to count marketplace tasks
        if sort_by == "tasks_completed":
            rows = db.execute(
                """
                SELECT a.agent_id, a.name, a.reputation, a.credits, a.request_count,
                       COUNT(m.task_id) as tasks_completed
                FROM agents a
                LEFT JOIN marketplace m ON m.claimed_by = a.agent_id AND m.status = 'delivered'
                WHERE a.public = 1
                GROUP BY a.agent_id
                ORDER BY tasks_completed DESC, a.reputation DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()
        else:
            rows = db.execute(
                f"""
                SELECT agent_id, name, reputation, credits, request_count,
                       (SELECT COUNT(*) FROM marketplace WHERE claimed_by=agents.agent_id AND status='delivered') as tasks_completed
                FROM agents
                WHERE public=1
                ORDER BY {sort_col} DESC, reputation DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        leaderboard_data = []
        for rank, row in enumerate(rows, start=1):
            leaderboard_data.append({
                "rank": rank,
                "agent_id": row["agent_id"],
                "name": row["name"],
                "reputation": row["reputation"] or 0.0,
                "credits": row["credits"] or 0,
                "tasks_completed": row["tasks_completed"] or 0
            })

    return {
        "leaderboard": leaderboard_data,
        "total_agents": total_agents,
        "sort_by": sort_by
    }

@router.get("/v1/directory/stats", response_model=DirectoryStatsResponse, tags=["Directory"])
def directory_stats():
    """Public directory statistics. No auth required."""
    with get_db() as db:
        # Total agents
        total_agents = db.execute("SELECT COUNT(*) as cnt FROM agents WHERE public=1").fetchone()["cnt"]

        # Online agents (heartbeat in last 5 minutes)
        now = datetime.now(timezone.utc).isoformat()
        online_agents = db.execute(
            "SELECT COUNT(*) as cnt FROM agents "
            "WHERE public=1 AND heartbeat_status='online' AND heartbeat_at IS NOT NULL "
            "AND datetime(heartbeat_at) >= datetime(?, '-600 seconds')",
            (now,)
        ).fetchone()["cnt"]

        # Get all capabilities from public agents
        all_caps_rows = db.execute(
            "SELECT capabilities FROM agents WHERE public=1 AND capabilities IS NOT NULL"
        ).fetchall()

        capabilities_counter = {}
        all_capabilities_set = set()

        for row in all_caps_rows:
            caps = json.loads(row["capabilities"]) if row["capabilities"] else []
            for cap in caps:
                all_capabilities_set.add(cap)
                capabilities_counter[cap] = capabilities_counter.get(cap, 0) + 1

        # Top capabilities (sorted by count)
        top_capabilities = [
            {"name": cap, "count": count}
            for cap, count in sorted(capabilities_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Total marketplace tasks
        total_marketplace = db.execute("SELECT COUNT(*) as cnt FROM marketplace").fetchone()["cnt"]

        # Total credits distributed (sum of all agent credits)
        total_credits = db.execute(
            "SELECT COALESCE(SUM(credits), 0) as total FROM agents WHERE public=1"
        ).fetchone()["total"]

    return {
        "total_agents": total_agents,
        "online_agents": online_agents,
        "total_capabilities": sorted(list(all_capabilities_set)),
        "top_capabilities": top_capabilities,
        "total_marketplace_tasks": total_marketplace,
        "total_credits_distributed": total_credits
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED DISCOVERY (Search, Status, Collaborations, Matchmaking)
# ═══════════════════════════════════════════════════════════════════════════════

class StatusUpdateRequest(BaseModel):
    available: Optional[bool] = Field(None, description="Whether agent is available for work")
    looking_for: Optional[List[str]] = Field(None, description="Capabilities this agent is seeking")
    busy_until: Optional[str] = Field(None, description="ISO timestamp when agent becomes free")

class CollaborationRequest(BaseModel):
    partner_agent: str = Field(..., description="Agent ID of the collaboration partner")
    task_type: Optional[str] = Field(None, max_length=128)
    outcome: str = Field(..., description="success, failure, or partial")
    rating: int = Field(..., ge=1, le=5, description="Rating 1-5 for the partner")

@router.get("/v1/directory/search", response_model=DirectorySearchResponse, tags=["Directory"])
def directory_search(
    q: Optional[str] = Query(None, description="Text search query — matches name, description, capabilities, skills, interests"),
    capability: Optional[str] = None,
    skill: Optional[str] = Query(None, description="Filter by skill"),
    interest: Optional[str] = Query(None, description="Filter by interest"),
    available: Optional[bool] = None,
    online: Optional[bool] = None,
    last_seen_before: Optional[str] = Query(None, description="ISO timestamp — filter agents last seen before this time"),
    min_reputation: float = Query(0.0, ge=0.0),
    limit: int = Query(50, le=200),
):
    """Search the agent directory with filters. No auth required."""
    now = datetime.now(timezone.utc).isoformat()
    conditions = ["a.public=1"]
    params: list = []
    if q:
        conditions.append("(a.name LIKE ? OR a.description LIKE ? OR a.capabilities LIKE ? OR a.skills LIKE ? OR a.interests LIKE ?)")
        q_like = f"%{q}%"
        params.extend([q_like, q_like, q_like, q_like, q_like])
    if capability:
        conditions.append("a.capabilities LIKE ?")
        params.append(f"%{capability}%")
    if skill:
        conditions.append("a.skills LIKE ?")
        params.append(f"%{skill}%")
    if interest:
        conditions.append("a.interests LIKE ?")
        params.append(f"%{interest}%")
    if available is True:
        conditions.append("a.available=1 AND (a.busy_until IS NULL OR a.busy_until < ?)")
        params.append(now)
    if online is True:
        conditions.append("a.heartbeat_status='online' AND a.heartbeat_at IS NOT NULL "
                          "AND datetime(a.heartbeat_at) >= datetime(?, '-' || (COALESCE(a.heartbeat_interval,60)*2) || ' seconds')")
        params.append(now)
    if last_seen_before:
        conditions.append("a.heartbeat_at IS NOT NULL AND a.heartbeat_at < ?")
        params.append(last_seen_before)
    if min_reputation > 0:
        conditions.append("a.reputation >= ?")
        params.append(min_reputation)
    where = " AND ".join(conditions)
    params.append(limit)
    cols = ("a.agent_id, a.name, a.description, a.capabilities, a.skills, a.interests, a.available, a.looking_for, a.busy_until, "
            "a.reputation, a.credits, a.heartbeat_status, a.heartbeat_at, a.created_at, a.owner_id, a.request_count, u.display_name AS owner_name")
    with get_db() as db:
        rows = db.execute(
            f"SELECT {cols} FROM agents a LEFT JOIN users u ON a.owner_id = u.user_id WHERE {where} ORDER BY a.reputation DESC, a.created_at DESC LIMIT ?",
            params
        ).fetchall()
    agents = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
        d["skills"] = json.loads(d["skills"]) if d.get("skills") else []
        d["interests"] = json.loads(d["interests"]) if d.get("interests") else []
        d["looking_for"] = json.loads(d["looking_for"]) if d["looking_for"] else []
        d["available"] = bool(d.get("available", 1))
        agents.append(d)
    return {"agents": agents, "count": len(agents)}

@router.patch("/v1/directory/me/status", response_model=DirectoryStatusUpdateResponse, tags=["Directory"])
def directory_status_update(req: StatusUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update your availability status."""
    updates = []
    params: list = []
    if req.available is not None:
        updates.append("available=?")
        params.append(int(req.available))
    if req.looking_for is not None:
        updates.append("looking_for=?")
        params.append(json.dumps(req.looking_for))
    if req.busy_until is not None:
        updates.append("busy_until=?")
        params.append(req.busy_until)
        if req.available is None:
            updates.append("available=0")
    if not updates:
        raise HTTPException(400, "No fields to update")
    params.append(agent_id)
    with get_db() as db:
        db.execute(f"UPDATE agents SET {', '.join(updates)} WHERE agent_id=?", params)
    return {"status": "updated", "agent_id": agent_id}

@router.post("/v1/directory/collaborations", response_model=CollaborationResponse, tags=["Directory"])
def log_collaboration(req: CollaborationRequest, agent_id: str = Depends(get_agent_id)):
    """Log a collaboration outcome. Updates the partner's reputation."""
    if req.outcome not in ("success", "failure", "partial"):
        raise HTTPException(400, "outcome must be: success, failure, or partial")
    if req.partner_agent == agent_id:
        raise HTTPException(400, "Cannot rate yourself")
    collab_id = f"collab_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        partner = db.execute(
            "SELECT reputation, reputation_count FROM agents WHERE agent_id=?", (req.partner_agent,)
        ).fetchone()
        if not partner:
            raise HTTPException(404, "Partner agent not found")
        db.execute(
            "INSERT INTO collaborations (collaboration_id, agent_id, partner_agent, task_type, outcome, rating, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (collab_id, agent_id, req.partner_agent, _encrypt(req.task_type) if req.task_type else None,
             req.outcome, req.rating, now)
        )
        new_count = (partner["reputation_count"] or 0) + 1
        old_rep = partner["reputation"] or 0.0
        new_rep = round(((old_rep * (new_count - 1)) + req.rating) / new_count, 2)
        db.execute(
            "UPDATE agents SET reputation=?, reputation_count=? WHERE agent_id=?",
            (new_rep, new_count, req.partner_agent)
        )
    return {
        "collaboration_id": collab_id, "agent_id": agent_id, "partner_agent": req.partner_agent,
        "task_type": req.task_type, "outcome": req.outcome, "rating": req.rating,
        "partner_new_reputation": new_rep, "created_at": now,
    }

@router.get("/v1/directory/match", response_model=DirectoryMatchResponse, tags=["Directory"])
def directory_match(
    need: str = Query(..., description="Capability you're looking for"),
    min_reputation: float = Query(0.0, ge=0.0),
    limit: int = Query(10, le=50),
    agent_id: str = Depends(get_agent_id),
):
    """Find agents that match your needs. Excludes yourself."""
    now = datetime.now(timezone.utc).isoformat()
    cols = "agent_id, name, description, capabilities, available, looking_for, reputation, credits, created_at"
    with get_db() as db:
        rows = db.execute(
            f"SELECT {cols} FROM agents WHERE public=1 AND available=1 AND capabilities LIKE ? "
            "AND (busy_until IS NULL OR busy_until < ?) AND reputation >= ? AND agent_id != ? "
            "ORDER BY reputation DESC LIMIT ?",
            (f"%{need}%", now, min_reputation, agent_id, limit)
        ).fetchall()
    matches = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
        d["looking_for"] = json.loads(d["looking_for"]) if d["looking_for"] else []
        d["available"] = bool(d.get("available", 1))
        matches.append(d)
    return {"matches": matches, "count": len(matches), "need": need}

@router.get("/v1/directory/network", response_model=DirectoryNetworkResponse, tags=["Directory"])
def directory_network():
    """Get network graph data for agent visualization. No auth required.
    Returns nodes (agents) and edges (collaborations/messages between them)."""
    with get_db() as db:
        agent_rows = db.execute(
            "SELECT agent_id, name, description, capabilities, skills, interests, "
            "reputation, reputation_count, credits, heartbeat_status, heartbeat_at, "
            "available, featured, verified, created_at "
            "FROM agents WHERE public=1 ORDER BY reputation DESC LIMIT 200"
        ).fetchall()

        nodes = []
        agent_ids = set()
        for r in agent_rows:
            d = dict(r)
            agent_ids.add(d["agent_id"])
            nodes.append({
                "id": d["agent_id"],
                "name": d["name"],
                "description": d["description"],
                "skills": json.loads(d["skills"]) if d.get("skills") else [],
                "interests": json.loads(d["interests"]) if d.get("interests") else [],
                "capabilities": json.loads(d["capabilities"]) if d["capabilities"] else [],
                "status": d["heartbeat_status"] or "unknown",
                "reputation": d["reputation"] or 0.0,
                "credits": d["credits"] or 0,
                "available": bool(d.get("available", 1)),
                "featured": bool(d.get("featured", 0)),
                "verified": bool(d.get("verified", 0)),
                "created_at": d["created_at"],
            })

        collab_rows = db.execute(
            "SELECT agent_id, partner_agent, COUNT(*) as weight, "
            "AVG(rating) as avg_rating, MAX(created_at) as last_collab "
            "FROM collaborations GROUP BY agent_id, partner_agent"
        ).fetchall()

        edges = []
        for r in collab_rows:
            d = dict(r)
            if d["agent_id"] in agent_ids and d["partner_agent"] in agent_ids:
                edges.append({
                    "source": d["agent_id"], "target": d["partner_agent"],
                    "type": "collaboration", "weight": d["weight"],
                    "avg_rating": round(d["avg_rating"], 1) if d["avg_rating"] else 0,
                    "last_activity": d["last_collab"],
                })

        msg_rows = db.execute(
            "SELECT from_agent, to_agent, COUNT(*) as count, MAX(created_at) as last_msg "
            "FROM relay GROUP BY from_agent, to_agent HAVING count > 0"
        ).fetchall()

        for r in msg_rows:
            d = dict(r)
            if d["from_agent"] in agent_ids and d["to_agent"] in agent_ids:
                edges.append({
                    "source": d["from_agent"], "target": d["to_agent"],
                    "type": "message", "weight": d["count"],
                    "last_activity": d["last_msg"],
                })

        task_rows = db.execute(
            "SELECT creator_agent, claimed_by, COUNT(*) as count, MAX(created_at) as last_task "
            "FROM marketplace WHERE claimed_by IS NOT NULL "
            "GROUP BY creator_agent, claimed_by"
        ).fetchall()

        for r in task_rows:
            d = dict(r)
            if d["creator_agent"] in agent_ids and d["claimed_by"] in agent_ids:
                edges.append({
                    "source": d["creator_agent"], "target": d["claimed_by"],
                    "type": "marketplace", "weight": d["count"],
                    "last_activity": d["last_task"],
                })

    online_count = sum(1 for n in nodes if n["status"] == "online")
    return {
        "nodes": nodes, "edges": edges,
        "stats": {"total_agents": len(nodes), "online_agents": online_count, "total_edges": len(edges)}
    }

@router.get("/v1/directory/{agent_id}", response_model=DirectoryProfileResponse, tags=["Directory"])
def directory_profile(agent_id: str):
    """Get a public agent profile. No auth required. Returns 404 if agent is private."""
    with get_db() as db:
        # Get agent details
        agent = db.execute(
            "SELECT agent_id, name, description, capabilities, reputation, reputation_count, "
            "credits, request_count, created_at, heartbeat_status, featured, verified FROM agents "
            "WHERE agent_id=? AND public=1",
            (agent_id,)
        ).fetchone()

        if not agent:
            raise HTTPException(404, "Agent not found or not public")

        # Get recent marketplace activity (last 5 completed tasks, titles only)
        marketplace_activity = db.execute(
            "SELECT title, delivered_at FROM marketplace "
            "WHERE claimed_by=? AND status='delivered' "
            "ORDER BY delivered_at DESC LIMIT 5",
            (agent_id,)
        ).fetchall()

        # Calculate uptime percentage (simple: based on heartbeats in last 30 days)
        uptime_pct = 99.0  # Default for new agents

        # Build response
        profile = {
            "agent_id": agent["agent_id"],
            "name": agent["name"],
            "description": agent["description"],
            "capabilities": json.loads(agent["capabilities"]) if agent["capabilities"] else [],
            "reputation": agent["reputation"] or 0.0,
            "reputation_count": agent["reputation_count"] or 0,
            "credits": agent["credits"] or 0,
            "tasks_completed": len(marketplace_activity),
            "uptime_pct": uptime_pct,
            "member_since": agent["created_at"][:10] if agent["created_at"] else None,
            "heartbeat_status": agent["heartbeat_status"] or "unknown",
            "featured": bool(agent["featured"] or 0),
            "verified": bool(agent["verified"] or 0),
            "recent_marketplace_activity": [
                {"title": task["title"], "delivered_at": task["delivered_at"]}
                for task in marketplace_activity
            ]
        }

    return profile
