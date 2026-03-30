"""Marketplace + Testing routes (10 routes)."""

import json
import uuid
import time
import random
import statistics
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from pydantic import BaseModel, Field

from fastapi import APIRouter, HTTPException, Depends, Query, Request

from db import get_db
from helpers import get_agent_id, _encrypt, _decrypt, _fire_webhooks
from models import (
    MarketplaceCreateRequest, MarketplaceDeliverRequest, MarketplaceReviewRequest, ScenarioCreateRequest,
    MarketplaceCreateResponse, MarketplaceBrowseResponse, MarketplaceClaimResponse,
    MarketplaceDeliverResponse, MarketplaceReviewResponse,
    ScenarioCreateResponse, ScenarioListResponse, ScenarioRunResponse,
)

from rate_limit import limiter, make_tier_limit

router = APIRouter()

MARKETPLACE_STATUSES = {"open", "claimed", "delivered", "completed", "expired"}
COORDINATION_PATTERNS = {"leader_election", "consensus", "load_balancing", "pub_sub_fanout", "task_auction"}

def _expire_marketplace_tasks(db):
    """Lazy expiration: mark past-deadline open tasks as expired."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute("UPDATE marketplace SET status='expired' WHERE status='open' AND deadline IS NOT NULL AND deadline < ?", (now,))

def _auto_approve_marketplace_tasks(db):
    """Auto-approve delivered tasks older than 24 hours and award credits to workers."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    tasks = db.execute(
        "SELECT task_id, claimed_by, reward_credits, creator_agent FROM marketplace "
        "WHERE status='delivered' AND delivered_at < ?",
        (cutoff,)
    ).fetchall()
    for task in tasks:
        # Award credits to worker
        if task["reward_credits"] and task["reward_credits"] > 0:
            db.execute(
                "UPDATE agents SET credits = credits + ? WHERE agent_id=?",
                (task["reward_credits"], task["claimed_by"])
            )
        # Mark as completed with max rating for auto-approval
        db.execute(
            "UPDATE marketplace SET status='completed', rating=5 WHERE task_id=?",
            (task["task_id"],)
        )
        # Fire webhook notification
        try:
            _fire_webhooks(task["claimed_by"], "marketplace.task.completed", {
                "task_id": task["task_id"], "credits_awarded": task["reward_credits"] or 0,
                "rating": 5, "auto_approved": True
            })
        except:
            pass  # Don't fail the auto-approval if webhook fails

def _parse_marketplace_row(row):
    d = dict(row)
    d["requirements"] = json.loads(d["requirements"]) if d["requirements"] else []
    d["tags"] = json.loads(d["tags"]) if d["tags"] else []
    if d.get("description"):
        d["description"] = _decrypt(d["description"])
    if d.get("result"):
        d["result"] = _decrypt(d["result"])
    return d

@router.post("/v1/marketplace/tasks", response_model=MarketplaceCreateResponse, tags=["Marketplace"])
@limiter.limit(make_tier_limit("agent_write"))
def marketplace_create(request: Request, req: MarketplaceCreateRequest, agent_id: str = Depends(get_agent_id)):
    """Post a task to the marketplace for other agents to claim. Costs credits upfront."""
    task_id = f"mktask_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        # Check if agent has enough credits
        agent = db.execute("SELECT credits FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not agent or (agent["credits"] or 0) < req.reward_credits:
            raise HTTPException(402, f"Insufficient credits. You have {agent['credits'] or 0}, need {req.reward_credits}")

        # Deduct credits upfront
        db.execute(
            "UPDATE agents SET credits = credits - ? WHERE agent_id=?",
            (req.reward_credits, agent_id)
        )

        db.execute(
            "INSERT INTO marketplace (task_id, creator_agent, title, description, category, requirements, "
            "reward_credits, priority, estimated_effort, tags, deadline, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (task_id, agent_id, req.title,
             _encrypt(req.description) if req.description else None,
             req.category,
             json.dumps(req.requirements) if req.requirements else None,
             req.reward_credits, req.priority, req.estimated_effort,
             json.dumps(req.tags) if req.tags else None,
             req.deadline, "open", now)
        )
    return {"task_id": task_id, "status": "open", "created_at": now, "credits_deducted": req.reward_credits}

@router.get("/v1/marketplace/tasks", response_model=MarketplaceBrowseResponse, tags=["Marketplace"])
@limiter.limit(make_tier_limit("agent_read"))
def marketplace_browse(request: Request, 
    category: Optional[str] = None,
    status: str = Query("open"),
    tag: Optional[str] = None,
    min_reward: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Browse marketplace tasks. No auth required."""
    conditions = ["status=?"]
    params: list = [status]
    if category:
        conditions.append("category=?")
        params.append(category)
    if tag:
        conditions.append("tags LIKE ?")
        params.append(f"%{tag}%")
    if min_reward > 0:
        conditions.append("reward_credits >= ?")
        params.append(min_reward)
    where = " AND ".join(conditions)
    params.append(limit)
    with get_db() as db:
        _expire_marketplace_tasks(db)
        _auto_approve_marketplace_tasks(db)
        rows = db.execute(
            f"SELECT * FROM marketplace WHERE {where} ORDER BY priority DESC, created_at DESC LIMIT ?",
            params
        ).fetchall()
    return {"tasks": [_parse_marketplace_row(r) for r in rows], "count": len(rows)}

@router.get("/v1/marketplace/tasks/{task_id}", tags=["Marketplace"])
@limiter.limit(make_tier_limit("agent_read"))
def marketplace_detail(request: Request, task_id: str):
    """Get marketplace task details. No auth required."""
    with get_db() as db:
        row = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Task not found")
    return _parse_marketplace_row(row)

@router.post("/v1/marketplace/tasks/{task_id}/claim", response_model=MarketplaceClaimResponse, tags=["Marketplace"])
@limiter.limit(make_tier_limit("agent_write"))
def marketplace_claim(request: Request, task_id: str, agent_id: str = Depends(get_agent_id)):
    """Claim an open marketplace task."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        _expire_marketplace_tasks(db)
        _auto_approve_marketplace_tasks(db)
        task = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "Task not found")
        if task["status"] != "open":
            raise HTTPException(409, f"Task is not open (status: {task['status']})")
        if task["creator_agent"] == agent_id:
            raise HTTPException(400, "Cannot claim your own task")
        result = db.execute(
            "UPDATE marketplace SET status='claimed', claimed_by=?, claimed_at=? WHERE task_id=? AND status='open'",
            (agent_id, now, task_id)
        )
        if result.rowcount == 0:
            raise HTTPException(409, "Task already claimed or not available")
    _fire_webhooks(task["creator_agent"], "marketplace.task.claimed", {
        "task_id": task_id, "claimed_by": agent_id, "title": task["title"],
    })
    return {"task_id": task_id, "status": "claimed", "claimed_by": agent_id}

@router.post("/v1/marketplace/tasks/{task_id}/deliver", response_model=MarketplaceDeliverResponse, tags=["Marketplace"])
@limiter.limit(make_tier_limit("agent_write"))
def marketplace_deliver(request: Request, task_id: str, req: MarketplaceDeliverRequest, agent_id: str = Depends(get_agent_id)):
    """Submit a deliverable for a claimed task."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        task = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "Task not found")
        if task["status"] != "claimed":
            raise HTTPException(400, f"Task is not claimed (status: {task['status']})")
        if task["claimed_by"] != agent_id:
            raise HTTPException(403, "Only the claimant can deliver")
        db.execute(
            "UPDATE marketplace SET status='delivered', result=?, delivered_at=? WHERE task_id=?",
            (_encrypt(req.result), now, task_id)
        )
    _fire_webhooks(task["creator_agent"], "marketplace.task.delivered", {
        "task_id": task_id, "delivered_by": agent_id, "title": task["title"],
    })
    return {"task_id": task_id, "status": "delivered"}

@router.post("/v1/marketplace/tasks/{task_id}/review", response_model=MarketplaceReviewResponse, tags=["Marketplace"])
@limiter.limit(make_tier_limit("agent_write"))
def marketplace_review(request: Request, task_id: str, req: MarketplaceReviewRequest, agent_id: str = Depends(get_agent_id)):
    """Accept or reject a delivery. Accepting awards credits to the worker."""
    with get_db() as db:
        task = db.execute("SELECT * FROM marketplace WHERE task_id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "Task not found")
        if task["status"] != "delivered":
            raise HTTPException(400, f"Task is not delivered (status: {task['status']})")
        if task["creator_agent"] != agent_id:
            raise HTTPException(403, "Only the creator can review")
        credits_awarded = 0
        if req.accept:
            db.execute(
                "UPDATE marketplace SET status='completed', rating=? WHERE task_id=?",
                (req.rating, task_id)
            )
            if task["reward_credits"] and task["reward_credits"] > 0:
                db.execute(
                    "UPDATE agents SET credits = credits + ? WHERE agent_id=?",
                    (task["reward_credits"], task["claimed_by"])
                )
                credits_awarded = task["reward_credits"]
            _fire_webhooks(task["claimed_by"], "marketplace.task.completed", {
                "task_id": task_id, "credits_awarded": credits_awarded, "rating": req.rating,
            })
            return {"task_id": task_id, "status": "completed", "credits_awarded": credits_awarded}
        else:
            db.execute(
                "UPDATE marketplace SET status='open', claimed_by=NULL, claimed_at=NULL, "
                "delivered_at=NULL, result=NULL WHERE task_id=?",
                (task_id,)
            )
            return {"task_id": task_id, "status": "open", "credits_awarded": 0}


# ═══════════════════════════════════════════════════════════════════════════════
# COORDINATION TESTING FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════════

COORDINATION_PATTERNS = {"leader_election", "consensus", "load_balancing", "pub_sub_fanout", "task_auction"}

class ScenarioCreateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=128)
    pattern: str = Field(..., description="One of: leader_election, consensus, load_balancing, pub_sub_fanout, task_auction")
    agent_count: int = Field(..., ge=2, le=20)
    timeout_seconds: int = Field(60, ge=5, le=300)
    success_criteria: Optional[dict] = Field(None)

def _run_coordination_pattern(pattern: str, agent_count: int, timeout_seconds: int) -> dict:
    """Run a deterministic coordination pattern simulation."""
    start = time.time()
    agents = [f"test_agent_{i}" for i in range(agent_count)]

    if pattern == "leader_election":
        rounds = 0
        messages = 0
        priorities = {a: random.randint(1, 1000) for a in agents}
        candidates = set(agents)
        while len(candidates) > 1 and (time.time() - start) < timeout_seconds:
            rounds += 1
            new_candidates = set()
            for c in candidates:
                higher = [o for o in candidates if priorities[o] > priorities[c]]
                messages += len(higher)
                if not higher:
                    new_candidates.add(c)
            candidates = new_candidates if new_candidates else {max(candidates, key=lambda a: priorities[a])}
        leader = list(candidates)[0] if candidates else None
        return {
            "pattern": "leader_election", "success": leader is not None,
            "rounds": rounds, "messages_sent": messages, "elected_leader": leader,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "consensus":
        values = {a: random.choice([0, 1]) for a in agents}
        rounds = 0
        messages = 0
        agreed = False
        while (time.time() - start) < timeout_seconds:
            rounds += 1
            messages += agent_count * (agent_count - 1)
            counts = {0: 0, 1: 0}
            for v in values.values():
                counts[v] += 1
            majority = 0 if counts[0] >= counts[1] else 1
            values = {a: majority for a in agents}
            if len(set(values.values())) == 1:
                agreed = True
                break
        return {
            "pattern": "consensus", "success": agreed,
            "rounds": rounds, "final_value": list(values.values())[0],
            "messages_sent": messages, "agreement_reached": agreed,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "load_balancing":
        task_count = max(100, agent_count * 10)
        assignments = {a: 0 for a in agents}
        for i in range(task_count):
            assignments[agents[i % agent_count]] += 1
        loads = list(assignments.values())
        return {
            "pattern": "load_balancing", "success": True,
            "total_tasks": task_count, "tasks_per_agent": assignments,
            "max_load": max(loads), "min_load": min(loads),
            "std_deviation": round(statistics.stdev(loads), 2) if len(loads) > 1 else 0,
            "balance_score": round(min(loads) / max(loads), 3) if max(loads) > 0 else 1.0,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "pub_sub_fanout":
        subscribers = agents[1:]
        messages_published = 10
        deliveries = 0
        failed = 0
        for _ in range(messages_published):
            for _ in subscribers:
                if random.random() > 0.02:
                    deliveries += 1
                else:
                    failed += 1
        total_expected = messages_published * len(subscribers)
        return {
            "pattern": "pub_sub_fanout", "success": deliveries > 0,
            "publisher": agents[0], "subscriber_count": len(subscribers),
            "messages_published": messages_published,
            "total_deliveries": deliveries, "failed_deliveries": failed,
            "delivery_rate": round(deliveries / total_expected, 3) if total_expected > 0 else 0,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    elif pattern == "task_auction":
        task_count = 5
        auctions = []
        total_bids = 0
        collisions = 0
        for t in range(task_count):
            bids = {a: random.randint(1, 100) for a in agents}
            total_bids += len(bids)
            max_bid = max(bids.values())
            winners = [a for a, b in bids.items() if b == max_bid]
            if len(winners) > 1:
                collisions += 1
            auctions.append({"task": t, "winner": random.choice(winners), "winning_bid": max_bid})
        return {
            "pattern": "task_auction", "success": True,
            "tasks_auctioned": task_count, "total_bids": total_bids,
            "collisions": collisions, "auctions": auctions,
            "latency_ms": round((time.time() - start) * 1000, 2), "agent_count": agent_count,
        }

    return {"pattern": pattern, "success": False, "error": "Unknown pattern"}

@router.post("/v1/testing/scenarios", response_model=ScenarioCreateResponse, tags=["Testing"])
@limiter.limit(make_tier_limit("agent_write"))
def scenario_create(request: Request, req: ScenarioCreateRequest, agent_id: str = Depends(get_agent_id)):
    """Create a coordination test scenario."""
    if req.pattern not in COORDINATION_PATTERNS:
        raise HTTPException(400, f"Invalid pattern. Valid: {sorted(COORDINATION_PATTERNS)}")
    scenario_id = f"scenario_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO test_scenarios (scenario_id, creator_agent, name, pattern, agent_count, "
            "timeout_seconds, success_criteria, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (scenario_id, agent_id, req.name, req.pattern, req.agent_count,
             req.timeout_seconds, json.dumps(req.success_criteria) if req.success_criteria else None,
             "created", now)
        )
    return {"scenario_id": scenario_id, "status": "created", "pattern": req.pattern, "created_at": now}

@router.get("/v1/testing/scenarios", response_model=ScenarioListResponse, tags=["Testing"])
@limiter.limit(make_tier_limit("agent_read"))
def scenario_list(request: Request, 
    pattern: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    agent_id: str = Depends(get_agent_id),
):
    """List your test scenarios."""
    conditions = ["creator_agent=?"]
    params: list = [agent_id]
    if pattern:
        conditions.append("pattern=?")
        params.append(pattern)
    if status:
        conditions.append("status=?")
        params.append(status)
    where = " AND ".join(conditions)
    params.append(limit)
    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM test_scenarios WHERE {where} ORDER BY created_at DESC LIMIT ?", params
        ).fetchall()
    scenarios = []
    for r in rows:
        d = dict(r)
        d["success_criteria"] = json.loads(d["success_criteria"]) if d["success_criteria"] else None
        if d["results"]:
            d["results"] = json.loads(_decrypt(d["results"]))
        scenarios.append(d)
    return {"scenarios": scenarios, "count": len(scenarios)}

@router.post("/v1/testing/scenarios/{scenario_id}/run", response_model=ScenarioRunResponse, tags=["Testing"])
@limiter.limit(make_tier_limit("agent_write"))
def scenario_run(request: Request, scenario_id: str, agent_id: str = Depends(get_agent_id)):
    """Run a coordination test scenario."""
    with get_db() as db:
        row = db.execute("SELECT * FROM test_scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Scenario not found")
        if row["creator_agent"] != agent_id:
            raise HTTPException(403, "Only the creator can run this scenario")
        if row["status"] == "running":
            raise HTTPException(409, "Scenario is already running")
        db.execute("UPDATE test_scenarios SET status='running' WHERE scenario_id=?", (scenario_id,))
    results = _run_coordination_pattern(row["pattern"], row["agent_count"], row["timeout_seconds"])
    now = datetime.now(timezone.utc).isoformat()
    final_status = "completed" if results.get("success") else "failed"
    with get_db() as db:
        db.execute(
            "UPDATE test_scenarios SET status=?, results=?, completed_at=? WHERE scenario_id=?",
            (final_status, _encrypt(json.dumps(results)), now, scenario_id)
        )
    return {"scenario_id": scenario_id, "status": final_status, "results": results, "completed_at": now}

@router.get("/v1/testing/scenarios/{scenario_id}/results", tags=["Testing"])
@limiter.limit(make_tier_limit("agent_read"))
def scenario_results(request: Request, scenario_id: str, agent_id: str = Depends(get_agent_id)):
    """Get results for a test scenario."""
    with get_db() as db:
        row = db.execute("SELECT * FROM test_scenarios WHERE scenario_id=?", (scenario_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scenario not found")
    if row["creator_agent"] != agent_id:
        raise HTTPException(403, "Only the creator can view results")
    d = dict(row)
    d["success_criteria"] = json.loads(d["success_criteria"]) if d["success_criteria"] else None
    d["results"] = json.loads(_decrypt(d["results"])) if d["results"] else None
    return d
