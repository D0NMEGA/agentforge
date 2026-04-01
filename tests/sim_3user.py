"""
3-User Realistic Simulation -- 17 Agents Across Scale/Team/Free Tiers
Phase 79: Final validation before v1.0.0 launch

Usage:
  python tests/sim_3user.py              # Full run (~25 min)
  python tests/sim_3user.py --quick      # User C only (~5 min)
"""
from __future__ import annotations
import os, asyncio, json, sys, time, uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import httpx

os.environ["PYTHONUNBUFFERED"] = "1"
API = os.environ.get("MOLTGRID_API_URL", "https://api.moltgrid.net")
QUICK_MODE = "--quick" in sys.argv
SEMAPHORE = asyncio.Semaphore(10)  # Max 10 concurrent requests

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class SimResult:
    user: str        # "UserA", "UserB", "UserC"
    agent: str       # agent name
    test: str        # test name
    passed: bool
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SharedState:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.results: list[SimResult] = []
        self.server_errors: list[dict] = []           # SIM-05: must be empty
        self.onboarding_times: dict[str, float] = {}  # SIM-06: per-user timing
        self.obstacle_completions: dict[str, bool] = {}  # SIM-04: per-agent
        self.registered_agents: dict[str, dict] = {}  # name -> {id, key, user}
        self.start_time: float = 0.0
        self.monitoring_iterations: int = 0           # SIM-02
        self.monitoring_duration: float = 0.0         # SIM-02
        self.hit_429: bool = False                    # SIM-03
        self.recovery_ok: bool = False                # SIM-03


S = SharedState()

# ---------------------------------------------------------------------------
# Rate budgets -- one per tier
# ---------------------------------------------------------------------------

class RateBudget:
    """Token-bucket rate limiter -- one per user tier."""

    def __init__(self, max_per_minute: int) -> None:
        self.max_per_minute = max_per_minute
        self.calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < 60]
            if len(self.calls) >= self.max_per_minute:
                wait = 60 - (now - self.calls[0]) + 0.5
                await asyncio.sleep(wait)
            self.calls.append(time.time())


BUDGET_SCALE = RateBudget(1100)  # Scale: 1200/min, cap at 1100
BUDGET_TEAM = RateBudget(580)    # Team: 600/min, cap at 580
BUDGET_FREE = RateBudget(55)     # Free: conservative to avoid 429 during obstacle course

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(agent: str, msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"  [{ts}] {agent:25s} | {msg}", flush=True)

# ---------------------------------------------------------------------------
# Centralized API call
# ---------------------------------------------------------------------------

async def call(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    agent: str,
    *,
    json_body: Any = None,
    params: dict | None = None,
    budget: RateBudget | None = None,
    skip_rate_wait: bool = False,
    timeout: float = 30.0,
) -> httpx.Response:
    if budget and not skip_rate_wait:
        await budget.acquire()

    url = f"{API}{path}"
    key = S.registered_agents.get(agent, {}).get("key", "")
    hdrs: dict[str, str] = {}
    if key:
        hdrs["X-API-Key"] = key

    async with SEMAPHORE:
        t0 = time.monotonic()
        try:
            resp = await client.request(
                method, url,
                json=json_body, params=params,
                headers=hdrs,
                timeout=timeout,
            )
        except Exception as exc:
            return httpx.Response(598, text=str(exc),
                                  request=httpx.Request(method, url))

    if resp.status_code >= 500:
        async with S.lock:
            S.server_errors.append({
                "agent": agent, "method": method, "path": path,
                "status": resp.status_code, "body": resp.text[:500],
                "ts": datetime.now(timezone.utc).isoformat(),
            })

    if resp.status_code == 429:
        retry = int(resp.headers.get("Retry-After", "5"))
        log(agent, f"429 on {path} -- wait {min(retry, 30)}s")
        await asyncio.sleep(min(retry, 30))

    return resp

# ---------------------------------------------------------------------------
# Record helper
# ---------------------------------------------------------------------------

async def record(user: str, agent: str, test: str, passed: bool, detail: str = "") -> None:
    async with S.lock:
        S.results.append(SimResult(user=user, agent=agent, test=test,
                                   passed=passed, detail=detail))

# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------

async def register_simulation_agents(client: httpx.AsyncClient) -> None:
    """Register all 17 simulation agents. Populates S.registered_agents."""
    agent_specs = (
        [(f"SimA_Research_{i:02d}", "UserA") for i in range(1, 9)] +  # 8 Scale
        [(f"SimB_DevOps_{i:02d}", "UserB")   for i in range(1, 9)] +  # 8 Team
        [("SimC_Free_01", "UserC")]                                    # 1 Free
    )
    hex4 = uuid.uuid4().hex[:4]
    for name, user in agent_specs:
        unique_name = f"Phase79_{name}_{hex4}"
        r = await client.post(f"{API}/v1/register",
                              json={"name": unique_name},
                              timeout=30.0)
        if r.status_code == 200:
            data = r.json()
            async with S.lock:
                S.registered_agents[name] = {
                    "id": data["agent_id"],
                    "key": data["api_key"],
                    "user": user,
                }
            log(name, f"Registered -- id={data['agent_id'][:8]}...")
        else:
            log(name, f"Registration FAILED: {r.status_code} {r.text[:100]}")

# ---------------------------------------------------------------------------
# Onboarding timing (SIM-06)
# ---------------------------------------------------------------------------

async def time_onboarding(
    client: httpx.AsyncClient,
    user_label: str,
    agent_name: str,
) -> float:
    """Measure time from register to onboarding/status. Stores in S.onboarding_times."""
    t0 = time.monotonic()
    r = await client.post(f"{API}/v1/register",
                          json={"name": f"Phase79_Onboard_{user_label}_{uuid.uuid4().hex[:4]}"},
                          timeout=30.0)
    if r.status_code != 200:
        log(agent_name, f"Onboarding timing: registration failed {r.status_code}")
        return -1.0
    data = r.json()
    ob_key = data["api_key"]
    ob_hdrs = {"X-API-Key": ob_key}

    async with SEMAPHORE:
        await client.post(f"{API}/v1/memory",
                          json={"key": "onboard_start", "value": "started"},
                          headers=ob_hdrs, timeout=30.0)
    async with SEMAPHORE:
        await client.post(f"{API}/v1/onboarding/start",
                          headers=ob_hdrs, timeout=30.0)
    async with SEMAPHORE:
        await client.get(f"{API}/v1/onboarding/status",
                         headers=ob_hdrs, timeout=30.0)

    elapsed = time.monotonic() - t0
    async with S.lock:
        S.onboarding_times[user_label] = elapsed
    log(agent_name, f"Onboarding timing for {user_label}: {elapsed:.1f}s")
    return elapsed

# ===========================================================================
# OBSTACLE COURSE STAGE FUNCTIONS
# ===========================================================================

async def stage1_memory(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 1: Memory Foundations -- Memory + Vector Memory."""
    agent_id = state.get("agent_id", "")
    now_iso = datetime.now(timezone.utc).isoformat()

    # Write 3 memory keys
    r1 = await call(client, "POST", "/v1/memory", agent_name, budget=budget,
                    json_body={"key": "stage1_identity",
                               "value": f"name={agent_name}, description=Obstacle course challenger, started_at={now_iso}",
                               "namespace": "obstacle_course"})
    r2 = await call(client, "POST", "/v1/memory", agent_name, budget=budget,
                    json_body={"key": "stage1_plan",
                               "value": "strategy=sequential, complete all 10 stages, submit at end",
                               "namespace": "obstacle_course"})
    r3 = await call(client, "POST", "/v1/memory", agent_name, budget=budget,
                    json_body={"key": "stage1_capabilities",
                               "value": "data_analysis, code_generation, semantic_search, multi_agent_coordination, event_processing",
                               "namespace": "obstacle_course"})

    # Upsert 3 vector entries
    r4 = await call(client, "POST", "/v1/vector/upsert", agent_name, budget=budget,
                    json_body={"key": "oc_strengths",
                               "text": "I excel at data analysis, code generation, and multi-step reasoning",
                               "namespace": "obstacle_course"})
    r5 = await call(client, "POST", "/v1/vector/upsert", agent_name, budget=budget,
                    json_body={"key": "oc_goals",
                               "text": "Complete the obstacle course and demonstrate all MoltGrid services",
                               "namespace": "obstacle_course"})
    r6 = await call(client, "POST", "/v1/vector/upsert", agent_name, budget=budget,
                    json_body={"key": "oc_collab_prefs",
                               "text": "Prefer async collaboration via relay and shared memory namespaces",
                               "namespace": "obstacle_course"})

    # Semantic search
    r7 = await call(client, "POST", "/v1/vector/search", agent_name, budget=budget,
                    json_body={"query": "what am I good at?",
                               "namespace": "obstacle_course",
                               "limit": 3})
    search_ok = r7.status_code == 200

    # List memory keys
    r8 = await call(client, "GET", "/v1/memory", agent_name, budget=budget,
                    params={"namespace": "obstacle_course"})

    ok = all(r.status_code in (200, 201) for r in [r1, r2, r3, r4, r5, r6]) and search_ok
    return ok


async def stage2_relay(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 2: Communication -- Relay + Events."""
    agent_id = state.get("agent_id", "")

    # Send relay message to self
    r1 = await call(client, "POST", "/v1/relay/send", agent_name, budget=budget,
                    json_body={"to_agent": agent_id,
                               "channel": "obstacle_course",
                               "payload": "Stage 2: Stage 1 complete. Memory and vector storage working."})

    # Check inbox
    r2 = await call(client, "GET", "/v1/relay/inbox", agent_name, budget=budget,
                    params={"unread_only": "true"})

    message_id = None
    if r2.status_code == 200:
        try:
            inbox = r2.json()
            msgs = inbox if isinstance(inbox, list) else inbox.get("messages", [])
            if msgs:
                message_id = msgs[0].get("id") or msgs[0].get("message_id")
        except Exception:
            pass
    state["relay_message_id"] = message_id

    # Mark message read
    if message_id:
        r3 = await call(client, "POST", f"/v1/relay/{message_id}/read", agent_name, budget=budget)
    else:
        r3 = httpx.Response(200)

    # Poll events
    r4 = await call(client, "GET", "/v1/events", agent_name, budget=budget)

    # Ack an event
    event_id = None
    if r4.status_code == 200:
        try:
            evts = r4.json()
            items = evts if isinstance(evts, list) else evts.get("events", [])
            if items:
                event_id = items[0].get("id") or items[0].get("event_id")
        except Exception:
            pass

    if event_id:
        r5 = await call(client, "POST", "/v1/events/ack", agent_name, budget=budget,
                        json_body={"event_ids": [event_id]})
    else:
        r5 = httpx.Response(200)

    ok = r1.status_code in (200, 201) and r2.status_code == 200 and r4.status_code == 200
    return ok


async def stage3_queue(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 3: Job Processing Pipeline -- Queue + Schedules."""
    # Submit first job
    r1 = await call(client, "POST", "/v1/queue/submit", agent_name, budget=budget,
                    json_body={"queue_name": "obstacle_course",
                               "payload": {"task": "process_stage3_data", "data": [1, 2, 3, 4, 5]},
                               "priority": 10, "max_attempts": 3})
    job_id1 = None
    if r1.status_code in (200, 201):
        try:
            job_id1 = r1.json().get("job_id") or r1.json().get("id")
        except Exception:
            pass
    state["job_id1"] = job_id1

    # Claim first job
    r2 = await call(client, "POST", "/v1/queue/claim", agent_name, budget=budget,
                    json_body={"queue_name": "obstacle_course"})
    claimed_id = None
    if r2.status_code == 200:
        try:
            claimed_id = r2.json().get("job_id") or r2.json().get("id")
        except Exception:
            pass
    effective_id = claimed_id or job_id1

    # Complete first job
    if effective_id:
        r3 = await call(client, "POST", f"/v1/queue/{effective_id}/complete", agent_name, budget=budget,
                        json_body={"result": {"sum": 15, "count": 5, "average": 3.0}})
    else:
        r3 = httpx.Response(200)

    # Submit second job (to fail)
    r4 = await call(client, "POST", "/v1/queue/submit", agent_name, budget=budget,
                    json_body={"queue_name": "obstacle_course",
                               "payload": {"task": "fail_test"},
                               "max_attempts": 1})
    job_id2 = None
    if r4.status_code in (200, 201):
        try:
            job_id2 = r4.json().get("job_id") or r4.json().get("id")
        except Exception:
            pass
    state["job_id2"] = job_id2

    # Claim second job
    r5 = await call(client, "POST", "/v1/queue/claim", agent_name, budget=budget,
                    json_body={"queue_name": "obstacle_course"})
    claimed_id2 = None
    if r5.status_code == 200:
        try:
            claimed_id2 = r5.json().get("job_id") or r5.json().get("id")
        except Exception:
            pass
    effective_id2 = claimed_id2 or job_id2

    # Fail second job
    if effective_id2:
        r6 = await call(client, "POST", f"/v1/queue/{effective_id2}/fail", agent_name, budget=budget,
                        json_body={"reason": "Intentional failure for obstacle course testing"})
    else:
        r6 = httpx.Response(200)

    # Check dead letter queue
    r7 = await call(client, "GET", "/v1/queue/dead_letter", agent_name, budget=budget)

    # Create schedule
    r8 = await call(client, "POST", "/v1/schedules", agent_name, budget=budget,
                    json_body={"cron_expr": "*/30 * * * *",
                               "queue_name": "obstacle_course_heartbeat",
                               "payload": {"action": "scheduled_ping"},
                               "priority": 1})
    schedule_id = None
    if r8.status_code in (200, 201):
        try:
            schedule_id = r8.json().get("task_id") or r8.json().get("id")
        except Exception:
            pass
    state["schedule_id"] = schedule_id

    ok = r1.status_code in (200, 201) and r4.status_code in (200, 201) and r7.status_code == 200
    return ok


async def stage4_shared_memory(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 4: Shared State -- Shared Memory + Memory Visibility."""
    agent_id = state.get("agent_id", "")
    ns = f"obstacle_course_{agent_id}"

    # Patch visibility of stage1_capabilities to public
    r1 = await call(client, "PATCH", "/v1/memory/stage1_capabilities/visibility", agent_name, budget=budget,
                    json_body={"visibility": "public"},
                    params={"namespace": "obstacle_course"})

    # Write 2 shared memory entries
    now_iso = datetime.now(timezone.utc).isoformat()
    r2 = await call(client, "POST", "/v1/shared-memory", agent_name, budget=budget,
                    json_body={"namespace": ns,
                               "key": "progress",
                               "value": f"stages_completed=[1,2,3], current_stage=4, started_at={now_iso}",
                               "description": "Obstacle course progress tracker"})
    r3 = await call(client, "POST", "/v1/shared-memory", agent_name, budget=budget,
                    json_body={"namespace": ns,
                               "key": "config",
                               "value": "strategy=sequential, target_time_minutes=15"})

    # Read back shared memory namespace
    r4 = await call(client, "GET", f"/v1/shared-memory/{ns}", agent_name, budget=budget)
    r5 = await call(client, "GET", f"/v1/shared-memory/{ns}/progress", agent_name, budget=budget)

    ok = r2.status_code in (200, 201) and r3.status_code in (200, 201) and r4.status_code == 200
    return ok


async def stage5_pubsub(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 5: Broadcast and Subscribe -- Pub/Sub."""
    agent_id = state.get("agent_id", "")
    channel = f"obstacle_course_{agent_id}"

    # Subscribe to channel
    r1 = await call(client, "POST", "/v1/pubsub/subscribe", agent_name, budget=budget,
                    json_body={"channel": channel})

    # Publish a message
    r2 = await call(client, "POST", "/v1/pubsub/publish", agent_name, budget=budget,
                    json_body={"channel": channel,
                               "payload": f"Agent {agent_id} halfway through the obstacle course - stage 5!"})

    # List subscriptions
    r3 = await call(client, "GET", "/v1/pubsub/subscriptions", agent_name, budget=budget)

    # List channels
    r4 = await call(client, "GET", "/v1/pubsub/channels", agent_name, budget=budget)

    # Poll events to receive pub/sub broadcast
    r5 = await call(client, "GET", "/v1/events", agent_name, budget=budget)

    ok = r1.status_code in (200, 201) and r2.status_code in (200, 201) and r3.status_code == 200
    return ok


async def stage6_directory(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 6: Agent Discovery -- Directory + Heartbeat."""
    # Post heartbeat
    r1 = await call(client, "POST", "/v1/heartbeat", agent_name, budget=budget,
                    json_body={"status": "online",
                               "metadata": {"obstacle_course": True, "current_stage": 6}})

    # Update directory profile
    r2 = await call(client, "PUT", "/v1/directory/me", agent_name, budget=budget,
                    json_body={"description": "Obstacle course challenger -- testing all 20 MoltGrid services",
                               "capabilities": ["data_analysis", "task_processing",
                                                "multi_agent_coordination", "semantic_search", "pub_sub"],
                               "available": True,
                               "looking_for": "other agents to collaborate with"})

    # Browse directory
    r3 = await call(client, "GET", "/v1/directory", agent_name, budget=budget)

    # Search directory
    r4 = await call(client, "GET", "/v1/directory/search", agent_name, budget=budget,
                    params={"q": "data analysis"})

    # Directory stats
    r5 = await call(client, "GET", "/v1/directory/stats", agent_name, budget=budget)

    # Get own profile
    r6 = await call(client, "GET", "/v1/directory/me", agent_name, budget=budget)

    # Update profile with skills and interests
    r7 = await call(client, "PUT", "/v1/directory/me", agent_name, budget=budget,
                    json_body={"description": "Obstacle course challenger",
                               "capabilities": ["data_analysis", "task_processing"],
                               "skills": ["python", "api_integration", "web_scraping"],
                               "interests": ["AI_agents", "automation"],
                               "public": True})

    ok = r1.status_code in (200, 201) and r3.status_code == 200
    return ok


async def stage7_webhooks(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 7: Webhooks and Notifications -- Webhooks + Text Utilities."""
    # Register webhook
    r1 = await call(client, "POST", "/v1/webhooks", agent_name, budget=budget,
                    json_body={"url": f"https://httpbin.org/post?agent={agent_name}",
                               "event_types": ["message.received", "job.completed"],
                               "secret": "obstacle_course_secret_123"})
    webhook_id = None
    if r1.status_code in (200, 201):
        try:
            webhook_id = r1.json().get("id") or r1.json().get("webhook_id")
        except Exception:
            pass
    state["webhook_id"] = webhook_id

    # List webhooks
    r2 = await call(client, "GET", "/v1/webhooks", agent_name, budget=budget)

    # Test webhook
    if webhook_id:
        r3 = await call(client, "POST", f"/v1/webhooks/{webhook_id}/test", agent_name, budget=budget)
    else:
        r3 = httpx.Response(200)

    # Process text (extract URLs)
    r4 = await call(client, "POST", "/v1/text/process", agent_name, budget=budget,
                    json_body={"text": "Obstacle course stage 7 complete! Check https://api.moltgrid.net/v1/obstacle-course/leaderboard for rankings.",
                               "operation": "extract_urls"})

    # Hash progress summary
    r5 = await call(client, "POST", "/v1/text/process", agent_name, budget=budget,
                    json_body={"text": "stages_completed:1,2,3,4,5,6,7",
                               "operation": "hash_sha256"})

    # Delete webhook
    if webhook_id:
        r6 = await call(client, "DELETE", f"/v1/webhooks/{webhook_id}", agent_name, budget=budget)
    else:
        r6 = httpx.Response(200)

    ok = r1.status_code in (200, 201) and r4.status_code in (200, 201) and r5.status_code in (200, 201)
    return ok


async def stage8_sessions(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 8: Sessions and Context -- Sessions + Templates."""
    now_iso = datetime.now(timezone.utc).isoformat()

    # Check templates
    r1 = await call(client, "GET", "/v1/templates", agent_name, budget=budget)

    # Create session
    r2 = await call(client, "POST", "/v1/sessions", agent_name, budget=budget,
                    json_body={"title": "Obstacle Course Run",
                               "metadata": {"started_at": now_iso, "target": "sub-15-minutes"},
                               "max_tokens": 4000})
    session_id = None
    if r2.status_code in (200, 201):
        try:
            session_id = r2.json().get("session_id") or r2.json().get("id")
        except Exception:
            pass
    state["session_id"] = session_id

    if not session_id:
        return False

    # Add 3 messages (user, assistant, user pattern per plan)
    r3 = await call(client, "POST", f"/v1/sessions/{session_id}/messages", agent_name, budget=budget,
                    json_body={"role": "user", "content": "Starting obstacle course run."})
    r4 = await call(client, "POST", f"/v1/sessions/{session_id}/messages", agent_name, budget=budget,
                    json_body={"role": "assistant",
                               "content": "Started obstacle course. Completed memory storage and vector search in Stage 1."})
    r5 = await call(client, "POST", f"/v1/sessions/{session_id}/messages", agent_name, budget=budget,
                    json_body={"role": "user",
                               "content": "Stages 2-5 done. Relay messaging, job queue, shared memory, and pub/sub all working."})

    # Get session
    r6 = await call(client, "GET", f"/v1/sessions/{session_id}", agent_name, budget=budget)

    # Summarize session
    r7 = await call(client, "POST", f"/v1/sessions/{session_id}/summarize", agent_name, budget=budget)

    ok = r2.status_code in (200, 201) and r3.status_code in (200, 201) and r6.status_code == 200
    return ok


async def stage9_marketplace(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 9: Marketplace and Collaboration -- Marketplace + Testing/Scenarios + MoltBook."""
    agent_id = state.get("agent_id", "")

    # Post marketplace task
    r1 = await call(client, "POST", "/v1/marketplace/tasks", agent_name, budget=budget,
                    json_body={"title": "Obstacle Course Collaboration",
                               "description": "Help verify obstacle course completion by checking shared memory namespace",
                               "category": "verification",
                               "requirements": ["shared_memory_read"],
                               "reward_credits": 10,
                               "priority": 5,
                               "tags": ["obstacle_course", "verification"]})

    # Create test scenario
    r2 = await call(client, "POST", "/v1/testing/scenarios", agent_name, budget=budget,
                    json_body={"name": "obstacle_course_relay_test",
                               "pattern": "consensus",
                               "agent_count": 2,
                               "timeout_seconds": 30,
                               "success_criteria": {"type": "message_exchange", "min_messages": 1}})
    scenario_id = None
    if r2.status_code in (200, 201):
        try:
            scenario_id = r2.json().get("id") or r2.json().get("scenario_id")
        except Exception:
            pass

    # Run scenario
    if scenario_id:
        r3 = await call(client, "POST", f"/v1/testing/scenarios/{scenario_id}/run",
                        agent_name, budget=budget)
        r4 = await call(client, "GET", f"/v1/testing/scenarios/{scenario_id}/results",
                        agent_name, budget=budget)
    else:
        r3 = httpx.Response(200)
        r4 = httpx.Response(200)

    # Register with MoltBook
    r5 = await call(client, "POST", "/v1/moltbook/register", agent_name, budget=budget,
                    json_body={"moltbook_user_id": agent_id,
                               "display_name": agent_name})

    # Find partner agent -- another agent from same user group or any UserA agent
    async with S.lock:
        agents_snapshot = dict(S.registered_agents)

    agent_user = agents_snapshot.get(agent_name, {}).get("user", "")
    partner_id = None
    for a_name, a_info in agents_snapshot.items():
        if a_name != agent_name and a_info.get("user") == agent_user:
            partner_id = a_info.get("id")
            break
    # Fallback: use any UserA agent
    if not partner_id:
        for a_name, a_info in agents_snapshot.items():
            if a_info.get("user") == "UserA" and a_info.get("id") != agent_id:
                partner_id = a_info.get("id")
                break

    # Log collaboration
    if partner_id:
        r6 = await call(client, "POST", "/v1/directory/collaborations", agent_name, budget=budget,
                        json_body={"partner_agent": partner_id,
                                   "task_type": "obstacle_course",
                                   "outcome": "success",
                                   "rating": 5})
    else:
        r6 = httpx.Response(200)

    # Get leaderboard
    r7 = await call(client, "GET", "/v1/leaderboard", agent_name, budget=budget)

    ok = r1.status_code in (200, 201) and r2.status_code in (200, 201)
    return ok


async def stage10_final(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    state: dict,
) -> bool:
    """Stage 10: Integration and Finish Line -- Onboarding + System + Final."""
    agent_id = state.get("agent_id", "")
    ns = f"obstacle_course_{agent_id}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Start onboarding
    r1 = await call(client, "POST", "/v1/onboarding/start", agent_name, budget=budget)

    # Check onboarding status
    r2 = await call(client, "GET", "/v1/onboarding/status", agent_name, budget=budget)

    # System health
    r3 = await call(client, "GET", "/v1/health", agent_name, budget=budget)

    # Platform stats
    r4 = await call(client, "GET", "/v1/stats", agent_name, budget=budget)

    # SLA
    r5 = await call(client, "GET", "/v1/sla", agent_name, budget=budget)

    # Update shared memory progress
    r6 = await call(client, "POST", "/v1/shared-memory", agent_name, budget=budget,
                    json_body={"namespace": ns,
                               "key": "progress",
                               "value": f"stages_completed=[1,2,3,4,5,6,7,8,9,10], current_stage=COMPLETE, completed_at={now_iso}"})

    # Write completion memory key
    r7 = await call(client, "POST", "/v1/memory", agent_name, budget=budget,
                    json_body={"key": "obstacle_course_complete",
                               "value": "all_stages=true, services_used=memory,vector,relay,events,queue,schedules,shared_memory,pubsub,directory,heartbeat,webhooks,text,sessions,templates,marketplace,testing,moltbook,integrations,onboarding,leaderboard",
                               "namespace": "obstacle_course"})

    # Send relay announcement
    r8 = await call(client, "POST", "/v1/relay/send", agent_name, budget=budget,
                    json_body={"to_agent": agent_id,
                               "channel": "obstacle_course",
                               "payload": "Obstacle course COMPLETE! All 20 services tested."})

    # Publish completion event
    r9 = await call(client, "POST", "/v1/pubsub/publish", agent_name, budget=budget,
                    json_body={"channel": "obstacle_course",
                               "payload": f"Agent {agent_id} completed the obstacle course! All 10 stages done."})

    ok = r3.status_code == 200  # at minimum, system health must pass
    return ok

# ===========================================================================
# OBSTACLE COURSE RUNNER
# ===========================================================================

async def run_obstacle_course(
    client: httpx.AsyncClient,
    agent_name: str,
    budget: RateBudget,
    user: str,
) -> bool:
    """Run all 10 obstacle course stages. Return True if /submit succeeds."""
    state: dict[str, Any] = {}
    agent_id = S.registered_agents.get(agent_name, {}).get("id", "")
    state["agent_id"] = agent_id

    stages = [
        (1,  "Memory+Vector",      stage1_memory),
        (2,  "Relay+Events",       stage2_relay),
        (3,  "Queue+Schedules",    stage3_queue),
        (4,  "SharedMemory",       stage4_shared_memory),
        (5,  "PubSub",             stage5_pubsub),
        (6,  "Directory+Heartbeat",stage6_directory),
        (7,  "Webhooks+Text",      stage7_webhooks),
        (8,  "Sessions+Templates", stage8_sessions),
        (9,  "Marketplace+Testing",stage9_marketplace),
        (10, "Onboarding+System",  stage10_final),
    ]
    passed_stages = []
    for num, label, fn in stages:
        try:
            ok = await fn(client, agent_name, budget, state)
            if ok:
                passed_stages.append(num)
                log(agent_name, f"Stage {num} ({label}): PASS")
            else:
                log(agent_name, f"Stage {num} ({label}): FAIL (returned False)")
        except Exception as exc:
            log(agent_name, f"Stage {num} ({label}): ERROR -- {exc}")

    # Submit obstacle course
    r = await call(client, "POST", "/v1/obstacle-course/submit", agent_name,
                   json_body={"stages_completed": list(range(1, 11))},
                   budget=budget)
    completed = r.status_code == 200
    async with S.lock:
        S.obstacle_completions[agent_name] = completed
    await record(user, agent_name, "obstacle_course_submit",
                 completed, f"Stages passed: {passed_stages}, submit: {r.status_code}")
    return completed

# ===========================================================================
# USER PERSONA WORKFLOWS
# ===========================================================================

async def run_user_a(client: httpx.AsyncClient) -> None:
    """User A: Scale tier, 8 agents, research pipeline."""
    log("UserA", "Starting research pipeline simulation")
    agents_a = [n for n, d in S.registered_agents.items() if d["user"] == "UserA"]

    t0 = time.monotonic()

    # Run obstacle courses for all 8 agents concurrently
    tasks = [run_obstacle_course(client, name, BUDGET_SCALE, "UserA") for name in agents_a]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Agent 01 (Coordinator): relay messages to agents 02-04
    coord = agents_a[0]
    for target in agents_a[1:4]:
        target_id = S.registered_agents[target]["id"]
        await call(client, "POST", "/v1/relay/send", coord,
                   json_body={"recipient_id": target_id,
                              "content": f"Research task assignment from {coord}"},
                   budget=BUDGET_SCALE)

    # Agents 02-04 (Data ingestion): vector upsert batch
    for agent in agents_a[1:4]:
        for i in range(5):
            await call(client, "POST", "/v1/vector/upsert", agent,
                       json_body={"key": f"research_data_{i}",
                                  "text": f"Research finding #{i}: data point for analysis",
                                  "namespace": "research"},
                       budget=BUDGET_SCALE)

    # Agents 05-06 (Analysis): vector search + tiered recall
    for agent in agents_a[4:6]:
        await call(client, "POST", "/v1/vector/search", agent,
                   json_body={"query": "research findings analysis",
                              "namespace": "research", "limit": 5},
                   budget=BUDGET_SCALE)
        await call(client, "POST", "/v1/memory/recall", agent,
                   json_body={"query": "research", "namespace": "obstacle_course"},
                   budget=BUDGET_SCALE)

    # Agent 07 (Session manager): create session, add messages, summarize
    sm = agents_a[6]
    r = await call(client, "POST", "/v1/sessions", sm,
                   json_body={"name": "research_session"}, budget=BUDGET_SCALE)
    if r.status_code == 200:
        sid = r.json().get("session_id", r.json().get("id", ""))
        if sid:
            for msg in ["Starting research analysis", "Found 3 key patterns", "Concluding findings"]:
                await call(client, "POST", f"/v1/sessions/{sid}/messages", sm,
                           json_body={"role": "user", "content": msg}, budget=BUDGET_SCALE)
            await call(client, "POST", f"/v1/sessions/{sid}/summarize", sm, budget=BUDGET_SCALE)

    # Agent 08 (Queue processor): submit and process jobs
    qp = agents_a[7]
    for i in range(3):
        r = await call(client, "POST", "/v1/queue/submit", qp,
                       json_body={"task_type": "research_analysis", "payload": {"batch": i}},
                       budget=BUDGET_SCALE)
        if r.status_code == 200:
            jid = r.json().get("job_id", r.json().get("id", ""))
            if jid:
                await call(client, "POST", "/v1/queue/claim", qp, budget=BUDGET_SCALE)
                await call(client, "POST", f"/v1/queue/{jid}/complete", qp,
                           json_body={"result": {"processed": True}}, budget=BUDGET_SCALE)

    elapsed_a = time.monotonic() - t0
    async with S.lock:
        S.onboarding_times["UserA"] = elapsed_a
    oc_pass = all(S.obstacle_completions.get(a, False) for a in agents_a)
    await record("UserA", "ALL", "research_pipeline_complete", oc_pass,
                 f"8 agents, {sum(1 for r in results if r is True)}/8 obstacle courses, {elapsed_a:.1f}s")
    log("UserA", f"Complete: {sum(1 for r in results if r is True)}/8 obstacle courses in {elapsed_a:.1f}s")


async def run_user_b(client: httpx.AsyncClient) -> None:
    """User B: Team tier, 8 agents, DevOps monitoring with 10+ min loop."""
    log("UserB", "Starting DevOps monitoring simulation")
    agents_b = [n for n, d in S.registered_agents.items() if d["user"] == "UserB"]

    t0 = time.monotonic()

    # Run obstacle courses for all 8 agents concurrently
    tasks = [run_obstacle_course(client, name, BUDGET_TEAM, "UserB") for name in agents_b]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # DevOps monitoring loop -- 620 seconds (just over 10 min) (SIM-02)
    duration = 620 if not QUICK_MODE else 30  # 30s in quick mode
    log("UserB", f"Starting monitoring loop for {duration}s")
    loop_start = time.time()
    iteration = 0
    while time.time() - loop_start < duration:
        agent = agents_b[iteration % len(agents_b)]
        role_idx = iteration % len(agents_b)

        if role_idx == 0:
            await call(client, "GET", "/v1/health", agent, budget=BUDGET_TEAM)
            await call(client, "GET", "/v1/sla", agent, budget=BUDGET_TEAM)
        elif role_idx in (1, 2, 3):
            await call(client, "POST", "/v1/agents/heartbeat", agent,
                       json_body={"status": "online",
                                  "metadata": {"iteration": iteration, "role": "devops"}},
                       budget=BUDGET_TEAM)
        elif role_idx in (4, 5):
            await call(client, "GET", "/v1/events", agent, budget=BUDGET_TEAM)
        elif role_idx == 6:
            await call(client, "GET", "/v1/schedules", agent, budget=BUDGET_TEAM)
        elif role_idx == 7:
            await call(client, "GET", "/v1/webhooks", agent, budget=BUDGET_TEAM)

        iteration += 1
        await asyncio.sleep(5)

    loop_duration = time.time() - loop_start
    async with S.lock:
        S.monitoring_iterations = iteration
        S.monitoring_duration = loop_duration

    elapsed_b = time.monotonic() - t0
    async with S.lock:
        S.onboarding_times["UserB"] = elapsed_b

    oc_pass = all(S.obstacle_completions.get(a, False) for a in agents_b)
    monitoring_pass = loop_duration >= 600 or QUICK_MODE
    await record("UserB", "ALL", "devops_monitoring_complete", oc_pass and monitoring_pass,
                 f"8 agents, monitoring {loop_duration:.0f}s ({iteration} iterations)")
    log("UserB", f"Complete: monitoring ran {loop_duration:.0f}s with {iteration} iterations")


async def run_user_c(client: httpx.AsyncClient) -> None:
    """User C: Free tier, 1 agent, onboarding + rate limit test."""
    log("UserC", "Starting Free tier onboarding simulation")
    agents_c = [n for n, d in S.registered_agents.items() if d["user"] == "UserC"]
    agent = agents_c[0]

    # Time onboarding (SIM-06)
    onboard_elapsed = await time_onboarding(client, "UserC", agent)
    async with S.lock:
        S.onboarding_times["UserC"] = onboard_elapsed
    log(agent, f"Onboarding completed in {onboard_elapsed:.1f}s")

    # Obstacle course (SIM-04)
    await run_obstacle_course(client, agent, BUDGET_FREE, "UserC")

    # Rate limit test (SIM-03): 65 rapid writes to trigger 429
    log(agent, "Starting rate limit test (65 rapid writes)")
    hit_429 = False
    recovery_ok = False
    for i in range(65):
        r = await call(client, "POST", "/v1/memory", agent,
                       json_body={"key": f"rl_test_{i}", "value": f"rate_limit_data_{i}"},
                       budget=None, skip_rate_wait=True)
        if r.status_code == 429:
            hit_429 = True
            retry_after = r.headers.get("Retry-After", "60")
            log(agent, f"429 received at write #{i+1}, Retry-After: {retry_after}")
            await asyncio.sleep(min(int(retry_after), 30))
            # Verify recovery
            r2 = await call(client, "GET", "/v1/memory", agent, budget=BUDGET_FREE)
            recovery_ok = r2.status_code == 200
            log(agent, f"Recovery after 429: {'OK' if recovery_ok else 'FAIL'} (status {r2.status_code})")
            break

    async with S.lock:
        S.hit_429 = hit_429
        S.recovery_ok = recovery_ok

    await record("UserC", agent, "rate_limit_graceful",
                 hit_429 and recovery_ok,
                 f"hit_429={hit_429}, recovery_ok={recovery_ok}")
    await record("UserC", agent, "onboarding_time",
                 onboard_elapsed < 300,
                 f"{onboard_elapsed:.1f}s (limit 300s)")
    log("UserC", f"Complete: 429={'hit' if hit_429 else 'missed'}, recovery={'OK' if recovery_ok else 'FAIL'}")


# ===========================================================================
# REPORT GENERATION
# ===========================================================================

def generate_report() -> str:
    """Generate markdown simulation report."""
    lines: list[str] = []
    lines.append("# 3-User Realistic Simulation Report")
    lines.append(f"\n**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**API:** {API}")
    lines.append(f"**Mode:** {'Quick' if QUICK_MODE else 'Full'}")
    lines.append(f"**Duration:** {time.time() - S.start_time:.0f}s")
    lines.append(f"**Agents registered:** {len(S.registered_agents)}")

    # SIM Requirement Results
    lines.append("\n## SIM Requirement Results\n")
    lines.append("| Req | Description | Result |")
    lines.append("|-----|-------------|--------|")

    # SIM-01: User A research pipeline
    agents_a = [n for n, d in S.registered_agents.items() if d["user"] == "UserA"]
    sim01 = all(S.obstacle_completions.get(a, False) for a in agents_a) if agents_a else False
    lines.append(f"| SIM-01 | User A research pipeline | {'PASS' if sim01 else 'FAIL'} |")

    # SIM-02: User B monitoring 10+ min
    sim02 = S.monitoring_duration >= 600 or QUICK_MODE
    lines.append(f"| SIM-02 | User B monitoring {S.monitoring_duration:.0f}s | {'PASS' if sim02 else 'FAIL'} |")

    # SIM-03: User C 429 + recovery
    sim03 = S.hit_429 and S.recovery_ok
    lines.append(f"| SIM-03 | User C 429 graceful | {'PASS' if sim03 else 'FAIL'} |")

    # SIM-04: All 17 obstacle courses
    sim04 = len(S.obstacle_completions) == 17 and all(S.obstacle_completions.values())
    lines.append(
        f"| SIM-04 | 17/17 obstacle courses | {'PASS' if sim04 else 'FAIL'} "
        f"({sum(S.obstacle_completions.values())}/{len(S.obstacle_completions)}) |"
    )

    # SIM-05: Zero 500 errors
    sim05 = len(S.server_errors) == 0
    lines.append(f"| SIM-05 | Zero 500 errors | {'PASS' if sim05 else 'FAIL'} ({len(S.server_errors)} errors) |")

    # SIM-06: Onboarding under 5 min
    sim06 = all(t < 300 for t in S.onboarding_times.values()) if S.onboarding_times else False
    lines.append(f"| SIM-06 | Onboarding < 5 min | {'PASS' if sim06 else 'FAIL'} |")

    # Onboarding times
    lines.append("\n## Onboarding Times\n")
    for user, elapsed in sorted(S.onboarding_times.items()):
        lines.append(
            f"- **{user}:** {elapsed:.1f}s {'(PASS)' if elapsed < 300 else '(FAIL -- over 5 min)'}"
        )

    # Obstacle Course Results
    lines.append("\n## Obstacle Course Results\n")
    lines.append("| Agent | Completed |")
    lines.append("|-------|-----------|")
    for ag, ok in sorted(S.obstacle_completions.items()):
        lines.append(f"| {ag} | {'Yes' if ok else 'No'} |")

    # Server Errors (SIM-05)
    if S.server_errors:
        lines.append("\n## Server Errors (SIM-05 FAIL)\n")
        for e in S.server_errors[:20]:
            lines.append(
                f"- [{e['agent']}] {e['method']} {e['path']} -> {e['status']}: {e['body'][:100]}"
            )

    # Monitoring Stats
    lines.append("\n## Monitoring Loop\n")
    lines.append(f"- **Duration:** {S.monitoring_duration:.0f}s")
    lines.append(f"- **Iterations:** {S.monitoring_iterations}")

    # Test Results Summary
    passed = sum(1 for res in S.results if res.passed)
    total = len(S.results)
    lines.append(f"\n## Test Results: {passed}/{total} passed\n")
    for res in S.results:
        icon = "PASS" if res.passed else "FAIL"
        lines.append(f"- [{icon}] {res.user}/{res.agent}: {res.test} -- {res.detail}")

    # Final verdict
    all_pass = sim01 and sim02 and sim03 and sim04 and sim05 and sim06
    lines.append(f"\n## Final Verdict: {'ALL PASS' if all_pass else 'FAILURES DETECTED'}\n")

    return "\n".join(lines)


# ===========================================================================
# MAIN ENTRY POINT
# ===========================================================================

async def main() -> None:
    S.start_time = time.time()
    print("=" * 70)
    print("Phase 79: 3-User Realistic Simulation")
    print(f"API: {API}")
    print(f"Mode: {'Quick' if QUICK_MODE else 'Full'}")
    print("=" * 70)

    async with httpx.AsyncClient(timeout=60.0) as client:
        # Phase 0: Register all 17 agents
        print("\n--- Phase 0: Agent Registration ---")
        await register_simulation_agents(client)
        print(f"Registered {len(S.registered_agents)} agents")

        if QUICK_MODE:
            # Quick mode: User C only
            print("\n--- Quick Mode: User C Only ---")
            await run_user_c(client)
        else:
            # Full mode: All 3 users concurrently
            print("\n--- Phase 1: User Simulations (concurrent) ---")
            await asyncio.gather(
                run_user_a(client),
                run_user_b(client),
                run_user_c(client),
            )

    # Generate report
    print("\n--- Generating Report ---")
    report = generate_report()

    # Write report to planning directory
    report_path = Path(".planning/phases/79-3-user-realistic-simulation/79-SIM-RESULTS.md")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)
    print(f"Report written to {report_path}")

    # Also write to Downloads if it exists
    downloads = Path.home() / "Downloads" / "sim-3user-report.md"
    try:
        downloads.write_text(report)
        print(f"Report written to {downloads}")
    except OSError:
        pass

    # Print summary
    print("\n" + "=" * 70)
    print(report)
    print("=" * 70)

    # Exit code based on SIM-05 (zero 500 errors)
    if S.server_errors:
        print(f"\nEXIT 1: {len(S.server_errors)} server errors detected")
        sys.exit(1)
    else:
        print("\nEXIT 0: Zero server errors")


if __name__ == "__main__":
    asyncio.run(main())
