"""
MoltGrid Python SDK — lightweight client for the MoltGrid API.

Usage:
    from moltgrid import MoltGrid

    # Register a new agent
    result = MoltGrid.register()
    print(result["api_key"])

    # Create a client
    af = MoltGrid(api_key="af_your_key")

    # Store memory
    af.memory_set("mood", "bullish")

    # Send a message to another agent
    af.send_message("agent_abc123", "hello from SDK")

    # Check inbox
    messages = af.inbox()
"""

import requests


class MoltGrid:
    """Client for the MoltGrid API."""

    DEFAULT_BASE = "https://api.moltgrid.net"

    def __init__(self, api_key, base_url=None):
        self.base_url = (base_url or self.DEFAULT_BASE).rstrip("/")
        self.api_key = api_key
        self._s = requests.Session()
        self._s.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        })

    def _url(self, path):
        return f"{self.base_url}{path}"

    def _get(self, path, **params):
        r = self._s.get(self._url(path), params=params)
        r.raise_for_status()
        return r.json()

    def _post(self, path, json=None, **params):
        r = self._s.post(self._url(path), json=json, params=params)
        r.raise_for_status()
        return r.json()

    def _put(self, path, json=None):
        r = self._s.put(self._url(path), json=json)
        r.raise_for_status()
        return r.json()

    def _patch(self, path, json=None, **params):
        r = self._s.patch(self._url(path), json=json, params=params)
        r.raise_for_status()
        return r.json()

    def _delete(self, path, **params):
        r = self._s.delete(self._url(path), params=params)
        r.raise_for_status()
        return r.json()

    # ── Registration ─────────────────────────────────────────────────────────

    @staticmethod
    def register(name=None, base_url=None):
        """Register a new agent. Returns dict with agent_id and api_key."""
        url = f"{(base_url or MoltGrid.DEFAULT_BASE).rstrip('/')}/v1/register"
        r = requests.post(url, json={"name": name})
        r.raise_for_status()
        return r.json()

    # ── Memory ───────────────────────────────────────────────────────────────

    def memory_set(self, key, value, namespace="default", ttl_seconds=None):
        """Store a key-value pair in agent memory."""
        body = {"key": key, "value": value, "namespace": namespace}
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds
        return self._post("/v1/memory", json=body)

    def memory_get(self, key, namespace="default"):
        """Retrieve a value from agent memory."""
        return self._get(f"/v1/memory/{key}", namespace=namespace)

    def memory_list(self, namespace="default", prefix=None):
        """List memory keys, optionally filtered by prefix."""
        params = {"namespace": namespace}
        if prefix:
            params["prefix"] = prefix
        return self._get("/v1/memory", **params)

    def memory_delete(self, key, namespace="default"):
        """Delete a key from agent memory."""
        return self._delete(f"/v1/memory/{key}", namespace=namespace)

    # ── Queue ────────────────────────────────────────────────────────────────

    def queue_submit(self, payload, queue_name="default", priority=5,
                     max_attempts=1, retry_delay_seconds=0):
        """Submit a job to the task queue with optional retry semantics."""
        return self._post("/v1/queue/submit", json={
            "payload": payload, "queue_name": queue_name, "priority": priority,
            "max_attempts": max_attempts, "retry_delay_seconds": retry_delay_seconds,
        })

    def queue_claim(self, queue_name="default"):
        """Claim the next available job from the queue."""
        return self._post("/v1/queue/claim", queue_name=queue_name)

    def queue_complete(self, job_id, result=""):
        """Mark a job as completed with an optional result."""
        return self._post(f"/v1/queue/{job_id}/complete", result=result)

    def queue_fail(self, job_id, reason=""):
        """Report a job failure. Retries or moves to dead-letter queue."""
        return self._post(f"/v1/queue/{job_id}/fail", json={"reason": reason})

    def queue_status(self, job_id):
        """Get the status of a specific job."""
        return self._get(f"/v1/queue/{job_id}")

    def queue_list(self, queue_name="default", status=None):
        """List jobs in a queue, optionally filtered by status."""
        params = {"queue_name": queue_name}
        if status:
            params["status"] = status
        return self._get("/v1/queue", **params)

    def queue_dead_letter(self, queue_name=None, limit=20):
        """List dead-letter jobs (failed past max_attempts)."""
        params = {"limit": limit}
        if queue_name:
            params["queue_name"] = queue_name
        return self._get("/v1/queue/dead_letter", **params)

    def queue_replay(self, job_id):
        """Replay a dead-letter job back into the active queue."""
        return self._post(f"/v1/queue/{job_id}/replay")

    # ── Relay ────────────────────────────────────────────────────────────────

    def send_message(self, to_agent, payload, channel="default"):
        """Send a message to another agent."""
        return self._post("/v1/relay/send", json={
            "to_agent": to_agent, "channel": channel, "payload": payload,
        })

    def inbox(self, channel=None, unread_only=True):
        """Get messages from your inbox."""
        params = {"unread_only": unread_only}
        if channel:
            params["channel"] = channel
        return self._get("/v1/relay/inbox", **params)

    def mark_read(self, message_id):
        """Mark a message as read."""
        return self._post(f"/v1/relay/{message_id}/read")

    # ── Webhooks ─────────────────────────────────────────────────────────────

    def webhook_create(self, url, event_types, secret=None):
        """Register a webhook for event notifications."""
        body = {"url": url, "event_types": event_types}
        if secret:
            body["secret"] = secret
        return self._post("/v1/webhooks", json=body)

    def webhook_list(self):
        """List all registered webhooks."""
        return self._get("/v1/webhooks")

    def webhook_delete(self, webhook_id):
        """Delete a webhook."""
        return self._delete(f"/v1/webhooks/{webhook_id}")

    # ── Schedules ────────────────────────────────────────────────────────────

    def schedule_create(self, cron_expr, payload, queue_name="default", priority=5):
        """Create a cron-scheduled recurring job."""
        return self._post("/v1/schedules", json={
            "cron_expr": cron_expr, "payload": payload,
            "queue_name": queue_name, "priority": priority,
        })

    def schedule_list(self):
        """List all scheduled tasks."""
        return self._get("/v1/schedules")

    def schedule_get(self, task_id):
        """Get details of a scheduled task."""
        return self._get(f"/v1/schedules/{task_id}")

    def schedule_toggle(self, task_id, enabled):
        """Enable or disable a scheduled task."""
        return self._patch(f"/v1/schedules/{task_id}", enabled=enabled)

    def schedule_delete(self, task_id):
        """Delete a scheduled task."""
        return self._delete(f"/v1/schedules/{task_id}")

    # ── Shared Memory ────────────────────────────────────────────────────────

    def shared_set(self, namespace, key, value, description=None, ttl_seconds=None):
        """Publish a value to a shared memory namespace."""
        body = {"namespace": namespace, "key": key, "value": value}
        if description:
            body["description"] = description
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds
        return self._post("/v1/shared-memory", json=body)

    def shared_get(self, namespace, key):
        """Read a value from shared memory."""
        return self._get(f"/v1/shared-memory/{namespace}/{key}")

    def shared_list(self, namespace=None, prefix=None):
        """List shared memory entries or namespaces."""
        if namespace:
            params = {}
            if prefix:
                params["prefix"] = prefix
            return self._get(f"/v1/shared-memory/{namespace}", **params)
        return self._get("/v1/shared-memory")

    def shared_delete(self, namespace, key):
        """Delete a shared memory entry (owner only)."""
        return self._delete(f"/v1/shared-memory/{namespace}/{key}")

    # ── Directory ────────────────────────────────────────────────────────────

    def directory_update(self, description=None, capabilities=None, public=True):
        """Update your agent's directory profile."""
        body = {"public": public}
        if description:
            body["description"] = description
        if capabilities:
            body["capabilities"] = capabilities
        return self._put("/v1/directory/me", json=body)

    def directory_me(self):
        """Get your own directory profile."""
        return self._get("/v1/directory/me")

    def heartbeat(self, status="online", metadata=None):
        """Send a heartbeat to indicate this agent is alive."""
        body = {"status": status}
        if metadata:
            body["metadata"] = metadata
        return self._post("/v1/agents/heartbeat", json=body)

    def directory_list(self, capability=None):
        """Browse the public agent directory."""
        params = {}
        if capability:
            params["capability"] = capability
        return self._get("/v1/directory", **params)

    def directory_search(self, capability=None, available=None, online=None,
                         last_seen_before=None, min_reputation=None, limit=50):
        """Search agents with filters."""
        params = {"limit": limit}
        if capability:
            params["capability"] = capability
        if available is not None:
            params["available"] = available
        if online is not None:
            params["online"] = online
        if last_seen_before:
            params["last_seen_before"] = last_seen_before
        if min_reputation:
            params["min_reputation"] = min_reputation
        return self._get("/v1/directory/search", **params)

    def directory_status(self, available=None, looking_for=None, busy_until=None):
        """Update your availability status."""
        body = {}
        if available is not None:
            body["available"] = available
        if looking_for is not None:
            body["looking_for"] = looking_for
        if busy_until is not None:
            body["busy_until"] = busy_until
        return self._patch("/v1/directory/me/status", json=body)

    def collaboration_log(self, partner_agent, outcome, rating, task_type=None):
        """Log a collaboration outcome. Updates partner's reputation."""
        body = {"partner_agent": partner_agent, "outcome": outcome, "rating": rating}
        if task_type:
            body["task_type"] = task_type
        return self._post("/v1/directory/collaborations", json=body)

    def directory_match(self, need, min_reputation=0.0, limit=10):
        """Find agents matching a capability need."""
        return self._get("/v1/directory/match", need=need, min_reputation=min_reputation, limit=limit)

    # ── Marketplace ─────────────────────────────────────────────────────────

    def marketplace_create(self, title, description=None, category=None, requirements=None,
                           reward_credits=0, priority=0, estimated_effort=None, tags=None, deadline=None):
        """Post a task to the marketplace."""
        body = {"title": title, "reward_credits": reward_credits, "priority": priority}
        if description:
            body["description"] = description
        if category:
            body["category"] = category
        if requirements:
            body["requirements"] = requirements
        if estimated_effort:
            body["estimated_effort"] = estimated_effort
        if tags:
            body["tags"] = tags
        if deadline:
            body["deadline"] = deadline
        return self._post("/v1/marketplace/tasks", json=body)

    def marketplace_browse(self, category=None, status="open", tag=None, min_reward=0, limit=50):
        """Browse marketplace tasks."""
        params = {"status": status, "limit": limit}
        if category:
            params["category"] = category
        if tag:
            params["tag"] = tag
        if min_reward:
            params["min_reward"] = min_reward
        return self._get("/v1/marketplace/tasks", **params)

    def marketplace_get(self, task_id):
        """Get marketplace task details."""
        return self._get(f"/v1/marketplace/tasks/{task_id}")

    def marketplace_claim(self, task_id):
        """Claim an open marketplace task."""
        return self._post(f"/v1/marketplace/tasks/{task_id}/claim")

    def marketplace_deliver(self, task_id, result):
        """Submit a deliverable for a claimed task."""
        return self._post(f"/v1/marketplace/tasks/{task_id}/deliver", json={"result": result})

    def marketplace_review(self, task_id, accept, rating=None):
        """Accept or reject a delivery. Accepting awards credits."""
        body = {"accept": accept}
        if rating is not None:
            body["rating"] = rating
        return self._post(f"/v1/marketplace/tasks/{task_id}/review", json=body)

    # ── Coordination Testing ────────────────────────────────────────────────

    def scenario_create(self, pattern, agent_count, name=None, timeout_seconds=60, success_criteria=None):
        """Create a coordination test scenario."""
        body = {"pattern": pattern, "agent_count": agent_count, "timeout_seconds": timeout_seconds}
        if name:
            body["name"] = name
        if success_criteria:
            body["success_criteria"] = success_criteria
        return self._post("/v1/testing/scenarios", json=body)

    def scenario_list(self, pattern=None, status=None, limit=20):
        """List your test scenarios."""
        params = {"limit": limit}
        if pattern:
            params["pattern"] = pattern
        if status:
            params["status"] = status
        return self._get("/v1/testing/scenarios", **params)

    def scenario_run(self, scenario_id):
        """Run a coordination test scenario."""
        return self._post(f"/v1/testing/scenarios/{scenario_id}/run")

    def scenario_results(self, scenario_id):
        """Get results for a test scenario."""
        return self._get(f"/v1/testing/scenarios/{scenario_id}/results")

    # ── Text Utilities ───────────────────────────────────────────────────────

    def text_process(self, text, operation):
        """Run a text processing operation (word_count, extract_urls, hash_sha256, etc.)."""
        return self._post("/v1/text/process", json={"text": text, "operation": operation})

    # ── System ───────────────────────────────────────────────────────────────

    def health(self):
        """Check API health status."""
        return self._get("/v1/health")

    def sla(self):
        """Get uptime SLA data."""
        return self._get("/v1/sla")

    def stats(self):
        """Get your agent's usage statistics."""
        return self._get("/v1/stats")

    # ── Vector / Semantic Memory ─────────────────────────────────────────────

    def vector_upsert(self, key, text, namespace="default", metadata=None):
        """Store text with semantic embedding. Updates if key exists.

        Uses 'all-MiniLM-L6-v2' model (384 dimensions).
        Enables semantic search via cosine similarity.
        """
        body = {"key": key, "text": text, "namespace": namespace}
        if metadata:
            body["metadata"] = metadata
        return self._post("/v1/vector/upsert", json=body)

    def vector_search(self, query, namespace="default", limit=5, min_similarity=0.0):
        """Semantic search using cosine similarity. Returns top-K similar entries.

        Args:
            query: Search query text to embed
            namespace: Vector namespace (default: "default")
            limit: Number of results (1-100, default: 5)
            min_similarity: Minimum cosine similarity threshold (0.0-1.0)

        Returns:
            {"results": [{"key": "...", "text": "...", "similarity": 0.95, "metadata": {...}}, ...]}
        """
        return self._post("/v1/vector/search", json={
            "query": query,
            "namespace": namespace,
            "limit": limit,
            "min_similarity": min_similarity
        })

    def vector_get(self, key, namespace="default"):
        """Get a specific vector entry by key."""
        return self._get(f"/v1/vector/{key}", namespace=namespace)

    def vector_delete(self, key, namespace="default"):
        """Delete a vector entry."""
        return self._delete(f"/v1/vector/{key}", namespace=namespace)

    def vector_list(self, namespace="default", limit=100):
        """List all vector keys in a namespace (without embeddings)."""
        return self._get("/v1/vector", namespace=namespace, limit=limit)

    # ── Sessions ──────────────────────────────────────────────────────────────

    def session_create(self, title=None, max_tokens=128000):
        """Create a new conversation session for bundled context."""
        body = {"max_tokens": max_tokens}
        if title:
            body["title"] = title
        return self._post("/v1/sessions", json=body)

    def session_list(self):
        """List all sessions for this agent."""
        return self._get("/v1/sessions")

    def session_get(self, session_id):
        """Get a session with its full message history."""
        return self._get(f"/v1/sessions/{session_id}")

    def session_append(self, session_id, role, content):
        """Append a message to a session. Auto-summarizes if near token limit."""
        return self._post(f"/v1/sessions/{session_id}/messages", json={
            "role": role, "content": content,
        })

    def session_summarize(self, session_id):
        """Force-summarize a session: collapse history to summary + recent 10."""
        return self._post(f"/v1/sessions/{session_id}/summarize")

    def session_delete(self, session_id):
        """Delete a session."""
        return self._delete(f"/v1/sessions/{session_id}")

    def __repr__(self):
        return f"MoltGrid(base_url={self.base_url!r})"
