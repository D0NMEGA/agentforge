"""Tests for FUNC-04, FUNC-05, FUNC-06 functionality fixes.

FUNC-04: Tiered recall mid-tier namespace mismatch -- returns empty due to wrong namespace query
FUNC-05: Tiered summarize vector promotion path validation
FUNC-06: GET /v1/events missing event_type filter parameter
"""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import numpy as np
import pytest

import db as _db_module


# ---------------------------------------------------------------------------
# FUNC-04: Tiered Recall mid-tier namespace mismatch
# ---------------------------------------------------------------------------

class TestFUNC04TieredRecall:
    """FUNC-04: Tiered recall returns empty results due to namespace mismatch.

    tiered_store_event persists with namespace 'agent:{agent_id}' but
    tiered_recall queries namespace IN ('default', 'notes') -- these never match.
    """

    def test_tiered_recall_returns_mid_tier_results(self, client, seed_agents):
        """Store event with persist=True, then recall via mid tier. Expect count >= 1."""
        a1 = seed_agents["agent1"]
        headers = {"X-API-Key": a1["key"]}

        # Step 1: Create a session
        resp = client.post("/v1/sessions", json={"name": "test-session"}, headers=headers)
        assert resp.status_code == 200, f"Session create failed: {resp.text}"
        session_id = resp.json()["session_id"]

        # Step 2: Store event with persist=True so it lands in mid-tier memory
        resp = client.post(
            "/v1/tiered/store_event",
            json={
                "session_id": session_id,
                "data": "important note about testing",
                "role": "user",
                "persist": True,
                "note_key": "test_note",
            },
            headers=headers,
        )
        assert resp.status_code == 200, f"Store event failed: {resp.text}"
        assert resp.json()["persisted"] is True

        # Step 3: Recall from mid tier
        resp = client.post(
            "/v1/tiered/recall",
            json={"query": "testing", "tiers": ["mid"], "k": 5},
            headers=headers,
        )
        assert resp.status_code == 200, f"Recall failed: {resp.text}"
        data = resp.json()

        # Step 4: Assert at least one result returned
        assert data["count"] >= 1, (
            f"Expected count >= 1 from mid-tier recall, got {data['count']}. "
            f"Bug: tiered_recall queries namespace IN ('default', 'notes') but "
            f"tiered_store_event stores with namespace 'agent:{{agent_id}}'"
        )

        # Step 5: Assert at least one result has tier=mid
        mid_results = [r for r in data["results"] if r.get("tier") == "mid"]
        assert len(mid_results) >= 1, f"Expected tier=mid results, got: {data['results']}"


# ---------------------------------------------------------------------------
# FUNC-05: Tiered summarize vector promotion
# ---------------------------------------------------------------------------

class TestFUNC05TieredSummarize:
    """FUNC-05: Tiered summarize endpoint promotes session summary to vector_memory."""

    def test_tiered_summarize_promotes_to_vector(self, client, seed_agents):
        """Create session with 12+ messages, summarize, expect promoted=True."""
        a1 = seed_agents["agent1"]
        headers = {"X-API-Key": a1["key"]}

        # Step 1: Create a session
        resp = client.post("/v1/sessions", json={"name": "summarize-test"}, headers=headers)
        assert resp.status_code == 200, f"Session create failed: {resp.text}"
        session_id = resp.json()["session_id"]

        # Step 2: Append 12 non-system messages to exceed auto-summarize threshold (>10)
        for i in range(12):
            resp = client.post(
                f"/v1/sessions/{session_id}/append",
                json={"role": "user", "content": f"Message number {i + 1}: unique content for summarization test"},
                headers=headers,
            )
            assert resp.status_code == 200, f"Append message {i+1} failed: {resp.text}"

        # Step 3: Call summarize with mocked _embed_text to avoid torch/model dependency
        with patch("routers.tiered_memory._embed_text", return_value=np.zeros(384, dtype=np.float32)):
            resp = client.post(
                f"/v1/tiered/summarize/{session_id}",
                headers=headers,
            )

        assert resp.status_code == 200, f"Summarize failed: {resp.text}"
        data = resp.json()

        # Step 4: Assert promoted=True
        assert data["promoted"] is True, (
            f"Expected promoted=True but got {data['promoted']}. "
            f"summary_text: '{data.get('summary_text', '')}'"
        )

        # Step 5: Assert summary_text is non-empty and starts with expected prefix
        assert data["summary_text"], "Expected non-empty summary_text"
        assert data["summary_text"].startswith("Summary of previous conversation:"), (
            f"Expected summary_text to start with 'Summary of previous conversation:', "
            f"got: '{data['summary_text'][:80]}'"
        )

        # Step 6: Assert vector namespace is long_term
        assert data["vector_namespace"] == "long_term", (
            f"Expected vector_namespace='long_term', got '{data['vector_namespace']}'"
        )


# ---------------------------------------------------------------------------
# FUNC-06: Events endpoint missing event_type filter
# ---------------------------------------------------------------------------

class TestFUNC06EventsFilter:
    """FUNC-06: GET /v1/events has no event_type filter parameter."""

    def _insert_events(self, seed_agents, event_specs):
        """Insert events directly into agent_events table for testing."""
        db_path = seed_agents["db_path"]
        agent_id = seed_agents["agent1"]["id"]
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        for event_type, payload in event_specs:
            event_id = f"evt_{uuid.uuid4().hex[:16]}"
            conn.execute(
                "INSERT INTO agent_events (event_id, agent_id, event_type, payload, created_at, acknowledged) "
                "VALUES (?, ?, ?, ?, ?, 0)",
                (event_id, agent_id, event_type, json.dumps({"data": payload}), now),
            )
        conn.commit()
        conn.close()

    def test_events_filter_by_event_type(self, client, seed_agents):
        """GET /v1/events?event_type=task.created returns only task.created events."""
        a1 = seed_agents["agent1"]
        headers = {"X-API-Key": a1["key"]}

        # Insert one task.created and one memory.updated event
        self._insert_events(seed_agents, [
            ("task.created", "task was created"),
            ("memory.updated", "memory was updated"),
        ])

        # Filter by task.created
        resp = client.get("/v1/events?event_type=task.created", headers=headers)
        assert resp.status_code == 200, f"Events filter request failed: {resp.text}"
        data = resp.json()

        assert "events" in data, f"Expected 'events' key in response, got: {data}"
        events = data["events"]

        # All returned events must be task.created
        event_types = [e["event_type"] for e in events]
        assert all(et == "task.created" for et in event_types), (
            f"Expected only task.created events, got: {event_types}. "
            f"Bug: GET /v1/events has no event_type query parameter"
        )

        # Ensure memory.updated is NOT in results
        assert "memory.updated" not in event_types, (
            f"memory.updated should not appear when filtering for task.created, got: {event_types}"
        )

        # At least one task.created event should be returned
        assert len(events) >= 1, "Expected at least one task.created event"

    def test_events_no_filter_returns_all(self, client, seed_agents):
        """GET /v1/events without filter returns all event types."""
        a1 = seed_agents["agent1"]
        headers = {"X-API-Key": a1["key"]}

        # Insert both event types
        self._insert_events(seed_agents, [
            ("task.created", "another task"),
            ("memory.updated", "another memory update"),
        ])

        # No filter -- should return all
        resp = client.get("/v1/events", headers=headers)
        assert resp.status_code == 200, f"Events request failed: {resp.text}"
        data = resp.json()

        assert "events" in data, f"Expected 'events' key in response, got: {data}"
        events = data["events"]
        event_types = set(e["event_type"] for e in events)

        assert "task.created" in event_types, f"Expected task.created in unfiltered results, got: {event_types}"
        assert "memory.updated" in event_types, f"Expected memory.updated in unfiltered results, got: {event_types}"
