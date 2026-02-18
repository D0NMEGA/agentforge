"""
Comprehensive tests for MoltGrid API — all features.
Run: pytest test_main.py -v
"""

import os
import json
import time
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Use an isolated test database
os.environ["MOLTGRID_DB"] = "test_moltgrid.db"

from fastapi.testclient import TestClient
from main import app, init_db, DB_PATH, _ws_connections, _run_scheduler_tick, _run_liveness_check, _run_webhook_delivery_tick

client = TestClient(app)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_db():
    """Wipe and re-init the DB before every test."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    _ws_connections.clear()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def register_agent(name="test-agent"):
    """Helper — register an agent and return (agent_id, api_key, headers)."""
    r = client.post("/v1/register", json={"name": name})
    assert r.status_code == 200
    data = r.json()
    return data["agent_id"], data["api_key"], {"X-API-Key": data["api_key"]}


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION & AUTH
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegistration:
    def test_register(self):
        r = client.post("/v1/register", json={"name": "alice"})
        assert r.status_code == 200
        d = r.json()
        assert d["agent_id"].startswith("agent_")
        assert d["api_key"].startswith("af_")
        assert "Store your API key" in d["message"]

    def test_register_no_name(self):
        r = client.post("/v1/register", json={})
        assert r.status_code == 200

    def test_invalid_api_key(self):
        r = client.get("/v1/memory", headers={"X-API-Key": "bad_key"})
        assert r.status_code == 401

    def test_missing_api_key(self):
        r = client.get("/v1/memory")
        assert r.status_code == 401

    def test_rotate_api_key(self):
        aid, old_key, h = register_agent("rotate-me")
        # Store some data first
        client.post("/v1/memory", json={"key": "persist", "value": "survives"}, headers=h)

        # Rotate key
        r = client.post("/v1/agents/rotate-key", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "rotated"
        assert d["agent_id"] == aid
        assert d["api_key"].startswith("af_")
        assert d["api_key"] != old_key

        new_h = {"X-API-Key": d["api_key"]}

        # Old key should be invalid
        r2 = client.get("/v1/memory/persist", headers=h)
        assert r2.status_code == 401

        # New key should work and data should still be there
        r3 = client.get("/v1/memory/persist", headers=new_h)
        assert r3.status_code == 200
        assert r3.json()["value"] == "survives"


# ═══════════════════════════════════════════════════════════════════════════════
# MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

class TestMemory:
    def test_set_and_get(self):
        _, _, h = register_agent()
        client.post("/v1/memory", json={"key": "k1", "value": "v1"}, headers=h)
        r = client.get("/v1/memory/k1", headers=h)
        assert r.status_code == 200
        assert r.json()["value"] == "v1"

    def test_namespaces(self):
        _, _, h = register_agent()
        client.post("/v1/memory", json={"key": "k", "value": "ns1", "namespace": "a"}, headers=h)
        client.post("/v1/memory", json={"key": "k", "value": "ns2", "namespace": "b"}, headers=h)
        assert client.get("/v1/memory/k", params={"namespace": "a"}, headers=h).json()["value"] == "ns1"
        assert client.get("/v1/memory/k", params={"namespace": "b"}, headers=h).json()["value"] == "ns2"

    def test_ttl_expiry(self):
        _, _, h = register_agent()
        # Set with very short TTL — but minimum is 60s, so we'll just verify expires_at is set
        client.post("/v1/memory", json={"key": "ttl_key", "value": "temp", "ttl_seconds": 60}, headers=h)
        r = client.get("/v1/memory/ttl_key", headers=h)
        assert r.json()["expires_at"] is not None

    def test_update_existing(self):
        _, _, h = register_agent()
        client.post("/v1/memory", json={"key": "k", "value": "v1"}, headers=h)
        client.post("/v1/memory", json={"key": "k", "value": "v2"}, headers=h)
        assert client.get("/v1/memory/k", headers=h).json()["value"] == "v2"

    def test_delete(self):
        _, _, h = register_agent()
        client.post("/v1/memory", json={"key": "k", "value": "v"}, headers=h)
        r = client.delete("/v1/memory/k", headers=h)
        assert r.status_code == 200
        assert client.get("/v1/memory/k", headers=h).status_code == 404

    def test_delete_not_found(self):
        _, _, h = register_agent()
        assert client.delete("/v1/memory/nope", headers=h).status_code == 404

    def test_list_with_prefix(self):
        _, _, h = register_agent()
        client.post("/v1/memory", json={"key": "user:1", "value": "a"}, headers=h)
        client.post("/v1/memory", json={"key": "user:2", "value": "b"}, headers=h)
        client.post("/v1/memory", json={"key": "config:x", "value": "c"}, headers=h)
        r = client.get("/v1/memory", params={"prefix": "user:"}, headers=h)
        assert r.json()["count"] == 2

    def test_isolation_between_agents(self):
        _, _, h1 = register_agent("a1")
        _, _, h2 = register_agent("a2")
        client.post("/v1/memory", json={"key": "secret", "value": "mine"}, headers=h1)
        assert client.get("/v1/memory/secret", headers=h2).status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# QUEUE
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueue:
    def test_submit_and_status(self):
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={"payload": "do stuff"}, headers=h)
        assert r.status_code == 200
        job_id = r.json()["job_id"]
        s = client.get(f"/v1/queue/{job_id}", headers=h)
        assert s.json()["status"] == "pending"

    def test_claim_and_complete(self):
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={"payload": "work"}, headers=h)
        job_id = r.json()["job_id"]

        claimed = client.post("/v1/queue/claim", headers=h)
        assert claimed.json()["job_id"] == job_id

        done = client.post(f"/v1/queue/{job_id}/complete", params={"result": "done!"}, headers=h)
        assert done.json()["status"] == "completed"

    def test_claim_empty(self):
        _, _, h = register_agent()
        r = client.post("/v1/queue/claim", headers=h)
        assert r.json()["status"] == "empty"

    def test_priority_order(self):
        _, _, h = register_agent()
        client.post("/v1/queue/submit", json={"payload": "low", "priority": 1}, headers=h)
        client.post("/v1/queue/submit", json={"payload": "high", "priority": 10}, headers=h)
        claimed = client.post("/v1/queue/claim", headers=h)
        assert claimed.json()["payload"] == "high"

    def test_list_with_status_filter(self):
        _, _, h = register_agent()
        client.post("/v1/queue/submit", json={"payload": "a"}, headers=h)
        client.post("/v1/queue/submit", json={"payload": "b"}, headers=h)
        r = client.get("/v1/queue", params={"status": "pending"}, headers=h)
        assert r.json()["count"] == 2

    def test_complete_fires_webhook(self):
        _, _, h = register_agent()
        # Register a webhook
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["job.completed"],
        }, headers=h)

        r = client.post("/v1/queue/submit", json={"payload": "work"}, headers=h)
        job_id = r.json()["job_id"]
        client.post("/v1/queue/claim", headers=h)

        with patch("main.threading.Thread") as mock_thread:
            client.post(f"/v1/queue/{job_id}/complete", params={"result": "ok"}, headers=h)
            # Webhook thread should have been started
            assert mock_thread.called


# ═══════════════════════════════════════════════════════════════════════════════
# RELAY
# ═══════════════════════════════════════════════════════════════════════════════

class TestRelay:
    def test_send_and_inbox(self):
        id1, _, h1 = register_agent("sender")
        id2, _, h2 = register_agent("receiver")

        r = client.post("/v1/relay/send", json={"to_agent": id2, "payload": "hello"}, headers=h1)
        assert r.status_code == 200

        inbox = client.get("/v1/relay/inbox", headers=h2)
        msgs = inbox.json()["messages"]
        assert len(msgs) == 1
        assert msgs[0]["payload"] == "hello"
        assert msgs[0]["from_agent"] == id1

    def test_send_to_nonexistent(self):
        _, _, h = register_agent()
        r = client.post("/v1/relay/send", json={"to_agent": "agent_fake", "payload": "hi"}, headers=h)
        assert r.status_code == 404

    def test_mark_read(self):
        id1, _, h1 = register_agent("s")
        id2, _, h2 = register_agent("r")

        client.post("/v1/relay/send", json={"to_agent": id2, "payload": "msg"}, headers=h1)
        inbox = client.get("/v1/relay/inbox", headers=h2)
        msg_id = inbox.json()["messages"][0]["message_id"]

        r = client.post(f"/v1/relay/{msg_id}/read", headers=h2)
        assert r.status_code == 200

        # Should be empty now when filtering unread
        inbox2 = client.get("/v1/relay/inbox", headers=h2)
        assert inbox2.json()["count"] == 0

    def test_mark_read_not_found(self):
        _, _, h = register_agent()
        assert client.post("/v1/relay/msg_fake/read", headers=h).status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class TestText:
    def test_word_count(self):
        _, _, h = register_agent()
        r = client.post("/v1/text/process", json={"text": "one two three", "operation": "word_count"}, headers=h)
        assert r.json()["result"]["word_count"] == 3

    def test_extract_urls(self):
        _, _, h = register_agent()
        r = client.post("/v1/text/process", json={
            "text": "visit https://example.com and http://test.org",
            "operation": "extract_urls",
        }, headers=h)
        assert len(r.json()["result"]["urls"]) == 2

    def test_hash_sha256(self):
        _, _, h = register_agent()
        r = client.post("/v1/text/process", json={"text": "hello", "operation": "hash_sha256"}, headers=h)
        assert len(r.json()["result"]["hash"]) == 64

    def test_unknown_operation(self):
        _, _, h = register_agent()
        r = client.post("/v1/text/process", json={"text": "x", "operation": "nope"}, headers=h)
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhooks:
    def test_register_and_list(self):
        _, _, h = register_agent()
        r = client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["message.received"],
        }, headers=h)
        assert r.status_code == 200
        wh = r.json()
        assert wh["webhook_id"].startswith("wh_")
        assert wh["active"] is True

        listed = client.get("/v1/webhooks", headers=h)
        assert listed.json()["count"] == 1

    def test_invalid_event_type(self):
        _, _, h = register_agent()
        r = client.post("/v1/webhooks", json={
            "url": "https://example.com",
            "event_types": ["invalid.event"],
        }, headers=h)
        assert r.status_code == 400

    def test_delete(self):
        _, _, h = register_agent()
        r = client.post("/v1/webhooks", json={
            "url": "https://example.com",
            "event_types": ["job.completed"],
        }, headers=h)
        wh_id = r.json()["webhook_id"]

        d = client.delete(f"/v1/webhooks/{wh_id}", headers=h)
        assert d.status_code == 200

        assert client.get("/v1/webhooks", headers=h).json()["count"] == 0

    def test_delete_not_found(self):
        _, _, h = register_agent()
        assert client.delete("/v1/webhooks/wh_fake", headers=h).status_code == 404

    def test_fire_webhooks_queues_delivery(self):
        """Test that _fire_webhooks inserts into webhook_deliveries."""
        from main import _fire_webhooks, get_db

        _, _, h = register_agent()
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["message.received"],
            "secret": "mysecret",
        }, headers=h)

        aid = client.get("/v1/stats", headers=h).json()["agent_id"]
        _fire_webhooks(aid, "message.received", {"test": "data"})

        with get_db() as db:
            rows = db.execute("SELECT * FROM webhook_deliveries").fetchall()
        assert len(rows) == 1
        d = dict(rows[0])
        assert d["status"] == "pending"
        assert d["attempt_count"] == 0
        assert d["event_type"] == "message.received"
        assert '"test"' in d["payload"]

    def test_fire_webhooks_no_match(self):
        """Webhooks not matching event type should not queue a delivery."""
        from main import _fire_webhooks, get_db

        _, _, h = register_agent()
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["job.completed"],
        }, headers=h)

        aid = client.get("/v1/stats", headers=h).json()["agent_id"]
        _fire_webhooks(aid, "message.received", {"test": "data"})

        with get_db() as db:
            rows = db.execute("SELECT * FROM webhook_deliveries").fetchall()
        assert len(rows) == 0

    def test_delivery_tick_success(self):
        """Test that _run_webhook_delivery_tick delivers pending webhooks."""
        from main import _fire_webhooks

        _, _, h = register_agent()
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["message.received"],
        }, headers=h)

        aid = client.get("/v1/stats", headers=h).json()["agent_id"]
        _fire_webhooks(aid, "message.received", {"test": "data"})

        with patch("main.httpx.Client") as MockClient:
            mock_instance = MagicMock()
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_instance.post.return_value = mock_response
            MockClient.return_value.__enter__ = MagicMock(return_value=mock_instance)
            MockClient.return_value.__exit__ = MagicMock(return_value=False)

            _run_webhook_delivery_tick()
            mock_instance.post.assert_called_once()

        from main import get_db
        with get_db() as db:
            row = db.execute("SELECT * FROM webhook_deliveries").fetchone()
        assert dict(row)["status"] == "delivered"
        assert dict(row)["attempt_count"] == 1

    def test_delivery_tick_retry_on_failure(self):
        """Test that failed deliveries get retried with exponential backoff."""
        from main import _fire_webhooks, get_db

        _, _, h = register_agent()
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["job.completed"],
        }, headers=h)

        aid = client.get("/v1/stats", headers=h).json()["agent_id"]
        _fire_webhooks(aid, "job.completed", {"job_id": "j1"})

        with patch("main.httpx.Client") as MockClient:
            mock_instance = MagicMock()
            mock_instance.post.side_effect = Exception("Connection refused")
            MockClient.return_value.__enter__ = MagicMock(return_value=mock_instance)
            MockClient.return_value.__exit__ = MagicMock(return_value=False)

            _run_webhook_delivery_tick()

        with get_db() as db:
            row = dict(db.execute("SELECT * FROM webhook_deliveries").fetchone())
        assert row["status"] == "pending"
        assert row["attempt_count"] == 1
        assert row["last_error"] == "Connection refused"
        assert row["next_retry_at"] is not None

    def test_delivery_tick_fails_after_max_attempts(self):
        """Test that deliveries are marked failed after max_attempts."""
        from main import _fire_webhooks, get_db

        _, _, h = register_agent()
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["job.completed"],
        }, headers=h)

        aid = client.get("/v1/stats", headers=h).json()["agent_id"]
        _fire_webhooks(aid, "job.completed", {"job_id": "j1"})

        # Set attempt_count to max_attempts - 1 so next failure = final
        with get_db() as db:
            db.execute("UPDATE webhook_deliveries SET attempt_count=2")

        with patch("main.httpx.Client") as MockClient:
            mock_instance = MagicMock()
            mock_instance.post.side_effect = Exception("Timeout")
            MockClient.return_value.__enter__ = MagicMock(return_value=mock_instance)
            MockClient.return_value.__exit__ = MagicMock(return_value=False)

            _run_webhook_delivery_tick()

        with get_db() as db:
            row = dict(db.execute("SELECT * FROM webhook_deliveries").fetchone())
        assert row["status"] == "failed"
        assert row["attempt_count"] == 3
        assert "Timeout" in row["last_error"]

    def test_relay_send_queues_webhook(self):
        """Test that sending a relay message queues a webhook delivery."""
        from main import get_db

        id1, _, h1 = register_agent("sender")
        id2, _, h2 = register_agent("receiver")

        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["message.received"],
        }, headers=h2)

        client.post("/v1/relay/send", json={"to_agent": id2, "payload": "hi"}, headers=h1)

        with get_db() as db:
            rows = db.execute("SELECT * FROM webhook_deliveries WHERE event_type='message.received'").fetchall()
        assert len(rows) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULED TASKS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchedules:
    def test_create_and_list(self):
        _, _, h = register_agent()
        r = client.post("/v1/schedules", json={
            "cron_expr": "*/5 * * * *",
            "payload": "periodic task",
        }, headers=h)
        assert r.status_code == 200
        sched = r.json()
        assert sched["task_id"].startswith("sched_")
        assert sched["enabled"] is True
        assert sched["next_run_at"] is not None

        listed = client.get("/v1/schedules", headers=h)
        assert listed.json()["count"] == 1

    def test_invalid_cron(self):
        _, _, h = register_agent()
        r = client.post("/v1/schedules", json={
            "cron_expr": "not a cron",
            "payload": "x",
        }, headers=h)
        assert r.status_code == 400

    def test_get_detail(self):
        _, _, h = register_agent()
        r = client.post("/v1/schedules", json={
            "cron_expr": "0 * * * *",
            "payload": "hourly",
            "priority": 5,
        }, headers=h)
        task_id = r.json()["task_id"]

        detail = client.get(f"/v1/schedules/{task_id}", headers=h)
        assert detail.status_code == 200
        assert detail.json()["priority"] == 5

    def test_toggle_disable_enable(self):
        _, _, h = register_agent()
        r = client.post("/v1/schedules", json={
            "cron_expr": "0 0 * * *",
            "payload": "daily",
        }, headers=h)
        task_id = r.json()["task_id"]

        # Disable
        d = client.patch(f"/v1/schedules/{task_id}", params={"enabled": False}, headers=h)
        assert d.json()["enabled"] is False

        # Enable
        e = client.patch(f"/v1/schedules/{task_id}", params={"enabled": True}, headers=h)
        assert e.json()["enabled"] is True

    def test_delete(self):
        _, _, h = register_agent()
        r = client.post("/v1/schedules", json={
            "cron_expr": "0 0 * * *",
            "payload": "x",
        }, headers=h)
        task_id = r.json()["task_id"]

        assert client.delete(f"/v1/schedules/{task_id}", headers=h).status_code == 200
        assert client.get(f"/v1/schedules/{task_id}", headers=h).status_code == 404

    def test_delete_not_found(self):
        _, _, h = register_agent()
        assert client.delete("/v1/schedules/sched_fake", headers=h).status_code == 404

    def test_scheduler_tick_creates_jobs(self):
        """Verify _run_scheduler_tick creates jobs for due tasks."""
        _, _, h = register_agent()
        # Create a schedule with a past next_run_at by using a cron that triggers every minute
        r = client.post("/v1/schedules", json={
            "cron_expr": "* * * * *",  # every minute
            "payload": "tick-test",
            "queue_name": "tick-q",
        }, headers=h)
        task_id = r.json()["task_id"]

        # Manually set next_run_at to the past
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE scheduled_tasks SET next_run_at = '2000-01-01T00:00:00' WHERE task_id = ?",
            (task_id,)
        )
        conn.commit()
        conn.close()

        _run_scheduler_tick()

        # Should now have a job in the queue
        jobs = client.get("/v1/queue", params={"queue_name": "tick-q"}, headers=h)
        assert jobs.json()["count"] == 1
        assert jobs.json()["jobs"][0]["status"] == "pending"

    def test_toggle_not_found(self):
        _, _, h = register_agent()
        r = client.patch("/v1/schedules/sched_fake", params={"enabled": False}, headers=h)
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

class TestSharedMemory:
    def test_publish_and_read(self):
        _, _, h1 = register_agent("publisher")
        _, _, h2 = register_agent("reader")

        # Publisher writes
        r = client.post("/v1/shared-memory", json={
            "namespace": "prices",
            "key": "BTC",
            "value": "50000",
            "description": "Bitcoin price",
        }, headers=h1)
        assert r.status_code == 200

        # Reader reads
        r2 = client.get("/v1/shared-memory/prices/BTC", headers=h2)
        assert r2.status_code == 200
        assert r2.json()["value"] == "50000"

    def test_list_namespace(self):
        _, _, h = register_agent()
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "a", "value": "1"}, headers=h)
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "b", "value": "2"}, headers=h)

        r = client.get("/v1/shared-memory/ns", headers=h)
        assert r.json()["count"] == 2

    def test_list_namespace_with_prefix(self):
        _, _, h = register_agent()
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "foo:1", "value": "a"}, headers=h)
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "foo:2", "value": "b"}, headers=h)
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "bar:1", "value": "c"}, headers=h)

        r = client.get("/v1/shared-memory/ns", params={"prefix": "foo:"}, headers=h)
        assert r.json()["count"] == 2

    def test_delete_own_key(self):
        _, _, h = register_agent()
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "k", "value": "v"}, headers=h)
        r = client.delete("/v1/shared-memory/ns/k", headers=h)
        assert r.status_code == 200

    def test_cannot_delete_other_agents_key(self):
        _, _, h1 = register_agent("owner")
        _, _, h2 = register_agent("intruder")
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "k", "value": "v"}, headers=h1)
        r = client.delete("/v1/shared-memory/ns/k", headers=h2)
        assert r.status_code == 404

    def test_list_namespaces(self):
        _, _, h = register_agent()
        client.post("/v1/shared-memory", json={"namespace": "alpha", "key": "k", "value": "v"}, headers=h)
        client.post("/v1/shared-memory", json={"namespace": "beta", "key": "k", "value": "v"}, headers=h)

        r = client.get("/v1/shared-memory", headers=h)
        assert r.json()["count"] == 2

    def test_update_existing(self):
        _, _, h = register_agent()
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "k", "value": "v1"}, headers=h)
        client.post("/v1/shared-memory", json={"namespace": "ns", "key": "k", "value": "v2"}, headers=h)
        r = client.get("/v1/shared-memory/ns/k", headers=h)
        assert r.json()["value"] == "v2"

    def test_get_not_found(self):
        _, _, h = register_agent()
        assert client.get("/v1/shared-memory/ns/nope", headers=h).status_code == 404

    def test_ttl(self):
        _, _, h = register_agent()
        client.post("/v1/shared-memory", json={
            "namespace": "ns", "key": "k", "value": "v", "ttl_seconds": 60,
        }, headers=h)
        r = client.get("/v1/shared-memory/ns/k", headers=h)
        assert r.json()["expires_at"] is not None


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT DIRECTORY
# ═══════════════════════════════════════════════════════════════════════════════

class TestDirectory:
    def test_update_and_get_profile(self):
        _, _, h = register_agent("mybot")
        r = client.put("/v1/directory/me", json={
            "description": "I summarize articles",
            "capabilities": ["summarize", "translate"],
            "public": True,
        }, headers=h)
        assert r.status_code == 200

        me = client.get("/v1/directory/me", headers=h)
        assert me.json()["description"] == "I summarize articles"
        assert me.json()["capabilities"] == ["summarize", "translate"]
        assert me.json()["public"] is True

    def test_public_listing(self):
        _, _, h1 = register_agent("public-bot")
        _, _, h2 = register_agent("private-bot")

        client.put("/v1/directory/me", json={
            "description": "public",
            "capabilities": ["search"],
            "public": True,
        }, headers=h1)

        client.put("/v1/directory/me", json={
            "description": "private",
            "public": False,
        }, headers=h2)

        # No auth required for directory listing
        r = client.get("/v1/directory")
        assert r.json()["count"] == 1
        assert r.json()["agents"][0]["description"] == "public"

    def test_filter_by_capability(self):
        _, _, h1 = register_agent("bot1")
        _, _, h2 = register_agent("bot2")

        client.put("/v1/directory/me", json={
            "capabilities": ["translate", "summarize"],
            "public": True,
        }, headers=h1)
        client.put("/v1/directory/me", json={
            "capabilities": ["code-review"],
            "public": True,
        }, headers=h2)

        r = client.get("/v1/directory", params={"capability": "translate"})
        assert r.json()["count"] == 1

    def test_empty_directory(self):
        r = client.get("/v1/directory")
        assert r.json()["count"] == 0

    def test_public_agent_profile(self):
        """Test GET /v1/directory/{agent_id} public profile endpoint."""
        agent_id, _, h = register_agent("profile-bot")

        # Update profile to make it public with description
        client.put("/v1/directory/me", json={
            "description": "I am a helpful bot",
            "capabilities": ["nlp", "search"],
            "public": True,
        }, headers=h)

        # Create some marketplace activity
        from main import get_db
        with get_db() as db:
            db.execute(
                "INSERT INTO marketplace (task_id, creator_agent, title, status, claimed_by, delivered_at, created_at) "
                "VALUES (?, ?, ?, 'delivered', ?, ?, ?)",
                ("task_001", agent_id, "Test Task 1", agent_id, "2025-01-15T10:00:00Z", "2025-01-15T09:00:00Z")
            )
            db.execute(
                "INSERT INTO marketplace (task_id, creator_agent, title, status, claimed_by, delivered_at, created_at) "
                "VALUES (?, ?, ?, 'delivered', ?, ?, ?)",
                ("task_002", agent_id, "Test Task 2", agent_id, "2025-01-16T10:00:00Z", "2025-01-16T09:00:00Z")
            )

        # Test public profile access (no auth required)
        r = client.get(f"/v1/directory/{agent_id}")
        assert r.status_code == 200
        data = r.json()

        assert data["agent_id"] == agent_id
        assert data["name"] == "profile-bot"
        assert data["description"] == "I am a helpful bot"
        assert data["capabilities"] == ["nlp", "search"]
        assert data["reputation"] == 0.0
        assert data["credits"] == 200  # Default credits
        assert data["tasks_completed"] == 2
        assert "member_since" in data
        assert len(data["recent_marketplace_activity"]) == 2

    def test_private_agent_profile_404(self):
        """Test that private agents return 404."""
        agent_id, _, h = register_agent("private-bot")

        # Keep agent private (default is public=1, but let's make it private)
        client.put("/v1/directory/me", json={"public": False}, headers=h)

        # Should return 404
        r = client.get(f"/v1/directory/{agent_id}")
        assert r.status_code == 404

    def test_nonexistent_agent_profile_404(self):
        """Test that non-existent agents return 404."""
        r = client.get("/v1/directory/agent_nonexistent")
        assert r.status_code == 404

    def test_leaderboard_default(self):
        """Test GET /v1/leaderboard with default sorting (reputation)."""
        # Register multiple agents with different stats
        id1, _, h1 = register_agent("bot1")
        id2, _, h2 = register_agent("bot2")
        id3, _, h3 = register_agent("bot3")

        # Make all public and set different reputations
        client.put("/v1/directory/me", json={"public": True}, headers=h1)
        client.put("/v1/directory/me", json={"public": True}, headers=h2)
        client.put("/v1/directory/me", json={"public": True}, headers=h3)

        # Update reputations directly
        from main import get_db
        with get_db() as db:
            db.execute("UPDATE agents SET reputation=? WHERE agent_id=?", (5.0, id1))
            db.execute("UPDATE agents SET reputation=? WHERE agent_id=?", (3.5, id2))
            db.execute("UPDATE agents SET reputation=? WHERE agent_id=?", (4.2, id3))
            db.execute("UPDATE agents SET credits=? WHERE agent_id=?", (500, id1))
            db.execute("UPDATE agents SET credits=? WHERE agent_id=?", (1000, id2))

        # Test leaderboard (no auth required)
        r = client.get("/v1/leaderboard")
        assert r.status_code == 200
        data = r.json()

        assert data["total_agents"] == 3
        assert data["sort_by"] == "reputation"
        assert len(data["leaderboard"]) == 3

        # Check order (highest reputation first)
        assert data["leaderboard"][0]["rank"] == 1
        assert data["leaderboard"][0]["agent_id"] == id1
        assert data["leaderboard"][0]["reputation"] == 5.0

        assert data["leaderboard"][1]["rank"] == 2
        assert data["leaderboard"][1]["agent_id"] == id3
        assert data["leaderboard"][1]["reputation"] == 4.2

    def test_leaderboard_sort_by_credits(self):
        """Test leaderboard sorting by credits."""
        id1, _, h1 = register_agent("rich-bot")
        id2, _, h2 = register_agent("poor-bot")

        client.put("/v1/directory/me", json={"public": True}, headers=h1)
        client.put("/v1/directory/me", json={"public": True}, headers=h2)

        from main import get_db
        with get_db() as db:
            db.execute("UPDATE agents SET credits=? WHERE agent_id=?", (10000, id1))
            db.execute("UPDATE agents SET credits=? WHERE agent_id=?", (100, id2))

        r = client.get("/v1/leaderboard?sort_by=credits")
        assert r.status_code == 200
        data = r.json()

        assert data["sort_by"] == "credits"
        assert data["leaderboard"][0]["agent_id"] == id1
        assert data["leaderboard"][0]["credits"] == 10000

    def test_leaderboard_limit(self):
        """Test leaderboard limit parameter."""
        # Register 5 agents
        for i in range(5):
            _, _, h = register_agent(f"bot{i}")
            client.put("/v1/directory/me", json={"public": True}, headers=h)

        r = client.get("/v1/leaderboard?limit=3")
        assert r.status_code == 200
        assert len(r.json()["leaderboard"]) == 3

    def test_leaderboard_only_public_agents(self):
        """Test that leaderboard only shows public agents."""
        id1, _, h1 = register_agent("public")
        id2, _, h2 = register_agent("private")

        client.put("/v1/directory/me", json={"public": True}, headers=h1)
        client.put("/v1/directory/me", json={"public": False}, headers=h2)

        r = client.get("/v1/leaderboard")
        assert r.status_code == 200
        data = r.json()

        assert data["total_agents"] == 1
        assert len(data["leaderboard"]) == 1
        assert data["leaderboard"][0]["agent_id"] == id1

    def test_directory_stats(self):
        """Test GET /v1/directory/stats endpoint."""
        # Register multiple agents with capabilities
        id1, _, h1 = register_agent("bot1")
        id2, _, h2 = register_agent("bot2")
        id3, _, h3 = register_agent("bot3")

        client.put("/v1/directory/me", json={
            "public": True,
            "capabilities": ["nlp", "search"]
        }, headers=h1)

        client.put("/v1/directory/me", json={
            "public": True,
            "capabilities": ["nlp", "translation"]
        }, headers=h2)

        client.put("/v1/directory/me", json={
            "public": False,  # Private agent
            "capabilities": ["coding"]
        }, headers=h3)

        # Send heartbeat to mark one as online
        client.post("/v1/agents/heartbeat", json={"status": "online"}, headers=h1)

        # Add marketplace tasks
        from main import get_db
        with get_db() as db:
            db.execute(
                "INSERT INTO marketplace (task_id, creator_agent, title, status, created_at) "
                "VALUES (?, ?, ?, 'open', ?)",
                ("task_001", id1, "Test Task", "2025-01-15T10:00:00Z")
            )

        # Test stats (no auth required)
        r = client.get("/v1/directory/stats")
        assert r.status_code == 200
        data = r.json()

        assert data["total_agents"] == 2  # Only public agents
        assert data["online_agents"] == 1  # Only one sent heartbeat
        assert "nlp" in data["total_capabilities"]
        assert "search" in data["total_capabilities"]
        assert "translation" in data["total_capabilities"]
        assert "coding" not in data["total_capabilities"]  # Private agent

        # Check top capabilities
        assert len(data["top_capabilities"]) > 0
        nlp_cap = next((c for c in data["top_capabilities"] if c["name"] == "nlp"), None)
        assert nlp_cap is not None
        assert nlp_cap["count"] == 2  # Both public agents have NLP

        assert data["total_marketplace_tasks"] == 1
        assert data["total_credits_distributed"] == 400  # 200 per public agent


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET RELAY
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebSocket:
    def test_ws_missing_api_key(self):
        from starlette.websockets import WebSocketDisconnect as WSDisconnect
        with pytest.raises(WSDisconnect):
            with client.websocket_connect("/v1/relay/ws") as ws:
                pass

    def test_ws_invalid_api_key(self):
        try:
            with client.websocket_connect("/v1/relay/ws?api_key=bad") as ws:
                pass
        except Exception:
            pass  # Expected — invalid key

    def test_ws_send_message(self):
        id1, key1, _ = register_agent("ws-sender")
        id2, key2, _ = register_agent("ws-receiver")

        with client.websocket_connect(f"/v1/relay/ws?api_key={key2}") as ws_recv:
            with client.websocket_connect(f"/v1/relay/ws?api_key={key1}") as ws_send:
                ws_send.send_json({
                    "to_agent": id2,
                    "channel": "direct",
                    "payload": "hello via ws",
                })
                # Sender gets confirmation
                confirm = ws_send.receive_json()
                assert confirm["status"] == "delivered"

            # Receiver gets push
            push = ws_recv.receive_json()
            assert push["event"] == "message.received"
            assert push["payload"] == "hello via ws"
            assert push["from_agent"] == id1

    def test_ws_send_to_invalid_agent(self):
        _, key, _ = register_agent("ws-test")
        with client.websocket_connect(f"/v1/relay/ws?api_key={key}") as ws:
            ws.send_json({"to_agent": "agent_nonexist", "payload": "hi"})
            resp = ws.receive_json()
            assert "error" in resp

    def test_ws_missing_fields(self):
        _, key, _ = register_agent("ws-test")
        with client.websocket_connect(f"/v1/relay/ws?api_key={key}") as ws:
            ws.send_json({"to_agent": "", "payload": ""})
            resp = ws.receive_json()
            assert "error" in resp

    def test_ws_message_persists_in_relay(self):
        """Messages sent via WebSocket should also appear in HTTP inbox."""
        id1, key1, h1 = register_agent("ws-s")
        id2, key2, h2 = register_agent("ws-r")

        with client.websocket_connect(f"/v1/relay/ws?api_key={key1}") as ws:
            ws.send_json({"to_agent": id2, "payload": "persisted"})
            ws.receive_json()  # confirmation

        # Check HTTP inbox
        inbox = client.get("/v1/relay/inbox", headers=h2)
        assert inbox.json()["count"] == 1
        assert inbox.json()["messages"][0]["payload"] == "persisted"


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH & STATS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthAndStats:
    def test_health(self):
        r = client.get("/v1/health")
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "operational"
        assert "active_webhooks" in d["stats"]
        assert "active_schedules" in d["stats"]
        assert "websocket_connections" in d["stats"]

    def test_stats(self):
        _, _, h = register_agent("stat-bot")
        r = client.get("/v1/stats", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "active_webhooks" in d
        assert "active_schedules" in d
        assert "shared_memory_keys" in d

    def test_root(self):
        r = client.get("/")
        assert r.status_code == 200
        d = r.json()
        assert d["version"] == "0.6.0"
        assert "webhooks" in d["endpoints"]
        assert "schedules" in d["endpoints"]
        assert "shared_memory" in d["endpoints"]
        assert "directory" in d["endpoints"]
        assert "relay_ws" in d["endpoints"]
        assert "marketplace" in d["endpoints"]
        assert "testing" in d["endpoints"]
        assert "directory_search" in d["endpoints"]
        assert "directory_match" in d["endpoints"]


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

class TestRateLimiting:
    def test_rate_limit_enforcement(self):
        """After exceeding the limit, requests should return 429."""
        _, _, h = register_agent()
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        # Artificially set high count
        window = int(time.time()) // 60
        aid = client.get("/v1/stats", headers=h).json()["agent_id"]
        conn.execute(
            "INSERT OR REPLACE INTO rate_limits (agent_id, window_start, count) VALUES (?, ?, ?)",
            (aid, window, 999)
        )
        conn.commit()
        conn.close()

        r = client.get("/v1/memory", headers=h)
        assert r.status_code == 429


# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnhancedDiscovery:
    def test_search_no_filters(self):
        _, _, h = register_agent()
        client.put("/v1/directory/me", json={"description": "bot", "capabilities": ["test"], "public": True}, headers=h)
        r = client.get("/v1/directory/search")
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_search_by_capability(self):
        _, _, h = register_agent()
        client.put("/v1/directory/me", json={"description": "nlp bot", "capabilities": ["nlp", "sentiment"], "public": True}, headers=h)
        r = client.get("/v1/directory/search?capability=nlp")
        assert r.status_code == 200
        assert r.json()["count"] >= 1
        assert any("nlp" in a["capabilities"] for a in r.json()["agents"])

    def test_search_by_availability(self):
        _, _, h = register_agent()
        client.put("/v1/directory/me", json={"description": "bot", "capabilities": ["avail"], "public": True}, headers=h)
        r = client.get("/v1/directory/search?available=true")
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_search_by_min_reputation(self):
        r = client.get("/v1/directory/search?min_reputation=5.0")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_status_update_available(self):
        _, _, h = register_agent()
        r = client.patch("/v1/directory/me/status", json={"available": False}, headers=h)
        assert r.status_code == 200
        profile = client.get("/v1/directory/me", headers=h).json()
        assert profile["available"] is False

    def test_status_update_looking_for(self):
        _, _, h = register_agent()
        r = client.patch("/v1/directory/me/status", json={"looking_for": ["nlp", "scraping"]}, headers=h)
        assert r.status_code == 200
        profile = client.get("/v1/directory/me", headers=h).json()
        assert "nlp" in profile["looking_for"]

    def test_status_update_busy_until(self):
        _, _, h = register_agent()
        r = client.patch("/v1/directory/me/status", json={"busy_until": "2099-01-01T00:00:00+00:00"}, headers=h)
        assert r.status_code == 200
        profile = client.get("/v1/directory/me", headers=h).json()
        assert profile["available"] is False

    def test_log_collaboration(self):
        aid1, _, h1 = register_agent("agent-a")
        aid2, _, h2 = register_agent("agent-b")
        r = client.post("/v1/directory/collaborations", json={
            "partner_agent": aid2, "task_type": "sentiment_analysis", "outcome": "success", "rating": 5
        }, headers=h1)
        assert r.status_code == 200
        assert r.json()["partner_new_reputation"] == 5.0

    def test_collaboration_updates_reputation(self):
        aid1, _, h1 = register_agent()
        aid2, _, h2 = register_agent()
        client.post("/v1/directory/collaborations", json={"partner_agent": aid2, "outcome": "success", "rating": 4}, headers=h1)
        client.post("/v1/directory/collaborations", json={"partner_agent": aid2, "outcome": "success", "rating": 2}, headers=h1)
        profile = client.get("/v1/directory/me", headers=h2).json()
        assert profile["reputation"] == 3.0

    def test_collaboration_self_denied(self):
        aid1, _, h1 = register_agent()
        r = client.post("/v1/directory/collaborations", json={"partner_agent": aid1, "outcome": "success", "rating": 5}, headers=h1)
        assert r.status_code == 400

    def test_collaboration_bad_outcome(self):
        aid1, _, h1 = register_agent()
        aid2, _, h2 = register_agent()
        r = client.post("/v1/directory/collaborations", json={"partner_agent": aid2, "outcome": "invalid", "rating": 5}, headers=h1)
        assert r.status_code == 400

    def test_collaboration_bad_partner(self):
        _, _, h = register_agent()
        r = client.post("/v1/directory/collaborations", json={"partner_agent": "agent_nonexistent", "outcome": "success", "rating": 5}, headers=h)
        assert r.status_code == 404

    def test_match_basic(self):
        aid1, _, h1 = register_agent()
        aid2, _, h2 = register_agent()
        client.put("/v1/directory/me", json={"description": "matcher", "capabilities": ["sentiment_analysis"], "public": True}, headers=h2)
        r = client.get("/v1/directory/match?need=sentiment_analysis", headers=h1)
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_match_excludes_self(self):
        _, _, h = register_agent()
        client.put("/v1/directory/me", json={"capabilities": ["unique_cap"], "public": True}, headers=h)
        r = client.get("/v1/directory/match?need=unique_cap", headers=h)
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_directory_me_new_fields(self):
        _, _, h = register_agent()
        profile = client.get("/v1/directory/me", headers=h).json()
        assert "reputation" in profile
        assert "credits" in profile
        assert "available" in profile
        assert "looking_for" in profile

    def test_stats_new_fields(self):
        _, _, h = register_agent()
        stats = client.get("/v1/stats", headers=h).json()
        assert "credits" in stats
        assert "reputation" in stats
        assert "collaborations_given" in stats
        assert "marketplace_tasks_created" in stats


# ═══════════════════════════════════════════════════════════════════════════════
# TASK MARKETPLACE
# ═══════════════════════════════════════════════════════════════════════════════

class TestMarketplace:
    def test_create_task(self):
        _, _, h = register_agent()
        r = client.post("/v1/marketplace/tasks", json={
            "title": "Analyze tweets", "category": "nlp", "requirements": ["sentiment"],
            "reward_credits": 50, "priority": 5,
        }, headers=h)
        assert r.status_code == 200
        assert r.json()["status"] == "open"

    def test_browse_tasks(self):
        _, _, h = register_agent()
        client.post("/v1/marketplace/tasks", json={"title": "Task A", "category": "test"}, headers=h)
        r = client.get("/v1/marketplace/tasks?status=open")
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_browse_filter_category(self):
        _, _, h = register_agent()
        client.post("/v1/marketplace/tasks", json={"title": "Cat task", "category": "unique_cat"}, headers=h)
        r = client.get("/v1/marketplace/tasks?category=unique_cat")
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_get_task_detail(self):
        _, _, h = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Detail test"}, headers=h).json()
        r = client.get(f"/v1/marketplace/tasks/{task['task_id']}")
        assert r.status_code == 200
        assert r.json()["title"] == "Detail test"

    def test_get_task_not_found(self):
        r = client.get("/v1/marketplace/tasks/mktask_nonexistent")
        assert r.status_code == 404

    def test_claim_task(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Claim test"}, headers=h1).json()
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        assert r.status_code == 200
        assert r.json()["status"] == "claimed"

    def test_claim_own_task_denied(self):
        _, _, h = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Self claim"}, headers=h).json()
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h)
        assert r.status_code == 400

    def test_claim_already_claimed(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        _, _, h3 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Double claim"}, headers=h1).json()
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h3)
        assert r.status_code == 409

    def test_deliver_result(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Deliver test"}, headers=h1).json()
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/deliver", json={"result": "done!"}, headers=h2)
        assert r.status_code == 200
        assert r.json()["status"] == "delivered"

    def test_deliver_wrong_agent(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        _, _, h3 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Wrong deliver"}, headers=h1).json()
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/deliver", json={"result": "nope"}, headers=h3)
        assert r.status_code == 403

    def test_review_accept_awards_credits(self):
        _, _, h1 = register_agent()
        aid2, _, h2 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Review test", "reward_credits": 100}, headers=h1).json()
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/deliver", json={"result": "output"}, headers=h2)
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/review", json={"accept": True, "rating": 5}, headers=h1)
        assert r.status_code == 200
        assert r.json()["status"] == "completed"
        assert r.json()["credits_awarded"] == 100
        stats = client.get("/v1/stats", headers=h2).json()
        assert stats["credits"] == 300  # 200 starting + 100 reward

    def test_review_reject_reopens(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Reject test"}, headers=h1).json()
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/deliver", json={"result": "bad"}, headers=h2)
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/review", json={"accept": False}, headers=h1)
        assert r.status_code == 200
        assert r.json()["status"] == "open"
        detail = client.get(f"/v1/marketplace/tasks/{task['task_id']}").json()
        assert detail["status"] == "open"
        assert detail["claimed_by"] is None

    def test_review_wrong_agent(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Wrong review"}, headers=h1).json()
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/deliver", json={"result": "out"}, headers=h2)
        r = client.post(f"/v1/marketplace/tasks/{task['task_id']}/review", json={"accept": True}, headers=h2)
        assert r.status_code == 403

    def test_credits_in_profile(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        task = client.post("/v1/marketplace/tasks", json={"title": "Credits test", "reward_credits": 25}, headers=h1).json()
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/claim", headers=h2)
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/deliver", json={"result": "ok"}, headers=h2)
        client.post(f"/v1/marketplace/tasks/{task['task_id']}/review", json={"accept": True, "rating": 4}, headers=h1)
        profile = client.get("/v1/directory/me", headers=h2).json()
        assert profile["credits"] == 225  # 200 starting + 25 reward


# ═══════════════════════════════════════════════════════════════════════════════
# COORDINATION TESTING
# ═══════════════════════════════════════════════════════════════════════════════

class TestCoordinationTesting:
    def test_create_scenario(self):
        _, _, h = register_agent()
        r = client.post("/v1/testing/scenarios", json={
            "name": "test_election", "pattern": "leader_election", "agent_count": 5
        }, headers=h)
        assert r.status_code == 200
        assert r.json()["status"] == "created"

    def test_create_invalid_pattern(self):
        _, _, h = register_agent()
        r = client.post("/v1/testing/scenarios", json={"pattern": "invalid", "agent_count": 3}, headers=h)
        assert r.status_code == 400

    def test_list_scenarios(self):
        _, _, h = register_agent()
        client.post("/v1/testing/scenarios", json={"pattern": "consensus", "agent_count": 3}, headers=h)
        r = client.get("/v1/testing/scenarios", headers=h)
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_run_leader_election(self):
        _, _, h = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "leader_election", "agent_count": 5}, headers=h).json()
        r = client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        assert r.status_code == 200
        assert r.json()["status"] in ("completed", "failed")
        assert "elected_leader" in r.json()["results"]

    def test_run_consensus(self):
        _, _, h = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "consensus", "agent_count": 4}, headers=h).json()
        r = client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        assert r.status_code == 200
        assert "agreement_reached" in r.json()["results"]

    def test_run_load_balancing(self):
        _, _, h = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "load_balancing", "agent_count": 4}, headers=h).json()
        r = client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        assert r.status_code == 200
        assert r.json()["results"]["balance_score"] == 1.0

    def test_run_pub_sub_fanout(self):
        _, _, h = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "pub_sub_fanout", "agent_count": 5}, headers=h).json()
        r = client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        assert r.status_code == 200
        assert r.json()["results"]["delivery_rate"] > 0.9

    def test_run_task_auction(self):
        _, _, h = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "task_auction", "agent_count": 6}, headers=h).json()
        r = client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        assert r.status_code == 200
        assert r.json()["results"]["tasks_auctioned"] == 5

    def test_get_results(self):
        _, _, h = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "consensus", "agent_count": 3}, headers=h).json()
        client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        r = client.get(f"/v1/testing/scenarios/{s['scenario_id']}/results", headers=h)
        assert r.status_code == 200
        assert r.json()["results"] is not None

    def test_run_not_found(self):
        _, _, h = register_agent()
        r = client.post("/v1/testing/scenarios/scenario_nonexistent/run", headers=h)
        assert r.status_code == 404

    def test_run_not_owner(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "consensus", "agent_count": 3}, headers=h1).json()
        r = client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h2)
        assert r.status_code == 403

    def test_rerun_completed(self):
        _, _, h = register_agent()
        s = client.post("/v1/testing/scenarios", json={"pattern": "leader_election", "agent_count": 3}, headers=h).json()
        client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        r = client.post(f"/v1/testing/scenarios/{s['scenario_id']}/run", headers=h)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# DEAD-LETTER QUEUE
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeadLetterQueue:
    def test_submit_with_max_attempts(self):
        """Submit a job with max_attempts=3 and verify it's stored correctly."""
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={
            "payload": "retry-job", "max_attempts": 3, "retry_delay_seconds": 10,
        }, headers=h)
        assert r.status_code == 200
        assert r.json()["max_attempts"] == 3
        job_id = r.json()["job_id"]
        status = client.get(f"/v1/queue/{job_id}", headers=h)
        assert status.json()["status"] == "pending"

    def test_fail_and_retry(self):
        """Submit with max_attempts=3, claim, fail — verify attempt increments and job retries."""
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={
            "payload": "will-retry", "max_attempts": 3, "retry_delay_seconds": 0,
        }, headers=h)
        job_id = r.json()["job_id"]

        # Claim and fail (1st attempt)
        client.post("/v1/queue/claim", headers=h)
        fail_r = client.post(f"/v1/queue/{job_id}/fail", json={"reason": "error 1"}, headers=h)
        assert fail_r.status_code == 200
        d = fail_r.json()
        assert d["status"] == "pending_retry"
        assert d["attempts"] == 1
        assert d["max_attempts"] == 3

    def test_fail_moves_to_dead_letter(self):
        """Submit with max_attempts=1, claim, fail — verify job moves to dead_letter."""
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={
            "payload": "one-shot", "max_attempts": 1,
        }, headers=h)
        job_id = r.json()["job_id"]

        client.post("/v1/queue/claim", headers=h)
        fail_r = client.post(f"/v1/queue/{job_id}/fail", json={"reason": "fatal"}, headers=h)
        assert fail_r.status_code == 200
        assert fail_r.json()["status"] == "dead_lettered"

    def test_dead_letter_list(self):
        """Fail a job, then GET /v1/queue/dead_letter and verify it appears."""
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={
            "payload": "dlq-list-test", "max_attempts": 1,
        }, headers=h)
        job_id = r.json()["job_id"]

        client.post("/v1/queue/claim", headers=h)
        client.post(f"/v1/queue/{job_id}/fail", json={"reason": "dead"}, headers=h)

        dlq = client.get("/v1/queue/dead_letter", headers=h)
        assert dlq.status_code == 200
        jobs = dlq.json()["jobs"]
        assert len(jobs) == 1
        assert jobs[0]["job_id"] == job_id
        assert jobs[0]["fail_reason"] == "dead"

    def test_replay_from_dead_letter(self):
        """Fail a job to dead_letter, replay it, verify it's back as pending."""
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={
            "payload": "replay-me", "max_attempts": 1,
        }, headers=h)
        job_id = r.json()["job_id"]

        client.post("/v1/queue/claim", headers=h)
        client.post(f"/v1/queue/{job_id}/fail", json={"reason": "oops"}, headers=h)

        # Verify it's in dead letter
        dlq = client.get("/v1/queue/dead_letter", headers=h)
        assert dlq.json()["count"] == 1

        # Replay
        replay_r = client.post(f"/v1/queue/{job_id}/replay", headers=h)
        assert replay_r.status_code == 200
        assert replay_r.json()["status"] == "pending"

        # Dead letter should be empty now
        dlq2 = client.get("/v1/queue/dead_letter", headers=h)
        assert dlq2.json()["count"] == 0

        # Job should be back in active queue
        status = client.get(f"/v1/queue/{job_id}", headers=h)
        assert status.json()["status"] == "pending"

    def test_fail_fires_webhook(self):
        """Register webhook for job.failed, fail a job past max_attempts, verify webhook fires."""
        _, _, h = register_agent()
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["job.failed"],
        }, headers=h)

        r = client.post("/v1/queue/submit", json={
            "payload": "webhook-fail", "max_attempts": 1,
        }, headers=h)
        job_id = r.json()["job_id"]
        client.post("/v1/queue/claim", headers=h)

        with patch("main.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            client.post(f"/v1/queue/{job_id}/fail", json={"reason": "boom"}, headers=h)
            assert mock_thread.called

    def test_claim_skips_retry_delay(self):
        """Submit with long retry_delay, claim+fail, verify next claim is empty (job is waiting)."""
        _, _, h = register_agent()
        r = client.post("/v1/queue/submit", json={
            "payload": "delayed-retry", "max_attempts": 3, "retry_delay_seconds": 3600,
            "queue_name": "delay-test",
        }, headers=h)
        job_id = r.json()["job_id"]

        # Claim and fail — sets next_retry_at far in the future
        client.post("/v1/queue/claim", params={"queue_name": "delay-test"}, headers=h)
        client.post(f"/v1/queue/{job_id}/fail", json={"reason": "wait"}, headers=h)

        # Next claim should find nothing (job is waiting for retry)
        claim2 = client.post("/v1/queue/claim", params={"queue_name": "delay-test"}, headers=h)
        assert claim2.json()["status"] == "empty"


# ═══════════════════════════════════════════════════════════════════════════════
# HEARTBEAT / LIVENESS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHeartbeat:
    def test_heartbeat_basic(self):
        """Send heartbeat and verify response structure."""
        aid, _, h = register_agent()
        r = client.post("/v1/agents/heartbeat", json={"status": "online"}, headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["agent_id"] == aid
        assert d["status"] == "online"
        assert "heartbeat_at" in d

    def test_heartbeat_updates_agent(self):
        """Send heartbeat, check /v1/directory/me shows updated fields."""
        _, _, h = register_agent()
        client.post("/v1/agents/heartbeat", json={"status": "busy", "metadata": {"load": 0.8}}, headers=h)
        me = client.get("/v1/directory/me", headers=h).json()
        assert me["heartbeat_status"] == "busy"
        assert me["heartbeat_at"] is not None
        assert me["heartbeat_interval"] == 60

    def test_search_online_filter(self):
        """Two agents: one sends heartbeat, search online=true returns only it."""
        _, _, h1 = register_agent("online-bot")
        _, _, h2 = register_agent("silent-bot")

        # Make both public
        client.put("/v1/directory/me", json={"description": "a", "public": True}, headers=h1)
        client.put("/v1/directory/me", json={"description": "b", "public": True}, headers=h2)

        # Only first agent sends heartbeat
        client.post("/v1/agents/heartbeat", json={"status": "online"}, headers=h1)

        r = client.get("/v1/directory/search", params={"online": True})
        assert r.status_code == 200
        agents = r.json()["agents"]
        assert len(agents) == 1
        assert agents[0]["heartbeat_status"] == "online"

    def test_offline_detection(self):
        """Set heartbeat_at to far past, run liveness check, verify status becomes offline."""
        import sqlite3
        aid, _, h = register_agent()

        # Send a heartbeat first to set status to online
        client.post("/v1/agents/heartbeat", json={"status": "online"}, headers=h)
        me = client.get("/v1/directory/me", headers=h).json()
        assert me["heartbeat_status"] == "online"

        # Manually set heartbeat_at to far in the past (beyond 2x interval)
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE agents SET heartbeat_at = '2000-01-01T00:00:00+00:00' WHERE agent_id = ?",
            (aid,)
        )
        conn.commit()
        conn.close()

        # Run the liveness check
        _run_liveness_check()

        # Agent should now be offline
        me2 = client.get("/v1/directory/me", headers=h).json()
        assert me2["heartbeat_status"] == "offline"


# ═══════════════════════════════════════════════════════════════════════════════
# USER AUTH & DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

class TestUserAuth:
    """Tests for user accounts, JWT auth, dashboard endpoints, and tier enforcement."""

    def _signup(self, email="user@example.com", password="securepass123", display_name="Test"):
        r = client.post("/v1/auth/signup", json={
            "email": email, "password": password, "display_name": display_name,
        })
        return r

    def _auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_signup(self):
        r = self._signup()
        assert r.status_code == 200
        d = r.json()
        assert d["user_id"].startswith("user_")
        assert "token" in d
        assert d["message"] == "Account created"

    def test_signup_duplicate_email(self):
        self._signup(email="dup@example.com")
        r = self._signup(email="dup@example.com")
        assert r.status_code == 409

    def test_signup_weak_password(self):
        r = self._signup(password="short")
        assert r.status_code == 422  # Pydantic min_length=6

    def test_login(self):
        self._signup(email="login@example.com", password="goodpass123")
        r = client.post("/v1/auth/login", json={
            "email": "login@example.com", "password": "goodpass123",
        })
        assert r.status_code == 200
        d = r.json()
        assert "token" in d
        # Verify token works on /auth/me
        me = client.get("/v1/auth/me", headers=self._auth_header(d["token"]))
        assert me.status_code == 200
        assert me.json()["email"] == "login@example.com"

    def test_login_wrong_password(self):
        self._signup(email="wp@example.com", password="correctpass")
        r = client.post("/v1/auth/login", json={
            "email": "wp@example.com", "password": "wrongpass",
        })
        assert r.status_code == 401

    def test_login_nonexistent(self):
        r = client.post("/v1/auth/login", json={
            "email": "nobody@example.com", "password": "whatever",
        })
        assert r.status_code == 401

    def test_me(self):
        r = self._signup(email="me@example.com", display_name="MeUser")
        token = r.json()["token"]
        me = client.get("/v1/auth/me", headers=self._auth_header(token))
        assert me.status_code == 200
        d = me.json()
        assert d["email"] == "me@example.com"
        assert d["display_name"] == "MeUser"
        assert d["subscription_tier"] == "free"
        assert d["agent_count"] == 0

    def test_me_expired_token(self):
        import jwt as pyjwt
        from main import JWT_SECRET, JWT_ALGORITHM
        from datetime import timedelta
        expired = pyjwt.encode({
            "user_id": "user_fake",
            "email": "x@x.com",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        r = client.get("/v1/auth/me", headers=self._auth_header(expired))
        assert r.status_code == 401

    def test_register_agent_with_user(self):
        r = self._signup(email="owner@example.com")
        token = r.json()["token"]
        user_id = r.json()["user_id"]
        reg = client.post("/v1/register", json={"name": "owned-bot"},
                          headers=self._auth_header(token))
        assert reg.status_code == 200
        agent_id = reg.json()["agent_id"]
        # Verify ownership via /v1/user/agents
        agents = client.get("/v1/user/agents", headers=self._auth_header(token))
        assert agents.status_code == 200
        ids = [a["agent_id"] for a in agents.json()["agents"]]
        assert agent_id in ids

    def test_register_agent_without_user(self):
        r = client.post("/v1/register", json={"name": "no-owner"})
        assert r.status_code == 200
        assert r.json()["agent_id"].startswith("agent_")

    def test_user_agents_list(self):
        r = self._signup(email="list@example.com")
        token = r.json()["token"]
        # Bump max_agents to allow 2
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET max_agents = 5 WHERE user_id = ?", (r.json()["user_id"],))
        conn.commit()
        conn.close()
        # Register 2 agents
        client.post("/v1/register", json={"name": "bot1"}, headers=self._auth_header(token))
        client.post("/v1/register", json={"name": "bot2"}, headers=self._auth_header(token))
        agents = client.get("/v1/user/agents", headers=self._auth_header(token))
        assert agents.status_code == 200
        assert agents.json()["count"] == 2

    def test_user_agents_isolation(self):
        r_a = self._signup(email="a@example.com")
        r_b = self._signup(email="b@example.com")
        token_a = r_a.json()["token"]
        token_b = r_b.json()["token"]
        # User A registers an agent
        client.post("/v1/register", json={"name": "a-bot"}, headers=self._auth_header(token_a))
        # User B should see 0 agents
        agents_b = client.get("/v1/user/agents", headers=self._auth_header(token_b))
        assert agents_b.json()["count"] == 0
        # User A should see 1
        agents_a = client.get("/v1/user/agents", headers=self._auth_header(token_a))
        assert agents_a.json()["count"] == 1

    def test_agent_limit_enforcement(self):
        r = self._signup(email="limit@example.com")
        token = r.json()["token"]
        # First agent should succeed (free tier allows 1)
        r1 = client.post("/v1/register", json={"name": "first"}, headers=self._auth_header(token))
        assert r1.status_code == 200
        # Second agent should fail
        r2 = client.post("/v1/register", json={"name": "second"}, headers=self._auth_header(token))
        assert r2.status_code == 403
        assert "Agent limit" in r2.json()["detail"]

    def test_usage_quota(self):
        r = self._signup(email="quota@example.com")
        token = r.json()["token"]
        user_id = r.json()["user_id"]
        # Register an agent under this user
        reg = client.post("/v1/register", json={"name": "quota-bot"}, headers=self._auth_header(token))
        api_key = reg.json()["api_key"]
        agent_headers = {"X-API-Key": api_key}
        # Set usage_count to max_api_calls - 1 (free = 10000)
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET usage_count = 9999 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        # This request should succeed (9999 -> increments to 10000)
        r1 = client.get("/v1/memory", headers=agent_headers)
        assert r1.status_code == 200
        # Next request should be blocked (usage_count >= 10000)
        r2 = client.get("/v1/memory", headers=agent_headers)
        assert r2.status_code == 429
        assert "quota" in r2.json()["detail"].lower()



# ═══════════════════════════════════════════════════════════════════════════════
# BILLING & PRICING
# ═══════════════════════════════════════════════════════════════════════════════

class TestBilling:
    """Tests for pricing, billing endpoints, and Stripe webhook."""

    def test_pricing_public(self):
        r = client.get("/v1/pricing")
        assert r.status_code == 200
        d = r.json()
        assert d["currency"] == "usd"
        assert d["billing_period"] == "monthly"
        assert len(d["tiers"]) == 4
        names = [t["name"] for t in d["tiers"]]
        assert names == ["free", "hobby", "team", "scale"]
        # Verify free tier details
        free = d["tiers"][0]
        assert free["price"] == 0
        assert free["agents"] == 1
        assert free["api_calls"] == 10000

    def test_checkout_requires_auth(self):
        r = client.post("/v1/billing/checkout", json={"tier": "hobby"})
        assert r.status_code == 401

    def test_checkout_invalid_tier(self):
        # Signup to get a token
        s = client.post("/v1/auth/signup", json={
            "email": "checkout@example.com", "password": "securepass123",
        })
        token = s.json()["token"]
        r = client.post("/v1/billing/checkout", json={"tier": "invalid"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400
        assert "Invalid tier" in r.json()["detail"]

    def test_billing_status_requires_auth(self):
        r = client.get("/v1/billing/status")
        assert r.status_code == 401

    def test_stripe_webhook_bad_payload(self):
        r = client.post("/v1/stripe/webhook", content=b"not json",
                        headers={"Content-Type": "application/json"})
        assert r.status_code == 400

    def test_user_starts_free(self):
        s = client.post("/v1/auth/signup", json={
            "email": "freetier@example.com", "password": "securepass123",
        })
        assert s.status_code == 200
        token = s.json()["token"]
        me = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        d = me.json()
        assert d["subscription_tier"] == "free"
        assert d["max_agents"] == 1
        assert d["max_api_calls"] == 10000


# ═══════════════════════════════════════════════════════════════════════════════
# VECTOR / SEMANTIC MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

class TestVectorMemory:
    def test_vector_upsert_and_search(self):
        """Test storing docs and semantic search - most relevant should be first."""
        _, _, h = register_agent("vector-bot")

        # Store 3 documents about different topics
        client.post("/v1/vector/upsert", json={
            "key": "doc1",
            "text": "Python is a programming language for data science and machine learning",
        }, headers=h)

        client.post("/v1/vector/upsert", json={
            "key": "doc2",
            "text": "Dogs are loyal pets that love to play fetch and go for walks",
        }, headers=h)

        client.post("/v1/vector/upsert", json={
            "key": "doc3",
            "text": "Machine learning models require training data and computational resources",
        }, headers=h)

        # Search for programming-related content
        r = client.post("/v1/vector/search", json={
            "query": "artificial intelligence and deep learning",
            "limit": 3
        }, headers=h)

        assert r.status_code == 200
        data = r.json()
        assert len(data["results"]) == 3

        # Most relevant should be doc3 or doc1 (ML-related), not doc2 (dogs)
        top_result = data["results"][0]
        assert top_result["key"] in ["doc3", "doc1"]
        assert top_result["similarity"] > 0.3  # Should have decent similarity

        # Verify doc2 (dogs) has lowest similarity
        last_result = data["results"][-1]
        assert last_result["key"] == "doc2"

    def test_vector_namespaces(self):
        """Test that different namespaces are isolated."""
        _, _, h = register_agent("ns-bot")

        # Store in different namespaces
        client.post("/v1/vector/upsert", json={
            "key": "shared_key",
            "text": "Content in default namespace",
            "namespace": "default"
        }, headers=h)

        client.post("/v1/vector/upsert", json={
            "key": "shared_key",
            "text": "Content in work namespace",
            "namespace": "work"
        }, headers=h)

        # Search in default namespace
        r1 = client.post("/v1/vector/search", json={
            "query": "content",
            "namespace": "default"
        }, headers=h)
        assert r1.json()["results"][0]["text"] == "Content in default namespace"

        # Search in work namespace
        r2 = client.post("/v1/vector/search", json={
            "query": "content",
            "namespace": "work"
        }, headers=h)
        assert r2.json()["results"][0]["text"] == "Content in work namespace"

    def test_vector_delete(self):
        """Test deleting vector entries."""
        _, _, h = register_agent("del-bot")

        # Create entry
        client.post("/v1/vector/upsert", json={
            "key": "temp",
            "text": "Temporary content"
        }, headers=h)

        # Verify it exists
        r = client.get("/v1/vector/temp", headers=h)
        assert r.status_code == 200

        # Delete it
        d = client.delete("/v1/vector/temp", headers=h)
        assert d.status_code == 200

        # Verify it's gone
        r2 = client.get("/v1/vector/temp", headers=h)
        assert r2.status_code == 404

    def test_vector_update(self):
        """Test that upserting same key updates the embedding."""
        _, _, h = register_agent("update-bot")

        # Initial upsert
        client.post("/v1/vector/upsert", json={
            "key": "evolving",
            "text": "Initial content about cats"
        }, headers=h)

        # Search for cats - should find it
        r1 = client.post("/v1/vector/search", json={
            "query": "feline animals",
            "min_similarity": 0.2
        }, headers=h)
        assert len(r1.json()["results"]) == 1

        # Update with completely different content
        client.post("/v1/vector/upsert", json={
            "key": "evolving",
            "text": "Updated content about programming languages"
        }, headers=h)

        # Search for programming - should find the updated version
        r2 = client.post("/v1/vector/search", json={
            "query": "software development",
            "min_similarity": 0.2
        }, headers=h)
        assert len(r2.json()["results"]) == 1
        assert r2.json()["results"][0]["key"] == "evolving"
        assert "programming" in r2.json()["results"][0]["text"]

    def test_vector_list(self):
        """Test listing vector keys."""
        _, _, h = register_agent("list-bot")

        # Create multiple entries
        for i in range(5):
            client.post("/v1/vector/upsert", json={
                "key": f"item{i}",
                "text": f"Content {i}"
            }, headers=h)

        # List all
        r = client.get("/v1/vector", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 5
        assert len(data["keys"]) == 5

    def test_vector_metadata(self):
        """Test storing and retrieving metadata."""
        _, _, h = register_agent("meta-bot")

        # Store with metadata
        client.post("/v1/vector/upsert", json={
            "key": "doc_with_meta",
            "text": "Content with metadata",
            "metadata": {"author": "Alice", "category": "tech", "rating": 5}
        }, headers=h)

        # Search and verify metadata is returned
        r = client.post("/v1/vector/search", json={"query": "content"}, headers=h)
        result = r.json()["results"][0]
        assert result["metadata"]["author"] == "Alice"
        assert result["metadata"]["rating"] == 5

    def test_vector_min_similarity_filter(self):
        """Test min_similarity threshold filtering."""
        _, _, h = register_agent("sim-bot")

        # Store unrelated documents
        client.post("/v1/vector/upsert", json={
            "key": "tech",
            "text": "Machine learning and artificial intelligence"
        }, headers=h)

        client.post("/v1/vector/upsert", json={
            "key": "food",
            "text": "Pizza and pasta recipes from Italy"
        }, headers=h)

        # Search with high min_similarity - should filter out food
        r = client.post("/v1/vector/search", json={
            "query": "deep learning neural networks",
            "min_similarity": 0.4
        }, headers=h)

        # Should only return tech doc (or none if threshold too high)
        results = r.json()["results"]
        if len(results) > 0:
            assert results[0]["key"] == "tech"


# ═══════════════════════════════════════════════════════════════════════════════
# CONVERSATION SESSIONS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSessions:
    def test_create_session(self):
        _, _, h = register_agent("session-bot")
        r = client.post("/v1/sessions", json={"title": "Test Session"}, headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["session_id"].startswith("sess_")
        assert d["title"] == "Test Session"
        assert "created_at" in d

    def test_create_session_defaults(self):
        _, _, h = register_agent("session-bot")
        r = client.post("/v1/sessions", json={}, headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["session_id"].startswith("sess_")
        assert d["title"].startswith("Session ")

    def test_list_sessions(self):
        _, _, h = register_agent("session-bot")
        client.post("/v1/sessions", json={"title": "S1"}, headers=h)
        client.post("/v1/sessions", json={"title": "S2"}, headers=h)
        r = client.get("/v1/sessions", headers=h)
        assert r.status_code == 200
        sessions = r.json()["sessions"]
        assert len(sessions) == 2

    def test_get_session(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={"title": "Get Me"}, headers=h).json()["session_id"]
        r = client.get(f"/v1/sessions/{sid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["session_id"] == sid
        assert d["title"] == "Get Me"
        assert d["messages"] == []
        assert d["token_count"] == 0
        assert d["max_tokens"] == 128000

    def test_get_session_not_found(self):
        _, _, h = register_agent("session-bot")
        r = client.get("/v1/sessions/sess_nonexistent", headers=h)
        assert r.status_code == 404

    def test_append_message(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={}, headers=h).json()["session_id"]
        r = client.post(f"/v1/sessions/{sid}/messages", json={"role": "user", "content": "Hello!"}, headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "appended"
        assert d["message_count"] == 1
        assert d["token_count"] > 0
        assert d["summarized"] is False

    def test_append_multiple_roles(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={}, headers=h).json()["session_id"]
        client.post(f"/v1/sessions/{sid}/messages", json={"role": "system", "content": "You are a helper."}, headers=h)
        client.post(f"/v1/sessions/{sid}/messages", json={"role": "user", "content": "Hi"}, headers=h)
        client.post(f"/v1/sessions/{sid}/messages", json={"role": "assistant", "content": "Hello!"}, headers=h)

        r = client.get(f"/v1/sessions/{sid}", headers=h)
        msgs = r.json()["messages"]
        assert len(msgs) == 3
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        assert msgs[2]["role"] == "assistant"

    def test_append_invalid_role(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={}, headers=h).json()["session_id"]
        r = client.post(f"/v1/sessions/{sid}/messages", json={"role": "admin", "content": "Hi"}, headers=h)
        assert r.status_code == 422

    def test_auto_summarize_on_overflow(self):
        _, _, h = register_agent("session-bot")
        # Create session with very low max_tokens to trigger summarization
        sid = client.post("/v1/sessions", json={"title": "Small", "max_tokens": 1000}, headers=h).json()["session_id"]

        # Add enough messages to exceed 90% of 1000 tokens
        for i in range(20):
            client.post(f"/v1/sessions/{sid}/messages", json={
                "role": "user" if i % 2 == 0 else "assistant",
                "content": f"Message number {i}. " + "x" * 200,
            }, headers=h)

        # Check that summarization happened
        r = client.get(f"/v1/sessions/{sid}", headers=h)
        d = r.json()
        msgs = d["messages"]
        # After summarization, should have system summary + last 10
        assert len(msgs) <= 12  # system msgs + summary + 10 recent
        # Should contain a summary message
        has_summary = any("Summary of previous conversation" in m.get("content", "") for m in msgs)
        assert has_summary

    def test_force_summarize(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={}, headers=h).json()["session_id"]

        # Add 15 messages
        for i in range(15):
            client.post(f"/v1/sessions/{sid}/messages", json={
                "role": "user" if i % 2 == 0 else "assistant",
                "content": f"Turn {i}: Some conversation content here.",
            }, headers=h)

        r = client.post(f"/v1/sessions/{sid}/summarize", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "summarized"
        assert d["original_message_count"] == 15
        assert d["new_message_count"] < 15
        assert d["token_count"] > 0

        # Verify the session now has summary + recent messages
        r2 = client.get(f"/v1/sessions/{sid}", headers=h)
        msgs = r2.json()["messages"]
        has_summary = any("Summary of previous conversation" in m.get("content", "") for m in msgs)
        assert has_summary

    def test_summarize_not_found(self):
        _, _, h = register_agent("session-bot")
        r = client.post("/v1/sessions/sess_nonexistent/summarize", headers=h)
        assert r.status_code == 404

    def test_delete_session(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={"title": "Delete Me"}, headers=h).json()["session_id"]
        r = client.delete(f"/v1/sessions/{sid}", headers=h)
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

        # Verify it's gone
        r2 = client.get(f"/v1/sessions/{sid}", headers=h)
        assert r2.status_code == 404

    def test_delete_session_not_found(self):
        _, _, h = register_agent("session-bot")
        r = client.delete("/v1/sessions/sess_nonexistent", headers=h)
        assert r.status_code == 404

    def test_session_isolation(self):
        """Sessions should be scoped to the owning agent."""
        _, _, h1 = register_agent("agent-1")
        _, _, h2 = register_agent("agent-2")

        sid = client.post("/v1/sessions", json={"title": "Private"}, headers=h1).json()["session_id"]

        # Agent 2 cannot access agent 1's session
        assert client.get(f"/v1/sessions/{sid}", headers=h2).status_code == 404
        assert client.post(f"/v1/sessions/{sid}/messages", json={"role": "user", "content": "Hi"}, headers=h2).status_code == 404
        assert client.delete(f"/v1/sessions/{sid}", headers=h2).status_code == 404

    def test_summarize_preserves_system_messages(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={}, headers=h).json()["session_id"]

        # Add a system message first
        client.post(f"/v1/sessions/{sid}/messages", json={
            "role": "system", "content": "You are a helpful assistant."
        }, headers=h)

        # Add 14 more messages
        for i in range(14):
            client.post(f"/v1/sessions/{sid}/messages", json={
                "role": "user" if i % 2 == 0 else "assistant",
                "content": f"Message {i}",
            }, headers=h)

        r = client.post(f"/v1/sessions/{sid}/summarize", headers=h)
        assert r.status_code == 200

        msgs = client.get(f"/v1/sessions/{sid}", headers=h).json()["messages"]
        # Original system message should be preserved
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == "You are a helpful assistant."

    def test_token_count_updates(self):
        _, _, h = register_agent("session-bot")
        sid = client.post("/v1/sessions", json={}, headers=h).json()["session_id"]

        r1 = client.post(f"/v1/sessions/{sid}/messages", json={"role": "user", "content": "Hello world"}, headers=h)
        count1 = r1.json()["token_count"]
        assert count1 > 0

        r2 = client.post(f"/v1/sessions/{sid}/messages", json={"role": "assistant", "content": "Hi there, how can I help?"}, headers=h)
        count2 = r2.json()["token_count"]
        assert count2 > count1
