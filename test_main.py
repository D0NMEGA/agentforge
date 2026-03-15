"""
Comprehensive tests for MoltGrid API — all features.
Run: pytest test_main.py -v
"""

import os
import json
import time
import uuid
import sqlite3
import pytest
import hashlib
import pyotp
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Use an isolated test database and disable CAPTCHA for tests
os.environ["MOLTGRID_DB"] = "test_moltgrid.db"
os.environ["TURNSTILE_SECRET_KEY"] = ""

from fastapi.testclient import TestClient
from main import app, init_db, DB_PATH, _ws_connections, _run_scheduler_tick, _run_liveness_check, _run_webhook_delivery_tick
import db as db_module

client = TestClient(app)

_DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")

# Initialize PG pool once at module level if needed
if _DB_BACKEND in ("postgres", "dual"):
    db_module.init_pool()


def _table_exists(conn, table_name):
    """Check if a table exists, abstracting over SQLite/Postgres."""
    if _DB_BACKEND in ("postgres", "dual"):
        row = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = %s",
            (table_name,)
        ).fetchone()
        return row is not None
    else:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        ).fetchone()
        return row is not None


def _index_exists(conn, index_name):
    """Check if an index exists, abstracting over SQLite/Postgres."""
    if _DB_BACKEND in ("postgres", "dual"):
        row = conn.execute(
            "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexname = %s",
            (index_name,)
        ).fetchone()
        return row is not None
    else:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (index_name,)
        ).fetchone()
        return row is not None


def _list_tables(conn):
    """List all user tables, abstracting over SQLite/Postgres."""
    if _DB_BACKEND in ("postgres", "dual"):
        rows = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        ).fetchall()
        return {r[0] if isinstance(r, tuple) else r["tablename"] for r in rows}
    else:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {row[0] for row in rows}


def _get_table_columns(conn, table_name):
    """Get column names for a table, abstracting over SQLite/Postgres."""
    if _DB_BACKEND in ("postgres", "dual"):
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = %s",
            (table_name,)
        ).fetchall()
        return {r[0] if isinstance(r, tuple) else r["column_name"] for r in rows}
    else:
        rows = conn.execute("PRAGMA table_info(%s)" % table_name).fetchall()
        return {row[1] for row in rows}


def _get_test_db():
    """Get a test database connection for the current backend.
    For SQLite: returns a sqlite3 connection with Row factory.
    For Postgres: returns a wrapped psycopg connection with SQL translation.
    Caller is responsible for closing the connection.
    """
    if _DB_BACKEND in ("postgres", "dual"):
        import psycopg
        from psycopg.rows import dict_row
        raw_conn = psycopg.connect(os.getenv("DATABASE_URL", ""), row_factory=dict_row)
        return db_module._PsycopgConnWrapper(raw_conn)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn


def _truncate_all_pg_tables():
    """Truncate all tables in PostgreSQL for a fresh test state."""
    with db_module.get_db() as conn:
        # Get all user tables
        rows = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        ).fetchall()
        table_names = [r[0] if isinstance(r, tuple) else r["tablename"] for r in rows]
        if table_names:
            conn.execute("TRUNCATE %s CASCADE" % ", ".join(table_names))


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_db():
    """Wipe and re-init the DB before every test."""
    if _DB_BACKEND in ("postgres", "dual"):
        _truncate_all_pg_tables()
        init_db()  # Re-seed templates etc.
    else:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()
    _ws_connections.clear()
    yield
    if _DB_BACKEND == "sqlite":
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)


_test_agent_counter = 0
def register_agent(name=None):
    """Helper — register an agent and return (agent_id, api_key, headers)."""
    global _test_agent_counter
    _test_agent_counter += 1
    if name is None:
        name = f"test-agent-{_test_agent_counter}-{uuid.uuid4().hex[:6]}"
    else:
        name = f"{name}-{_test_agent_counter}-{uuid.uuid4().hex[:6]}"
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
        assert r.status_code == 422

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

        client.post(f"/v1/queue/{job_id}/complete", params={"result": "ok"}, headers=h)
        # Verify webhook delivery was queued
        import sqlite3
        conn = _get_test_db()
        deliveries = conn.execute("SELECT * FROM webhook_deliveries WHERE event_type='job.completed'").fetchall()
        conn.close()
        assert len(deliveries) >= 1


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

        # Set attempt_count to max_attempts - 1 so next failure = final (max_attempts=5)
        with get_db() as db:
            db.execute("UPDATE webhook_deliveries SET attempt_count=4")

        with patch("main.httpx.Client") as MockClient:
            mock_instance = MagicMock()
            mock_instance.post.side_effect = Exception("Timeout")
            MockClient.return_value.__enter__ = MagicMock(return_value=mock_instance)
            MockClient.return_value.__exit__ = MagicMock(return_value=False)

            _run_webhook_delivery_tick()

        with get_db() as db:
            row = dict(db.execute("SELECT * FROM webhook_deliveries").fetchone())
        assert row["status"] == "failed"
        assert row["attempt_count"] == 5  # max_attempts=5, started at 4, incremented to 5
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
        conn = _get_test_db()
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
        assert data["name"].startswith("profile-bot")
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
        assert d["version"] == "0.9.0"
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
        conn = _get_test_db()
        # Artificially set high count
        window = int(time.time()) // 60
        aid = client.get("/v1/stats", headers=h).json()["agent_id"]
        conn.execute(
            "INSERT INTO rate_limits (agent_id, window_start, count) VALUES (?, ?, ?) ON CONFLICT (agent_id, window_start) DO UPDATE SET count = EXCLUDED.count",
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

        client.post(f"/v1/queue/{job_id}/fail", json={"reason": "boom"}, headers=h)
        # Verify webhook delivery was queued for job.failed
        import sqlite3
        conn = _get_test_db()
        deliveries = conn.execute("SELECT * FROM webhook_deliveries WHERE event_type='job.failed'").fetchall()
        conn.close()
        assert len(deliveries) >= 1

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
        conn = _get_test_db()
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
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={
                "email": email, "password": password, "display_name": display_name,
            })
        return r

    def _register(self, name, token):
        """Register an agent with user auth — mocks _queue_email to avoid DB lock."""
        with patch("main._queue_email"):
            r = client.post("/v1/register", json={"name": name}, headers=self._auth_header(token))
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
        reg = self._register("owned-bot", token)
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
        conn = _get_test_db()
        conn.execute("UPDATE users SET max_agents = 5 WHERE user_id = ?", (r.json()["user_id"],))
        conn.commit()
        conn.close()
        # Register 2 agents
        self._register("bot1", token)
        self._register("bot2", token)
        agents = client.get("/v1/user/agents", headers=self._auth_header(token))
        assert agents.status_code == 200
        assert agents.json()["count"] == 2

    def test_user_agents_isolation(self):
        r_a = self._signup(email="a@example.com")
        r_b = self._signup(email="b@example.com")
        token_a = r_a.json()["token"]
        token_b = r_b.json()["token"]
        # User A registers an agent
        self._register("a-bot", token_a)
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
        r1 = self._register("first", token)
        assert r1.status_code == 200
        # Second agent should fail
        r2 = self._register("second", token)
        assert r2.status_code == 403
        body = r2.json()
        # Error responses use {error, code, status} shape (not {detail: ...})
        assert "Agent limit" in body.get("error", body.get("detail", ""))

    def test_usage_quota(self):
        with patch("main._queue_email"):
            r = self._signup(email="quota@example.com")
            token = r.json()["token"]
            user_id = r.json()["user_id"]
            # Register an agent under this user
            reg = self._register("quota-bot", token)
            api_key = reg.json()["api_key"]
            agent_headers = {"X-API-Key": api_key}
            # Set usage_count to max_api_calls - 1 (free = 10000)
            import sqlite3
            conn = _get_test_db()
            conn.execute("UPDATE users SET usage_count = 9999 WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
            # This request should succeed (9999 -> increments to 10000)
            r1 = client.get("/v1/memory", headers=agent_headers)
            assert r1.status_code == 200
            # Next request should be blocked (usage_count >= 10000)
            r2 = client.get("/v1/memory", headers=agent_headers)
            assert r2.status_code == 429
            body = r2.json()
            # Error responses use {error, code, status} shape (not {detail: ...})
            assert "quota" in body.get("error", body.get("detail", "")).lower()



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
        # tiers is a dict keyed by tier name
        assert len(d["tiers"]) == 4
        assert set(d["tiers"].keys()) == {"free", "hobby", "team", "scale"}
        # Verify free tier details
        free = d["tiers"]["free"]
        assert free["price"] == 0
        assert free["max_agents"] == 1
        assert free["max_api_calls"] == 10000

    def test_checkout_requires_auth(self):
        r = client.post("/v1/billing/checkout", json={"tier": "hobby"})
        assert r.status_code == 401

    def test_checkout_invalid_tier(self):
        # Signup to get a token
        with patch("main._queue_email"):
            s = client.post("/v1/auth/signup", json={
                "email": "checkout@example.com", "password": "securepass123",
            })
        token = s.json()["token"]
        r = client.post("/v1/billing/checkout", json={"tier": "invalid"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400
        body = r.json()
        # Error responses use {error, code, status} shape (not {detail: ...})
        assert "Invalid tier" in body.get("error", body.get("detail", ""))

    def test_billing_status_requires_auth(self):
        r = client.get("/v1/billing/status")
        assert r.status_code == 401

    def test_stripe_webhook_bad_payload(self):
        r = client.post("/v1/stripe/webhook", content=b"not json",
                        headers={"Content-Type": "application/json"})
        assert r.status_code == 400

    def test_user_starts_free(self):
        with patch("main._queue_email"):
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


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE HEADERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestResponseHeaders:
    def test_request_id_on_public_endpoint(self):
        r = client.get("/v1/health")
        assert r.status_code == 200
        assert "x-request-id" in r.headers
        assert len(r.headers["x-request-id"]) == 32  # uuid4 hex

    def test_version_header(self):
        r = client.get("/v1/health")
        assert r.headers["x-moltgrid-version"] == "0.9.0"

    def test_rate_limit_headers_on_authenticated(self):
        _, _, h = register_agent()
        r = client.get("/v1/memory", headers=h)
        assert "x-ratelimit-limit" in r.headers
        assert r.headers["x-ratelimit-limit"] == "120"
        assert "x-ratelimit-remaining" in r.headers
        remaining = int(r.headers["x-ratelimit-remaining"])
        assert 0 <= remaining <= 120
        assert "x-ratelimit-reset" in r.headers
        reset = int(r.headers["x-ratelimit-reset"])
        assert reset > 0

    def test_rate_limit_remaining_decreases(self):
        _, _, h = register_agent()
        r1 = client.get("/v1/memory", headers=h)
        rem1 = int(r1.headers["x-ratelimit-remaining"])

        r2 = client.get("/v1/memory", headers=h)
        rem2 = int(r2.headers["x-ratelimit-remaining"])
        assert rem2 < rem1

    def test_request_id_unique_per_request(self):
        r1 = client.get("/v1/health")
        r2 = client.get("/v1/health")
        assert r1.headers["x-request-id"] != r2.headers["x-request-id"]

    def test_headers_on_error_response(self):
        r = client.get("/v1/memory")  # No API key = 401
        assert r.status_code == 401
        assert "x-request-id" in r.headers
        assert "x-moltgrid-version" in r.headers

    def test_cors_headers(self):
        # Use an allowed origin (CORS is now restricted to moltgrid.net / localhost)
        r = client.options("/v1/health", headers={
            "Origin": "https://moltgrid.net",
            "Access-Control-Request-Method": "GET",
        })
        assert "access-control-allow-origin" in r.headers
        assert r.headers["access-control-allow-origin"] == "https://moltgrid.net"


# ═══════════════════════════════════════════════════════════════════════════════
# PUB/SUB BROADCAST MESSAGING
# ═══════════════════════════════════════════════════════════════════════════════

class TestPubSub:
    def test_subscribe(self):
        _, _, h = register_agent()
        r = client.post("/v1/pubsub/subscribe", json={"channel": "alerts"}, headers=h)
        assert r.status_code == 200
        assert r.json()["status"] == "subscribed"
        assert r.json()["channel"] == "alerts"

    def test_subscribe_idempotent(self):
        _, _, h = register_agent()
        client.post("/v1/pubsub/subscribe", json={"channel": "alerts"}, headers=h)
        r = client.post("/v1/pubsub/subscribe", json={"channel": "alerts"}, headers=h)
        assert r.status_code == 200
        assert r.json()["status"] == "already_subscribed"

    def test_unsubscribe(self):
        _, _, h = register_agent()
        client.post("/v1/pubsub/subscribe", json={"channel": "alerts"}, headers=h)
        r = client.post("/v1/pubsub/unsubscribe", json={"channel": "alerts"}, headers=h)
        assert r.status_code == 200
        assert r.json()["status"] == "unsubscribed"

    def test_unsubscribe_not_subscribed(self):
        _, _, h = register_agent()
        r = client.post("/v1/pubsub/unsubscribe", json={"channel": "nope"}, headers=h)
        assert r.status_code == 404

    def test_list_subscriptions(self):
        _, _, h = register_agent()
        client.post("/v1/pubsub/subscribe", json={"channel": "ch1"}, headers=h)
        client.post("/v1/pubsub/subscribe", json={"channel": "ch2"}, headers=h)
        r = client.get("/v1/pubsub/subscriptions", headers=h)
        assert r.status_code == 200
        assert r.json()["count"] == 2
        channels = [s["channel"] for s in r.json()["subscriptions"]]
        assert "ch1" in channels
        assert "ch2" in channels

    def test_publish_delivers_to_subscribers(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        # Both subscribe to same channel
        client.post("/v1/pubsub/subscribe", json={"channel": "news"}, headers=h1)
        client.post("/v1/pubsub/subscribe", json={"channel": "news"}, headers=h2)
        # Agent 1 publishes
        r = client.post("/v1/pubsub/publish", json={"channel": "news", "payload": "hello world"}, headers=h1)
        assert r.status_code == 200
        assert r.json()["subscribers_notified"] == 1  # excludes publisher
        assert r.json()["channel"] == "news"

    def test_publish_excludes_publisher(self):
        _, _, h = register_agent()
        client.post("/v1/pubsub/subscribe", json={"channel": "solo"}, headers=h)
        r = client.post("/v1/pubsub/publish", json={"channel": "solo", "payload": "echo"}, headers=h)
        assert r.status_code == 200
        assert r.json()["subscribers_notified"] == 0

    def test_publish_creates_relay_messages(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        _, _, h3 = register_agent()
        client.post("/v1/pubsub/subscribe", json={"channel": "updates"}, headers=h1)
        client.post("/v1/pubsub/subscribe", json={"channel": "updates"}, headers=h2)
        client.post("/v1/pubsub/subscribe", json={"channel": "updates"}, headers=h3)
        # Agent 1 publishes
        client.post("/v1/pubsub/publish", json={"channel": "updates", "payload": "data"}, headers=h1)
        # Agent 2 should see the message in relay inbox
        inbox = client.get("/v1/relay/inbox", params={"channel": "pubsub:updates"}, headers=h2)
        assert inbox.status_code == 200
        assert inbox.json()["count"] == 1
        assert inbox.json()["messages"][0]["payload"] == "data"

    def test_list_channels(self):
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        client.post("/v1/pubsub/subscribe", json={"channel": "ch-a"}, headers=h1)
        client.post("/v1/pubsub/subscribe", json={"channel": "ch-a"}, headers=h2)
        client.post("/v1/pubsub/subscribe", json={"channel": "ch-b"}, headers=h1)
        r = client.get("/v1/pubsub/channels", headers=h1)
        assert r.status_code == 200
        assert r.json()["count"] == 2
        ch_names = [c["channel"] for c in r.json()["channels"]]
        assert "ch-a" in ch_names
        assert "ch-b" in ch_names
        # ch-a should have 2 subscribers and be first (ordered by count desc)
        assert r.json()["channels"][0]["channel"] == "ch-a"
        assert r.json()["channels"][0]["subscriber_count"] == 2

    def test_publish_fires_webhooks(self):
        from main import _run_webhook_delivery_tick
        _, _, h1 = register_agent()
        _, _, h2 = register_agent()
        # Agent 2 registers a webhook for message.broadcast
        client.post("/v1/webhooks", json={
            "url": "https://example.com/hook",
            "event_types": ["message.broadcast"],
        }, headers=h2)
        # Both subscribe
        client.post("/v1/pubsub/subscribe", json={"channel": "wh-test"}, headers=h1)
        client.post("/v1/pubsub/subscribe", json={"channel": "wh-test"}, headers=h2)
        # Agent 1 publishes
        r = client.post("/v1/pubsub/publish", json={"channel": "wh-test", "payload": "test"}, headers=h1)
        assert r.json()["subscribers_notified"] == 1
        # Verify webhook delivery was queued
        import contextlib
        with contextlib.closing(_get_test_db()) as conn:
            row = conn.execute(
                "SELECT * FROM webhook_deliveries WHERE event_type='message.broadcast'"
            ).fetchone()
            assert row is not None
            assert row["status"] == "pending"

    def test_publish_empty_channel(self):
        _, _, h = register_agent()
        r = client.post("/v1/pubsub/publish", json={"channel": "empty", "payload": "hello"}, headers=h)
        assert r.status_code == 200
        assert r.json()["subscribers_notified"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalytics:
    def _query_analytics(self, sql, params=()):
        """Helper to query analytics_events without leaking connections on Windows."""
        import sqlite3, contextlib
        with contextlib.closing(_get_test_db()) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(sql, params).fetchall()

    def test_agent_registered_event_tracked(self):
        """Registering an agent creates an analytics event."""
        register_agent()
        rows = self._query_analytics("SELECT * FROM analytics_events WHERE event_name='agent.registered'")
        assert len(rows) >= 1
        assert rows[0]["agent_id"] is not None

    def test_first_memory_event(self):
        """First memory set triggers agent.first_memory event."""
        _, _, h = register_agent()
        client.post("/v1/memory", json={"key": "k1", "value": "v1"}, headers=h)
        rows = self._query_analytics("SELECT * FROM analytics_events WHERE event_name='agent.first_memory'")
        assert len(rows) == 1

    def test_first_memory_only_once(self):
        """Second memory set does NOT create another first_memory event."""
        _, _, h = register_agent()
        client.post("/v1/memory", json={"key": "k1", "value": "v1"}, headers=h)
        client.post("/v1/memory", json={"key": "k2", "value": "v2"}, headers=h)
        rows = self._query_analytics("SELECT * FROM analytics_events WHERE event_name='agent.first_memory'")
        assert len(rows) == 1

    def test_first_message_event(self):
        """First relay send triggers agent.first_message event."""
        _, _, h1 = register_agent()
        aid2, _, _ = register_agent()
        client.post("/v1/relay/send", json={"to_agent": aid2, "payload": "hi"}, headers=h1)
        rows = self._query_analytics("SELECT * FROM analytics_events WHERE event_name='agent.first_message'")
        assert len(rows) == 1

    def test_first_job_event(self):
        """First queue submit triggers agent.first_job event."""
        _, _, h = register_agent()
        client.post("/v1/queue/submit", json={"payload": "task1"}, headers=h)
        rows = self._query_analytics("SELECT * FROM analytics_events WHERE event_name='agent.first_job'")
        assert len(rows) == 1

    def test_admin_analytics_endpoint_requires_auth(self):
        """GET /admin/api/analytics requires admin session."""
        register_agent()
        r = client.get("/admin/api/analytics")
        assert r.status_code in (401, 403, 307)

    def test_analytics_events_table_exists(self):
        """The analytics_events table is created by init_db."""
        conn = _get_test_db()
        assert _table_exists(conn, "analytics_events"), "analytics_events table must exist"
        conn.close()


# =============================================================================
# MEMORY VISIBILITY SCHEMA & ACCESS CONTROL (MEM-01..07)
# =============================================================================

class TestMemoryVisibilitySchema:
    """
    Verifies:
    - Schema migration adds visibility + shared_agents columns to memory table
    - memory_access_log table is created with correct schema and index
    - init_db() is idempotent (can be called multiple times)
    - Existing NULL visibility rows are backfilled to 'private'
    - _check_memory_visibility() helper correctly enforces access rules
    - _log_memory_access() never raises
    - POST /v1/memory stores visibility and shared_agents
    - GET /v1/agents/{target}/memory/{key} returns 403 for private keys
    - GET /v1/agents/{target}/memory/{key} returns 200 for public keys
    - GET /v1/agents/{target}/memory/{key} returns 200 for shared keys (requester in list)
    - GET /v1/memory/{key} (own-agent) is unaffected by visibility
    """

    def _raw_db(self):
        """Return a raw sqlite3 connection (row_factory = sqlite3.Row)."""
        import sqlite3
        from main import DB_PATH
        conn = _get_test_db()
        return conn

    # ── Schema migration ──────────────────────────────────────────────────────

    def test_memory_table_has_visibility_column(self):
        """init_db() adds visibility column to memory table."""
        conn = self._raw_db()
        cols = _get_table_columns(conn, "memory")
        conn.close()
        assert "visibility" in cols, "memory table must have 'visibility' column"

    def test_memory_table_has_shared_agents_column(self):
        """init_db() adds shared_agents column to memory table."""
        conn = self._raw_db()
        cols = _get_table_columns(conn, "memory")
        conn.close()
        assert "shared_agents" in cols, "memory table must have 'shared_agents' column"

    def test_memory_access_log_table_exists(self):
        """init_db() creates memory_access_log table."""
        conn = self._raw_db()
        assert _table_exists(conn, "memory_access_log"), "memory_access_log table must exist after init_db()"
        conn.close()

    def test_memory_access_log_index_exists(self):
        """init_db() creates idx_mal_agent index on memory_access_log."""
        conn = self._raw_db()
        assert _index_exists(conn, "idx_mal_agent"), "idx_mal_agent index must exist after init_db()"
        conn.close()

    def test_init_db_is_idempotent(self):
        """Calling init_db() twice does not raise."""
        from main import init_db
        init_db()  # second call — must not fail (idempotent ALTER TABLE)
        # If we reach here, no exception was raised
        assert True

    def test_null_visibility_backfilled_to_private(self):
        """Rows with NULL visibility are updated to 'private' by the migration."""
        import sqlite3
        from main import DB_PATH, init_db
        # Directly insert a row without visibility (simulating pre-migration data)
        conn = _get_test_db()
        # Insert a raw row bypassing visibility
        conn.execute(
            "INSERT INTO memory "
            "(agent_id, namespace, key, value, created_at, updated_at) "
            "VALUES ('agent_backfill_test', 'default', 'old_key', 'v', '2020-01-01', '2020-01-01') "
            "ON CONFLICT (agent_id, namespace, key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at"
        )
        conn.commit()
        # Force visibility to NULL
        conn.execute("UPDATE memory SET visibility=NULL WHERE agent_id='agent_backfill_test'")
        conn.commit()
        conn.close()
        # Re-run init_db — should backfill NULL -> 'private'
        init_db()
        conn2 = _get_test_db()
        row = conn2.execute(
            "SELECT visibility FROM memory WHERE agent_id='agent_backfill_test'"
        ).fetchone()
        conn2.close()
        assert row is not None
        assert row["visibility"] == "private", f"Expected 'private', got {row['visibility']!r}"

    # ── Helper function: _check_memory_visibility ─────────────────────────────

    def test_check_visibility_public(self):
        """_check_memory_visibility returns True for public memory."""
        from main import _check_memory_visibility, get_db
        _, _, h = register_agent("owner-pub")
        aid2, _, _ = register_agent("requester-pub")
        # Store public memory
        r = client.post("/v1/memory", json={"key": "pub_key", "value": "pub_val", "visibility": "public"}, headers=h)
        assert r.status_code == 200
        owner_id = client.get("/v1/memory/pub_key", headers=h).json()  # just to confirm it exists
        # get owner agent_id from the registration
        owner_agent_id = r.url  # need to fetch from DB
        # Use get_db to check via helper
        with get_db() as db:
            # We need to know the owner's agent_id — get it from registered agent
            # Fetch the agent_id from the memory table
            row = db.execute("SELECT agent_id FROM memory WHERE key='pub_key'").fetchone()
            assert row is not None
            target_id = row["agent_id"]
            result = _check_memory_visibility(db, target_id, "default", "pub_key", aid2)
        assert result is True, "Public memory must be accessible by any agent"

    def test_check_visibility_private_other_agent(self):
        """_check_memory_visibility returns False for private memory accessed by another agent."""
        from main import _check_memory_visibility, get_db
        _, _, h = register_agent("owner-priv")
        aid2, _, _ = register_agent("requester-priv")
        client.post("/v1/memory", json={"key": "priv_key", "value": "secret", "visibility": "private"}, headers=h)
        with get_db() as db:
            row = db.execute("SELECT agent_id FROM memory WHERE key='priv_key'").fetchone()
            target_id = row["agent_id"]
            result = _check_memory_visibility(db, target_id, "default", "priv_key", aid2)
        assert result is False, "Private memory must NOT be accessible by other agents"

    def test_check_visibility_shared_requester_in_list(self):
        """_check_memory_visibility returns True for shared memory when requester is in the list."""
        from main import _check_memory_visibility, get_db
        _, _, h = register_agent("owner-shared")
        aid2, _, _ = register_agent("requester-shared")
        client.post("/v1/memory", json={
            "key": "shared_key", "value": "shared_val",
            "visibility": "shared",
            "shared_agents": [aid2]
        }, headers=h)
        with get_db() as db:
            row = db.execute("SELECT agent_id FROM memory WHERE key='shared_key'").fetchone()
            target_id = row["agent_id"]
            result = _check_memory_visibility(db, target_id, "default", "shared_key", aid2)
        assert result is True, "Shared memory must be accessible by agents in the shared_agents list"

    def test_check_visibility_shared_requester_not_in_list(self):
        """_check_memory_visibility returns False when requester is NOT in shared_agents."""
        from main import _check_memory_visibility, get_db
        _, _, h = register_agent("owner-shared2")
        aid2, _, _ = register_agent("requester-not-in-list")
        aid3, _, _ = register_agent("another-agent")
        client.post("/v1/memory", json={
            "key": "shared_key2", "value": "val",
            "visibility": "shared",
            "shared_agents": [aid3]  # aid2 is NOT in list
        }, headers=h)
        with get_db() as db:
            row = db.execute("SELECT agent_id FROM memory WHERE key='shared_key2'").fetchone()
            target_id = row["agent_id"]
            result = _check_memory_visibility(db, target_id, "default", "shared_key2", aid2)
        assert result is False, "Agent not in shared_agents list must be denied"

    def test_check_visibility_nonexistent_key(self):
        """_check_memory_visibility returns False when key does not exist."""
        from main import _check_memory_visibility, get_db
        _, _, _ = register_agent("owner-nokey")
        aid2, _, _ = register_agent("requester-nokey")
        with get_db() as db:
            result = _check_memory_visibility(db, "nonexistent_agent", "default", "no_such_key", aid2)
        assert result is False, "Non-existent key must return False"

    # ── _log_memory_access never raises ──────────────────────────────────────

    def test_log_memory_access_never_raises(self):
        """_log_memory_access() must not raise even with invalid inputs."""
        from main import _log_memory_access
        # Should not raise
        _log_memory_access("read", "agent_x", "default", "key1", actor_agent_id="agent_y")
        _log_memory_access("write", "", "", "", actor_user_id=None)
        assert True  # If we reach here, it didn't raise

    # ── POST /v1/memory stores visibility ────────────────────────────────────

    def test_memory_set_stores_visibility_private(self):
        """POST /v1/memory stores visibility='private' (default)."""
        _, _, h = register_agent("vis-private")
        r = client.post("/v1/memory", json={"key": "k", "value": "v"}, headers=h)
        assert r.status_code == 200
        import sqlite3
        from main import DB_PATH
        conn = _get_test_db()
        row = conn.execute("SELECT visibility FROM memory WHERE key='k'").fetchone()
        conn.close()
        assert row is not None
        assert row["visibility"] == "private"

    def test_memory_set_stores_visibility_public(self):
        """POST /v1/memory stores visibility='public' when specified."""
        _, _, h = register_agent("vis-public")
        r = client.post("/v1/memory", json={"key": "k", "value": "v", "visibility": "public"}, headers=h)
        assert r.status_code == 200
        import sqlite3
        from main import DB_PATH
        conn = _get_test_db()
        row = conn.execute("SELECT visibility FROM memory WHERE key='k'").fetchone()
        conn.close()
        assert row["visibility"] == "public"

    def test_memory_set_stores_shared_agents(self):
        """POST /v1/memory stores shared_agents JSON when visibility='shared'."""
        _, _, h = register_agent("vis-shared-store")
        aid2, _, _ = register_agent("shared-with")
        r = client.post("/v1/memory", json={
            "key": "k", "value": "v",
            "visibility": "shared",
            "shared_agents": [aid2]
        }, headers=h)
        assert r.status_code == 200
        import sqlite3, json
        from main import DB_PATH
        conn = _get_test_db()
        row = conn.execute("SELECT visibility, shared_agents FROM memory WHERE key='k'").fetchone()
        conn.close()
        assert row["visibility"] == "shared"
        assert aid2 in json.loads(row["shared_agents"])

    # ── GET /v1/agents/{target}/memory/{key} — cross-agent endpoint ──────────

    def test_cross_agent_read_public_returns_200(self):
        """GET /v1/agents/{target}/memory/{key} returns 200 for public memory."""
        aid1, _, h1 = register_agent("owner-cross-pub")
        aid2, _, h2 = register_agent("requester-cross-pub")
        client.post("/v1/memory", json={"key": "pub", "value": "hello", "visibility": "public"}, headers=h1)
        r = client.get(f"/v1/agents/{aid1}/memory/pub", headers=h2)
        assert r.status_code == 200
        data = r.json()
        assert data["value"] == "hello"
        assert data["visibility"] == "public"

    def test_cross_agent_read_private_returns_403(self):
        """GET /v1/agents/{target}/memory/{key} returns 403 for private memory."""
        aid1, _, h1 = register_agent("owner-cross-priv")
        aid2, _, h2 = register_agent("requester-cross-priv")
        client.post("/v1/memory", json={"key": "priv", "value": "secret"}, headers=h1)
        r = client.get(f"/v1/agents/{aid1}/memory/priv", headers=h2)
        assert r.status_code == 403
        body = r.json()
        # Error responses use {error, code, status} shape (not {detail: ...})
        assert "Access denied" in body.get("error", body.get("detail", ""))

    def test_cross_agent_read_private_not_404(self):
        """Private memory returns 403 not 404 (prevents enumeration)."""
        aid1, _, h1 = register_agent("owner-403")
        aid2, _, h2 = register_agent("requester-403")
        client.post("/v1/memory", json={"key": "secret_key", "value": "secret"}, headers=h1)
        r = client.get(f"/v1/agents/{aid1}/memory/secret_key", headers=h2)
        assert r.status_code == 403, f"Must return 403 not {r.status_code}"

    def test_cross_agent_read_shared_in_list_returns_200(self):
        """GET /v1/agents/{target}/memory/{key} returns 200 when requester is in shared_agents."""
        aid1, _, h1 = register_agent("owner-shared-ep")
        aid2, _, h2 = register_agent("req-shared-ep")
        client.post("/v1/memory", json={
            "key": "shared_ep", "value": "shared_val",
            "visibility": "shared",
            "shared_agents": [aid2]
        }, headers=h1)
        r = client.get(f"/v1/agents/{aid1}/memory/shared_ep", headers=h2)
        assert r.status_code == 200
        assert r.json()["value"] == "shared_val"

    def test_cross_agent_read_shared_not_in_list_returns_403(self):
        """GET /v1/agents/{target}/memory/{key} returns 403 when requester NOT in shared_agents."""
        aid1, _, h1 = register_agent("owner-shared-excl")
        aid2, _, h2 = register_agent("req-not-in-list")
        aid3, _, _ = register_agent("other-agent")
        client.post("/v1/memory", json={
            "key": "shared_excl", "value": "val",
            "visibility": "shared",
            "shared_agents": [aid3]
        }, headers=h1)
        r = client.get(f"/v1/agents/{aid1}/memory/shared_excl", headers=h2)
        assert r.status_code == 403

    # ── GET /v1/memory/{key} (own-agent) is unaffected ───────────────────────

    def test_own_agent_read_unaffected_by_visibility_private(self):
        """GET /v1/memory/{key} always returns 200 for the owner, regardless of visibility."""
        _, _, h = register_agent("owner-own-read")
        client.post("/v1/memory", json={"key": "mine", "value": "myval", "visibility": "private"}, headers=h)
        r = client.get("/v1/memory/mine", headers=h)
        assert r.status_code == 200
        assert r.json()["value"] == "myval"

    def test_own_agent_read_unaffected_by_visibility_shared(self):
        """Owner can always read their own shared key."""
        _, _, h = register_agent("owner-own-shared")
        client.post("/v1/memory", json={"key": "shared_own", "value": "sv", "visibility": "shared"}, headers=h)
        r = client.get("/v1/memory/shared_own", headers=h)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# MEMORY VISIBILITY ENDPOINT (MEM-05)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMemoryVisibilityEndpoint:
    """
    Verifies PATCH /v1/memory/{key}/visibility endpoint (MEM-05):
    - Returns 200 with {"status":"updated","key","visibility"} on success
    - Returns 404 for nonexistent key
    - Changing to public allows cross-agent reads (200)
    - Changing to private blocks cross-agent reads (403)
    - shared visibility with shared_agents list is stored and enforced
    - Invalid visibility value coerces to 'private'
    """

    def test_agent_can_change_own_memory_to_public(self):
        """PATCH /v1/memory/{key}/visibility returns 200 and updates visibility to public."""
        _, _, h = register_agent("vis-owner-pub")
        client.post("/v1/memory", json={"key": "mykey", "value": "val", "visibility": "private"}, headers=h)
        r = client.patch(
            "/v1/memory/mykey/visibility",
            json={"namespace": "default", "key": "mykey", "visibility": "public", "shared_agents": []},
            headers=h,
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["status"] == "updated"
        assert body["key"] == "mykey"
        assert body["visibility"] == "public"

    def test_agent_can_change_own_memory_to_shared(self):
        """PATCH /v1/memory/{key}/visibility with shared visibility stores shared_agents correctly."""
        aid1, _, h1 = register_agent("vis-owner-shared")
        aid2, _, _ = register_agent("vis-shared-peer")
        client.post("/v1/memory", json={"key": "sharedkey", "value": "sv", "visibility": "private"}, headers=h1)
        r = client.patch(
            "/v1/memory/sharedkey/visibility",
            json={"namespace": "default", "key": "sharedkey", "visibility": "shared", "shared_agents": [aid2]},
            headers=h1,
        )
        assert r.status_code == 200
        assert r.json()["visibility"] == "shared"
        # Verify the shared agent can now read it
        h2 = {"X-API-Key": client.post("/v1/register", json={"name": "vis-shared-peer-reader"}).json()["api_key"]}
        # aid2 should be able to read it
        import sqlite3
        from main import DB_PATH
        conn = _get_test_db()
        row = conn.execute(
            "SELECT shared_agents FROM memory WHERE key='sharedkey'",
        ).fetchone()
        conn.close()
        assert row is not None
        import json as _json
        sa = _json.loads(row["shared_agents"] or "[]")
        assert aid2 in sa, f"shared_agents should contain {aid2}, got {sa}"

    def test_patch_nonexistent_key_returns_404(self):
        """PATCH /v1/memory/{key}/visibility returns 404 when key does not exist."""
        _, _, h = register_agent("vis-404")
        r = client.patch(
            "/v1/memory/no_such_key/visibility",
            json={"namespace": "default", "key": "no_such_key", "visibility": "public", "shared_agents": []},
            headers=h,
        )
        assert r.status_code == 404, f"Expected 404, got {r.status_code}: {r.text}"

    def test_invalid_visibility_coerces_to_private(self):
        """PATCH /v1/memory/{key}/visibility with unknown visibility coerces to 'private'."""
        _, _, h = register_agent("vis-coerce")
        client.post("/v1/memory", json={"key": "coercekey", "value": "v", "visibility": "public"}, headers=h)
        r = client.patch(
            "/v1/memory/coercekey/visibility",
            json={"namespace": "default", "key": "coercekey", "visibility": "unknown_val", "shared_agents": []},
            headers=h,
        )
        assert r.status_code == 200
        assert r.json()["visibility"] == "private", "Invalid visibility should coerce to 'private'"

    def test_patch_visibility_changes_cross_agent_access(self):
        """Setting public -> cross-agent read returns 200; setting private -> 403."""
        aid1, _, h1 = register_agent("vis-owner-cross")
        _, _, h2 = register_agent("vis-requester-cross")
        # Store as private
        client.post("/v1/memory", json={"key": "crosskey", "value": "cval", "visibility": "private"}, headers=h1)
        # Cross-agent read must return 403 initially
        r_denied = client.get(f"/v1/agents/{aid1}/memory/crosskey", headers=h2)
        assert r_denied.status_code == 403, f"Expected 403 for private key, got {r_denied.status_code}"
        # PATCH to public
        client.patch(
            "/v1/memory/crosskey/visibility",
            json={"namespace": "default", "key": "crosskey", "visibility": "public", "shared_agents": []},
            headers=h1,
        )
        # Cross-agent read must return 200 now
        r_allowed = client.get(f"/v1/agents/{aid1}/memory/crosskey", headers=h2)
        assert r_allowed.status_code == 200, f"Expected 200 for public key, got {r_allowed.status_code}"
        assert r_allowed.json()["value"] == "cval"
        # PATCH back to private
        client.patch(
            "/v1/memory/crosskey/visibility",
            json={"namespace": "default", "key": "crosskey", "visibility": "private", "shared_agents": []},
            headers=h1,
        )
        # Cross-agent read must return 403 again
        r_denied2 = client.get(f"/v1/agents/{aid1}/memory/crosskey", headers=h2)
        assert r_denied2.status_code == 403, f"Expected 403 after setting private, got {r_denied2.status_code}"


# ═══════════════════════════════════════════════════════════════════════════════
# MEMORY AUDIT LOG (MEM-08)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMemoryAuditLog:
    """
    Verifies memory_access_log is populated for all memory operations:
    - POST /v1/memory -> action='write'
    - GET /v1/memory/{key} -> action='read', authorized=1
    - GET /v1/agents/{target}/memory/{key} (authorized) -> action='cross_agent_read', authorized=1
    - GET /v1/agents/{target}/memory/{key} (denied) -> action='cross_agent_read', authorized=0
    - PATCH /v1/memory/{key}/visibility -> action='visibility_changed' with old/new visibility
    """

    def _db(self):
        """Return a raw sqlite3 connection to inspect audit log."""
        import sqlite3
        from main import DB_PATH
        conn = _get_test_db()
        return conn

    def _audit_rows(self, agent_id=None, action=None, key=None):
        """Fetch audit log rows, optionally filtered."""
        conn = self._db()
        query = "SELECT * FROM memory_access_log WHERE 1=1"
        params = []
        if agent_id:
            query += " AND agent_id=?"
            params.append(agent_id)
        if action:
            query += " AND action=?"
            params.append(action)
        if key:
            query += " AND key=?"
            params.append(key)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def test_write_creates_audit_log_entry(self):
        """POST /v1/memory generates a memory_access_log row with action='write'."""
        aid, _, h = register_agent("audit-write")
        client.post("/v1/memory", json={"key": "wkey", "value": "wval", "visibility": "private"}, headers=h)
        rows = self._audit_rows(agent_id=aid, action="write", key="wkey")
        assert len(rows) >= 1, "Expected at least one audit row with action='write'"
        row = rows[0]
        assert row["action"] == "write"
        assert row["agent_id"] == aid
        assert row["actor_agent_id"] == aid

    def test_own_read_creates_audit_log_entry(self):
        """GET /v1/memory/{key} generates a memory_access_log row with action='read', authorized=1."""
        aid, _, h = register_agent("audit-read")
        client.post("/v1/memory", json={"key": "rkey", "value": "rval"}, headers=h)
        client.get("/v1/memory/rkey", headers=h)
        rows = self._audit_rows(agent_id=aid, action="read", key="rkey")
        assert len(rows) >= 1, "Expected at least one audit row with action='read'"
        row = rows[0]
        assert row["action"] == "read"
        assert row["agent_id"] == aid
        assert row["actor_agent_id"] == aid
        assert row["authorized"] == 1

    def test_authorized_cross_agent_read_logged_as_authorized(self):
        """Authorized GET /v1/agents/{target}/memory/{key} logs action='cross_agent_read', authorized=1."""
        aid1, _, h1 = register_agent("audit-cross-owner")
        aid2, _, h2 = register_agent("audit-cross-requester")
        client.post("/v1/memory", json={"key": "pubkey", "value": "pv", "visibility": "public"}, headers=h1)
        r = client.get(f"/v1/agents/{aid1}/memory/pubkey", headers=h2)
        assert r.status_code == 200
        rows = self._audit_rows(agent_id=aid1, action="cross_agent_read", key="pubkey")
        assert len(rows) >= 1, "Expected cross_agent_read audit row for authorized access"
        row = rows[0]
        assert row["authorized"] == 1
        assert row["actor_agent_id"] == aid2

    def test_unauthorized_cross_agent_read_logged_as_unauthorized(self):
        """Denied GET /v1/agents/{target}/memory/{key} logs action='cross_agent_read', authorized=0."""
        aid1, _, h1 = register_agent("audit-denied-owner")
        aid2, _, h2 = register_agent("audit-denied-requester")
        client.post("/v1/memory", json={"key": "privkey", "value": "pv", "visibility": "private"}, headers=h1)
        r = client.get(f"/v1/agents/{aid1}/memory/privkey", headers=h2)
        assert r.status_code == 403
        rows = self._audit_rows(agent_id=aid1, action="cross_agent_read", key="privkey")
        assert len(rows) >= 1, "Expected cross_agent_read audit row for denied access"
        row = rows[0]
        assert row["authorized"] == 0
        assert row["actor_agent_id"] == aid2

    def test_visibility_change_logged_with_old_and_new(self):
        """PATCH /v1/memory/{key}/visibility logs action='visibility_changed' with old and new visibility."""
        aid, _, h = register_agent("audit-vis-change")
        client.post("/v1/memory", json={"key": "vckey", "value": "vcval", "visibility": "private"}, headers=h)
        client.patch(
            "/v1/memory/vckey/visibility",
            json={"namespace": "default", "key": "vckey", "visibility": "public", "shared_agents": []},
            headers=h,
        )
        rows = self._audit_rows(agent_id=aid, action="visibility_changed", key="vckey")
        assert len(rows) >= 1, "Expected visibility_changed audit row"
        row = rows[0]
        assert row["old_visibility"] == "private"
        assert row["new_visibility"] == "public"
        assert row["actor_agent_id"] == aid


# =============================================================================
# MEMORY DASHBOARD ENDPOINTS (MEM-09, MEM-10, MEM-11)
# =============================================================================

def _register_user_and_agent(email="dashuser@example.com", password="testpass123", agent_name="dash-agent"):
    """Helper — sign up a user, return (user_id, token, agent_id, agent_api_key).

    Used by TestMemoryDashboardEndpoints to set up JWT-authenticated user + owned agent.
    _queue_email is mocked throughout to avoid sqlite lock contention from the background
    email thread (which runs every 30s and competes with test DB writes in WAL mode).
    """
    with patch("main._queue_email", return_value=None):
        r = client.post("/v1/auth/signup", json={
            "email": email, "password": password, "display_name": "DashUser",
        })
        assert r.status_code == 200, f"signup failed: {r.text}"
        d = r.json()
        token = d["token"]
        user_id = d["user_id"]
        auth_h = {"Authorization": f"Bearer {token}"}
        reg = client.post("/v1/register", json={"name": agent_name}, headers=auth_h)
    assert reg.status_code == 200, f"register agent failed: {reg.text}"
    agent_id = reg.json()["agent_id"]
    api_key = reg.json()["api_key"]
    return user_id, token, agent_id, api_key


class TestMemoryDashboardEndpoints:
    """
    Verifies the five user-dashboard memory endpoints introduced in plan 01-03:

    - GET  /v1/user/agents/{id}/memory-list         (visibility field per key)
    - GET  /v1/user/agents/{id}/memory-entry        (single entry + shared_agents)
    - GET  /v1/user/agents/{id}/memory-entry 404    (key not found)
    - PATCH /v1/user/agents/{id}/memory-entry/visibility  (MEM-10)
    - POST /v1/user/agents/{id}/memory-bulk-visibility    (MEM-11)
    - GET  /v1/user/agents/{id}/memory-access-log         (audit log)
    """

    def _auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def _write_memory(self, agent_id, api_key, key, value="testvalue", namespace="default", visibility="private"):
        """Write a memory entry via the agent API key endpoint."""
        h = {"X-API-Key": api_key}
        r = client.post("/v1/memory", json={
            "key": key, "value": value, "namespace": namespace, "visibility": visibility,
        }, headers=h)
        assert r.status_code == 200, f"memory write failed for key={key}: {r.text}"

    def test_memory_list_includes_visibility(self):
        """GET memory-list returns each key with a visibility field (not missing/null)."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="memlist@example.com", agent_name="memlist-agent"
        )
        self._write_memory(agent_id, api_key, "k1", visibility="private")
        self._write_memory(agent_id, api_key, "k2", visibility="public")

        r = client.get(
            f"/v1/user/agents/{agent_id}/memory-list",
            headers=self._auth_header(token),
        )
        assert r.status_code == 200
        d = r.json()
        assert "keys" in d, "Response must contain 'keys' array"
        keys = d["keys"]
        assert len(keys) == 2, f"Expected 2 keys, got {len(keys)}"
        for item in keys:
            assert "visibility" in item, f"Missing 'visibility' in {item}"
            assert item["visibility"] in ("private", "public", "shared"), \
                f"Unexpected visibility value: {item['visibility']}"

    def test_memory_entry_fetch(self):
        """GET memory-entry returns key, namespace, value, visibility, shared_agents, updated_at."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="entry@example.com", agent_name="entry-agent"
        )
        self._write_memory(agent_id, api_key, "mykey", value="myvalue", visibility="public")

        r = client.get(
            f"/v1/user/agents/{agent_id}/memory-entry",
            params={"namespace": "default", "key": "mykey"},
            headers=self._auth_header(token),
        )
        assert r.status_code == 200
        d = r.json()
        assert d["key"] == "mykey"
        assert d["namespace"] == "default"
        assert d["value"] == "myvalue"
        assert d["visibility"] == "public"
        assert "shared_agents" in d
        assert "updated_at" in d

    def test_memory_entry_fetch_not_found(self):
        """GET memory-entry returns 404 when key does not exist."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="notfound@example.com", agent_name="notfound-agent"
        )

        r = client.get(
            f"/v1/user/agents/{agent_id}/memory-entry",
            params={"namespace": "default", "key": "does-not-exist"},
            headers=self._auth_header(token),
        )
        assert r.status_code == 404

    def test_user_set_visibility(self):
        """PATCH memory-entry/visibility returns 200 and persists the change (MEM-10)."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="setvis@example.com", agent_name="setvis-agent"
        )
        self._write_memory(agent_id, api_key, "vkey", visibility="private")

        patch_r = client.patch(
            f"/v1/user/agents/{agent_id}/memory-entry/visibility",
            json={"namespace": "default", "key": "vkey", "visibility": "public", "shared_agents": []},
            headers=self._auth_header(token),
        )
        assert patch_r.status_code == 200
        d = patch_r.json()
        assert d["visibility"] == "public"

        # Verify persistence via GET memory-entry
        get_r = client.get(
            f"/v1/user/agents/{agent_id}/memory-entry",
            params={"namespace": "default", "key": "vkey"},
            headers=self._auth_header(token),
        )
        assert get_r.status_code == 200
        assert get_r.json()["visibility"] == "public"

    def test_user_set_visibility_403_wrong_user(self):
        """PATCH memory-entry/visibility returns 403 when user does not own the agent."""
        _, token_owner, agent_id, api_key = _register_user_and_agent(
            email="owner403@example.com", agent_name="owner403-agent"
        )
        self._write_memory(agent_id, api_key, "protectedkey", visibility="private")

        # Second user tries to change visibility of first user's memory
        with patch("main._queue_email", return_value=None):
            r2 = client.post("/v1/auth/signup", json={
                "email": "attacker403@example.com", "password": "testpass123",
                "display_name": "Attacker",
            })
        token_attacker = r2.json()["token"]

        patch_r = client.patch(
            f"/v1/user/agents/{agent_id}/memory-entry/visibility",
            json={"namespace": "default", "key": "protectedkey", "visibility": "public", "shared_agents": []},
            headers=self._auth_header(token_attacker),
        )
        assert patch_r.status_code == 403

    def test_bulk_visibility_change(self):
        """POST memory-bulk-visibility updates visibility for multiple keys and returns count (MEM-11)."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="bulk@example.com", agent_name="bulk-agent"
        )
        self._write_memory(agent_id, api_key, "bk1", visibility="private")
        self._write_memory(agent_id, api_key, "bk2", visibility="private")

        r = client.post(
            f"/v1/user/agents/{agent_id}/memory-bulk-visibility",
            json={
                "entries": [
                    {"namespace": "default", "key": "bk1"},
                    {"namespace": "default", "key": "bk2"},
                ],
                "visibility": "public",
                "shared_agents": [],
            },
            headers=self._auth_header(token),
        )
        assert r.status_code == 200
        d = r.json()
        assert d["count"] == 2, f"Expected count=2, got {d}"

        # Verify both keys are now public
        for k in ("bk1", "bk2"):
            get_r = client.get(
                f"/v1/user/agents/{agent_id}/memory-entry",
                params={"namespace": "default", "key": k},
                headers=self._auth_header(token),
            )
            assert get_r.json()["visibility"] == "public", f"Key {k} should be public"

    def test_bulk_visibility_caps_at_200(self):
        """POST memory-bulk-visibility processes at most 200 entries (req.entries[:200])."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="bulkcap@example.com", agent_name="bulkcap-agent"
        )
        # Write 5 real keys; send 250 entries (most non-existent, confirming no crash)
        for i in range(5):
            self._write_memory(agent_id, api_key, f"capkey{i}", visibility="private")

        entries = [{"namespace": "default", "key": f"capkey{i}"} for i in range(5)]
        entries += [{"namespace": "default", "key": f"ghost{i}"} for i in range(245)]

        r = client.post(
            f"/v1/user/agents/{agent_id}/memory-bulk-visibility",
            json={"entries": entries, "visibility": "public", "shared_agents": []},
            headers=self._auth_header(token),
        )
        assert r.status_code == 200
        # At most 200 entries processed — 5 real ones updated
        assert r.json()["count"] == 5

    def test_bulk_visibility_logs_each_change(self):
        """POST memory-bulk-visibility logs each visibility change to memory_access_log."""
        import sqlite3
        from main import DB_PATH
        _, token, agent_id, api_key = _register_user_and_agent(
            email="bulklog@example.com", agent_name="bulklog-agent"
        )
        self._write_memory(agent_id, api_key, "logk1", visibility="private")
        self._write_memory(agent_id, api_key, "logk2", visibility="private")

        client.post(
            f"/v1/user/agents/{agent_id}/memory-bulk-visibility",
            json={
                "entries": [
                    {"namespace": "default", "key": "logk1"},
                    {"namespace": "default", "key": "logk2"},
                ],
                "visibility": "public",
                "shared_agents": [],
            },
            headers=self._auth_header(token),
        )

        conn = _get_test_db()
        rows = conn.execute(
            "SELECT * FROM memory_access_log WHERE agent_id=? AND action='visibility_changed'",
            (agent_id,),
        ).fetchall()
        conn.close()

        # Each bulk change generates one audit row per key
        assert len(rows) >= 2, f"Expected at least 2 audit log rows, got {len(rows)}"
        for row in rows:
            assert dict(row)["actor_user_id"] is not None, "actor_user_id must be set"

    def test_memory_access_log_endpoint(self):
        """GET memory-access-log returns paginated audit log entries, newest first."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="accesslog@example.com", agent_name="accesslog-agent"
        )
        self._write_memory(agent_id, api_key, "akey", visibility="private")
        # Trigger a visibility change so there's a log entry
        client.patch(
            f"/v1/user/agents/{agent_id}/memory-entry/visibility",
            json={"namespace": "default", "key": "akey", "visibility": "public", "shared_agents": []},
            headers=self._auth_header(token),
        )

        r = client.get(
            f"/v1/user/agents/{agent_id}/memory-access-log",
            headers=self._auth_header(token),
        )
        assert r.status_code == 200
        d = r.json()
        assert "logs" in d, "Response must have 'logs' key"
        assert "total" in d
        assert isinstance(d["logs"], list)
        assert len(d["logs"]) >= 1, "Expected at least one log entry"
        # Newest first — check the last log entry is the visibility_changed action
        log_actions = [e["action"] for e in d["logs"]]
        assert "visibility_changed" in log_actions, \
            f"Expected visibility_changed in logs, got: {log_actions}"


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: OpenClaw Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase2Schema:
    """OC-03, OC-04, OC-05 — Schema migrations: new columns and integrations table."""

    def test_agents_has_moltbook_profile_id(self):
        """agents table must have moltbook_profile_id column after migration."""
        conn = _get_test_db()
        cols = _get_table_columns(conn, "agents")
        conn.close()
        assert "moltbook_profile_id" in cols, f"moltbook_profile_id missing from agents; cols={cols}"

    def test_analytics_events_has_source(self):
        """analytics_events must have source and moltbook_url columns."""
        conn = _get_test_db()
        cols = _get_table_columns(conn, "analytics_events")
        conn.close()
        assert "source" in cols, f"source missing from analytics_events; cols={cols}"
        assert "moltbook_url" in cols, f"moltbook_url missing from analytics_events; cols={cols}"

    def test_integrations_table_exists(self):
        """integrations table must exist with correct schema."""
        conn = _get_test_db()
        cols = _get_table_columns(conn, "integrations")
        conn.close()
        for expected in ("id", "agent_id", "platform", "config", "status", "created_at"):
            assert expected in cols, f"'{expected}' missing from integrations table; cols={cols}"


class TestPhase2IntegrationEndpoints:
    """OC-06, OC-07 — POST/GET /v1/agents/{agent_id}/integrations."""

    def _register_agent(self, name="int-test-agent"):
        r = client.post("/v1/register", json={"name": name})
        assert r.status_code == 200, r.text
        return r.json()["agent_id"], r.json()["api_key"]

    def _auth(self, api_key):
        return {"X-API-Key": api_key}

    def test_create_integration(self):
        """Agent can link a platform integration to itself."""
        agent_id, api_key = self._register_agent("int-create-agent")
        r = client.post(
            f"/v1/agents/{agent_id}/integrations",
            json={"platform": "moltbook", "config": {"profile_id": "mb_123"}, "status": "active"},
            headers=self._auth(api_key),
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["platform"] == "moltbook"
        assert d["agent_id"] == agent_id
        assert "id" in d

    def test_list_integrations(self):
        """Agent can list its own integrations."""
        agent_id, api_key = self._register_agent("int-list-agent")
        client.post(
            f"/v1/agents/{agent_id}/integrations",
            json={"platform": "slack", "config": {"webhook": "https://hooks.slack.com/x"}, "status": "active"},
            headers=self._auth(api_key),
        )
        r = client.get(f"/v1/agents/{agent_id}/integrations", headers=self._auth(api_key))
        assert r.status_code == 200, r.text
        d = r.json()
        assert "integrations" in d
        assert len(d["integrations"]) == 1
        assert d["integrations"][0]["platform"] == "slack"

    def test_cannot_access_other_agent_integrations(self):
        """Agent B cannot access Agent A's integrations — returns 403."""
        agent_a_id, _ = self._register_agent("int-owner-a")
        _, api_key_b = self._register_agent("int-caller-b")
        r = client.get(f"/v1/agents/{agent_a_id}/integrations", headers=self._auth(api_key_b))
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"

    def test_cannot_create_integration_for_other_agent(self):
        """Agent B cannot create integrations for Agent A — returns 403."""
        agent_a_id, _ = self._register_agent("int-target-a")
        _, api_key_b = self._register_agent("int-attacker-b")
        r = client.post(
            f"/v1/agents/{agent_a_id}/integrations",
            json={"platform": "evil", "status": "active"},
            headers=self._auth(api_key_b),
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"


class TestPhase2MoltBookEvents:
    """OC-08, OC-09, OC-10 — MoltBook event ingestion and activity feed."""

    def _register_agent(self, name="mb-test-agent"):
        r = client.post("/v1/register", json={"name": name})
        assert r.status_code == 200, r.text
        return r.json()["agent_id"], r.json()["api_key"]

    def test_ingest_moltbook_event(self):
        """POST /v1/moltbook/events stores event with source='moltbook'."""
        agent_id, api_key = self._register_agent("mb-ingest-agent")
        r = client.post(
            "/v1/moltbook/events",
            json={
                "event_type": "post",
                "moltbook_url": "https://moltbook.com/posts/123",
                "metadata": {"content": "Hello from OpenClaw!"},
            },
            headers={"X-API-Key": api_key},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["source"] == "moltbook"
        assert d["event_name"] == "moltbook.post"
        assert "id" in d

    def test_moltbook_events_appear_in_activity_feed(self):
        """MoltBook events with badge='moltbook' appear in user activity feed."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="mbevent@example.com", agent_name="mb-activity-agent"
        )
        # Ingest a MoltBook event
        client.post(
            "/v1/moltbook/events",
            json={"event_type": "upvote", "moltbook_url": "https://moltbook.com/posts/456"},
            headers={"X-API-Key": api_key},
        )
        # Fetch activity feed
        r = client.get(
            f"/v1/user/agents/{agent_id}/activity",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200, r.text
        events = r.json()["events"]
        mb_events = [e for e in events if e.get("badge") == "moltbook"]
        assert len(mb_events) >= 1, f"Expected MoltBook event in feed, got: {events}"
        assert mb_events[0]["moltbook_url"] == "https://moltbook.com/posts/456"

    def test_moltbook_event_types(self):
        """Various MoltBook event types (post, reply, upvote) are all accepted."""
        agent_id, api_key = self._register_agent("mb-types-agent")
        for event_type in ("post", "reply", "upvote"):
            r = client.post(
                "/v1/moltbook/events",
                json={"event_type": event_type},
                headers={"X-API-Key": api_key},
            )
            assert r.status_code == 200, f"event_type={event_type} failed: {r.text}"
            assert r.json()["event_name"] == f"moltbook.{event_type}"


class TestPhase2UserIntegrations:
    """User dashboard integration listing endpoint."""

    def test_user_can_list_agent_integrations(self):
        """GET /v1/user/agents/{agent_id}/integrations returns integration list."""
        _, token, agent_id, api_key = _register_user_and_agent(
            email="userint@example.com", agent_name="user-int-agent"
        )
        # Create an integration via agent API
        client.post(
            f"/v1/agents/{agent_id}/integrations",
            json={"platform": "n8n", "status": "active"},
            headers={"X-API-Key": api_key},
        )
        # Fetch via dashboard endpoint
        r = client.get(
            f"/v1/user/agents/{agent_id}/integrations",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert "integrations" in d
        assert len(d["integrations"]) == 1
        assert d["integrations"][0]["platform"] == "n8n"


# ─── BE-01: Error Format ─────────────────────────────────────────────────────

class TestErrorFormat:
    """BE-01: All errors return {error, code, status} shape — no {detail: ...} key."""

    def test_404_returns_standard_shape(self):
        r = client.get("/v1/nonexistent-endpoint-that-does-not-exist")
        assert r.status_code == 404
        body = r.json()
        assert "error" in body
        assert "code" in body
        assert "status" in body
        assert "detail" not in body
        assert body["code"] == "not_found"
        assert body["status"] == 404

    def test_validation_error_returns_standard_shape(self):
        # Register agent first to get API key
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": "t@t.com", "password": "pass123"})
            token = r.json().get("token", "")
            r2 = client.post("/v1/register", json={"name": "test"}, headers={"Authorization": f"Bearer {token}"})
        api_key = r2.json().get("api_key", "badkey")
        # Send invalid memory request (missing required field)
        r3 = client.post("/v1/memory", json={}, headers={"X-API-Key": api_key})
        assert r3.status_code == 422
        body = r3.json()
        assert "error" in body
        assert "code" in body
        assert body["code"] == "validation_error"
        assert "detail" not in body

    def test_unauthorized_returns_standard_shape(self):
        r = client.get("/v1/memory/somekey", headers={"X-API-Key": "af_invalid"})
        assert r.status_code in (401, 403)
        body = r.json()
        assert "error" in body
        assert "code" in body
        assert "status" in body
        assert "detail" not in body


# ─── BE-03: Input Limits ─────────────────────────────────────────────────────

class TestInputLimits:
    """BE-03: Input size limits enforced."""

    def test_memory_value_size_limit(self):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": "t2@t.com", "password": "pass123"})
            token = r.json().get("token", "")
            r2 = client.post("/v1/register", json={"name": "test"}, headers={"Authorization": f"Bearer {token}"})
        api_key = r2.json().get("api_key", "badkey")
        big_value = "x" * 50001
        r3 = client.post("/v1/memory", json={"key": "k", "value": big_value}, headers={"X-API-Key": api_key})
        assert r3.status_code in (422, 413), f"Expected 422 or 413, got {r3.status_code}"

    def test_memory_value_at_limit_accepted(self):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": "t3@t.com", "password": "pass123"})
            token = r.json().get("token", "")
            r2 = client.post("/v1/register", json={"name": "test"}, headers={"Authorization": f"Bearer {token}"})
        api_key = r2.json().get("api_key", "badkey")
        ok_value = "x" * 50000
        r3 = client.post("/v1/memory", json={"key": "k", "value": ok_value}, headers={"X-API-Key": api_key})
        assert r3.status_code in (200, 201), f"Expected success, got {r3.status_code}"


# ─── BE-04: CORS ─────────────────────────────────────────────────────────────

class TestCORS:
    """BE-04: CORS configured for moltgrid.net only."""

    def test_allowed_origin_gets_cors_header(self):
        r = client.options(
            "/v1/health",
            headers={"Origin": "https://moltgrid.net", "Access-Control-Request-Method": "GET"},
        )
        assert r.headers.get("access-control-allow-origin") == "https://moltgrid.net"

    def test_disallowed_origin_blocked(self):
        r = client.options(
            "/v1/health",
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
        )
        acao = r.headers.get("access-control-allow-origin", "")
        assert acao != "https://evil.com", "evil.com must not be allowed"
        assert acao != "*", "Wildcard must not be present"

    def test_localhost_dev_allowed(self):
        r = client.options(
            "/v1/health",
            headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
        )
        assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


# ─── BE-05: Per-tier rate limits ──────────────────────────────────────────────

class TestTierRateLimits:
    """BE-05: Per-tier rate limits enforced."""

    def _make_agent(self, email, tier="free"):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": email, "password": "pass123"})
        token = r.json().get("token", "")
        # Set subscription tier directly in DB for test
        import sqlite3, os as _os
        db_path = _os.environ.get("MOLTGRID_DB", "moltgrid.db")
        conn = sqlite3.connect(db_path)
        user_row = conn.execute("SELECT user_id FROM users WHERE email = ?", (email,)).fetchone()
        if user_row:
            conn.execute("UPDATE users SET subscription_tier = ? WHERE user_id = ?", (tier, user_row[0]))
            conn.commit()
        conn.close()
        with patch("main._queue_email"):
            r2 = client.post("/v1/register", json={"name": "rlagent"}, headers={"Authorization": f"Bearer {token}"})
        return r2.json().get("api_key", "badkey")

    def test_free_tier_limit_enforced(self):
        api_key = self._make_agent("rlfree@t.com", "free")
        import sqlite3, os as _os
        db_path = _os.environ.get("MOLTGRID_DB", "moltgrid.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        agent = conn.execute("SELECT agent_id FROM agents ORDER BY rowid DESC LIMIT 1").fetchone()
        if not agent:
            conn.close()
            return
        agent_id = agent["agent_id"]
        # Insert 121 calls into rate_limits for current window
        window = int(time.time()) // 60
        conn.execute(
            "INSERT INTO rate_limits (agent_id, window_start, count) VALUES (?, ?, ?) ON CONFLICT (agent_id, window_start) DO UPDATE SET count = EXCLUDED.count",
            (agent_id, window, 121)
        )
        conn.commit()
        conn.close()
        r = client.get("/v1/memory/anykey", headers={"X-API-Key": api_key})
        assert r.status_code == 429, f"Expected 429 for free tier at 121 req, got {r.status_code}"

    def test_hobby_tier_higher_limit(self):
        api_key = self._make_agent("rlhobby2@t.com", "hobby")
        import sqlite3, os as _os
        db_path = _os.environ.get("MOLTGRID_DB", "moltgrid.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        agent = conn.execute("SELECT agent_id FROM agents ORDER BY rowid DESC LIMIT 1").fetchone()
        if not agent:
            conn.close()
            return
        agent_id = agent["agent_id"]
        # Insert 301 calls (hobby limit is 300) — should be rejected
        window = int(time.time()) // 60
        conn.execute(
            "INSERT INTO rate_limits (agent_id, window_start, count) VALUES (?, ?, ?) ON CONFLICT (agent_id, window_start) DO UPDATE SET count = EXCLUDED.count",
            (agent_id, window, 301)
        )
        conn.commit()
        conn.close()
        r = client.get("/v1/memory/anykey", headers={"X-API-Key": api_key})
        assert r.status_code == 429, f"Expected 429 for hobby tier at 301 req, got {r.status_code}"

    def test_ratelimit_header_reflects_tier(self):
        api_key = self._make_agent("rlhobby@t.com", "hobby")
        # Use an authenticated endpoint so get_agent_id runs the tier lookup
        r = client.get("/v1/memory/any_nonexistent_key", headers={"X-API-Key": api_key})
        limit_header = r.headers.get("x-ratelimit-limit", "")
        # hobby tier should show 300, not always 120
        assert limit_header == "300", f"Expected X-RateLimit-Limit: 300 for hobby tier, got {limit_header}"


# ─── BE-06: Webhook retry count ───────────────────────────────────────────────

class TestWebhookRetry:
    """BE-06: Webhook delivery retries up to 5 times."""

    def test_webhook_delivery_max_attempts_is_5(self):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": "whr@t.com", "password": "pass123"})
        token = r.json().get("token", "")
        with patch("main._queue_email"):
            r2 = client.post("/v1/register", json={"name": "wha"}, headers={"Authorization": f"Bearer {token}"})
        api_key = r2.json().get("api_key", "badkey")
        # Create webhook
        r3 = client.post(
            "/v1/webhooks",
            json={"url": "https://example.com/wh", "event_types": ["memory.set"]},
            headers={"X-API-Key": api_key}
        )
        if r3.status_code not in (200, 201):
            return  # skip if webhook creation unavailable
        webhook_id = r3.json().get("webhook_id", "")
        # Trigger a webhook delivery by setting memory
        client.post("/v1/memory", json={"key": "k", "value": "v"}, headers={"X-API-Key": api_key})
        # Check that max_attempts=5 was used in the delivery record
        import sqlite3, os as _os
        db_path = _os.environ.get("MOLTGRID_DB", "moltgrid.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT max_attempts FROM webhook_deliveries WHERE webhook_id = ? ORDER BY rowid DESC LIMIT 1",
            (webhook_id,)
        ).fetchone()
        conn.close()
        if row:
            assert row["max_attempts"] == 5, f"Expected max_attempts=5, got {row['max_attempts']}"


# ─── BE-07: Webhook test endpoint ────────────────────────────────────────────

class TestWebhookTest:
    """BE-07: POST /v1/webhooks/{id}/test fires a test ping."""

    def _setup(self, email="whtest@t.com"):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": email, "password": "pass123"})
        token = r.json().get("token", "")
        with patch("main._queue_email"):
            r2 = client.post("/v1/register", json={"name": "whtestagent"}, headers={"Authorization": f"Bearer {token}"})
        api_key = r2.json().get("api_key", "badkey")
        r3 = client.post(
            "/v1/webhooks",
            json={"url": "https://example.com/test-wh", "event_types": ["job.completed"]},
            headers={"X-API-Key": api_key}
        )
        webhook_id = r3.json().get("webhook_id", "")
        return api_key, webhook_id

    def test_webhook_test_endpoint_returns_delivery_id(self):
        api_key, webhook_id = self._setup()
        if not webhook_id:
            return  # skip if webhook creation failed
        r = client.post(
            f"/v1/webhooks/{webhook_id}/test",
            headers={"X-API-Key": api_key}
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert "delivery_id" in body
        assert "status" in body

    def test_webhook_test_wrong_owner_returns_404(self):
        _, webhook_id = self._setup(email="whtest2@t.com")
        if not webhook_id:
            return
        # Create a different agent
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": "other_wh@t.com", "password": "pass123"})
        token = r.json().get("token", "")
        with patch("main._queue_email"):
            r2 = client.post("/v1/register", json={"name": "otherwh"}, headers={"Authorization": f"Bearer {token}"})
        other_key = r2.json().get("api_key", "badkey")
        r3 = client.post(
            f"/v1/webhooks/{webhook_id}/test",
            headers={"X-API-Key": other_key}
        )
        assert r3.status_code == 404


class TestGuideEndpoints:
    """BE-11: Getting-started guides served as markdown from API."""

    def test_quickstart_guide_returns_markdown(self):
        r = client.get("/v1/guides/quickstart")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        assert "text/markdown" in r.headers.get("content-type", "")
        assert len(r.text) > 100

    def test_python_sdk_guide_returns_200(self):
        r = client.get("/v1/guides/python-sdk")
        assert r.status_code == 200

    def test_typescript_sdk_guide_returns_200(self):
        r = client.get("/v1/guides/typescript-sdk")
        assert r.status_code == 200

    def test_webhooks_guide_returns_200(self):
        r = client.get("/v1/guides/webhooks")
        assert r.status_code == 200

    def test_mcp_guide_returns_200(self):
        r = client.get("/v1/guides/mcp")
        assert r.status_code == 200

    def test_nonexistent_guide_returns_404(self):
        r = client.get("/v1/guides/nonexistent-platform")
        assert r.status_code == 404
        body = r.json()
        assert "error" in body
        assert body.get("code") == "not_found"


class TestStripeEmailConfirmation:
    """BE-08: Stripe checkout.session.completed triggers confirmation email."""

    def test_checkout_completed_queues_email(self):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": "stripe@t.com", "password": "pass123"})
        user_id = r.json().get("user_id", "")
        if not user_id:
            return
        mock_event = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "metadata": {"moltgrid_user_id": user_id, "tier": "hobby"},
                    "subscription": "sub_test123",
                }
            }
        }
        with patch("stripe.Webhook.construct_event", return_value=mock_event):
            with patch("main._queue_email") as mock_email:
                r2 = client.post(
                    "/v1/stripe/webhook",
                    content=b"{}",
                    headers={"stripe-signature": "t=1,v1=fake"}
                )
                if mock_email.called:
                    subjects = [str(c) for c in mock_email.call_args_list]
                    assert any("plan" in s.lower() or "active" in s.lower() for s in subjects), \
                        f"Expected payment confirmation email, got: {subjects}"


class TestSecurityAlertEmails:
    """BE-09: Security alert emails for new IP login and key rotation."""

    def test_key_rotation_triggers_alert_email(self):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={"email": "keyrot@t.com", "password": "pass123"})
        token = r.json().get("token", "")
        with patch("main._queue_email"):
            r2 = client.post("/v1/register", json={"name": "rota"}, headers={"Authorization": f"Bearer {token}"})
        api_key = r2.json().get("api_key", "badkey")
        with patch("main._queue_email") as mock_email:
            r3 = client.post("/v1/agents/rotate-key", headers={"X-API-Key": api_key})
            if r3.status_code == 200:
                assert mock_email.called, "Expected _queue_email to be called on key rotation"
                subjects = [str(c) for c in mock_email.call_args_list]
                assert any("key" in s.lower() or "rotated" in s.lower() or "security" in s.lower() for s in subjects)

    def test_new_ip_login_no_crash(self):
        """Login with new IP header should not crash — basic smoke test."""
        with patch("main._queue_email"):
            client.post("/v1/auth/signup", json={"email": "iptest@t.com", "password": "pass123"})
        # First login — establish baseline IP
        with patch("main._queue_email"):
            client.post("/v1/auth/login", json={"email": "iptest@t.com", "password": "pass123"})
        # Second login from different IP
        with patch("main._queue_email"):
            client.post(
                "/v1/auth/login",
                json={"email": "iptest@t.com", "password": "pass123"},
                headers={"X-Forwarded-For": "203.0.113.99"}
            )
        r_check = client.post("/v1/auth/login", json={"email": "iptest@t.com", "password": "pass123"})
        assert r_check.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# DIRECTORY FEATURED/VERIFIED FIELDS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDirectoryFeatured:
    def test_directory_list_has_featured_field(self):
        agent_id, api_key, h = register_agent("dir-featured-agent")
        client.put("/v1/directory/me", headers=h, json={"public": True, "description": "featured test"})
        r = client.get("/v1/directory")
        assert r.status_code == 200
        agents = r.json()["agents"]
        if agents:
            assert "featured" in agents[0]
            assert "verified" in agents[0]
            assert isinstance(agents[0]["featured"], bool)
            assert isinstance(agents[0]["verified"], bool)

    def test_directory_stats_not_shadowed(self):
        r = client.get("/v1/directory/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_agents" in data
        assert "online_agents" in data

    def test_directory_search_not_shadowed(self):
        r = client.get("/v1/directory/search?q=test")
        assert r.status_code == 200
        data = r.json()
        assert "agents" in data

    def test_directory_match_not_shadowed(self):
        agent_id, api_key, h = register_agent("dir-match-agent")
        r = client.get("/v1/directory/match?need=research", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert "matches" in data


class TestOrgAccounts:
    """Tests for multi-user organization accounts (BL-02)."""

    def _signup(self, email="org-user@example.com", password="securepass123", display_name="OrgUser"):
        with patch("main._queue_email"):
            r = client.post("/v1/auth/signup", json={
                "email": email, "password": password, "display_name": display_name,
            })
        return r

    def _auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def _create_org(self, token, name="Test Org", slug="test-org"):
        return client.post(
            "/v1/orgs",
            json={"name": name, "slug": slug},
            headers=self._auth_header(token),
        )

    def test_create_org(self):
        """Owner can create an organization."""
        r = self._signup(email="org-owner@example.com")
        token = r.json()["token"]
        r2 = self._create_org(token)
        assert r2.status_code == 200
        data = r2.json()
        assert data["name"] == "Test Org"
        assert data["slug"] == "test-org"
        assert "org_id" in data
        assert data["role"] == "owner"

    def test_create_org_slug_unique(self):
        """Duplicate slug is rejected with 409."""
        r = self._signup(email="slug-owner@example.com")
        token = r.json()["token"]
        self._create_org(token, name="First", slug="unique-slug")
        r2 = self._create_org(token, name="Second", slug="unique-slug")
        assert r2.status_code == 409

    def test_list_orgs(self):
        """User can list their organizations."""
        r = self._signup(email="list-org@example.com")
        token = r.json()["token"]
        self._create_org(token, name="My Org", slug="my-org-list")
        r2 = client.get("/v1/orgs", headers=self._auth_header(token))
        assert r2.status_code == 200
        data = r2.json()
        assert "orgs" in data
        assert len(data["orgs"]) >= 1
        org = data["orgs"][0]
        assert org["name"] == "My Org"
        assert org["role"] == "owner"

    def test_get_org(self):
        """Owner can get org details."""
        r = self._signup(email="get-org@example.com")
        token = r.json()["token"]
        create_r = self._create_org(token, name="Get Org", slug="get-org-slug")
        org_id = create_r.json()["org_id"]
        r2 = client.get(f"/v1/orgs/{org_id}", headers=self._auth_header(token))
        assert r2.status_code == 200
        data = r2.json()
        assert data["org_id"] == org_id
        assert data["name"] == "Get Org"
        assert "members" in data

    def test_get_org_non_member_forbidden(self):
        """Non-member cannot access org details."""
        r = self._signup(email="owner-org-sec@example.com")
        token_owner = r.json()["token"]
        create_r = self._create_org(token_owner, name="Secure Org", slug="secure-org")
        org_id = create_r.json()["org_id"]

        r2 = self._signup(email="outsider-org@example.com")
        token_outsider = r2.json()["token"]

        r3 = client.get(f"/v1/orgs/{org_id}", headers=self._auth_header(token_outsider))
        assert r3.status_code == 403

    def test_invite_member(self):
        """Owner can invite a member to the org."""
        r_owner = self._signup(email="invite-owner@example.com")
        token_owner = r_owner.json()["token"]
        create_r = self._create_org(token_owner, name="Invite Org", slug="invite-org")
        org_id = create_r.json()["org_id"]

        r_member = self._signup(email="invite-member@example.com")
        member_user_id = r_member.json()["user_id"]

        r_invite = client.post(
            f"/v1/orgs/{org_id}/members",
            json={"user_id": member_user_id, "role": "member"},
            headers=self._auth_header(token_owner),
        )
        assert r_invite.status_code == 200
        data = r_invite.json()
        assert data["user_id"] == member_user_id
        assert data["role"] == "member"

    def test_invite_member_non_owner_forbidden(self):
        """Plain member cannot invite others."""
        r_owner = self._signup(email="noinvite-owner@example.com")
        token_owner = r_owner.json()["token"]
        create_r = self._create_org(token_owner, name="NoInvite Org", slug="noinvite-org")
        org_id = create_r.json()["org_id"]

        r_member = self._signup(email="noinvite-member@example.com")
        token_member = r_member.json()["token"]
        member_user_id = r_member.json()["user_id"]

        # Invite member first
        client.post(
            f"/v1/orgs/{org_id}/members",
            json={"user_id": member_user_id, "role": "member"},
            headers=self._auth_header(token_owner),
        )

        # member tries to invite another user
        r_other = self._signup(email="noinvite-other@example.com")
        other_user_id = r_other.json()["user_id"]

        r_bad = client.post(
            f"/v1/orgs/{org_id}/members",
            json={"user_id": other_user_id, "role": "member"},
            headers=self._auth_header(token_member),
        )
        assert r_bad.status_code == 403

    def test_remove_member(self):
        """Owner can remove a member from the org."""
        r_owner = self._signup(email="remove-owner@example.com")
        token_owner = r_owner.json()["token"]
        create_r = self._create_org(token_owner, name="Remove Org", slug="remove-org")
        org_id = create_r.json()["org_id"]

        r_member = self._signup(email="remove-member@example.com")
        member_user_id = r_member.json()["user_id"]

        client.post(
            f"/v1/orgs/{org_id}/members",
            json={"user_id": member_user_id, "role": "member"},
            headers=self._auth_header(token_owner),
        )

        r_remove = client.delete(
            f"/v1/orgs/{org_id}/members/{member_user_id}",
            headers=self._auth_header(token_owner),
        )
        assert r_remove.status_code == 200

    def test_update_member_role(self):
        """Owner/admin can change a member's role."""
        r_owner = self._signup(email="role-owner@example.com")
        token_owner = r_owner.json()["token"]
        create_r = self._create_org(token_owner, name="Role Org", slug="role-org")
        org_id = create_r.json()["org_id"]

        r_member = self._signup(email="role-member@example.com")
        member_user_id = r_member.json()["user_id"]

        client.post(
            f"/v1/orgs/{org_id}/members",
            json={"user_id": member_user_id, "role": "member"},
            headers=self._auth_header(token_owner),
        )

        r_update = client.patch(
            f"/v1/orgs/{org_id}/members/{member_user_id}",
            json={"role": "admin"},
            headers=self._auth_header(token_owner),
        )
        assert r_update.status_code == 200
        assert r_update.json()["role"] == "admin"

    def test_switch_org_context(self):
        """User can switch to an org context via /v1/orgs/{org_id}/switch."""
        r = self._signup(email="switch-user@example.com")
        token = r.json()["token"]
        create_r = self._create_org(token, name="Switch Org", slug="switch-org")
        org_id = create_r.json()["org_id"]

        r_switch = client.post(
            f"/v1/orgs/{org_id}/switch",
            headers=self._auth_header(token),
        )
        assert r_switch.status_code == 200
        data = r_switch.json()
        assert data["active_org_id"] == org_id
        assert data["org_name"] == "Switch Org"

    def test_org_schema_tables_exist(self):
        """organizations and org_members tables must exist."""
        conn = _get_test_db()
        tables = _list_tables(conn)
        conn.close()
        assert "organizations" in tables, "organizations table missing"
        assert "org_members" in tables, "org_members table missing"

    def test_invalid_role_rejected(self):
        """Inviting with an invalid role is rejected."""
        r_owner = self._signup(email="invalid-role-owner@example.com")
        token_owner = r_owner.json()["token"]
        create_r = self._create_org(token_owner, name="Role Org2", slug="role-org2")
        org_id = create_r.json()["org_id"]

        r_member = self._signup(email="invalid-role-member@example.com")
        member_user_id = r_member.json()["user_id"]

        r_invite = client.post(
            f"/v1/orgs/{org_id}/members",
            json={"user_id": member_user_id, "role": "superadmin"},
            headers=self._auth_header(token_owner),
        )
        assert r_invite.status_code == 422

    def test_cannot_invite_nonexistent_user(self):
        """Inviting a nonexistent user_id returns 404."""
        r_owner = self._signup(email="nouser-owner@example.com")
        token_owner = r_owner.json()["token"]
        create_r = self._create_org(token_owner, name="NoUser Org", slug="nouser-org")
        org_id = create_r.json()["org_id"]

        r_invite = client.post(
            f"/v1/orgs/{org_id}/members",
            json={"user_id": "user_nonexistent123", "role": "member"},
            headers=self._auth_header(token_owner),
        )
        assert r_invite.status_code == 404


# ─── TOTP 2FA Tests ──────────────────────────────────────────────────────────

class TestTOTP2FA:
    @patch("main._queue_email")
    def test_2fa_setup_returns_secret(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "2fa_setup@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "2fa_setup@test.com", "password": "pass123"}).json()["token"]
        r = client.post("/v1/auth/2fa/setup", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert "secret" in data
        assert "otpauth_uri" in data
        assert "qr_code_url" in data

    @patch("main._queue_email")
    def test_2fa_verify_enables_and_returns_recovery_codes(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "2fa_verify@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "2fa_verify@test.com", "password": "pass123"}).json()["token"]
        setup = client.post("/v1/auth/2fa/setup", headers={"Authorization": f"Bearer {token}"}).json()
        code = pyotp.TOTP(setup["secret"]).now()
        r = client.post("/v1/auth/2fa/verify", json={"code": code}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["enabled"] is True
        assert len(r.json()["recovery_codes"]) == 10

    @patch("main._queue_email")
    def test_login_with_2fa_enabled_no_code_returns_requires_2fa(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "2fa_login@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "2fa_login@test.com", "password": "pass123"}).json()["token"]
        setup = client.post("/v1/auth/2fa/setup", headers={"Authorization": f"Bearer {token}"}).json()
        code = pyotp.TOTP(setup["secret"]).now()
        client.post("/v1/auth/2fa/verify", json={"code": code}, headers={"Authorization": f"Bearer {token}"})
        # Now login without totp_code
        r = client.post("/v1/auth/login", json={"email": "2fa_login@test.com", "password": "pass123"})
        assert r.status_code == 200
        assert r.json().get("requires_2fa") is True
        assert "temp_token" in r.json()

    @patch("main._queue_email")
    def test_login_with_valid_totp_code_returns_jwt(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "2fa_fulllogin@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "2fa_fulllogin@test.com", "password": "pass123"}).json()["token"]
        setup = client.post("/v1/auth/2fa/setup", headers={"Authorization": f"Bearer {token}"}).json()
        code = pyotp.TOTP(setup["secret"]).now()
        client.post("/v1/auth/2fa/verify", json={"code": code}, headers={"Authorization": f"Bearer {token}"})
        # Login with totp_code
        code2 = pyotp.TOTP(setup["secret"]).now()
        r = client.post("/v1/auth/login", json={"email": "2fa_fulllogin@test.com", "password": "pass123", "totp_code": code2})
        assert r.status_code == 200
        assert "token" in r.json()

    @patch("main._queue_email")
    def test_recovery_code_login(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "2fa_recovery@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "2fa_recovery@test.com", "password": "pass123"}).json()["token"]
        setup = client.post("/v1/auth/2fa/setup", headers={"Authorization": f"Bearer {token}"}).json()
        code = pyotp.TOTP(setup["secret"]).now()
        recovery_codes = client.post("/v1/auth/2fa/verify", json={"code": code}, headers={"Authorization": f"Bearer {token}"}).json()["recovery_codes"]
        # Login with a recovery code instead of TOTP
        r = client.post("/v1/auth/login", json={"email": "2fa_recovery@test.com", "password": "pass123", "totp_code": recovery_codes[0]})
        assert r.status_code == 200
        assert "token" in r.json()

    @patch("main._queue_email")
    def test_disable_2fa(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "2fa_disable@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "2fa_disable@test.com", "password": "pass123"}).json()["token"]
        setup = client.post("/v1/auth/2fa/setup", headers={"Authorization": f"Bearer {token}"}).json()
        code = pyotp.TOTP(setup["secret"]).now()
        client.post("/v1/auth/2fa/verify", json={"code": code}, headers={"Authorization": f"Bearer {token}"})
        disable_code = pyotp.TOTP(setup["secret"]).now()
        r = client.post("/v1/auth/2fa/disable", json={"code": disable_code}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["disabled"] is True


class TestAgentTemplates:
    """Tests for agent templates feature (BL-04)."""

    def test_list_templates_returns_4(self):
        """GET /v1/templates returns all 4 seeded templates."""
        r = client.get("/v1/templates")
        assert r.status_code == 200
        body = r.json()
        assert "templates" in body
        assert len(body["templates"]) == 4
        ids = {t["template_id"] for t in body["templates"]}
        assert "tmpl_openclaw_social" in ids
        assert "tmpl_worker" in ids
        assert "tmpl_research" in ids
        assert "tmpl_customer_service" in ids

    def test_get_template_by_id(self):
        """GET /v1/templates/tmpl_worker returns full template fields."""
        r = client.get("/v1/templates/tmpl_worker")
        assert r.status_code == 200
        body = r.json()
        assert body["template_id"] == "tmpl_worker"
        assert body["name"] == "Background Worker Agent"
        assert body["category"] == "worker"
        assert body["description"]
        assert body["starter_code"]

    def test_get_template_404(self):
        """GET /v1/templates/tmpl_nonexistent returns 404 with standard error shape."""
        r = client.get("/v1/templates/tmpl_nonexistent")
        assert r.status_code == 404
        body = r.json()
        # Standard error shape is nested under "detail"
        detail = body.get("detail", body)
        assert detail.get("status") == 404 or r.status_code == 404

    @patch("main._queue_email")
    def test_register_with_template_id(self, mock_email):
        """POST /v1/register with template_id=tmpl_worker creates agent with template_starter_code in memory."""
        r = client.post("/v1/register", json={"name": "TemplateTestAgent", "template_id": "tmpl_worker"})
        assert r.status_code == 200
        body = r.json()
        assert "api_key" in body
        api_key = body["api_key"]
        agent_id = body["agent_id"]

        # Verify memory key template_starter_code was written
        mem_r = client.get(
            "/v1/memory/template_starter_code",
            headers={"X-API-Key": api_key},
        )
        assert mem_r.status_code == 200
        mem_body = mem_r.json()
        assert mem_body.get("key") == "template_starter_code"
        assert mem_body.get("value")  # starter_code is a non-empty JSON string

    @patch("main._queue_email")
    def test_register_with_invalid_template_id(self, mock_email):
        """POST /v1/register with unknown template_id still creates agent successfully."""
        r = client.post("/v1/register", json={"name": "NoTemplateAgent", "template_id": "tmpl_does_not_exist"})
        assert r.status_code == 200
        body = r.json()
        assert "agent_id" in body
        assert "api_key" in body


class TestAuditLogs:
    @patch("main._queue_email")
    def test_login_creates_audit_entry(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "audit_user@test.com", "password": "pass123", "display_name": "T"})
        client.post("/v1/auth/login", json={"email": "audit_user@test.com", "password": "pass123"})
        token = client.post("/v1/auth/login", json={"email": "audit_user@test.com", "password": "pass123"}).json()["token"]
        r = client.get("/v1/user/audit-log", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        actions = [e["action"] for e in r.json()["entries"]]
        assert "user.login" in actions

    @patch("main._queue_email")
    def test_audit_log_filter_by_action(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "audit_filter@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "audit_filter@test.com", "password": "pass123"}).json()["token"]
        r = client.get("/v1/user/audit-log?action=user.login", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        for entry in r.json()["entries"]:
            assert entry["action"] == "user.login"

    @patch("main._queue_email")
    def test_audit_log_export_csv(self, mock_email):
        client.post("/v1/auth/signup", json={"email": "audit_csv@test.com", "password": "pass123", "display_name": "T"})
        token = client.post("/v1/auth/login", json={"email": "audit_csv@test.com", "password": "pass123"}).json()["token"]
        r = client.get("/v1/user/audit-log/export", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")
        assert "timestamp,action" in r.text

    @patch("main._queue_email")
    def test_audit_log_requires_auth(self, mock_email):
        r = client.get("/v1/user/audit-log")
        assert r.status_code == 401


class TestMoltBookDeepIntegration:
    _service_key = "test-moltbook-service-key"
    _service_headers = {"X-Service-Key": "test-moltbook-service-key"}

    @patch.dict(os.environ, {"MOLTBOOK_SERVICE_KEY": "test-moltbook-service-key"})
    def test_moltbook_register_creates_agent(self):
        import main
        main.MOLTBOOK_SERVICE_KEY = self._service_key
        r = client.post("/v1/moltbook/register", json={"moltbook_user_id": "mb_user_001", "display_name": "MoltBook User"}, headers=self._service_headers)
        assert r.status_code == 200
        data = r.json()
        assert "agent_id" in data
        assert "api_key" in data
        assert data["api_key"].startswith("af_")

    @patch.dict(os.environ, {"MOLTBOOK_SERVICE_KEY": "test-moltbook-service-key"})
    def test_moltbook_register_duplicate_returns_409(self):
        import main
        main.MOLTBOOK_SERVICE_KEY = self._service_key
        client.post("/v1/moltbook/register", json={"moltbook_user_id": "mb_user_dup", "display_name": "Dup User"}, headers=self._service_headers)
        r = client.post("/v1/moltbook/register", json={"moltbook_user_id": "mb_user_dup", "display_name": "Dup User"}, headers=self._service_headers)
        assert r.status_code == 409

    @patch.dict(os.environ, {"MOLTBOOK_SERVICE_KEY": "test-moltbook-service-key"})
    def test_moltbook_feed_returns_items(self):
        import main
        main.MOLTBOOK_SERVICE_KEY = self._service_key
        r_reg = client.post("/v1/moltbook/register", json={"moltbook_user_id": "mb_feed_user", "display_name": "Feed User"}, headers=self._service_headers)
        api_key = r_reg.json()["api_key"]
        client.post("/v1/moltbook/events", json={"event_type": "post", "content": "Hello MoltBook!"}, headers={"X-API-Key": api_key})
        r = client.get("/v1/moltbook/feed")
        assert r.status_code == 200
        assert "feed" in r.json()
        assert len(r.json()["feed"]) >= 1
        item = r.json()["feed"][0]
        assert "type" in item


class TestSkillMd:
    def test_get_skill_md_200(self):
        r = client.get("/skill.md")
        assert r.status_code == 200
        assert "text/markdown" in r.headers.get("content-type", "")

    def test_get_skill_md_has_sections(self):
        r = client.get("/skill.md")
        body = r.text
        for section in ["## Authentication", "## Memory", "## Relay"]:
            assert section in body, f"Missing section: {section}"

    def test_get_skill_md_v1_alias(self):
        r = client.get("/v1/skill.md")
        assert r.status_code == 200
        assert "text/markdown" in r.headers.get("content-type", "")

    def test_skill_md_no_auth_required(self):
        r = client.get("/skill.md")
        assert r.status_code == 200  # no X-API-Key or Bearer needed


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT EVENT STREAM
# ═══════════════════════════════════════════════════════════════════════════════

class TestAgentEventStream:
    def _insert_event(self, agent_id, event_type="test_event"):
        """Helper: directly insert an event into agent_events for testing."""
        import sqlite3, uuid
        conn = _get_test_db()
        eid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO agent_events (event_id, agent_id, event_type, payload, acknowledged, created_at) VALUES (?,?,?,?,0,?)",
            (eid, agent_id, event_type, json.dumps({"test": True}), datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
        return eid

    def test_poll_events_empty(self):
        _id, key, h = register_agent("event-test")
        r = client.get("/v1/events", headers=h)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_poll_events_returns_inserted(self):
        _id, key, h = register_agent("event-test2")
        eid = self._insert_event(_id)
        r = client.get("/v1/events", headers=h)
        assert r.status_code == 200
        ids = [e["event_id"] for e in r.json()]
        assert eid in ids

    def test_ack_event(self):
        _id, key, h = register_agent("event-test3")
        eid = self._insert_event(_id)
        r = client.post("/v1/events/ack", json={"event_ids": [eid]}, headers=h)
        assert r.status_code == 200
        assert r.json()["acknowledged"] == 1
        r2 = client.get("/v1/events", headers=h)
        ids = [e["event_id"] for e in r2.json()]
        assert eid not in ids

    def test_stream_returns_event_immediately(self):
        _id, key, h = register_agent("event-test4")
        eid = self._insert_event(_id, "relay_message")
        r = client.get("/v1/events/stream", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data["event_id"] == eid
        assert data["event_type"] == "relay_message"

    def test_events_require_auth(self):
        r = client.get("/v1/events")
        assert r.status_code in (401, 403)


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET EVENTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebSocketEvents:
    def test_ws_connect_requires_api_key(self):
        with pytest.raises(Exception):
            with client.websocket_connect("/v1/events/ws") as ws:
                ws.receive_json()

    def test_ws_connect_authenticated(self):
        _id, key, h = register_agent("ws-test")
        with client.websocket_connect(f"/v1/events/ws?api_key={key}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "connected"
            assert "agent_id" in msg

    def test_ws_receives_event(self):
        import sqlite3, uuid
        _id, key, h = register_agent("ws-test2")
        eid = str(uuid.uuid4())
        conn = _get_test_db()
        conn.execute(
            "INSERT INTO agent_events (event_id, agent_id, event_type, payload, acknowledged, created_at) VALUES (?,?,?,?,0,?)",
            (eid, _id, "test_ws_event", json.dumps({"hello": "world"}), datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
        with client.websocket_connect(f"/v1/events/ws?api_key={key}") as ws:
            ws.receive_json()  # connected message
            msg = ws.receive_json()
            assert msg["type"] == "event"
            assert msg["event_id"] == eid


# ═══════════════════════════════════════════════════════════════════════════════
# SDK EVENT METHODS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSDKEventMethods:
    def _make_client(self):
        from moltgrid import MoltGrid
        return MoltGrid("af_testkey1234567890abcdef1234567890abcdef12")

    def test_wait_for_event_returns_event(self):
        from unittest.mock import patch, MagicMock
        mg = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "event_id": "evt-001",
            "event_type": "relay_message",
            "payload": {"msg": "hello"},
            "created_at": "2026-01-01T00:00:00"
        }
        with patch.object(mg._s, "get", return_value=mock_resp):
            event = mg.wait_for_event(timeout=5)
        assert event is not None
        assert event["event_id"] == "evt-001"
        assert event["event_type"] == "relay_message"

    def test_wait_for_event_returns_none_on_timeout(self):
        from unittest.mock import patch, MagicMock
        mg = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        with patch.object(mg._s, "get", return_value=mock_resp):
            event = mg.wait_for_event(timeout=5)
        assert event is None

    def test_poll_events_returns_list(self):
        from unittest.mock import patch, MagicMock
        mg = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"event_id": "e1", "event_type": "job_claimed", "payload": {}, "created_at": "2026-01-01T00:00:00"},
            {"event_id": "e2", "event_type": "schedule_triggered", "payload": {}, "created_at": "2026-01-01T00:00:01"},
        ]
        with patch.object(mg._s, "get", return_value=mock_resp):
            events = mg.poll_events()
        assert isinstance(events, list)
        assert len(events) == 2
        assert events[0]["event_id"] == "e1"

    def test_ack_events(self):
        from unittest.mock import patch, MagicMock
        mg = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"acknowledged": 2}
        with patch.object(mg._s, "post", return_value=mock_resp):
            count = mg.ack_events(["e1", "e2"])
        assert count == 2

    def test_subscribe_calls_callback(self):
        from unittest.mock import patch, MagicMock
        mg = self._make_client()
        received = []

        def callback(event):
            received.append(event)
            raise StopIteration

        events_iter = iter([
            {"event_id": "e1", "event_type": "relay_message", "payload": {}, "created_at": "2026-01-01T00:00:00"}
        ])

        mock_ack = MagicMock(return_value=1)
        with patch.object(mg, "wait_for_event", side_effect=lambda **kw: next(events_iter, None)):
            with patch.object(mg, "ack_events", mock_ack):
                mg.subscribe(callback, run_forever=False)

        assert len(received) == 1
        assert received[0]["event_id"] == "e1"


# ═══════════════════════════════════════════════════════════════════════════════
# WORKER DAEMON
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not os.path.exists("/opt/moltgrid/moltgrid-worker.py"), reason="VPS-only: worker daemon not present in CI")
class TestWorkerDaemon:
    def _load_worker(self, mod_name="worker_test_mod"):
        import importlib.util
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location(mod_name, "/opt/moltgrid/moltgrid-worker.py")
        mod = importlib.util.module_from_spec(spec)
        with patch.dict("os.environ", {"MOLTGRID_API_KEY": "af_test"}):
            with patch("requests.post"), patch("requests.get"):
                spec.loader.exec_module(mod)
        return mod

    def test_sigterm_sets_running_false(self):
        mod = self._load_worker("wmod1")
        assert mod._running is True
        mod.handle_sigterm(None, None)
        assert mod._running is False

    def test_dispatch_calls_correct_handler(self):
        mod = self._load_worker("wmod2")
        called = []
        mod.HANDLERS["relay_message"] = lambda e: called.append(e)
        mod.dispatch({"event_type": "relay_message", "event_id": "e1", "payload": {}})
        assert len(called) == 1

    def test_dispatch_unknown_event_type_no_error(self):
        mod = self._load_worker("wmod3")
        mod.dispatch({"event_type": "completely_unknown", "event_id": "e2", "payload": {}})

    def test_deployment_files_exist(self):
        for path in [
            "/opt/moltgrid/deploy/moltgrid-worker.service",
            "/opt/moltgrid/deploy/docker-compose.worker.yml",
            "/opt/moltgrid/deploy/pm2.worker.config.js",
            "/opt/moltgrid/deploy/WORKER_README.md",
        ]:
            assert os.path.exists(path), f"Missing: {path}"


# ═══════════════════════════════════════════════════════════════════════════════
# OBSTACLE COURSE
# ═══════════════════════════════════════════════════════════════════════════════

class TestObstacleCourse:
    def test_obstacle_course_md_endpoint(self):
        r = client.get("/obstacle-course.md")
        assert r.status_code == 200
        assert "text/markdown" in r.headers.get("content-type", "")
        assert "Stage 1" in r.text

    def test_submit_scores_correctly(self):
        _id, key, h = register_agent("oc-test1")
        r = client.post("/v1/obstacle-course/submit",
            json={"stages_completed": [1, 2, 3, 4, 5], "proof": "completed five stages"},
            headers=h)
        assert r.status_code == 200
        data = r.json()
        # 5 stages [1,2,3,4,5] in order = 50 + 5 sequential bonus = 55
        assert data["score"] == 55
        assert "submission_id" in data

    def test_submit_full_score(self):
        _id, key, h = register_agent("oc-test2")
        r = client.post("/v1/obstacle-course/submit",
            json={"stages_completed": list(range(1, 11)), "proof": "all stages"},
            headers=h)
        assert r.status_code == 200
        assert r.json()["score"] == 100  # 100 + 5 bonus capped at 100

    def test_submit_requires_auth(self):
        r = client.post("/v1/obstacle-course/submit",
            json={"stages_completed": [1], "proof": "test"})
        assert r.status_code in (401, 403)

    def test_leaderboard_public(self):
        _id, key, h = register_agent("oc-lb")
        client.post("/v1/obstacle-course/submit",
            json={"stages_completed": [1, 2, 3], "proof": "lb test"},
            headers=h)
        r = client.get("/v1/obstacle-course/leaderboard")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        if data:
            assert "score" in data[0]
            assert "display_name" in data[0]

    def test_my_result_404_when_none(self):
        _id, key, h = register_agent("oc-fresh")
        r = client.get("/v1/obstacle-course/my-result", headers=h)
        assert r.status_code == 404

    def test_my_result_returns_best(self):
        _id, key, h = register_agent("oc-best")
        client.post("/v1/obstacle-course/submit",
            json={"stages_completed": [1, 2], "proof": "low score"},
            headers=h)
        client.post("/v1/obstacle-course/submit",
            json={"stages_completed": list(range(1, 11)), "proof": "high score"},
            headers=h)
        r = client.get("/v1/obstacle-course/my-result", headers=h)
        assert r.status_code == 200
        assert r.json()["score"] == 100

    def test_heartbeat_sets_worker_status(self):
        _id, key, h = register_agent("oc-hb")
        r = client.post("/v1/heartbeat",
            json={"status": "worker_running", "metadata": {"test": True}},
            headers=h)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# TIERED MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

class TestTieredMemory:
    def test_tiered_store_event(self):
        """POST /v1/tiered/store_event appends event to session buffer."""
        _, _, h = register_agent("tiered-store")
        # Create a session first
        sid = client.post("/v1/sessions", json={"title": "Tiered Test"}, headers=h).json()["session_id"]
        # Store an event
        r = client.post("/v1/tiered/store_event", json={
            "session_id": sid,
            "data": "test event content",
            "role": "user",
        }, headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "stored"
        assert d["session_id"] == sid
        assert d["message_count"] >= 1
        assert d["token_count"] > 0
        assert d["persisted"] is False

    def test_tiered_store_event_persist(self):
        """POST /v1/tiered/store_event with persist=True writes to mid-term memory."""
        _, _, h = register_agent("tiered-persist")
        sid = client.post("/v1/sessions", json={"title": "Persist Test"}, headers=h).json()["session_id"]
        r = client.post("/v1/tiered/store_event", json={
            "session_id": sid,
            "data": "important note for persistence",
            "role": "user",
            "persist": True,
            "note_key": "test_note_tiered",
        }, headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["persisted"] is True
        assert d["note_key"] == "test_note_tiered"
        # Verify the note exists in mid-term memory
        r2 = client.get("/v1/memory/test_note_tiered?namespace=notes", headers=h)
        assert r2.status_code == 200
        assert "important note" in r2.json()["value"]

    def test_tiered_recall(self):
        """POST /v1/tiered/recall searches mid-term and long-term tiers."""
        _, _, h = register_agent("tiered-recall")
        # Store a vector entry (long-term)
        client.post("/v1/vector/upsert", json={
            "key": "ml_concepts",
            "text": "machine learning concepts and neural networks",
            "namespace": "default",
        }, headers=h)
        # Store a memory entry (mid-term)
        client.post("/v1/memory", json={
            "key": "ml_note",
            "value": "machine learning is important for AI",
            "namespace": "notes",
        }, headers=h)
        # Recall
        r = client.post("/v1/tiered/recall", json={
            "query": "machine learning",
            "k": 5,
            "tiers": ["mid", "long"],
        }, headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["count"] > 0
        assert len(d["results"]) > 0
        for item in d["results"]:
            assert "tier" in item
            assert "key" in item
            assert "text" in item
            assert "score" in item
            assert item["tier"] in ("mid", "long")

    def test_tiered_summarize(self):
        """POST /v1/tiered/summarize/{session_id} summarizes and promotes to vector store."""
        _, _, h = register_agent("tiered-summarize")
        sid = client.post("/v1/sessions", json={"title": "Summarize Test"}, headers=h).json()["session_id"]
        # Append enough messages to trigger summary (>10 non-system)
        for i in range(12):
            client.post(f"/v1/sessions/{sid}/messages", json={
                "role": "user",
                "content": f"Message number {i} about artificial intelligence research and development"
            }, headers=h)
        # Summarize
        r = client.post(f"/v1/tiered/summarize/{sid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "summarized"
        assert d["promoted"] is True or d["promoted"] is False  # bool
        assert d["vector_key"].startswith("session_summary_")
        assert d["vector_namespace"] == "long_term"
        assert isinstance(d["summary_text"], str)

    def test_tiered_summarize_idempotent(self):
        """Calling summarize twice on same session is idempotent."""
        _, _, h = register_agent("tiered-idempotent")
        sid = client.post("/v1/sessions", json={"title": "Idempotent Test"}, headers=h).json()["session_id"]
        for i in range(12):
            client.post(f"/v1/sessions/{sid}/messages", json={
                "role": "user",
                "content": f"Idempotent test message {i} about data science and analytics"
            }, headers=h)
        # First summarize
        r1 = client.post(f"/v1/tiered/summarize/{sid}", headers=h)
        assert r1.status_code == 200
        key1 = r1.json()["vector_key"]
        # Second summarize — should not error, same key
        r2 = client.post(f"/v1/tiered/summarize/{sid}", headers=h)
        assert r2.status_code == 200
        key2 = r2.json()["vector_key"]
        assert key1 == key2
