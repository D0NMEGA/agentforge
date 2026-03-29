"""
Phase 64 HIGH2 fixes -- test suite.

Tests for 6 high-severity bugs:
  HIGH2-01: /v1/directory/network 500 error
  HIGH2-02: Directory search not filtering by q param
  HIGH2-03: Queue name alias (queue -> queue_name)
  HIGH2-04: Job/task result not persisted from body
  HIGH2-05: Unicode corruption in encrypt/decrypt
  HIGH2-06: Memory TTL alias (ttl -> ttl_seconds)
"""
import sys
import os
import json
import uuid
import sqlite3
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db as _db_module
from db import _init_db_sqlite
from helpers import hash_key


# ---- Fixtures ----------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path):
    """Create a fresh SQLite DB with full schema."""
    db_path = str(tmp_path / "test_high2.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _init_db_sqlite(conn)
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def seed_agents(test_db):
    """Seed two test agents with known names for search testing."""
    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    now = datetime.now(timezone.utc).isoformat()
    agent1_id = f"agent_{uuid.uuid4().hex[:16]}"
    agent1_key = f"mg_{uuid.uuid4().hex}"
    agent2_id = f"agent_{uuid.uuid4().hex[:16]}"
    agent2_key = f"mg_{uuid.uuid4().hex}"
    conn.execute(
        "INSERT INTO agents (agent_id, api_key_hash, name, description, capabilities, skills, created_at, owner_id, public) VALUES (?,?,?,?,?,?,?,?,?)",
        (agent1_id, hash_key(agent1_key), "AlphaBot", "Alpha test agent", '["testing"]', '["search"]', now, "test_user", 1),
    )
    conn.execute(
        "INSERT INTO agents (agent_id, api_key_hash, name, description, capabilities, skills, created_at, owner_id, public) VALUES (?,?,?,?,?,?,?,?,?)",
        (agent2_id, hash_key(agent2_key), "BetaBot", "Beta test agent", '["testing"]', '["search"]', now, "test_user", 1),
    )
    conn.commit()
    conn.close()
    return {
        "db_path": test_db,
        "agent1": {"id": agent1_id, "key": agent1_key, "name": "AlphaBot"},
        "agent2": {"id": agent2_id, "key": agent2_key, "name": "BetaBot"},
    }


@pytest.fixture
def client(seed_agents):
    """TestClient using isolated test DB."""
    db_path = seed_agents["db_path"]
    with patch.object(_db_module, "DB_PATH", db_path), \
         patch.object(_db_module, "_sqlite_pool", None):
        from main import app
        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


# ---- HIGH2-01: directory_network returns 200, not 500 ------------------------

def test_directory_network_200(client, seed_agents):
    """GET /v1/directory/network returns 200 with nodes key."""
    resp = client.get("/v1/directory/network")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "nodes" in data


def test_directory_network_bad_json(client, seed_agents):
    """GET /v1/directory/network returns 200 even with invalid JSON in capabilities."""
    db_path = seed_agents["db_path"]
    conn = sqlite3.connect(db_path)
    # Insert agent with invalid JSON in capabilities
    bad_id = f"agent_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO agents (agent_id, api_key_hash, name, capabilities, skills, interests, created_at, owner_id, public) VALUES (?,?,?,?,?,?,?,?,?)",
        (bad_id, "fakehash", "BadJsonBot", "not valid json", "also bad", "really bad", now, "test_user", 1),
    )
    conn.commit()
    conn.close()

    resp = client.get("/v1/directory/network")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "nodes" in data


# ---- HIGH2-02: directory search filtering ------------------------------------

def test_directory_list_q_filter(client, seed_agents):
    """GET /v1/directory?q=Alpha returns only AlphaBot."""
    resp = client.get("/v1/directory?q=Alpha")
    assert resp.status_code == 200
    data = resp.json()
    names = [a["name"] for a in data["agents"]]
    assert "AlphaBot" in names
    assert "BetaBot" not in names


def test_directory_list_q_empty_result(client, seed_agents):
    """GET /v1/directory?q=zzzznonexistent returns empty list."""
    resp = client.get("/v1/directory?q=zzzznonexistent")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["agents"]) == 0


def test_directory_list_no_q(client, seed_agents):
    """GET /v1/directory (no q) returns both agents."""
    resp = client.get("/v1/directory")
    assert resp.status_code == 200
    data = resp.json()
    names = [a["name"] for a in data["agents"]]
    assert "AlphaBot" in names
    assert "BetaBot" in names


# ---- HIGH2-03: Queue name alias ----------------------------------------------

def test_queue_submit_queue_alias():
    """QueueSubmitRequest(queue='my_queue') sets queue_name='my_queue'."""
    from models import QueueSubmitRequest
    req = QueueSubmitRequest.model_validate({"payload": "test", "queue": "my_queue"})
    assert req.queue_name == "my_queue"


def test_queue_submit_queue_name_still_works():
    """QueueSubmitRequest(queue_name='my_queue') still works."""
    from models import QueueSubmitRequest
    req = QueueSubmitRequest.model_validate({"payload": "test", "queue_name": "my_queue"})
    assert req.queue_name == "my_queue"


# ---- HIGH2-04: Job/task result from body -------------------------------------

def test_queue_complete_result_from_body(client, seed_agents):
    """POST /v1/queue/{id}/complete with JSON body persists result."""
    key = seed_agents["agent1"]["key"]
    headers = {"X-API-Key": key}

    # Submit a job
    resp = client.post("/v1/queue/submit", json={"payload": "test_job"}, headers=headers)
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    # Claim the job
    resp = client.post("/v1/queue/claim", headers=headers)
    assert resp.status_code == 200

    # Complete with JSON body containing result
    resp = client.post(f"/v1/queue/{job_id}/complete", json={"result": {"sum": 15}}, headers=headers)
    assert resp.status_code == 200

    # Verify result was persisted
    resp = client.get(f"/v1/queue/{job_id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # Result should contain the sum value (could be JSON string or dict)
    result = data.get("result", "")
    if isinstance(result, str):
        assert "15" in result or "sum" in result, f"Result should contain sum:15, got: {result}"
    else:
        assert result.get("sum") == 15


def test_task_complete_result_from_body(client, seed_agents):
    """POST /v1/tasks/{id}/complete with JSON body persists result."""
    key = seed_agents["agent1"]["key"]
    headers = {"X-API-Key": key}

    # Create a task
    resp = client.post("/v1/tasks", json={
        "title": "Test task",
        "description": "For testing result persistence",
    }, headers=headers)
    assert resp.status_code == 200
    task_id = resp.json()["task_id"]

    # Claim the task
    resp = client.post(f"/v1/tasks/{task_id}/claim", headers=headers)
    assert resp.status_code == 200

    # Complete with JSON body containing result
    resp = client.post(f"/v1/tasks/{task_id}/complete", json={"result": "done"}, headers=headers)
    assert resp.status_code == 200

    # Verify result was persisted
    resp = client.get(f"/v1/tasks/{task_id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("result") == "done", f"Expected 'done', got: {data.get('result')}"


# ---- HIGH2-05: Unicode encrypt/decrypt round-trip ----------------------------

def test_encrypt_decrypt_emoji():
    """Emoji round-trips through _encrypt/_decrypt without corruption."""
    from helpers import _encrypt, _decrypt
    original = "Hello \U0001f30d"
    encrypted = _encrypt(original)
    decrypted = _decrypt(encrypted)
    assert decrypted == original, f"Expected {original!r}, got {decrypted!r}"


def test_encrypt_decrypt_cjk():
    """CJK characters round-trip through _encrypt/_decrypt."""
    from helpers import _encrypt, _decrypt
    original = "\u4f60\u597d\u4e16\u754c"
    encrypted = _encrypt(original)
    decrypted = _decrypt(encrypted)
    assert decrypted == original, f"Expected {original!r}, got {decrypted!r}"


def test_encrypt_decrypt_rtl():
    """RTL (Arabic) text round-trips through _encrypt/_decrypt."""
    from helpers import _encrypt, _decrypt
    original = "\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645"
    encrypted = _encrypt(original)
    decrypted = _decrypt(encrypted)
    assert decrypted == original, f"Expected {original!r}, got {decrypted!r}"


# ---- HIGH2-06: Memory TTL alias ----------------------------------------------

def test_memory_ttl_alias():
    """MemorySetRequest(ttl=60) sets ttl_seconds=60."""
    from models import MemorySetRequest
    req = MemorySetRequest.model_validate({"key": "k", "value": "v", "ttl": 60})
    assert req.ttl_seconds == 60


def test_memory_ttl_seconds_still_works():
    """MemorySetRequest(ttl_seconds=120) still works."""
    from models import MemorySetRequest
    req = MemorySetRequest.model_validate({"key": "k", "value": "v", "ttl_seconds": 120})
    assert req.ttl_seconds == 120
