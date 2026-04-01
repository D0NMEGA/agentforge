"""
Power Test v4.0 Regression Tests -- v6.0 Bug Fixes

Each phase adds tests here. Tests from completed phases become regression tests
that run on EVERY subsequent phase to catch regressions.

Run: pytest tests/test_powertest_regression.py -v
"""

import os
import json
import time
import hmac
import uuid
import pytest
from unittest.mock import patch

os.environ.setdefault("MOLTGRID_DB", "test_moltgrid.db")
os.environ.setdefault("TURNSTILE_SECRET_KEY", "")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")

from fastapi.testclient import TestClient
from main import app, init_db

client = TestClient(app)


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    """Initialize test database once for all tests."""
    init_db()
    yield


def _create_agent(name: str = None):
    """Create a test agent and return (agent_id, api_key, headers).

    Uses /v1/register (the actual agent registration endpoint).
    Mocks _queue_email per project CLAUDE.md requirements.
    """
    name = name or f"test-agent-{uuid.uuid4().hex[:8]}"

    with patch("routers.auth._get_queue_email", return_value=lambda *a, **kw: None):
        resp = client.post("/v1/register", json={
            "name": name
        })
    if resp.status_code not in (200, 201):
        # Name collision -- try with unique suffix
        name = f"{name}-{uuid.uuid4().hex[:4]}"
        with patch("routers.auth._get_queue_email", return_value=lambda *a, **kw: None):
            resp = client.post("/v1/register", json={"name": name})

    data = resp.json()
    agent_id = data["agent_id"]
    api_key = data["api_key"]
    headers = {"X-API-Key": api_key}
    return agent_id, api_key, headers


@pytest.fixture(scope="module")
def agent_a():
    """First test agent."""
    return _create_agent("regression-agent-a")


@pytest.fixture(scope="module")
def agent_b():
    """Second test agent (for cross-agent tests)."""
    return _create_agent("regression-agent-b")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 57: Memory Security & Namespace Isolation
# Tests added by Phase 57 executor. Become regression tests for phases 58-62.
# ═══════════════════════════════════════════════════════════════════════════

# SEC-01: Namespace injection blocked
# (3 tests: basic injection, various payloads, e2e cross-agent)

def test_sec01_namespace_param_ignored(agent_a, agent_b):
    """SEC-01: POST /v1/memory with injected namespace stores to caller's own namespace."""
    a_id, _, a_headers = agent_a
    b_id, _, b_headers = agent_b

    # Agent A writes with namespace injected to point at agent B's namespace
    injected_ns = f"agent:{b_id}"
    resp = client.post("/v1/memory", json={
        "key": "sec01-basic",
        "value": "secret-value",
        "namespace": injected_ns,
    }, headers=a_headers)
    assert resp.status_code == 200, f"POST failed: {resp.text}"

    # The stored namespace in response must be agent A's namespace, not B's
    body = resp.json()
    assert body.get("namespace") == f"agent:{a_id}", (
        f"SEC-01 FAIL: namespace was {body.get('namespace')!r}, expected agent:{a_id!r}"
    )

    # Verify Agent A can read it from their own namespace (direct read)
    r2 = client.get("/v1/memory/sec01-basic", headers=a_headers)
    assert r2.status_code == 200, f"Direct read failed: {r2.text}"

    # Verify the data is NOT accessible in agent B's namespace
    r3 = client.get("/v1/agents/{}/memory/sec01-basic".format(b_id), headers=b_headers)
    assert r3.status_code == 404, (
        f"SEC-01 FAIL: data leaked into agent B's namespace, got {r3.status_code}"
    )


def test_sec01_namespace_various_payloads(agent_a):
    """SEC-01: Various injected namespace values all resolve to agent:{caller_id}."""
    a_id, _, a_headers = agent_a

    payloads = [
        ("evil", "sec01-evil"),
        ("agent:other-agent-xyz", "sec01-agent-ns"),
        ("", "sec01-empty"),
        ("admin", "sec01-admin"),
    ]

    for ns_value, key in payloads:
        body = {"key": key, "value": "v"}
        if ns_value != "":
            body["namespace"] = ns_value
        resp = client.post("/v1/memory", json=body, headers=a_headers)
        assert resp.status_code == 200, f"POST failed for namespace={ns_value!r}: {resp.text}"
        stored_ns = resp.json().get("namespace")
        assert stored_ns == f"agent:{a_id}", (
            f"SEC-01 FAIL: namespace={ns_value!r} produced stored_ns={stored_ns!r}, expected agent:{a_id}"
        )


def test_sec01_injection_blocked_e2e(agent_a, agent_b):
    """SEC-01: Agent B cannot read Agent A's data by injecting namespace in POST."""
    a_id, _, a_headers = agent_a
    b_id, _, b_headers = agent_b

    # Agent A writes a private key
    client.post("/v1/memory", json={
        "key": "sec01-e2e-private",
        "value": "agent-a-secret",
        "visibility": "private",
    }, headers=a_headers)

    # Agent B tries to POST with namespace=agent:{A} then read -- must not reach A's data
    resp_b_post = client.post("/v1/memory", json={
        "key": "sec01-e2e-private",
        "value": "overwrite-attempt",
        "namespace": f"agent:{a_id}",
    }, headers=b_headers)
    assert resp_b_post.status_code == 200
    # B's write must go to agent:{B}, not agent:{A}
    assert resp_b_post.json().get("namespace") == f"agent:{b_id}"

    # Agent A's original value must be unchanged
    r_a = client.get("/v1/memory/sec01-e2e-private", headers=a_headers)
    assert r_a.status_code == 200
    assert r_a.json()["value"] == "agent-a-secret", (
        "SEC-01 FAIL: Agent B overwrote Agent A's memory via namespace injection"
    )


# SEC-02: Cross-agent 404 consistency
# (3 tests: nonexistent key, private key unauthorized, response shape match)

def test_sec02_consistent_404(agent_a, agent_b):
    """SEC-02: Cross-agent endpoint returns 404 for both nonexistent and unauthorized keys."""
    a_id, _, a_headers = agent_a
    b_id, _, b_headers = agent_b

    # Agent A stores a private key
    client.post("/v1/memory", json={
        "key": "sec02-private-key",
        "value": "private-data",
        "visibility": "private",
    }, headers=a_headers)

    # Agent B queries a key that doesn't exist at all
    r_nonexistent = client.get(f"/v1/agents/{a_id}/memory/sec02-does-not-exist", headers=b_headers)
    assert r_nonexistent.status_code == 404, (
        f"SEC-02 FAIL: nonexistent key returned {r_nonexistent.status_code}"
    )

    # Agent B queries a key that EXISTS but is private to A
    r_private = client.get(f"/v1/agents/{a_id}/memory/sec02-private-key", headers=b_headers)
    assert r_private.status_code == 404, (
        f"SEC-02 FAIL: unauthorized private key returned {r_private.status_code} instead of 404 (information leak)"
    )


def test_sec02_timing_constant(agent_a, agent_b):
    """SEC-02: Timing difference between not-found and unauthorized 404 is < 50ms over 10 iterations."""
    a_id, _, a_headers = agent_a
    b_id, _, b_headers = agent_b

    # Agent A stores a private key for timing target
    client.post("/v1/memory", json={
        "key": "sec02-timing-target",
        "value": "timing-test-value",
        "visibility": "private",
    }, headers=a_headers)

    not_found_times = []
    unauthorized_times = []

    for _ in range(10):
        t0 = time.perf_counter()
        client.get(f"/v1/agents/{a_id}/memory/sec02-does-not-exist-{uuid.uuid4().hex[:6]}", headers=b_headers)
        not_found_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        client.get(f"/v1/agents/{a_id}/memory/sec02-timing-target", headers=b_headers)
        unauthorized_times.append(time.perf_counter() - t0)

    avg_not_found = sum(not_found_times) / len(not_found_times)
    avg_unauthorized = sum(unauthorized_times) / len(unauthorized_times)
    diff_ms = abs(avg_not_found - avg_unauthorized) * 1000

    assert diff_ms < 50, (
        f"SEC-02 FAIL: timing difference is {diff_ms:.1f}ms (>50ms), leaks existence information. "
        f"avg_not_found={avg_not_found*1000:.1f}ms, avg_unauthorized={avg_unauthorized*1000:.1f}ms"
    )


def test_sec02_no_403(agent_a, agent_b):
    """SEC-02: Cross-agent endpoint never returns 403 (always 404 or 200)."""
    a_id, _, a_headers = agent_a
    b_id, _, b_headers = agent_b

    # Agent A writes several private keys
    for i in range(3):
        client.post("/v1/memory", json={
            "key": f"sec02-no403-key{i}",
            "value": f"private-value-{i}",
            "visibility": "private",
        }, headers=a_headers)

    # Agent B attempts to read all of them -- must never see 403
    for i in range(3):
        r = client.get(f"/v1/agents/{a_id}/memory/sec02-no403-key{i}", headers=b_headers)
        assert r.status_code != 403, (
            f"SEC-02 FAIL: cross-agent endpoint returned 403 for key{i}, which leaks that the key exists"
        )
        assert r.status_code in (200, 404), (
            f"SEC-02 FAIL: unexpected status {r.status_code} from cross-agent endpoint"
        )


# SEC-03: Self cross-agent read
# (3 tests: basic self-read, private key self-read, public key self-read)

def test_sec03_self_cross_agent_read(agent_a):
    """SEC-03: Agent reads own key via /v1/agents/{self_id}/memory/{key} and gets 200."""
    a_id, _, a_headers = agent_a

    # Write a key
    client.post("/v1/memory", json={
        "key": "sec03-self-read",
        "value": "self-read-value",
        "visibility": "private",
    }, headers=a_headers)

    # Read via cross-agent endpoint using own agent_id
    r = client.get(f"/v1/agents/{a_id}/memory/sec03-self-read", headers=a_headers)
    assert r.status_code == 200, (
        f"SEC-03 FAIL: self-read via cross-agent endpoint returned {r.status_code}: {r.text}"
    )
    assert r.json()["value"] == "self-read-value"


def test_sec03_self_read_private(agent_a):
    """SEC-03: Self-read via cross-agent endpoint works for private visibility keys."""
    a_id, _, a_headers = agent_a

    # Write private key
    client.post("/v1/memory", json={
        "key": "sec03-private-self",
        "value": "private-self-value",
        "visibility": "private",
    }, headers=a_headers)

    # Self-read must return 200 even though private
    r = client.get(f"/v1/agents/{a_id}/memory/sec03-private-self", headers=a_headers)
    assert r.status_code == 200, (
        f"SEC-03 FAIL: self-read of private key returned {r.status_code}, expected 200"
    )
    assert r.json()["value"] == "private-self-value"


def test_sec03_self_read_matches_direct(agent_a):
    """SEC-03: Data from /v1/agents/{self}/memory/{key} matches /v1/memory/{key}."""
    a_id, _, a_headers = agent_a

    client.post("/v1/memory", json={
        "key": "sec03-match-key",
        "value": "match-value-123",
        "visibility": "private",
    }, headers=a_headers)

    r_direct = client.get("/v1/memory/sec03-match-key", headers=a_headers)
    assert r_direct.status_code == 200

    r_cross = client.get(f"/v1/agents/{a_id}/memory/sec03-match-key", headers=a_headers)
    assert r_cross.status_code == 200, (
        f"SEC-03 FAIL: cross-agent self-read returned {r_cross.status_code}"
    )

    assert r_direct.json()["value"] == r_cross.json()["value"], (
        "SEC-03 FAIL: direct read and cross-agent self-read return different values"
    )


# SEC-04: Orphaned data cleanup
# (3 tests: no orphaned rows, default namespace reassigned, notes namespace preserved)

import sqlite3
import tempfile
import os as _os


def _make_migration_db():
    """Create an isolated in-memory or temp-file SQLite DB with memory + agents + memory_history tables."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    conn = sqlite3.connect(tmp.name)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            api_key_hash TEXT NOT NULL DEFAULT '',
            name TEXT,
            created_at TEXT NOT NULL DEFAULT '',
            owner_id TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS memory (
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            value TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT '',
            expires_at TEXT,
            visibility TEXT DEFAULT 'private',
            shared_agents TEXT,
            version INTEGER DEFAULT 1,
            PRIMARY KEY (agent_id, namespace, key)
        );
        CREATE TABLE IF NOT EXISTS memory_history (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            changed_by TEXT NOT NULL DEFAULT '',
            changed_at TEXT NOT NULL DEFAULT ''
        );
    """)
    conn.commit()
    conn.close()
    return tmp.name


def _run_migration(db_path):
    """Import and call migration run() with given db_path."""
    import sys
    moltgrid_root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    if moltgrid_root not in sys.path:
        sys.path.insert(0, moltgrid_root)
    from migrations.fix_orphaned_namespaces import run
    return run(db_path=db_path)


def test_sec04_migration_no_orphaned_rows():
    """SEC-04: After migration, zero rows where namespace encodes a different agent's ID."""
    db_path = _make_migration_db()
    try:
        conn = sqlite3.connect(db_path)
        # Insert agent_a into agents
        conn.execute(
            "INSERT INTO agents (agent_id, api_key_hash, name, created_at) VALUES (?, '', 'Agent A', '')",
            ("agent_a",),
        )
        # Insert a BOLA-exploit row: agent_id=agent_a but namespace=agent:agent_b
        conn.execute(
            "INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at) VALUES (?, ?, ?, ?, '', '')",
            ("agent_a", "agent:agent_b", "bola_key", "stolen_value"),
        )
        conn.commit()
        conn.close()

        counts = _run_migration(db_path)

        conn = sqlite3.connect(db_path)
        orphaned = conn.execute(
            "SELECT COUNT(*) FROM memory WHERE namespace LIKE 'agent:%' AND namespace != 'agent:' || agent_id"
        ).fetchone()[0]
        conn.close()

        assert orphaned == 0, (
            f"SEC-04 FAIL: {orphaned} orphaned rows remain after migration (expected 0)"
        )
        assert counts["orphaned_after"] == 0
    finally:
        _os.unlink(db_path)


def test_sec04_migration_default_namespace_reassigned():
    """SEC-04: Rows with namespace='default' are reassigned to namespace='agent:{agent_id}'."""
    db_path = _make_migration_db()
    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO agents (agent_id, api_key_hash, name, created_at) VALUES (?, '', 'Agent A', '')",
            ("agent_a",),
        )
        conn.execute(
            "INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at) VALUES (?, ?, ?, ?, '', '')",
            ("agent_a", "default", "legacy_key", "legacy_value"),
        )
        conn.commit()
        conn.close()

        _run_migration(db_path)

        conn = sqlite3.connect(db_path)
        default_count = conn.execute(
            "SELECT COUNT(*) FROM memory WHERE namespace = 'default'"
        ).fetchone()[0]
        row = conn.execute(
            "SELECT namespace FROM memory WHERE key = 'legacy_key' AND agent_id = 'agent_a'"
        ).fetchone()
        conn.close()

        assert default_count == 0, (
            f"SEC-04 FAIL: {default_count} rows still have namespace='default' after migration"
        )
        assert row is not None, "SEC-04 FAIL: legacy_key row was deleted instead of reassigned"
        assert row[0] == "agent:agent_a", (
            f"SEC-04 FAIL: expected namespace='agent:agent_a', got {row[0]!r}"
        )
    finally:
        _os.unlink(db_path)


def test_sec04_migration_preserves_notes_namespace():
    """SEC-04: Rows with namespace='notes' (tiered memory Tier 2) are left untouched."""
    db_path = _make_migration_db()
    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO agents (agent_id, api_key_hash, name, created_at) VALUES (?, '', 'Agent A', '')",
            ("agent_a",),
        )
        conn.execute(
            "INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at) VALUES (?, ?, ?, ?, '', '')",
            ("agent_a", "notes", "tier2_note", "important note content"),
        )
        conn.commit()
        conn.close()

        _run_migration(db_path)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT namespace, value FROM memory WHERE key = 'tier2_note' AND agent_id = 'agent_a'"
        ).fetchone()
        conn.close()

        assert row is not None, "SEC-04 FAIL: notes namespace row was deleted by migration"
        assert row[0] == "notes", (
            f"SEC-04 FAIL: notes namespace was changed to {row[0]!r} by migration"
        )
        assert row[1] == "important note content", "SEC-04 FAIL: notes namespace value was modified"
    finally:
        _os.unlink(db_path)


# SEC-05: Visibility PATCH for namespaced keys
# (3 tests: basic PATCH, PATCH with explicit namespace, PATCH private->public)

def test_sec05_visibility_patch_any_namespace(agent_a):
    """SEC-05: PATCH /v1/memory/{key}/visibility succeeds for keys stored via POST (auto-scoped namespace)."""
    a_id, _, a_headers = agent_a

    # Write a key (namespace auto-scoped to agent:{a_id})
    client.post("/v1/memory", json={
        "key": "sec05-patch-key",
        "value": "patch-test-value",
        "visibility": "private",
    }, headers=a_headers)

    # PATCH the visibility -- must work
    r = client.patch("/v1/memory/sec05-patch-key/visibility", json={
        "visibility": "public",
    }, headers=a_headers)
    assert r.status_code == 200, (
        f"SEC-05 FAIL: visibility PATCH returned {r.status_code}: {r.text}"
    )
    assert r.json()["visibility"] == "public"


def test_sec05_visibility_patch_ignores_namespace(agent_a):
    """SEC-05: PATCH with namespace injected in body still operates on agent:{caller_id} namespace."""
    a_id, _, a_headers = agent_a

    # Write a key
    client.post("/v1/memory", json={
        "key": "sec05-ignore-ns",
        "value": "ignore-ns-value",
        "visibility": "private",
    }, headers=a_headers)

    # PATCH with injected namespace in body -- must be ignored, operate on own namespace
    r = client.patch("/v1/memory/sec05-ignore-ns/visibility", json={
        "namespace": "evil-namespace",
        "visibility": "public",
    }, headers=a_headers)
    assert r.status_code == 200, (
        f"SEC-05 FAIL: visibility PATCH with injected namespace returned {r.status_code}: {r.text}"
    )
    assert r.json()["visibility"] == "public"

    # Verify the key is still readable (not lost due to wrong namespace resolution)
    r2 = client.get("/v1/memory/sec05-ignore-ns", headers=a_headers)
    assert r2.status_code == 200, "SEC-05 FAIL: key not found after visibility PATCH"


def test_sec05_visibility_patch_e2e(agent_a, agent_b):
    """SEC-05: Set visibility to shared, agent_b can read via cross-agent endpoint."""
    a_id, _, a_headers = agent_a
    b_id, _, b_headers = agent_b

    # Agent A writes a private key
    client.post("/v1/memory", json={
        "key": "sec05-e2e-shared",
        "value": "shared-e2e-value",
        "visibility": "private",
    }, headers=a_headers)

    # Agent B cannot read it yet
    r_before = client.get(f"/v1/agents/{a_id}/memory/sec05-e2e-shared", headers=b_headers)
    assert r_before.status_code == 404, f"Expected 404 before sharing, got {r_before.status_code}"

    # Agent A patches visibility to shared with agent_b
    r_patch = client.patch("/v1/memory/sec05-e2e-shared/visibility", json={
        "visibility": "shared",
        "shared_agents": [b_id],
    }, headers=a_headers)
    assert r_patch.status_code == 200, f"SEC-05 FAIL: PATCH returned {r_patch.status_code}: {r_patch.text}"

    # Agent B can now read it
    r_after = client.get(f"/v1/agents/{a_id}/memory/sec05-e2e-shared", headers=b_headers)
    assert r_after.status_code == 200, (
        f"SEC-05 FAIL: agent B cannot read shared key after PATCH, got {r_after.status_code}"
    )
    assert r_after.json()["value"] == "shared-e2e-value"


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 58: Queue & Task Lifecycle
# Tests added by Phase 58 executor.
# ═══════════════════════════════════════════════════════════════════════════

# QUE-01: Queue claim works
# (3 tests: basic claim, claim empty queue, claim specific queue)

def test_que01_claim_returns_job(agent_a):
    """QUE-01: Submit a job then claim it -- must return 200 with job_id + payload + priority."""
    _, _, a_headers = agent_a

    # Submit a job to the default queue
    submit_resp = client.post("/v1/queue/submit", json={
        "queue_name": "default",
        "payload": {"task": "do-work-que01-basic"},
        "priority": 5,
    }, headers=a_headers)
    assert submit_resp.status_code == 200, f"Submit failed: {submit_resp.text}"
    job_id = submit_resp.json()["job_id"]

    # Claim from the default queue
    claim_resp = client.post("/v1/queue/claim", params={"queue_name": "default"}, headers=a_headers)
    assert claim_resp.status_code == 200, (
        f"QUE-01 FAIL: claim returned {claim_resp.status_code}: {claim_resp.text}"
    )
    body = claim_resp.json()
    assert "job_id" in body, f"QUE-01 FAIL: no job_id in response: {body}"
    assert body["job_id"] == job_id, f"QUE-01 FAIL: expected {job_id}, got {body['job_id']}"
    assert "payload" in body, f"QUE-01 FAIL: no payload in response: {body}"
    assert "priority" in body, f"QUE-01 FAIL: no priority in response: {body}"
    assert body["priority"] == 5, f"QUE-01 FAIL: expected priority=5, got {body['priority']}"


def test_que01_claim_empty_queue(agent_a):
    """QUE-01: Claiming from an empty queue must return status=empty, never 500."""
    _, _, a_headers = agent_a

    # Use a unique queue name unlikely to have any jobs
    empty_queue = f"empty-queue-{uuid.uuid4().hex[:8]}"
    resp = client.post("/v1/queue/claim", params={"queue_name": empty_queue}, headers=a_headers)
    assert resp.status_code == 200, (
        f"QUE-01 FAIL: empty queue claim returned {resp.status_code} instead of 200: {resp.text}"
    )
    body = resp.json()
    assert body.get("status") == "empty", (
        f"QUE-01 FAIL: expected {{status: 'empty'}}, got {body}"
    )


def test_que01_claim_multiple_queues(agent_a):
    """QUE-01: Submit to 'alpha' and 'beta' queues, claim from each, assert correct job per queue."""
    _, _, a_headers = agent_a

    # Submit to alpha queue
    alpha_resp = client.post("/v1/queue/submit", json={
        "queue_name": "alpha",
        "payload": {"work": "alpha-task"},
        "priority": 1,
    }, headers=a_headers)
    assert alpha_resp.status_code == 200
    alpha_job_id = alpha_resp.json()["job_id"]

    # Submit to beta queue
    beta_resp = client.post("/v1/queue/submit", json={
        "queue_name": "beta",
        "payload": {"work": "beta-task"},
        "priority": 1,
    }, headers=a_headers)
    assert beta_resp.status_code == 200
    beta_job_id = beta_resp.json()["job_id"]

    # Claim from alpha -- must return the alpha job
    alpha_claim = client.post("/v1/queue/claim", params={"queue_name": "alpha"}, headers=a_headers)
    assert alpha_claim.status_code == 200, f"QUE-01 FAIL: alpha claim: {alpha_claim.text}"
    alpha_body = alpha_claim.json()
    assert "job_id" in alpha_body, f"QUE-01 FAIL: no job_id in alpha claim: {alpha_body}"
    assert alpha_body["job_id"] == alpha_job_id, (
        f"QUE-01 FAIL: alpha claim returned wrong job {alpha_body['job_id']}, expected {alpha_job_id}"
    )

    # Claim from beta -- must return the beta job
    beta_claim = client.post("/v1/queue/claim", params={"queue_name": "beta"}, headers=a_headers)
    assert beta_claim.status_code == 200, f"QUE-01 FAIL: beta claim: {beta_claim.text}"
    beta_body = beta_claim.json()
    assert "job_id" in beta_body, f"QUE-01 FAIL: no job_id in beta claim: {beta_body}"
    assert beta_body["job_id"] == beta_job_id, (
        f"QUE-01 FAIL: beta claim returned wrong job {beta_body['job_id']}, expected {beta_job_id}"
    )


# TSK-01: POST /complete exists
# (3 tests: basic complete, complete non-running task 404, complete wrong agent 403/404)

def test_tsk01_complete_running_task(agent_a):
    """TSK-01: Create task, claim it, POST /complete, assert 200 with status=completed."""
    _, _, a_headers = agent_a

    # Create a task
    create_resp = client.post("/v1/tasks", json={
        "title": "TSK-01 completion test",
        "description": "Test task for TSK-01",
        "priority": 3,
    }, headers=a_headers)
    assert create_resp.status_code == 200, f"Create task failed: {create_resp.text}"
    task_id = create_resp.json()["task_id"]

    # Claim the task to move it to running
    claim_resp = client.post(f"/v1/tasks/{task_id}/claim", headers=a_headers)
    assert claim_resp.status_code == 200, f"Claim task failed: {claim_resp.text}"
    assert claim_resp.json()["status"] == "running"

    # POST /complete
    complete_resp = client.post(f"/v1/tasks/{task_id}/complete", headers=a_headers)
    assert complete_resp.status_code == 200, (
        f"TSK-01 FAIL: POST /complete returned {complete_resp.status_code}: {complete_resp.text}"
    )
    body = complete_resp.json()
    assert body["status"] == "completed", (
        f"TSK-01 FAIL: expected status=completed, got {body.get('status')}"
    )
    assert body["task_id"] == task_id


def test_tsk01_complete_not_running_returns_404(agent_a):
    """TSK-01: POST /complete on a pending (not claimed) task must return 404."""
    _, _, a_headers = agent_a

    # Create a task but do NOT claim it (stays pending)
    create_resp = client.post("/v1/tasks", json={
        "title": "TSK-01 unclaimed test",
        "description": "Should not be completable",
        "priority": 1,
    }, headers=a_headers)
    assert create_resp.status_code == 200
    task_id = create_resp.json()["task_id"]

    # Attempt to complete without claiming first
    complete_resp = client.post(f"/v1/tasks/{task_id}/complete", headers=a_headers)
    assert complete_resp.status_code == 404, (
        f"TSK-01 FAIL: expected 404 for pending task, got {complete_resp.status_code}: {complete_resp.text}"
    )


def test_tsk01_complete_wrong_agent_returns_403_or_404(agent_a, agent_b):
    """TSK-01: Agent A claims a task, Agent B tries to POST /complete -- must return 403 or 404."""
    a_id, _, a_headers = agent_a
    b_id, _, b_headers = agent_b

    # Create and claim with agent A
    create_resp = client.post("/v1/tasks", json={
        "title": "TSK-01 wrong agent test",
        "description": "Agent A owns this",
        "priority": 1,
    }, headers=a_headers)
    assert create_resp.status_code == 200
    task_id = create_resp.json()["task_id"]

    claim_resp = client.post(f"/v1/tasks/{task_id}/claim", headers=a_headers)
    assert claim_resp.status_code == 200, f"Claim failed: {claim_resp.text}"

    # Agent B attempts to complete it
    complete_resp = client.post(f"/v1/tasks/{task_id}/complete", headers=b_headers)
    assert complete_resp.status_code in (403, 404), (
        f"TSK-01 FAIL: expected 403 or 404 for wrong agent, got {complete_resp.status_code}: {complete_resp.text}"
    )


# TSK-02: tasks_completed counter
# (3 tests: counter increments via POST /complete, counter increments via PATCH, profile counter)

def test_tsk02_directory_counter_increments_on_complete(agent_a):
    """TSK-02: Create task, claim, POST /complete -- leaderboard tasks_completed must be >= 1."""
    a_id, _, a_headers = agent_a

    # Make agent public first so it appears in leaderboard
    client.put("/v1/directory/me", json={"public": True, "name": f"tsk02-agent-{a_id[:8]}"}, headers=a_headers)

    # Create a task, claim it, complete it
    create_resp = client.post("/v1/tasks", json={
        "title": "TSK-02 counter test via complete",
        "priority": 1,
    }, headers=a_headers)
    assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
    task_id = create_resp.json()["task_id"]

    claim_resp = client.post(f"/v1/tasks/{task_id}/claim", headers=a_headers)
    assert claim_resp.status_code == 200, f"Claim failed: {claim_resp.text}"

    complete_resp = client.post(f"/v1/tasks/{task_id}/complete", headers=a_headers)
    assert complete_resp.status_code == 200, f"Complete failed: {complete_resp.text}"

    # Check leaderboard sorted by tasks_completed
    lb_resp = client.get("/v1/leaderboard?sort_by=tasks_completed&limit=100")
    assert lb_resp.status_code == 200, f"Leaderboard failed: {lb_resp.text}"
    entries = lb_resp.json()["leaderboard"]
    agent_entry = next((e for e in entries if e["agent_id"] == a_id), None)

    assert agent_entry is not None, (
        f"TSK-02 FAIL: agent {a_id} not found in leaderboard"
    )
    assert agent_entry["tasks_completed"] >= 1, (
        f"TSK-02 FAIL: tasks_completed={agent_entry['tasks_completed']}, expected >= 1. "
        "Agent tasks completions are not being counted in the directory counter."
    )


def test_tsk02_directory_counter_includes_patch_complete(agent_a):
    """TSK-02: Create task, claim, PATCH status=completed -- leaderboard tasks_completed >= 1."""
    a_id, _, a_headers = agent_a

    # Ensure agent is public
    client.put("/v1/directory/me", json={"public": True}, headers=a_headers)

    # Create a task, claim it, then complete via PATCH
    create_resp = client.post("/v1/tasks", json={
        "title": "TSK-02 counter test via PATCH",
        "priority": 2,
    }, headers=a_headers)
    assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
    task_id = create_resp.json()["task_id"]

    claim_resp = client.post(f"/v1/tasks/{task_id}/claim", headers=a_headers)
    assert claim_resp.status_code == 200, f"Claim failed: {claim_resp.text}"

    patch_resp = client.patch(f"/v1/tasks/{task_id}", json={"status": "completed"}, headers=a_headers)
    assert patch_resp.status_code == 200, f"PATCH complete failed: {patch_resp.text}"

    # Leaderboard (else branch -- not sorted by tasks_completed) must include agent_tasks counts
    lb_resp = client.get("/v1/leaderboard?sort_by=reputation&limit=100")
    assert lb_resp.status_code == 200
    entries = lb_resp.json()["leaderboard"]
    agent_entry = next((e for e in entries if e["agent_id"] == a_id), None)
    assert agent_entry is not None, f"TSK-02 FAIL: agent {a_id} not in reputation-sorted leaderboard"
    assert agent_entry["tasks_completed"] >= 1, (
        f"TSK-02 FAIL: tasks_completed={agent_entry['tasks_completed']} in reputation sort, expected >= 1"
    )


def test_tsk02_profile_counter_includes_agent_tasks(agent_a):
    """TSK-02: GET /v1/directory/{agent_id}/profile must include agent_tasks in tasks_completed."""
    a_id, _, a_headers = agent_a

    # Ensure agent is public
    client.put("/v1/directory/me", json={"public": True}, headers=a_headers)

    # Get baseline profile count
    profile_before = client.get(f"/v1/directory/{a_id}")
    assert profile_before.status_code == 200, f"Profile before failed: {profile_before.text}"
    count_before = profile_before.json()["tasks_completed"]

    # Complete another task
    create_resp = client.post("/v1/tasks", json={
        "title": "TSK-02 profile counter test",
        "priority": 0,
    }, headers=a_headers)
    assert create_resp.status_code == 200
    task_id = create_resp.json()["task_id"]

    client.post(f"/v1/tasks/{task_id}/claim", headers=a_headers)
    complete_resp = client.post(f"/v1/tasks/{task_id}/complete", headers=a_headers)
    assert complete_resp.status_code == 200, f"Complete failed: {complete_resp.text}"

    # Profile tasks_completed must have increased
    profile_after = client.get(f"/v1/directory/{a_id}")
    assert profile_after.status_code == 200
    count_after = profile_after.json()["tasks_completed"]

    assert count_after > count_before, (
        f"TSK-02 FAIL: profile tasks_completed did not increase after completing agent_task. "
        f"before={count_before}, after={count_after}. Profile only counts marketplace, not agent_tasks."
    )


# TSK-03: Priority validation
# (3 tests: string priority rejected, integer accepted, boundary values 0 and 10)

def test_tsk03_priority_string_returns_422(agent_a):
    """TSK-03: POST /v1/tasks with priority='high' must return 422 with 'priority' in error."""
    _, _, a_headers = agent_a

    resp = client.post("/v1/tasks", json={
        "title": "TSK-03 string priority test",
        "priority": "high",
    }, headers=a_headers)
    assert resp.status_code == 422, (
        f"TSK-03 FAIL: expected 422 for string priority, got {resp.status_code}: {resp.text}"
    )
    # The error message should reference priority
    body = resp.json()
    error_text = str(body).lower()
    assert "priority" in error_text, (
        f"TSK-03 FAIL: 422 response does not mention 'priority': {body}"
    )


def test_tsk03_priority_negative_returns_422(agent_a):
    """TSK-03: POST /v1/tasks with priority=-1 must return 422."""
    _, _, a_headers = agent_a

    resp = client.post("/v1/tasks", json={
        "title": "TSK-03 negative priority test",
        "priority": -1,
    }, headers=a_headers)
    assert resp.status_code == 422, (
        f"TSK-03 FAIL: expected 422 for priority=-1, got {resp.status_code}: {resp.text}"
    )


def test_tsk03_priority_valid_integer_succeeds(agent_a):
    """TSK-03: POST /v1/tasks with priority=5 must return 200."""
    _, _, a_headers = agent_a

    resp = client.post("/v1/tasks", json={
        "title": "TSK-03 valid priority test",
        "priority": 5,
    }, headers=a_headers)
    assert resp.status_code == 200, (
        f"TSK-03 FAIL: expected 200 for priority=5, got {resp.status_code}: {resp.text}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 59: Relay & Inbox Hardening
# Tests added by Phase 59 executor.
# ═══════════════════════════════════════════════════════════════════════════

# RLY-01: Mark as read
# (3 tests: basic mark-read, already-read idempotent, nonexistent message 404)

# RLY-02: All-channel default inbox
# (3 tests: no-filter returns all, explicit channel filters, channel=direct still works)

# RLY-03: skill.md field names (content verification test)
# (3 tests: to_agent field present, payload field present, no deprecated field names)

# RLY-04: Invalid cursor returns 400
# (3 tests: garbage cursor, empty string cursor, expired cursor)

# RLY-05: Negative limit returns 422
# (3 tests: limit=-1, limit=-999, limit=0 edge case)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 60: Pub/Sub & Event Stream
# Tests added by Phase 60 executor.
# ═══════════════════════════════════════════════════════════════════════════

# PUB-01: Wildcard matching
# (3 tests: task.* matches task.created, single-level wildcard, no false matches)

# PUB-02: Subscriber count accuracy
# (3 tests: self-subscription counted, multiple subscribers counted, unsubscribed not counted)

# PUB-03: Events accessible via polling
# (3 tests: pub/sub event in stream, channel filtering, timeout behavior)

# EVT-01/02: Cursor-based dedup
# (3 tests: after=id returns newer only, rapid polling no dupes, invalid cursor rejected)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 61: Infrastructure Hardening
# Tests added by Phase 61 executor.
# ═══════════════════════════════════════════════════════════════════════════

# INF-01: Nginx headers (production-only, skip in unit tests)

# INF-02: skill.md pub/sub fields (content verification)
# (3 tests: channel not topic, payload as string, working examples)

# INF-03: Heartbeat enum validation
# (3 tests: valid statuses accepted, invalid rejected with enum list, empty rejected)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 62: Ops Center Frontend
# Tests added by Phase 62 executor (Playwright-based, separate file).
# ═══════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 75: Critical Security + Queue Fixes
# Tests added by Phase 75 executor (SEC-01, SEC-02, SEC-05, SEC-06, SEC-07).
# ═══════════════════════════════════════════════════════════════════════════


def test_sec01_queue_claim_200():
    """SEC-01: Queue claim returns 200 with job JSON, not 500."""
    agent_id, api_key, headers = _create_agent("sec01-queue-claim")
    # Submit a job first
    resp = client.post("/v1/queue/submit", json={
        "queue_name": "test_q",
        "payload": {"task": "sec01_test"},
    }, headers=headers)
    assert resp.status_code == 200, f"Submit failed: {resp.text}"
    # Claim the job
    resp = client.post("/v1/queue/claim", params={"queue_name": "test_q"}, headers=headers)
    assert resp.status_code == 200, f"Claim failed with {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "job_id" in data, f"Missing job_id in response: {data}"
    assert data.get("claimed_by") == agent_id


def test_sec02_queue_complete_200():
    """SEC-02: Queue complete returns 200, not 405."""
    agent_id, api_key, headers = _create_agent("sec02-queue-complete")
    # Submit + claim
    resp = client.post("/v1/queue/submit", json={
        "queue_name": "test_q2",
        "payload": {"task": "sec02_test"},
    }, headers=headers)
    assert resp.status_code == 200
    resp = client.post("/v1/queue/claim", params={"queue_name": "test_q2"}, headers=headers)
    assert resp.status_code == 200
    claimed_job_id = resp.json()["job_id"]
    # Complete the job -- POST /v1/queue/{job_id}/complete
    resp = client.post(f"/v1/queue/{claimed_job_id}/complete", json={"result": "done"}, headers=headers)
    assert resp.status_code == 200, f"Complete failed with {resp.status_code}: {resp.text}"
    assert resp.json()["status"] == "completed"


def test_sec05_chat_gateway_key_validation():
    """SEC-05: Chat gateway rejects XSS/SQLi/path-traversal keys."""
    agent_id, api_key, headers = _create_agent("sec05-chat-key")
    # Path traversal
    resp = client.get("/v1/chat/memory/set", params={"key": api_key, "k": "../../../etc/passwd", "v": "test"})
    assert resp.status_code == 422, f"Path traversal not rejected: {resp.status_code}"
    # XSS in key
    resp = client.get("/v1/chat/memory/set", params={"key": api_key, "k": "<script>alert(1)</script>", "v": "test"})
    assert resp.status_code == 422, f"XSS key not rejected: {resp.status_code}"
    # SQLi in key
    resp = client.get("/v1/chat/memory/set", params={"key": api_key, "k": "'; DROP TABLE memory;--", "v": "test"})
    assert resp.status_code == 422, f"SQLi key not rejected: {resp.status_code}"
    # Valid key should work
    resp = client.get("/v1/chat/memory/set", params={"key": api_key, "k": "valid_key_123", "v": "test_value"})
    assert resp.status_code == 200, f"Valid key rejected: {resp.status_code}: {resp.text}"
    # Verify get also validates
    resp = client.get("/v1/chat/memory/get", params={"key": api_key, "k": "<script>alert(1)</script>"})
    assert resp.status_code == 422, f"XSS key not rejected on get: {resp.status_code}"


def test_sec06_chat_relay_inbox_200():
    """SEC-06: Chat relay inbox returns 200 with messages, not 500."""
    agent_id, api_key, headers = _create_agent("sec06-relay-inbox")
    resp = client.get("/v1/chat/relay/inbox", params={"key": api_key})
    assert resp.status_code == 200, f"Inbox failed with {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "messages" in data, f"Missing messages key: {data}"
    assert "count" in data


def test_sec07_internal_namespace_blocked():
    """SEC-07: __internal__ namespace prefix blocked on writes."""
    agent_id, api_key, headers = _create_agent("sec07-internal-ns")
    # Standard memory -- __internal__ key should be blocked
    resp = client.post("/v1/memory", json={
        "key": "__internal__secret",
        "value": "should_be_blocked",
    }, headers=headers)
    assert resp.status_code == 403, f"__internal__ key not blocked: {resp.status_code}: {resp.text}"
    # Chat gateway -- __internal__ key should also be blocked
    resp = client.get("/v1/chat/memory/set", params={
        "key": api_key, "k": "__internal__secret", "v": "should_be_blocked",
    })
    assert resp.status_code == 403, f"__internal__ key not blocked in chat: {resp.status_code}"

# OPS-01 through OPS-04: Visual tests in tests/test_ops_center_e2e.py


# SEC-03 (BOLA): Cross-account task claim returns 404
# SEC-04 (Ownership): Shared-memory namespace ownership bypass blocked


def test_sec03_cross_account_task_claim_404():
    """SEC-03: Cross-account task claim returns 404, not 200."""
    # Create agent A (account 1)
    agent_a_id, agent_a_key, headers_a = _create_agent("sec03-owner-a")

    # Create agent B with same registration, then set to a different owner_id
    agent_b_id, agent_b_key, headers_b = _create_agent("sec03-owner-b")

    # Update agent B's owner_id to a different account via direct DB access
    db_path = os.environ.get("MOLTGRID_DB", "test_moltgrid.db")
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE agents SET owner_id='different_account_999' WHERE agent_id=?", (agent_b_id,))
    conn.commit()
    conn.close()

    # Agent A creates a task
    resp = client.post("/v1/tasks", json={
        "title": "SEC-03 test task",
        "description": "Cross-account BOLA test",
    }, headers=headers_a)
    assert resp.status_code == 200, f"Task create failed: {resp.text}"
    task_id = resp.json()["task_id"]

    # Agent B (different account) tries to claim it -- should get 404
    resp = client.post(f"/v1/tasks/{task_id}/claim", headers=headers_b)
    assert resp.status_code == 404, (
        f"SEC-03 FAIL: cross-account claim should return 404, got {resp.status_code}: {resp.text}"
    )

    # Agent A (same account) should be able to claim it -- should get 200 or 409
    resp = client.post(f"/v1/tasks/{task_id}/claim", headers=headers_a)
    assert resp.status_code in (200, 409), (
        f"SEC-03 FAIL: same-account claim failed: {resp.status_code}: {resp.text}"
    )


def test_sec04_shared_memory_non_owner_403():
    """SEC-04: Shared-memory write from non-owner agent returns 403."""
    # Create two agents
    agent_a_id, agent_a_key, headers_a = _create_agent("sec04-agent-a")
    agent_b_id, agent_b_key, headers_b = _create_agent("sec04-agent-b")

    # Use a unique namespace to avoid collisions with parallel tests
    ns = f"sec04_ns_{uuid.uuid4().hex[:8]}"

    # Agent A writes to the namespace (becomes the owner)
    resp = client.post("/v1/shared-memory", json={
        "namespace": ns,
        "key": "first_key",
        "value": "agent_a_data",
    }, headers=headers_a)
    assert resp.status_code == 200, f"Agent A write failed: {resp.text}"

    # Agent B tries to write to the same namespace -- should get 403
    resp = client.post("/v1/shared-memory", json={
        "namespace": ns,
        "key": "second_key",
        "value": "agent_b_data",
    }, headers=headers_b)
    assert resp.status_code == 403, (
        f"SEC-04 FAIL: non-owner write should return 403, got {resp.status_code}: {resp.text}"
    )

    # Agent A can still write to the same namespace (owner)
    resp = client.post("/v1/shared-memory", json={
        "namespace": ns,
        "key": "another_key",
        "value": "more_data",
    }, headers=headers_a)
    assert resp.status_code == 200, (
        f"SEC-04 FAIL: owner write failed: {resp.status_code}: {resp.text}"
    )
