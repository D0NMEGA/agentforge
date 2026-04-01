"""
Tests for rate limiting headers and enforcement -- RATE-01 through RATE-05.

RATE-01: X-RateLimit-Remaining decrements on sequential requests
RATE-02: Free tier agent gets HTTP 429 at request N+1 when limit N is reached
RATE-03: make_tier_limit returns 10x base for Scale tier on non-fixed categories
RATE-04: Retry-After header is 60 for minute windows, 3600 for hour windows
RATE-05: X-RateLimit-Limit shows per-endpoint limit, not global tier limit

IMPORTANT: RATE_LIMIT_ENABLED=true -- unlike other test files that disable it.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["MOLTGRID_DB"] = "test_rate_limiting.db"
os.environ["TURNSTILE_SECRET_KEY"] = ""
os.environ["RATE_LIMIT_ENABLED"] = "true"   # ENABLED -- unlike other test files
os.environ["REDIS_URL"] = ""                 # Force in-memory storage

import asyncio
import uuid
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from limits import parse as parse_limit
from slowapi.wrappers import Limit
from main import app, init_db, _custom_rate_limit_handler
from rate_limit import make_tier_limit


client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Wipe and re-init the SQLite DB before every test."""
    db_path = str(tmp_path / "test_rate.db")
    monkeypatch.setenv("MOLTGRID_DB", db_path)
    import db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "_sqlite_pool", None)
    init_db()


@pytest.fixture(autouse=True)
def reset_limiter():
    """Reset in-memory rate limit storage between tests to avoid state bleed."""
    from rate_limit import limiter as _limiter
    yield
    try:
        # Clear all keys in the in-memory storage
        storage = _limiter.limiter.storage
        if hasattr(storage, "_storage"):
            storage._storage.clear()
        elif hasattr(storage, "storage"):
            storage.storage.clear()
    except Exception:
        pass


def _register_agent():
    """Register a fresh agent and return (agent_id, api_key, headers dict)."""
    name = f"rate-test-{uuid.uuid4().hex[:8]}"
    with patch("main._queue_email"):
        r = client.post("/v1/register", json={"name": name})
    assert r.status_code == 200, r.text
    data = r.json()
    return data["agent_id"], data["api_key"], {"X-API-Key": data["api_key"]}


# ─── RATE-01: X-RateLimit-Remaining decrements on sequential requests ─────────

class TestRateLimit01Decrement:
    """RATE-01: Two sequential requests to same endpoint with same API key
    must result in a lower X-RateLimit-Remaining on the second response."""

    def test_rate_limit_remaining_decrements(self):
        """Second request has lower X-RateLimit-Remaining than first."""
        _, _, headers = _register_agent()

        r1 = client.get("/v1/memory", headers=headers)
        assert r1.status_code == 200, f"First request failed: {r1.text}"

        remaining_1_str = r1.headers.get("X-RateLimit-Remaining")
        assert remaining_1_str is not None, "Missing X-RateLimit-Remaining on first response"
        remaining_1 = int(remaining_1_str)

        r2 = client.get("/v1/memory", headers=headers)
        assert r2.status_code == 200, f"Second request failed: {r2.text}"

        remaining_2_str = r2.headers.get("X-RateLimit-Remaining")
        assert remaining_2_str is not None, "Missing X-RateLimit-Remaining on second response"
        remaining_2 = int(remaining_2_str)

        assert remaining_2 < remaining_1, (
            f"X-RateLimit-Remaining did not decrement: first={remaining_1}, second={remaining_2}"
        )


# ─── RATE-02: Free tier write endpoint 429 at limit ──────────────────────────

class TestRateLimit02WriteLimit:
    """RATE-02: Free tier agent hitting agent_write endpoint gets 429
    after exceeding the 60/minute limit (tested with monkeypatched smaller limit)."""

    def test_free_tier_write_429_at_limit(self):
        """Request 61 returns HTTP 429 after 60 writes exhaust the free tier limit.

        Makes 61 actual POST /v1/memory requests. Each takes ~5ms, so 61
        requests completes in under 0.5s. This matches RATE-02 exactly.
        """
        _, _, headers = _register_agent()

        # First 60 requests should succeed (free tier agent_write = 60/minute)
        for i in range(60):
            r = client.post("/v1/memory", json={"key": f"k{i}", "value": "v"}, headers=headers)
            assert r.status_code in (200, 201), (
                f"Request {i+1} expected 200/201, got {r.status_code}: {r.text}"
            )

        # Request 61 must return 429
        r61 = client.post("/v1/memory", json={"key": "k_final", "value": "v"}, headers=headers)
        assert r61.status_code == 429, (
            f"Request 61 expected 429, got {r61.status_code}: {r61.text}"
        )


# ─── RATE-03: Scale tier 10x multiplier for non-fixed categories ─────────────

class TestRateLimit03ScaleTier:
    """RATE-03: make_tier_limit returns 10x base limit for Scale tier on
    non-fixed categories, and returns base for fixed categories."""

    def test_scale_tier_agent_write_10x(self):
        """Scale tier agent_write returns 600/minute (10x the 60/minute base)."""
        limit_fn = make_tier_limit("agent_write")
        result = limit_fn("scale:test123")
        assert result == "600/minute", f"Expected 600/minute, got {result}"

    def test_scale_tier_agent_read_10x(self):
        """Scale tier agent_read returns 1200/minute (10x the 120/minute base)."""
        limit_fn = make_tier_limit("agent_read")
        result = limit_fn("scale:test123")
        assert result == "1200/minute", f"Expected 1200/minute, got {result}"

    def test_fixed_category_admin_unchanged(self):
        """Admin is a fixed category -- limit is the same regardless of tier."""
        limit_fn = make_tier_limit("admin")
        # Should be 60/minute for all tiers
        assert limit_fn("free:ip") == "60/minute"
        assert limit_fn("scale:test123") == "60/minute"
        assert limit_fn("hobby:test456") == "60/minute"

    def test_fixed_category_billing_unchanged(self):
        """Billing is a fixed category -- limit is the same regardless of tier."""
        limit_fn = make_tier_limit("billing")
        assert limit_fn("free:ip") == "30/minute"
        assert limit_fn("scale:test123") == "30/minute"

    def test_free_tier_is_1x(self):
        """Free tier agent_write returns 60/minute (1x base)."""
        limit_fn = make_tier_limit("agent_write")
        assert limit_fn("free:test") == "60/minute"


# ─── RATE-04: Retry-After header correct window ───────────────────────────────

class TestRateLimit04RetryAfter:
    """RATE-04: _custom_rate_limit_handler returns Retry-After: 60 for minute
    limits and Retry-After: 3600 for hour limits."""

    def _make_exc(self, limit_str: str):
        """Build a real RateLimitExceeded with the given limit string."""
        from slowapi.errors import RateLimitExceeded
        limit_item = parse_limit(limit_str)
        wrapped = Limit(
            limit=limit_item,
            key_func=lambda r: "free:test",
            scope="test",
            per_method=False,
            methods=None,
            error_message=None,
            exempt_when=None,
            cost=1,
            override_defaults=False,
        )
        return RateLimitExceeded(wrapped)

    def test_retry_after_minute_window(self):
        """429 for a 60/minute limit returns Retry-After: 60."""
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.subscription_tier = "free"
        mock_request.state.endpoint_category = "agent_write"
        mock_request.state.request_id = "test-req-id"

        exc = self._make_exc("60/minute")

        response = asyncio.run(_custom_rate_limit_handler(mock_request, exc))
        assert response.status_code == 429
        assert response.headers.get("Retry-After") == "60", (
            f"Expected Retry-After: 60, got {response.headers.get('Retry-After')}"
        )

    def test_retry_after_hour_window(self):
        """429 for a 3/hour limit returns Retry-After: 3600."""
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.subscription_tier = "free"
        mock_request.state.endpoint_category = "auth_signup"
        mock_request.state.request_id = "test-req-id-2"

        exc = self._make_exc("3/hour")

        response = asyncio.run(_custom_rate_limit_handler(mock_request, exc))
        assert response.status_code == 429
        assert response.headers.get("Retry-After") == "3600", (
            f"Expected Retry-After: 3600, got {response.headers.get('Retry-After')}"
        )


# ─── RATE-05: X-RateLimit-Limit shows per-endpoint limit ─────────────────────

class TestRateLimit05PerEndpointLimit:
    """RATE-05: X-RateLimit-Limit header reflects the per-endpoint limit for
    the caller's tier, not the global tier limit (e.g. 60 for agent_write,
    120 for agent_read -- even though 120 is also the global free tier max,
    the source must be endpoint-specific)."""

    def test_write_endpoint_shows_60_not_120(self):
        """POST /v1/memory (agent_write, free tier) shows X-RateLimit-Limit: 60."""
        _, _, headers = _register_agent()

        r = client.post("/v1/memory", json={"key": "x", "value": "y"}, headers=headers)
        assert r.status_code in (200, 201), f"Unexpected status: {r.status_code}: {r.text}"

        limit_header = r.headers.get("X-RateLimit-Limit")
        assert limit_header is not None, "Missing X-RateLimit-Limit header"
        assert limit_header == "60", (
            f"Expected X-RateLimit-Limit: 60 (agent_write free tier), got {limit_header}"
        )

    def test_read_endpoint_shows_120(self):
        """GET /v1/memory (agent_read, free tier) shows X-RateLimit-Limit: 120."""
        _, _, headers = _register_agent()

        r = client.get("/v1/memory", headers=headers)
        assert r.status_code == 200, f"Unexpected status: {r.status_code}: {r.text}"

        limit_header = r.headers.get("X-RateLimit-Limit")
        assert limit_header is not None, "Missing X-RateLimit-Limit header"
        assert limit_header == "120", (
            f"Expected X-RateLimit-Limit: 120 (agent_read free tier), got {limit_header}"
        )
