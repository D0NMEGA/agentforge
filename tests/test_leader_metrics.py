"""
Tests for leader election (leader.py) and /metrics endpoint (metrics.py).
Run: pytest tests/test_leader_metrics.py -v
"""

import os
import pytest
from unittest.mock import patch, MagicMock

# Use test database, disable rate limiting
os.environ["MOLTGRID_DB"] = "test_moltgrid.db"
os.environ["TURNSTILE_SECRET_KEY"] = ""
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["REDIS_URL"] = ""  # No Redis in test

from fastapi.testclient import TestClient
from cache import response_cache
import asyncio


# ---------------------------------------------------------------------------
# Leader election tests
# ---------------------------------------------------------------------------


class TestLeaderElection:
    """Test leader.py acquire/release/is_leader functions."""

    def test_acquire_leadership_no_redis(self):
        """Without Redis, acquire_leadership should return True (fallback)."""
        import leader
        # Reset state
        leader._is_leader = False
        leader.WORKER_ID = f"worker-{os.getpid()}"

        with patch.object(leader, '_get_redis_client', return_value=None):
            result = leader.acquire_leadership()
        assert result is True
        assert leader.is_leader() is True

    def test_acquire_leadership_with_redis_success(self):
        """With Redis, acquire_leadership should SET NX and return True if acquired."""
        import leader
        leader._is_leader = False

        mock_client = MagicMock()
        mock_client.set.return_value = True  # SET NX succeeded
        mock_client.ping.return_value = True
        # Return this worker's ID so the renew thread doesn't lose leadership
        mock_client.get.return_value = leader.WORKER_ID

        with patch.object(leader, '_get_redis_client', return_value=mock_client):
            result = leader.acquire_leadership()
            assert result is True
            assert leader.is_leader() is True
            mock_client.set.assert_called_once()
            # Verify NX and EX args
            call_kwargs = mock_client.set.call_args
            assert call_kwargs.kwargs.get('nx') is True
            assert call_kwargs.kwargs.get('ex') == leader.LEADER_TTL
        # Clean up: stop the renewal thread
        leader._stop_event.set()

    def test_acquire_leadership_with_redis_already_taken(self):
        """If another worker holds the key, acquire should return False."""
        import leader
        leader._is_leader = False

        mock_client = MagicMock()
        mock_client.set.return_value = False  # SET NX failed (key exists)
        mock_client.get.return_value = "worker-99999"

        with patch.object(leader, '_get_redis_client', return_value=mock_client):
            result = leader.acquire_leadership()
        assert result is False
        assert leader.is_leader() is False

    def test_release_leadership_no_redis(self):
        """Release without Redis should just clear the flag."""
        import leader
        leader._is_leader = True
        leader._stop_event.clear()

        with patch.object(leader, '_get_redis_client', return_value=None):
            leader.release_leadership()
        assert leader.is_leader() is False

    def test_release_leadership_with_redis(self):
        """Release with Redis should call eval (Lua script) to atomically delete."""
        import leader
        leader._is_leader = True
        leader._stop_event.clear()

        mock_client = MagicMock()
        mock_client.eval.return_value = 1

        with patch.object(leader, '_get_redis_client', return_value=mock_client):
            leader.release_leadership()
        assert leader.is_leader() is False
        mock_client.eval.assert_called_once()

    def test_is_leader_default_false(self):
        """is_leader should be False by default."""
        import leader
        leader._is_leader = False
        assert leader.is_leader() is False

    def test_acquire_leadership_redis_exception(self):
        """If Redis raises an exception, fallback to leader=True."""
        import leader
        leader._is_leader = False

        mock_client = MagicMock()
        mock_client.set.side_effect = Exception("Connection refused")

        with patch.object(leader, '_get_redis_client', return_value=mock_client):
            result = leader.acquire_leadership()
        assert result is True  # fallback
        assert leader.is_leader() is True


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    """Test /metrics and /v1/metrics Prometheus endpoints."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        from main import app, init_db
        init_db()
        self.client = TestClient(app)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(response_cache.clear())
        loop.close()

    def test_metrics_returns_200(self):
        """GET /metrics should return 200."""
        resp = self.client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type(self):
        """Response should be Prometheus text format."""
        resp = self.client.get("/metrics")
        ct = resp.headers.get("content-type", "")
        assert "text/plain" in ct

    def test_metrics_contains_expected_metrics(self):
        """Response should contain key Prometheus metric names."""
        resp = self.client.get("/metrics")
        body = resp.text
        expected_metrics = [
            "moltgrid_info",
            "moltgrid_process_start_time_seconds",
            "moltgrid_process_uptime_seconds",
            "moltgrid_agents_total",
            "moltgrid_memory_keys_total",
            "moltgrid_queue_jobs_total",
            "moltgrid_messages_total",
            "moltgrid_worker_is_leader",
        ]
        for metric in expected_metrics:
            assert metric in body, f"Missing metric: {metric}"

    def test_metrics_prometheus_format(self):
        """Metrics should follow Prometheus text format (HELP, TYPE, value lines)."""
        resp = self.client.get("/metrics")
        body = resp.text
        # Should have HELP lines
        assert "# HELP moltgrid_agents_total" in body
        # Should have TYPE lines
        assert "# TYPE moltgrid_agents_total gauge" in body
        # Should have value lines (metric_name followed by a number)
        lines = body.strip().split("\n")
        value_lines = [l for l in lines if l and not l.startswith("#")]
        assert len(value_lines) > 0

    def test_metrics_v1_alias(self):
        """GET /v1/metrics should return the same data."""
        resp = self.client.get("/v1/metrics")
        assert resp.status_code == 200
        assert "moltgrid_agents_total" in resp.text

    def test_metrics_version_label(self):
        """moltgrid_info should include version label."""
        resp = self.client.get("/metrics")
        assert 'version="0.9.0"' in resp.text

    def test_metrics_cached(self):
        """Second call should return cached result (same content)."""
        resp1 = self.client.get("/metrics")
        resp2 = self.client.get("/metrics")
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Content should be identical (cached)
        assert resp1.text == resp2.text
