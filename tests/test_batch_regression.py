"""
Regression tests for FUNC-01 (memory batch partial failure) and FUNC-02 (queue batch partial failure).

These tests formally gate the requirement that batch endpoints return per-item results
with mixed success/failure isolation -- not a single all-or-nothing response.

FUNC-01: POST /v1/memory/batch returns {results: [...], total, succeeded, failed} with per-item success booleans
FUNC-02: POST /v1/queue/batch returns {results: [...], total, succeeded, failed} with per-item success booleans
"""
import pytest


class TestFUNC01MemoryBatchPartialFailure:
    """FUNC-01: Memory batch partial failure returns per-item results array."""

    def test_memory_batch_mixed_valid_invalid(self, client, seed_agents):
        """POST /v1/memory/batch with mixed valid/invalid items returns per-item results.

        The empty string key fails validation. The valid key succeeds.
        Response must have results array, succeeded >= 1, failed >= 1.
        """
        a1 = seed_agents["agent1"]
        items = [
            {"key": "invalid key with spaces!", "value": "should-fail-invalid-chars"},
            {"key": "valid_regression_key", "value": "should-succeed"},
            {"key": "valid_regression_key2", "value": "should-succeed-too"},
        ]
        resp = client.post(
            "/v1/memory/batch",
            json={"items": items},
            headers={"X-API-Key": a1["key"]},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()

        # Response envelope
        assert "results" in data, f"Missing 'results' in response: {data}"
        assert "total" in data, f"Missing 'total' in response: {data}"
        assert "succeeded" in data, f"Missing 'succeeded' in response: {data}"
        assert "failed" in data, f"Missing 'failed' in response: {data}"

        # Counts
        assert data["total"] == len(items), f"Expected total={len(items)}, got {data['total']}"
        assert data["succeeded"] >= 1, f"Expected at least 1 success, got succeeded={data['succeeded']}"
        assert data["failed"] >= 1, f"Expected at least 1 failure, got failed={data['failed']}"
        assert data["succeeded"] + data["failed"] == data["total"]

        # Per-item results
        assert len(data["results"]) == len(items), (
            f"Expected {len(items)} result items, got {len(data['results'])}"
        )
        for result in data["results"]:
            assert "success" in result, f"Result missing 'success' field: {result}"
            assert isinstance(result["success"], bool), (
                f"'success' must be bool, got {type(result['success'])}: {result}"
            )

        # Failed item has error info
        failed_items = [r for r in data["results"] if not r["success"]]
        assert len(failed_items) >= 1
        for failed in failed_items:
            assert failed.get("error") is not None, (
                f"Failed result must have 'error' field: {failed}"
            )

        # Successful items are readable
        for result in data["results"]:
            if result["success"]:
                key = result.get("key")
                if key:
                    read_resp = client.get(
                        f"/v1/memory/{key}",
                        headers={"X-API-Key": a1["key"]},
                    )
                    assert read_resp.status_code == 200, (
                        f"Stored key '{key}' not readable: {read_resp.text}"
                    )


class TestFUNC02QueueBatchPartialFailure:
    """FUNC-02: Queue batch partial failure returns per-item results array."""

    def test_queue_batch_mixed_valid_invalid(self, client, seed_agents):
        """POST /v1/queue/batch with mixed valid/invalid items returns per-item results.

        An oversized payload (> MAX_QUEUE_PAYLOAD_SIZE) fails validation.
        A small payload succeeds. Response must have results array with per-item success.
        """
        a1 = seed_agents["agent1"]
        # Oversized payload exceeds the 100KB limit enforced by queue batch
        oversized_payload = "x" * 200_000
        items = [
            {"payload": oversized_payload},
            {"payload": "small-valid-job-1"},
            {"payload": "small-valid-job-2"},
        ]
        resp = client.post(
            "/v1/queue/batch",
            json={"items": items},
            headers={"X-API-Key": a1["key"]},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()

        # Response envelope
        assert "results" in data, f"Missing 'results' in response: {data}"
        assert "total" in data, f"Missing 'total' in response: {data}"
        assert "succeeded" in data, f"Missing 'succeeded' in response: {data}"
        assert "failed" in data, f"Missing 'failed' in response: {data}"

        # Counts
        assert data["total"] == len(items), f"Expected total={len(items)}, got {data['total']}"
        assert data["succeeded"] >= 1, f"Expected at least 1 success, got succeeded={data['succeeded']}"
        assert data["failed"] >= 1, f"Expected at least 1 failure, got failed={data['failed']}"
        assert data["succeeded"] + data["failed"] == data["total"]

        # Per-item results
        assert len(data["results"]) == len(items), (
            f"Expected {len(items)} result items, got {len(data['results'])}"
        )
        for result in data["results"]:
            assert "success" in result, f"Result missing 'success' field: {result}"
            assert isinstance(result["success"], bool), (
                f"'success' must be bool, got {type(result['success'])}: {result}"
            )

        # Failed item has error info
        failed_items = [r for r in data["results"] if not r["success"]]
        assert len(failed_items) >= 1
        for failed in failed_items:
            assert failed.get("error") is not None, (
                f"Failed result must have 'error' field: {failed}"
            )
