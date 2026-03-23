---
phase: 43-sse-push-cursor-inbox
plan: 01
subsystem: real-time-push
tags: [sse, server-sent-events, sse-starlette, asyncio-queue, fan-out, last-event-id, push-delivery]
dependency_graph:
  requires: [42-02-relay-dead-letter]
  provides: [SSE-push-stream, sse-fan-out-infrastructure]
  affects: [helpers.py, state.py, routers/sse.py, main.py, test_main.py]
tech_stack:
  added: [sse-starlette==3.3.3, uvicorn-test-server-pattern]
  patterns: [asyncio-queue-fan-out, last-event-id-replay, sse-disconnect-cleanup]
key_files:
  created: [routers/sse.py]
  modified: [state.py, helpers.py, main.py, requirements.txt, test_main.py]
decisions:
  - asyncio.Queue per SSE subscriber, maxsize=100, intra-worker only (Redis pub/sub deferred to Plan 02)
  - X-Accel-Buffering: no header added to prevent Nginx buffering
  - Uvicorn test server in thread for streaming tests (httpx ASGITransport has httpx.disconnect deadlock with infinite generators)
  - EventSourceResponse ping=15 for RFC-compliant keepalives
  - Last-Event-ID replay uses created_at anchor query (not lexicographic message_id comparison)
metrics:
  duration: 32 minutes
  completed: 2026-03-23
  tasks_completed: 2/2
  files_changed: 6
  tests_passing: 342
---

# Phase 43 Plan 01: SSE Push Infrastructure Summary

SSE push stream live at GET /v1/agents/{id}/events using sse-starlette EventSourceResponse with asyncio.Queue fan-out from _queue_agent_event, Last-Event-ID replay from agent_events table, and 15s keepalive pings.

## What Was Built

### Task 1: Test scaffold + sse-starlette dependency (RED)

Three test classes appended to test_main.py:
- `TestSSEStream` (4 methods): auth, cross-agent 403, content-type check, Last-Event-ID replay
- `TestCursorInbox` (2 methods): cursor-after and cursor-empty pagination (RED, Plan 02)
- `TestHealthComponents` (1 method): /v1/health components dict (RED, Plan 02)

`sse-starlette==3.3.3` added to requirements.txt. Tests imported cleanly, 2 of 3 classes deliberately RED.

### Task 2: SSE infrastructure GREEN phase

**state.py:** Added `_sse_connections: dict[str, set] = {}` after `_ws_connections` declaration.

**helpers.py `_queue_agent_event`:** Extended to fan-out to SSE subscribers after DB commit. Imports `_sse_connections` from state, calls `q.put_nowait(push_payload)` for each registered queue. Slow consumers silently dropped (event remains available via Last-Event-ID replay).

**routers/sse.py (NEW):** GET /v1/agents/{agent_id_path}/events SSE endpoint.
- Auth via `Depends(get_agent_id)`, cross-agent subscription returns 403
- Last-Event-ID replay: queries `agent_events WHERE created_at > cursor_row.created_at ORDER BY created_at ASC LIMIT 100`
- Live push: registers `asyncio.Queue(maxsize=100)` in `_sse_connections`, yields `ServerSentEvent` objects
- Cleanup in `finally` block: discards queue, removes empty agent entry
- Returns `EventSourceResponse(generator(), ping=15, headers={"X-Accel-Buffering": "no"})`

**main.py:** Added `from routers import sse` and `app.include_router(sse.router)` after chat_gateway.

## Test Results

| Class | Tests | Result |
|-------|-------|--------|
| TestSSEStream::test_sse_requires_auth | 1 | PASS |
| TestSSEStream::test_sse_requires_own_agent | 1 | PASS |
| TestSSEStream::test_sse_content_type | 1 | PASS |
| TestSSEStream::test_last_event_id_replay | 1 | PASS |
| TestCursorInbox::test_inbox_cursor_after | 1 | FAIL (RED -- Plan 02) |
| TestCursorInbox::test_inbox_cursor_empty | 1 | PASS (returns 200 empty list) |
| TestHealthComponents::test_health_has_components | 1 | FAIL (RED -- Plan 02) |
| Pre-existing suite | 337 | PASS |

**Total:** 342 pass, 2 fail (expected RED), 4 skipped.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] httpx ASGITransport deadlock with infinite SSE generators**
- **Found during:** Task 2, test verification
- **Issue:** Both `starlette.testclient.TestClient.stream()` and `httpx.AsyncClient` with `ASGITransport` never send `http.disconnect` until the response body is fully consumed (controlled by `response_complete` event). Since SSE generators run infinitely, `receive()` never returns `http.disconnect`, so sse-starlette's `_listen_for_disconnect` never runs, causing the test to hang indefinitely.
- **Root cause:** httpx ASGITransport `receive()` waits on `response_complete.wait()` before returning `http.disconnect`. `response_complete` is set only when `more_body=False` is sent, which sse-starlette never sends for an active stream.
- **Fix:** Replaced `with self.client.stream()` in `test_sse_content_type` and `test_last_event_id_replay` with a live uvicorn server spinning up in a daemon thread on an ephemeral port. Real HTTP client (`httpx.Client`) connects to the server. When the test exits the `with hc.stream()` block, the TCP connection closes, which properly triggers `http.disconnect` in the running uvicorn/sse-starlette instance.
- **Files modified:** test_main.py
- **Commit:** 574563f

## Key Decisions

1. **Intra-worker SSE only:** asyncio.Queue fan-out works only within the same Uvicorn worker. With 4 workers (Phase 41), cross-worker SSE delivery is not guaranteed. Documented in routers/sse.py docstring. Redis pub/sub bridge deferred to Plan 02 if needed.

2. **uvicorn test server pattern:** Spinning up a real server in a test is heavier than TestClient but the only viable approach for testing infinite SSE streams. Each streaming test creates/destroys a uvicorn instance on an ephemeral port. Adds ~30s per streaming test. Acceptable for integration tests.

3. **Last-Event-ID replay uses created_at anchor:** UUID hex `event_id` strings are not time-ordered, so `WHERE event_id > last_event_id` would give wrong results. Instead, we look up `created_at` for the cursor event, then query `WHERE created_at > cursor_created_at ORDER BY created_at ASC`. Correct for ISO8601 lexicographic ordering.

4. **asyncio.Queue maxsize=100:** Prevents unbounded memory growth if an SSE subscriber is slow. Events beyond 100 are silently dropped (available via Last-Event-ID replay). Consistent with research recommendation.

5. **X-Accel-Buffering: no header:** Added to prevent Nginx from batching SSE events into chunks. sse-starlette does not add this automatically (confirmed from source).

## Success Criteria Verification

- GET /v1/agents/{id}/events returns 200 + text/event-stream: PASS (test_sse_content_type)
- GET /v1/agents/{id}/events returns 401 with no key: PASS (test_sse_requires_auth -- 401 from get_agent_id Depends)
- GET /v1/agents/{id}/events returns 403 with wrong agent key: PASS (test_sse_requires_own_agent)
- _queue_agent_event fans out to SSE subscribers: PASS (verified via test_last_event_id_replay and code review)
- Last-Event-ID replay: PASS (test_last_event_id_replay)
- sse-starlette==3.3.3 in requirements.txt: PASS
- All 337 pre-existing tests still pass: PASS
- TestCursorInbox and TestHealthComponents exist in test_main.py (failing RED): PASS

## Self-Check: PASSED

- routers/sse.py: FOUND
- state.py: FOUND
- 43-01-SUMMARY.md: FOUND
- Commit 7a389c1 (test scaffold): FOUND
- Commit 574563f (SSE infrastructure): FOUND
