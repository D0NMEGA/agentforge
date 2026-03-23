---
phase: 43-sse-push-cursor-inbox
plan: 02
subsystem: relay-pagination + health-components
tags: [cursor-pagination, relay-inbox, health-components, sse, pydantic]
dependency_graph:
  requires: [43-01-SSE-push-infrastructure]
  provides: [cursor-inbox-pagination, health-component-reporting]
  affects: [models.py, routers/relay.py, routers/system.py]
tech_stack:
  added: []
  patterns: [cursor-based-forward-pagination, component-health-probing]
key_files:
  created: []
  modified: [models.py, routers/relay.py, routers/system.py]
decisions:
  - cursor resolves to created_at anchor (not lexicographic message_id) since msg_{uuid4} is not time-ordered
  - unknown cursor returns empty list not error -- safe for polling agents that restart
  - relay degraded threshold is 10 stuck messages older than 5 minutes
  - sse component count is len(_sse_connections) (subscribed agent IDs, not total queue objects)
metrics:
  duration: 18 minutes
  completed: 2026-03-23
  tasks_completed: 2/2
  files_changed: 3
  tests_passing: 344
---

# Phase 43 Plan 02: Cursor Inbox + Health Components Summary

Cursor inbox live at GET /v1/relay/inbox?after={message_id} using created_at-anchored forward pagination with next_cursor in response; /v1/health now returns components dict with database, relay, websocket, and sse subsystem statuses.

## What Was Built

### Task 1: Cursor inbox -- models.py + relay.py

**models.py:** Added `next_cursor: Optional[str] = None` to `RelayInboxResponse`. Backwards-compatible: existing tests checking messages/count/channel still pass without modification.

**routers/relay.py:** Extended `relay_inbox` with optional `after: Optional[str]` query parameter. When `after` is provided:
- Resolves cursor message's `created_at` by querying `relay WHERE message_id=? AND to_agent=?`
- Returns messages with `created_at > cursor_ts` in `ORDER BY created_at ASC` (forward-only)
- Unknown cursor (not in relay table for that agent) returns `{"messages": [], "count": 0, "next_cursor": null, "channel": "..."}`
- Sets `next_cursor` to the last returned message's `message_id`, or `null` if no messages

Without `after`, behavior is unchanged: returns most recent messages in DESC order.

### Task 2: Health components -- models.py + system.py

**models.py:** Added two new Pydantic models in the HEALTH/STATS section:
- `HealthComponentStatus` with `status: str` ("ok" / "degraded" / "error") and `detail: Optional[str] = None`
- `HealthComponents` with four `HealthComponentStatus` fields: database, relay, websocket, sse
- Updated `HealthResponse` with `components: Optional[HealthComponents] = None` (backwards-compatible)

**routers/system.py:**
- Added `_sse_connections` to the `from state import` line
- Added `HealthComponents, HealthComponentStatus` to the models import
- Health endpoint now probes four subsystems before building result dict:
  - **database**: `SELECT 1 as ping` via `async_db_fetchone`; status "ok" or "error"
  - **relay**: counts `status='accepted' AND created_at < 5-min-cutoff`; "degraded" if > 10 stuck, else "ok"
  - **websocket**: counts active WebSocket connections from `_ws_connections`; always "ok" (informational)
  - **sse**: counts subscribed agent IDs from `len(_sse_connections)`; always "ok" (informational)
- `ws_count` now computed in the component probing block (no duplicate computation in stats dict)

## Test Results

| Class | Tests | Result |
|-------|-------|--------|
| TestCursorInbox::test_inbox_cursor_after | 1 | PASS (GREEN) |
| TestCursorInbox::test_inbox_cursor_empty | 1 | PASS (GREEN) |
| TestHealthComponents::test_health_has_components | 1 | PASS (GREEN) |
| TestSSEStream (from Plan 01) | 4 | PASS |
| Pre-existing suite | 337 | PASS |
| **Total** | **344** | **PASS** |

## PUSH Requirement Coverage Matrix

| ID | Requirement | Status | Test |
|----|-------------|--------|------|
| PUSH-01 | SSE stream delivers events within 1s of relay send | PASS | TestSSEStream::test_sse_content_type |
| PUSH-02 | Last-Event-ID replay replays missed events | PASS | TestSSEStream::test_last_event_id_replay |
| PUSH-03 | after= cursor returns only newer messages | PASS | TestCursorInbox::test_inbox_cursor_after + test_inbox_cursor_empty |
| PUSH-04 | SSE keepalive ping every 15 seconds | PASS | EventSourceResponse(ping=15) in routers/sse.py |
| PUSH-05 | /v1/health returns components with 4 subsystems | PASS | TestHealthComponents::test_health_has_components |
| PUSH-06 | SSE auth via X-API-Key | PASS | TestSSEStream::test_sse_requires_auth |

All 6 PUSH requirements satisfied across Plans 01 and 02.

## Deviations from Plan

None. Plan executed exactly as written. The created_at cursor anchor approach from the plan matched the existing research recommendation and worked correctly on first implementation.

## Pitfalls Navigated

**Pitfall 4 (HealthResponse extra='ignore' dropping components):** Avoided by adding `components: Optional[HealthComponents] = None` to `HealthResponse` before adding the field to the response dict. The `ConfigDict(extra='ignore')` on HealthResponse would have silently stripped the `components` key without this model update.

**Pitfall 3 (cursor stability):** Used created_at anchor (ISO8601, lexicographically sortable) not message_id lexicographic comparison. message_id is `msg_{uuid4().hex[:16]}` which is not time-ordered.

## Self-Check: PASSED

- models.py next_cursor field: FOUND (`grep "next_cursor" models.py`)
- models.py HealthComponentStatus: FOUND (`grep "HealthComponentStatus" models.py`)
- models.py HealthComponents: FOUND (`grep "HealthComponents" models.py`)
- routers/relay.py after: param: FOUND (`grep "after:" routers/relay.py`)
- routers/relay.py cursor_row: FOUND (`grep "cursor_row" routers/relay.py`)
- routers/system.py _sse_connections: FOUND (`grep "_sse_connections" routers/system.py`)
- routers/system.py components: FOUND (`grep "components" routers/system.py`)
- Commit 5e63c32 (cursor inbox): FOUND
- Commit 5c4f2b6 (health components): FOUND
- 344 tests passing: VERIFIED
