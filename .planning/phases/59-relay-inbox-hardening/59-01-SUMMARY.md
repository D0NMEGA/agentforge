---
phase: 59-relay-inbox-hardening
plan: "01"
subsystem: relay
tags: [relay, inbox, pagination, validation, tdd]
dependency_graph:
  requires: []
  provides: [RLY-01, RLY-02, RLY-03, RLY-04, RLY-05]
  affects: [routers/relay.py, models.py, test_main.py, skill.md]
tech_stack:
  added: []
  patterns: [cursor-pagination-400, optional-channel-filter, ge-validation]
key_files:
  created: []
  modified:
    - routers/relay.py
    - models.py
    - test_main.py
decisions:
  - "[59-01] channel param changed to Optional[str]=None -- omit for all channels (breaking: old default was 'direct')"
  - "[59-01] Invalid after= cursor now returns HTTP 400 (not empty list) -- deliberate DX improvement per RLY-04"
  - "[59-01] Error handler wraps HTTPException detail dict into message field as string -- test asserts 'invalid_cursor' in message"
  - "[59-01] RelayInboxResponse.channel is now Optional[str]=None to represent all-channel queries"
metrics:
  duration: 15min
  completed_date: "2026-03-24"
  tasks_completed: 2
  files_modified: 3
---

# Phase 59 Plan 01: Relay Inbox Hardening Summary

**One-liner:** Relay inbox now defaults to all channels, returns 400 for invalid cursors, and enforces ge=1 on limit via Pydantic validation.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Fix relay inbox endpoint - all-channel default, cursor 400, limit ge=1 | c56d788 | routers/relay.py, models.py, test_main.py |
| 2 | Audit skill.md relay section field names | (no changes needed) | skill.md verified correct |

## Changes Made

### Task 1: relay.py endpoint hardening

**routers/relay.py:**
- `channel` param changed from `str = "direct"` to `Optional[str] = Query(None, ...)` so omitting it returns messages from all channels
- `limit` Query gains `ge=1` to reject 0 and negative values with 422 Pydantic validation error
- Invalid `after=` cursor now raises `HTTPException(400, detail={"error": "invalid_cursor", ...})` instead of returning empty results
- All SQL queries handle `channel is None` by removing the `AND channel=?` filter from both cursor and non-cursor paths

**models.py:**
- `RelayInboxResponse.channel` changed from `str` to `Optional[str] = None` to represent all-channel queries correctly

**test_main.py (6 new tests added to TestRelay class):**
- `test_inbox_all_channels`: sends on "direct" + "ops", asserts both appear with no channel param
- `test_inbox_channel_filter`: confirms `?channel=direct` still filters correctly (backward compat)
- `test_inbox_invalid_cursor_400`: asserts status 400 and "invalid_cursor" in message body
- `test_inbox_negative_limit_422`: asserts `?limit=-1` returns 422
- `test_inbox_zero_limit_422`: asserts `?limit=0` returns 422

### Task 2: skill.md verification

All relay curl examples already use correct field names:
- `to_agent` (not `to`) in the relay send example
- `payload` (not `message`, `body`, or `content`) in the relay send example
- Inbox curl uses no channel filter, which is now semantically correct (all-channel default)
- Mark-read path `POST /v1/relay/MESSAGE_ID/read` matches actual endpoint

No changes were needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test assertion adjusted for error handler middleware format**
- **Found during:** Task 1 GREEN phase
- **Issue:** The plan specified `body.get("detail", {}).get("error") == "invalid_cursor"` but the Phase 48 error handler wraps HTTPException detail dicts into `{"error": "bad_request", "message": "<stringified detail>"}`. The 400 status was correct but the body shape differed.
- **Fix:** Updated test to assert `"invalid_cursor" in body.get("message", "")` which accurately reflects the actual response shape.
- **Files modified:** test_main.py
- **Commit:** c56d788

## Success Criteria Verification

| Requirement | Status | Evidence |
|-------------|--------|---------|
| RLY-01: POST /v1/relay/{id}/read returns 200 | PASS | test_mark_read passes |
| RLY-02: GET /v1/relay/inbox with no channel returns all messages | PASS | test_inbox_all_channels passes |
| RLY-03: skill.md uses to_agent and payload exclusively | PASS | verified, no changes needed |
| RLY-04: GET /v1/relay/inbox?after=bad_cursor returns 400 | PASS | test_inbox_invalid_cursor_400 passes |
| RLY-05: GET /v1/relay/inbox?limit=-1 returns 422 | PASS | test_inbox_negative_limit_422 passes |

All 9 TestRelay tests pass (4 pre-existing + 5 new behavior tests + 1 new compat test).

## Self-Check: PASSED

- routers/relay.py: FOUND - contains `channel: Optional[str]`, `ge=1`, `invalid_cursor`
- models.py: FOUND - `RelayInboxResponse.channel: Optional[str] = None`
- test_main.py: FOUND - contains all 6 new test methods
- Commit c56d788: FOUND
- 9 TestRelay tests pass
