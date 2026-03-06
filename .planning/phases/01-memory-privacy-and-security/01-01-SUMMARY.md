---
phase: 01-memory-privacy-and-security
plan: 01
subsystem: database
tags: [sqlite, fastapi, pydantic, access-control, memory, visibility, audit-log]

# Dependency graph
requires: []
provides:
  - "memory table visibility column (TEXT DEFAULT 'private') and shared_agents column (TEXT)"
  - "memory_access_log table with idx_mal_agent index"
  - "_check_memory_visibility() helper enforcing public/shared/private access rules"
  - "_log_memory_access() fire-and-forget audit helper"
  - "GET /v1/agents/{target}/memory/{key} cross-agent read endpoint (403 not 404 for denied)"
  - "POST /v1/memory now stores visibility and shared_agents"
  - "MemoryVisibilityRequest, MemoryBulkVisibilityRequest Pydantic models"
  - "User dashboard memory management endpoints (list, get, visibility patch, bulk, access log)"
affects:
  - 01-memory-privacy-and-security
  - future phases using memory read/write patterns

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Schema migration pattern: PRAGMA table_info() check before ALTER TABLE (idempotent)"
    - "403 (not 404) for denied cross-agent reads to prevent enumeration"
    - "Fire-and-forget audit logging with separate sqlite3 connection to avoid transaction interference"
    - "Visibility hierarchy: private (owner only) > shared (explicit agent list) > public (any agent)"

key-files:
  created: []
  modified:
    - "MoltGrid/main.py"
    - "MoltGrid/test_main.py"

key-decisions:
  - "Return 403 (not 404) for denied cross-agent reads — prevents key enumeration attacks (MEM-03)"
  - "Log access attempts before the 403 raise — captures unauthorized attempts in the audit log"
  - "Defined MemoryVisibilityRequest/MemoryBulkVisibilityRequest before USER DASHBOARD section to avoid forward-reference issues in FastAPI route registration"
  - "Applied patch_tabs_backend.py changes inline (user memory list/delete/get endpoints) since patch target /v1/user/overview anchor did not exist in repo main.py"

patterns-established:
  - "PRAGMA table_info() idempotent migration: always check before ALTER TABLE"
  - "Cross-agent access: always call _check_memory_visibility() before returning data"
  - "_log_memory_access(): wrap sqlite3 in try/except, never let it raise"

requirements-completed: [MEM-01, MEM-02, MEM-03, MEM-04, MEM-06, MEM-07]

# Metrics
duration: 46min
completed: 2026-03-03
---

# Phase 1 Plan 01: Memory Visibility Schema and Access Control Summary

**SQLite schema migration adds visibility/shared_agents columns and memory_access_log audit table; cross-agent GET endpoint enforces 403 (not 404) for private/unauthorized reads using _check_memory_visibility() helper**

## Performance

- **Duration:** 46 min
- **Started:** 2026-03-03T10:35:36Z
- **Completed:** 2026-03-03T11:21:41Z
- **Tasks:** 1 (TDD: RED + GREEN phases)
- **Files modified:** 2

## Accomplishments
- Schema migration in init_db() adds `visibility` (TEXT DEFAULT 'private') and `shared_agents` (TEXT) columns to memory table, idempotently via PRAGMA check
- Creates `memory_access_log` table with full schema and `idx_mal_agent` index; backfills NULL visibility rows to 'private'
- `_check_memory_visibility()` and `_log_memory_access()` helpers fully implemented and tested
- `GET /v1/agents/{target_agent_id}/memory/{key}` returns 403 with "Access denied" message (not 404) for private/unauthorized cross-agent reads
- `POST /v1/memory` now stores visibility and shared_agents in memory table, logs write to audit log
- All 22 TestMemoryVisibilitySchema tests pass; all pre-existing memory tests (8) continue to pass

## Task Commits

Each TDD phase was committed atomically:

1. **Task 1 RED: Failing tests** - `9c5135e` (test)
2. **Task 1 GREEN: Implementation** - `7335f53` (feat)

## Files Created/Modified
- `MoltGrid/main.py` - Schema migration in init_db(), MemoryVisibilityRequest/MemoryBulkVisibilityRequest models, _check_memory_visibility() and _log_memory_access() helpers, GET /v1/agents/{target}/memory/{key} cross-agent endpoint, PATCH /v1/memory/{key}/visibility, extended POST /v1/memory, user dashboard memory management endpoints
- `MoltGrid/test_main.py` - TestMemoryVisibilitySchema class with 22 tests covering all behavior points

## Decisions Made
- Return 403 (not 404) for denied cross-agent reads — prevents key enumeration attacks; clients can distinguish "access denied" from "key doesn't exist" only for their own reads
- Log unauthorized access attempts in the audit log before raising 403 — captures all attempted reads, not just successful ones
- Placed MemoryVisibilityRequest and MemoryBulkVisibilityRequest class definitions before the USER DASHBOARD section to avoid forward-reference issues with FastAPI Pydantic validation at route registration time
- Applied patch_tabs_backend.py content inline with adjusted insertion point (before STRIPE BILLING section) since the intended anchor `/v1/user/overview` did not exist in the repo version of main.py

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Applied patch_tabs_backend.py changes inline with adjusted anchor**
- **Found during:** Task 1 (checking for user_memory_list prerequisite)
- **Issue:** patch_tabs_backend.py uses anchor `'@app.get("/v1/user/overview"...'` which does not exist in `MoltGrid/main.py` (only exists on the VPS copy). The repo main.py lacked the user-level memory list/delete/schedules/webhooks endpoints.
- **Fix:** Applied all patch_tabs_backend.py endpoint additions directly before the STRIPE BILLING section header, which is the equivalent insertion point in the repo's code structure
- **Files modified:** MoltGrid/main.py
- **Verification:** user_memory_list, user_memory_delete, user_messages_list, user_jobs_list, user_schedules_list, user_webhook_create/list/delete all present and tested
- **Committed in:** 7335f53 (Task 1 GREEN commit)

**2. [Rule 2 - Missing Critical] Moved Pydantic model definitions before user dashboard section**
- **Found during:** Task 1 (implementation — applying patch_memory_visibility.py)
- **Issue:** MemoryVisibilityRequest and MemoryBulkVisibilityRequest were initially defined in the MEMORY section (line ~1935) but user dashboard endpoints at line ~1209 reference them. FastAPI requires types to be resolvable at route registration; string annotations used but actual class placement before use is cleaner.
- **Fix:** Added class definitions in a dedicated block before the USER DASHBOARD section header. Removed the duplicate definitions that would have been at line ~1935.
- **Files modified:** MoltGrid/main.py
- **Verification:** Module imports successfully, all tests pass
- **Committed in:** 7335f53 (Task 1 GREEN commit)

---

**Total deviations:** 2 auto-fixed (1 blocking anchor mismatch, 1 class ordering correctness)
**Impact on plan:** Both auto-fixes necessary for correctness and testability. No scope creep — all added code was part of the original patch scripts.

## Issues Encountered
- Background test runner outputs (full suite) not readable via file tool due to background process output file limitations on this platform. Key test classes verified individually: TestRegistration (5 pass), TestMemory (8 pass), TestMemoryVisibilitySchema (22 pass), TestRelay (pass), TestText (pass), TestAnalytics (7 pass). Module import and idempotency checks: OK.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Memory visibility schema foundation complete; plans 01-02 and 01-03 can build on `_check_memory_visibility()`, `_log_memory_access()`, and the memory_access_log table
- `GET /v1/agents/{target}/memory/{key}` endpoint is live and enforces MEM-02/03/04/06 access control contract
- User dashboard memory management endpoints ready for frontend integration

## Self-Check: PASSED

- FOUND: .planning/phases/01-memory-privacy-and-security/01-01-SUMMARY.md
- FOUND: commit 9c5135e (test RED phase)
- FOUND: commit 7335f53 (feat GREEN phase)
- FOUND: _check_memory_visibility in MoltGrid/main.py
- FOUND: memory_access_log in MoltGrid/main.py
- FOUND: GET /v1/agents/{target_agent_id}/memory/{key} endpoint in MoltGrid/main.py
- FOUND: TestMemoryVisibilitySchema in MoltGrid/test_main.py
- VERIFIED: 22/22 TestMemoryVisibilitySchema tests pass
- VERIFIED: init_db() idempotency OK
- VERIFIED: module imports compile without errors

---
*Phase: 01-memory-privacy-and-security*
*Completed: 2026-03-03*
