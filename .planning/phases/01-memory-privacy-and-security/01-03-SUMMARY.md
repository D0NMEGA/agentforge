---
phase: 01-memory-privacy-and-security
plan: 03
subsystem: api
tags: [fastapi, sqlite, jwt, memory, visibility, dashboard, audit-log]

# Dependency graph
requires:
  - phase: 01-memory-privacy-and-security/01-01
    provides: "visibility column in memory table, _verify_agent_ownership(), MemoryVisibilityRequest, MemoryBulkVisibilityRequest models"
  - phase: 01-memory-privacy-and-security/01-02
    provides: "_log_memory_access() helper, PATCH /v1/memory/{key}/visibility, memory_access_log table"
provides:
  - "GET /v1/user/agents/{id}/memory-list with visibility field per key"
  - "GET /v1/user/agents/{id}/memory-entry single entry with shared_agents"
  - "PATCH /v1/user/agents/{id}/memory-entry/visibility (MEM-10)"
  - "POST /v1/user/agents/{id}/memory-bulk-visibility up to 200 keys (MEM-11)"
  - "GET /v1/user/agents/{id}/memory-access-log paginated audit log"
  - ".vis-badge.shared CSS color blue (#00aaff) in dashboard.html (MEM-09)"
affects: [02-user-experience, vps-deployment, frontend-dashboard]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "_log_memory_access() must always be called OUTSIDE with get_db() context block"
    - "Batch log collection: accumulate (ns, key, old_vis) tuples in list, emit after DB context closes"
    - "_queue_email() mock required in tests that call /v1/auth/signup to avoid sqlite lock from background email thread"

key-files:
  created: []
  modified:
    - "MoltGrid/main.py"
    - "MoltGrid/test_main.py"
    - "dashboard.html"
    - "MoltGrid/dashboard.html"

key-decisions:
  - "bulk-visibility audit logs collected outside DB context using log_entries list (same pattern as 01-02 decision, applied here)"
  - "_register_user_and_agent() test helper mocks _queue_email to prevent sqlite lock from background email thread"
  - "MoltGrid/dashboard.html replaced with full-featured root dashboard.html (1054 lines -> 2399 lines) to serve memory UI"

patterns-established:
  - "Batch audit logging pattern: collect log data inside DB context, emit _log_memory_access() calls after context closes"
  - "User+agent test helper pattern: patch _queue_email to avoid background thread DB contention"

requirements-completed: [MEM-09, MEM-10, MEM-11]

# Metrics
duration: 28min
completed: 2026-03-03
---

# Phase 1 Plan 03: Memory Dashboard Endpoints Summary

**Five user-dashboard memory visibility endpoints (memory-list, memory-entry, memory-entry/visibility, memory-bulk-visibility, memory-access-log) with 9 passing tests, plus shared badge CSS corrected to blue (#00aaff) per MEM-09**

## Performance

- **Duration:** 28 min
- **Started:** 2026-03-03T~17:00:00Z
- **Completed:** 2026-03-03T~17:28:00Z
- **Tasks:** 3/3 (including checkpoint:human-verify — VPS deployment confirmed)
- **Files modified:** 4

## Accomplishments
- All 5 dashboard memory endpoints verified working with 9 new tests (TestMemoryDashboardEndpoints)
- Fixed user_memory_bulk_visibility to emit audit logs outside DB context (Rule 1 auto-fix)
- Shared visibility badge color corrected from orange (#ffaa00) to blue (#00aaff) per MEM-09
- MoltGrid/dashboard.html updated to full-featured version with memory tab UI (visBadge, renderTabMemory, showMemoryDetailModal, bulk action bar)

## Task Commits

Each task was committed atomically (in MoltGrid inner git repo):

1. **Task 1 RED: TestMemoryDashboardEndpoints (failing tests)** - `e22a00f` (test)
2. **Task 1 GREEN: Fix bulk-visibility audit log + all tests pass** - `d84662e` (feat)
3. **Task 2: Patch .vis-badge.shared color to blue** - `d0e5464` (feat)
4. **Task 3: checkpoint:human-verify** - CLEARED (VPS deployed, dashboard confirmed live)

_Note: TDD tasks have separate RED (test) and GREEN (feat) commits_

## Files Created/Modified
- `MoltGrid/main.py` - Fixed user_memory_bulk_visibility: _log_memory_access() calls moved outside with get_db() context
- `MoltGrid/test_main.py` - Added TestMemoryDashboardEndpoints class (9 tests) + _register_user_and_agent() helper
- `dashboard.html` (root) - .vis-badge.shared updated: orange -> blue (#00aaff)
- `MoltGrid/dashboard.html` - Replaced with full-featured root dashboard.html (includes memory tab UI)

## Decisions Made
- Collected (ns, key, old_vis) tuples inside the DB context then emitted audit logs after — same batch pattern documented from 01-02 but not yet applied to the bulk endpoint
- Used `patch("main._queue_email")` mock in test helper to prevent sqlite lock contention from the background email delivery thread (which runs every 30s during tests)
- Replaced MoltGrid/dashboard.html with the root version since FastAPI serves from MoltGrid/ directory and the existing file lacked all memory tab UI

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed user_memory_bulk_visibility: audit logs called inside DB context**
- **Found during:** Task 1 (test_bulk_visibility_logs_each_change failing with 0 rows)
- **Issue:** _log_memory_access() was called inside the `with get_db() as db:` block in user_memory_bulk_visibility. The function opens its own sqlite3.connect() which conflicts with the outer context, causing the INSERT to fail silently (exception swallowed by `except Exception: pass`). This is the same issue documented in STATE.md from plan 01-02: "_log_memory_access() must be called OUTSIDE with get_db() block".
- **Fix:** Changed to collect (ns, key, old_vis) tuples in a `log_entries` list inside the DB context, then emit all `_log_memory_access()` calls after the `with` block closes
- **Files modified:** MoltGrid/main.py
- **Verification:** test_bulk_visibility_logs_each_change now passes (2+ audit rows confirmed)
- **Committed in:** d84662e (Task 1 GREEN commit)

**2. [Rule 2 - Missing Critical] Added _queue_email mock to test helper**
- **Found during:** Task 1 (all tests failing with sqlite3.OperationalError: database is locked)
- **Issue:** /v1/auth/signup and /v1/register call _queue_email() which opens a new DB connection. The background email thread (_email_loop, runs every 30s) competes for the same WAL lock, causing OperationalError. No other tests that call signup worked either (TestUserAuth::test_signup also fails in isolation).
- **Fix:** Wrapped both signup and register calls in `with patch("main._queue_email", return_value=None):` in the _register_user_and_agent() helper
- **Files modified:** MoltGrid/test_main.py
- **Verification:** All 9 tests now pass consistently
- **Committed in:** e22a00f / d84662e (test RED and feat GREEN commits)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 missing test infrastructure)
**Impact on plan:** Both fixes essential for correctness and test reliability. No scope creep.

## Issues Encountered
- The background email thread runs during tests because FastAPI's lifespan starts it. This causes intermittent sqlite WAL lock contention whenever tests call signup/register. Pattern established: always mock _queue_email in tests that create users.

## User Setup Required
None — VPS deployment confirmed via checkpoint:human-verify. Code pushed to GitHub and deployed to VPS (82.180.139.113). Health check returned operational.

## Next Phase Readiness
- All 11 MEM requirements are implemented and VPS-deployed: MEM-01..07 (plan 01-01), MEM-08 (plan 01-02), MEM-09..11 (this plan)
- Phase 1 (Memory Privacy & Security) is fully complete — code live on VPS, dashboard confirmed operational
- Dashboard memory tab fully connected to backend endpoints; shared badge confirmed blue (#00aaff) on live site
- Ready to move to Phase 2: OpenClaw Integration

## Self-Check: PASSED

- FOUND: MoltGrid/main.py
- FOUND: MoltGrid/test_main.py
- FOUND: dashboard.html (root) with #00aaff
- FOUND: MoltGrid/dashboard.html with #00aaff
- FOUND: 01-03-SUMMARY.md
- FOUND: e22a00f (test RED commit)
- FOUND: d84662e (feat GREEN commit)
- FOUND: d0e5464 (feat badge commit)
- All 9 TestMemoryDashboardEndpoints tests: PASSED

---
*Phase: 01-memory-privacy-and-security*
*Completed: 2026-03-03*
