---
phase: 10-monolith-modularization
plan: 02
subsystem: infrastructure
tags: [modularization, router-extraction, fastapi-routers]
dependency_graph:
  requires: [config.py, state.py, models.py, helpers.py, routers/__init__.py]
  provides: [18 router modules, slim main.py]
  affects: [main.py, models.py]
tech_stack:
  added: []
  patterns: [fastapi-apirouter, lazy-import-for-mock-compat, module-re-export]
key_files:
  created:
    - routers/auth.py
    - routers/dashboard.py
    - routers/billing.py
    - routers/memory.py
    - routers/queue.py
    - routers/relay.py
    - routers/webhooks.py
    - routers/schedules.py
    - routers/vector.py
    - routers/directory.py
    - routers/marketplace.py
    - routers/pubsub.py
    - routers/integrations.py
    - routers/sessions.py
    - routers/events.py
    - routers/orgs.py
    - routers/admin.py
    - routers/system.py
  modified:
    - main.py
    - models.py
decisions:
  - "app.version replaced with literal '0.9.0' in router files to avoid importing app object"
  - "_queue_email accessed via lazy import from main module (_get_queue_email pattern) for test mock compatibility"
  - "MOLTBOOK_SERVICE_KEY accessed via lazy import from main module for test patching"
  - "__file__ paths in routers use parent.parent to resolve project root (routers/ is one level deeper)"
  - "Billing-specific helpers (_apply_tier, _get_or_create_stripe_customer, _tier_from_price) moved to billing router"
  - "_check_onboarding_progress moved to integrations router"
  - "httpx re-exported from main.py for test mock compatibility (patch('main.httpx.Client'))"
  - "models.py fixed: MemorySetRequest visibility/shared_agents, TOTP field names, ConfigDict on response models"
metrics:
  duration: 31min
  completed: "2026-03-15T05:04:00Z"
---

# Phase 10 Plan 02: Router Extraction + Slim main.py Summary

Moved all 188 route handlers from 6752-line main.py into 18 FastAPI APIRouter modules, rebuilt main.py as a 189-line orchestrator, and achieved 332 passing tests with zero test modifications.

## One-liner

18 router modules extracted from 6752-line monolith, main.py reduced to 189-line orchestrator with mock-compatible re-exports

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Create all 18 router modules | c31509b | routers/*.py (18 files) |
| 2 | Rebuild main.py as thin orchestrator | 4abfce9 | main.py (189 lines) |
| 3 | Fix import/wiring issues for test compatibility | 6f1324a | main.py, models.py, routers/*.py |

## What Was Built

### 18 Router Modules (routers/)

| Router | Routes | Tags |
|--------|--------|------|
| auth.py | 14 | Auth, User |
| dashboard.py | 33 | User Dashboard |
| billing.py | 7 | Billing, Templates |
| memory.py | 6 | Memory |
| queue.py | 8 | Queue |
| relay.py | 4 | Relay |
| webhooks.py | 4 | Webhooks |
| schedules.py | 5 | Schedules |
| vector.py | 10 | Vector Memory, Shared Memory |
| directory.py | 13 | Directory |
| marketplace.py | 10 | Marketplace, Testing |
| pubsub.py | 5 | Pub/Sub |
| integrations.py | 8 | Integrations, Onboarding |
| sessions.py | 6 | Sessions |
| events.py | 4 | Events |
| orgs.py | 8 | Orgs |
| admin.py | 20 | Admin |
| system.py | 23 | System, Obstacle Course, Documentation, Dashboard |
| **Total** | **188** | |

### main.py (189 lines)
Thin orchestrator containing only:
- Imports and re-exports (13 symbols for test compatibility)
- Lifespan handler (6 daemon threads)
- FastAPI app creation
- Exception handlers (3)
- CORS middleware
- Response headers middleware
- init_db() call
- 18 router includes

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed models.py field definitions**
- **Found during:** Task 3
- **Issue:** MemorySetRequest missing visibility/shared_agents fields, TOTP models had wrong field names (totp_code vs code), response models missing ConfigDict(extra='ignore')
- **Fix:** Updated models.py to match original main.py definitions
- **Files modified:** models.py

**2. [Rule 3 - Blocking] Mock compatibility for _queue_email**
- **Found during:** Task 3
- **Issue:** Tests use `patch("main._queue_email")` but routers import from helpers, so mock doesn't reach router code
- **Fix:** Added `_get_queue_email()` lazy import pattern that fetches _queue_email from main module at call time
- **Files modified:** routers/auth.py, routers/billing.py, routers/system.py

**3. [Rule 3 - Blocking] MOLTBOOK_SERVICE_KEY test patching**
- **Found during:** Task 3
- **Issue:** Tests set `main.MOLTBOOK_SERVICE_KEY` but router imported from config
- **Fix:** Changed to lazy import from main module
- **Files modified:** routers/integrations.py

**4. [Rule 1 - Bug] __file__ path resolution in routers**
- **Found during:** Task 3
- **Issue:** Routers use `__file__` for file paths but are one directory deeper than original main.py
- **Fix:** Use `parent.parent` or `_backend_dir` pointing to project root
- **Files modified:** routers/system.py, routers/admin.py, routers/integrations.py

**5. [Rule 1 - Bug] app.version reference in router modules**
- **Found during:** Task 3
- **Issue:** Router code references `app.version` but app is not in scope
- **Fix:** Replaced with literal "0.9.0"
- **Files modified:** routers/system.py, routers/admin.py

## Verification

- `wc -l main.py` = 189 lines (under 200)
- `pytest test_main.py -v --tb=short` = 332 passed, 4 skipped, 0 failures
- `ls routers/*.py | wc -l` = 19 (18 routers + __init__.py)
- All 13 test_main.py symbols re-exported from main.py
- All 188 routes registered via app.include_router()

## Self-Check: PASSED
