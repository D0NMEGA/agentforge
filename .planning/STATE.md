---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: completed
stopped_at: Completed 43-02-PLAN.md -- cursor inbox + health components live, 344 tests passing
last_updated: "2026-03-23T21:49:03.346Z"
last_activity: "2026-03-23 -- Plan 42-02 complete: relay dead-letter, status lifecycle, hop trace, 3 new endpoints"
progress:
  total_phases: 12
  completed_phases: 5
  total_plans: 10
  completed_plans: 12
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-03)

**Core value:** OpenClaw running on MoltGrid and posting on MoltBook IS the product — every feature should ask "how does this serve the MoltGrid -> OpenClaw -> MoltBook loop?"
**Current focus:** Phase 42 Plan 02 complete -- relay_send dead-letter refactor + status/trace/dead-letter endpoints

## Current Position

Phase: 42 (Fix Message Delivery)
Plan: 02 of 02 in current phase (plan 02 complete)
Status: TDD GREEN phase complete; 6/6 relay tests passing, 107/107 total tests passing
Last activity: 2026-03-23 -- Plan 42-02 complete: relay dead-letter, status lifecycle, hop trace, 3 new endpoints

Progress: [██████████] 100%

## Performance Metrics

**Velocity:**
- Total plans completed: 14
- Average duration: 20 min
- Total execution time: 4.7 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-memory-privacy-and-security | 3 | 99min | 33min |
| 09-postgresql-migration | 3 | 100min | 33min |
| 10-monolith-modularization | 2/2 | 39min | 20min |
| 14-quickstarts-and-playground | 2/2 | 4min | 2min |
| 40-backend-scalability-load-hardening | 3/3 | 12min | 4min |
| 41-production-scalability | 2/2 | 12min | 6min |
| 42-fix-message-delivery | 2/2 | 27min | 14min |

**Recent Trend:**
- Last 5 plans: 1min, 3min, 3min, 7min, 12min
- Trend: consistent

*Updated after each plan completion*
| Phase 43-sse-push-cursor-inbox P01 | 32 | 2 tasks | 6 files |
| Phase 43-sse-push-cursor-inbox P02 | 18 | 2 tasks | 3 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Supabase migration deferred -- all code targets SQLite on VPS; Supabase MCP used for schema planning only
- moltgrid-web frontend isolation -- no HTML/CSS/JS added to backend repo (except server-rendered admin pages pending P5 audit)
- Unified event stream (P8) -- single GET /v1/events beats agents polling relay + queue + memory separately
- obstacle-course.md doubles as QA gauntlet and agent onboarding -- DX feedback is product gold
- [01-01] 403 (not 404) for denied cross-agent reads -- prevents key enumeration attacks
- [01-01] MemoryVisibilityRequest defined before USER DASHBOARD section to avoid FastAPI forward-reference issues
- [01-01] patch_tabs_backend.py applied inline (adjusted anchor) since /v1/user/overview did not exist in repo main.py
- [01-02] action='cross_agent_read' (not 'read') for GET /v1/agents/{target}/memory/{key} -- distinguishes requester context in audit log
- [01-02] _log_memory_access() must be called OUTSIDE with get_db() block -- fire-and-forget uses its own sqlite3 connection, calling inside causes transaction interference
- [01-02] Invalid visibility coerces to 'private' (not rejected) -- consistent with write path behavior
- [Phase 01-03]: bulk-visibility audit logs collected outside DB context using log_entries list (same pattern as 01-02 decision, applied to bulk endpoint)
- [Phase 01-03]: _queue_email mock required in any test calling /v1/auth/signup or /v1/register to prevent background email thread sqlite lock contention
- [09-01] DB_BACKEND env var controls backend: sqlite (default), postgres, or dual
- [09-01] get_db() context manager replaces all direct sqlite3.connect calls
- [09-01] PsycopgConnWrapper provides sqlite3-compatible API over psycopg connections
- [09-03] Backend-agnostic test helpers replace all sqlite_master queries in tests
- [09-03] datetime() SQL translation uses precompiled regex with [^(),]+ to prevent cross-call matching
- [09-03] INSERT OR REPLACE replaced with ON CONFLICT DO UPDATE for PostgreSQL compatibility
- [09-03] TURNSTILE_SECRET_KEY="" disables CAPTCHA in test environment
- [10-01] All new modules are additive -- main.py unchanged, zero test modifications required
- [10-01] _get_embed_model in helpers.py uses import state to write _embed_model (avoids stale closure)
- [10-01] helpers.py includes _should_send_notification (needed by _check_usage_quota dependency chain)
- [10-02] app.version replaced with literal "0.9.0" in router files -- avoids importing app object into routers
- [10-02] _queue_email accessed via _get_queue_email() lazy import from main module for test mock compatibility
- [10-02] MOLTBOOK_SERVICE_KEY accessed via lazy import from main for test patching compatibility
- [10-02] __file__ paths in routers use parent.parent to resolve project root
- [10-02] models.py corrected: MemorySetRequest visibility field, TOTP field names, ConfigDict on response models
- [14-02] Bruno DSL format chosen over JSON for human readability and native Bruno app compatibility
- [14-02] Single api_key variable covers all agent-authenticated endpoints; jwt_token separate for user auth
- [14-01] Used actual SDK method names (memory_set, memory_get) not dot-notation aliases in guides
- [14-01] All guides use MoltGrid class import matching SDK source, not MoltGridClient
- [40-02] Manual cache get/set pattern over @cached_response decorator for consistency with existing code
- [40-02] Directory list cache key includes capability+limit params for correct per-query caching
- [40-02] RATE_LIMIT_ENABLED env var disables slowapi in tests (pre-existing 40-01 gap)
- [40-02] response_cache.clear() in test fixture prevents stale cached data between tests
- [40-03] Pass criteria locked: error_rate < 1.0% AND t_elapsed < 60s (strict less-than)
- [40-03] HTTP 500+ counted as errors; 4xx are expected and not counted
- [40-03] Scenarios without API key skip gracefully with success record
- [41-03] Redis SET NX with 30s TTL for leader election across Uvicorn workers
- [41-03] Lua script atomic release prevents race conditions on leader key deletion
- [41-03] Graceful fallback: assume leadership when Redis unavailable (single-worker compat)
- [41-03] 4 Uvicorn workers (up from 2), deploy.sh auto-installs redis-server
- [41-03] Prometheus text format for /metrics (industry-standard monitoring)
- [41-04] Evaluator separated from locust file to avoid gevent monkey-patching pytest conflicts
- [41-04] Task weights model real agent behavior: heartbeat 6, inbox 5, memory 3/2, jobs 1
- [41-04] Strict less-than for all pass criteria (p99 < 500ms, error < 0.1%, 5xx = 0)
- [42-01] ALTER TABLE migration guards add relay status columns; dead_letter_messages and message_hops tables created
- [42-02] relay_send returns 200 dead_lettered for unknown recipients (not 404) -- prevents recipient enumeration
- [42-02] GET /v1/messages/dead-letter registered before /{message_id}/status to avoid FastAPI route ambiguity
- [42-02] DeadLetterMessageListResponse renamed to avoid collision with queue DeadLetterListResponse in models.py
- [42-02] relay_mark_read updates status column + status_updated_at alongside read_at for lifecycle consistency
- [Phase 43-01]: asyncio.Queue fan-out for SSE (intra-worker only); Redis pub/sub deferred to Plan 02
- [Phase 43-01]: uvicorn test server pattern for infinite-stream SSE tests (httpx ASGITransport deadlock workaround)
- [Phase 43-01]: Last-Event-ID replay uses created_at anchor query not lexicographic event_id comparison
- [Phase 43-02]: cursor resolves to created_at anchor (not lexicographic message_id) since msg_{uuid4} is not time-ordered
- [Phase 43-02]: unknown cursor returns empty list not error for safe polling by agents that restart
- [Phase 43-02]: relay degraded threshold is 10 stuck messages older than 5 minutes

### Pending Todos

None yet.

### Blockers/Concerns

None -- Phase 42 Plan 02 complete.

## Session Continuity

Last session: 2026-03-23T21:48:56.408Z
Stopped at: Completed 43-02-PLAN.md -- cursor inbox + health components live, 344 tests passing
Resume file: None
