---
phase: 01-memory-privacy-and-security
verified: 2026-03-03T18:00:00Z
status: passed
score: 20/20 must-haves verified
re_verification: false
---

# Phase 1: Memory Privacy and Security Verification Report

**Phase Goal:** Agents can control who reads their memory — private by default, publicly shareable, or delegated to specific agents — with full audit trail and dashboard UI to manage it
**Verified:** 2026-03-03T18:00:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

All 20 truths are drawn directly from the three plan `must_haves.truths` sections (Plans 01-01, 01-02, 01-03).

#### Plan 01-01 Truths (Schema and Access Control)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | The memory table has a `visibility` column (TEXT DEFAULT 'private') and a `shared_agents` column (TEXT) | VERIFIED | `main.py:508-509` — both columns added via `PRAGMA table_info()` idempotent migration in `init_db()` |
| 2 | The memory_access_log table exists with the correct schema and index | VERIFIED | `main.py:517-533` — full 11-column schema + `idx_mal_agent` index created in `init_db()` |
| 3 | Existing memory rows with NULL visibility are backfilled to 'private' | VERIFIED | `main.py:513` — `UPDATE memory SET visibility='private' WHERE visibility IS NULL` in migration block |
| 4 | POST /v1/memory accepts `visibility` and `shared_agents` fields and stores them | VERIFIED | `main.py:1927-1933` — `MemorySetRequest` has both fields; `main.py:2061-2069` — INSERT includes both columns |
| 5 | GET /v1/agents/{target_agent_id}/memory/{key} returns 200 for public memory accessed by any authenticated agent | VERIFIED | `main.py:1990-2022` — endpoint calls `_check_memory_visibility()`; `test_main.py:2674` — `test_cross_agent_read_public_returns_200` |
| 6 | GET /v1/agents/{target_agent_id}/memory/{key} returns 403 (not 404) when a different agent tries to read a private memory key | VERIFIED | `main.py:2014` — `raise HTTPException(403, "Access denied...")` when `allowed=False`; `test_main.py:2685,2694` — `test_cross_agent_read_private_returns_403`, `test_cross_agent_read_private_not_404` |
| 7 | GET /v1/agents/{target_agent_id}/memory/{key} returns 200 for a shared key when the requester is in the shared_agents list | VERIFIED | `main.py:1966-1980` — `_check_memory_visibility()` parses `shared_agents` JSON and returns `True` if requester in list; `test_main.py:2702` — `test_cross_agent_read_shared_in_list_returns_200` |
| 8 | GET /v1/memory/{key} (own-agent read) does NOT enforce visibility — an agent can always read its own keys | VERIFIED | `main.py:2078-2093` — `memory_get()` queries `WHERE agent_id=?` only; no visibility filter; `test_main.py:2730,2738` — tests for private and shared keys both return 200 for owner |
| 9 | API response for GET /v1/agents/{target_agent_id}/memory/{key} 403 says 'Access denied' — not a generic 404 | VERIFIED | `main.py:2014` — message is `"Access denied: memory entry is private or not shared with you"` |

#### Plan 01-02 Truths (Visibility Endpoint and Audit Logging)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 10 | An agent can change the visibility of its own memory key by calling PATCH /v1/memory/{key}/visibility | VERIFIED | `main.py:2027-2049` — `memory_set_visibility()` endpoint registered; `test_main.py:2761,2776` — agent-changes-to-public and agent-changes-to-shared tests pass |
| 11 | PATCH /v1/memory/{key}/visibility returns 404 when the key does not exist | VERIFIED | `main.py:2038-2039` — `if not old: raise HTTPException(404, "Key not found")`; `test_main.py:2804` — `test_patch_nonexistent_key_returns_404` |
| 12 | Every memory write (POST /v1/memory) generates a memory_access_log row with action='write' | VERIFIED | `main.py:2073` — `_log_memory_access("write", ...)` called after INSERT; `test_main.py:2896` — `test_write_creates_audit_log_entry` |
| 13 | Every own-agent memory read (GET /v1/memory/{key}) generates a memory_access_log row with action='read' | VERIFIED | `main.py:2092` — `_log_memory_access("read", ...)` called outside `with get_db()` block; `test_main.py:2907` — `test_own_read_creates_audit_log_entry` |
| 14 | Every cross-agent read attempt generates a memory_access_log row — authorized=1 for allowed, authorized=0 for denied | VERIFIED | `main.py:2011-2013` — `_log_memory_access("cross_agent_read", ..., authorized=1 if allowed else 0)`; `test_main.py:2920,2933` — both authorized and unauthorized cross-agent reads logged |
| 15 | Every visibility change via PATCH /v1/memory/{key}/visibility generates a memory_access_log row with action='visibility_changed', old_visibility, and new_visibility populated | VERIFIED | `main.py:2045-2048` — `_log_memory_access("visibility_changed", ..., old_visibility=..., new_visibility=...)`; `test_main.py:2946` — `test_visibility_change_logged_with_old_and_new` |
| 16 | Audit log entries are written even if the main request returns an error (fire-and-forget pattern) | VERIFIED | `main.py:1942-1960` — `_log_memory_access()` uses `try/except Exception: pass`; all audit calls placed outside `with get_db()` context to avoid transaction interference |

#### Plan 01-03 Truths (Dashboard Endpoints and UI)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 17 | GET /v1/user/agents/{id}/memory-list returns visibility field for each key alongside key/value/namespace | VERIFIED | `main.py:1181-1184` — SELECT includes `COALESCE(visibility,'private') as visibility, shared_agents`; `test_main.py:3013` — `test_memory_list_includes_visibility` |
| 18 | GET /v1/user/agents/{id}/memory-entry?namespace=X&key=Y returns a single memory entry including its visibility and shared_agents | VERIFIED | `main.py:1196-1219` — fetches single row with visibility and shared_agents, parses JSON list; `test_main.py:3035` — `test_memory_entry_fetch` |
| 19 | PATCH /v1/user/agents/{id}/memory-entry/visibility changes the visibility of a specific memory key (JWT user auth) | VERIFIED | `main.py:1222-1246` — user-facing PATCH endpoint with `get_user_id` auth; `test_main.py:3069` — `test_user_set_visibility` |
| 20 | POST /v1/user/agents/{id}/memory-bulk-visibility changes visibility for up to 200 memory keys in one call; each change appears in memory_access_log | VERIFIED | `main.py:1249-1287` — iterates `req.entries[:200]` and emits `_log_memory_access("visibility_changed", ...)` for each after DB context closes; `test_main.py:3116,3170` — bulk change and bulk audit log tests |

**Score: 20/20 truths verified**

---

### Required Artifacts

| Artifact | Expected | Exists | Substantive | Wired | Status |
|----------|----------|--------|-------------|-------|--------|
| `MoltGrid/main.py` | Schema migration, `_check_memory_visibility()`, `_log_memory_access()`, `MemoryVisibilityRequest`, cross-agent GET endpoint | Yes (5,125 lines) | Yes — all required code present | Yes — endpoint calls helper; audit calls placed correctly | VERIFIED |
| `MoltGrid/main.py` | `memory_access_log` CREATE TABLE statement | Yes | Yes — 11-column schema at line 517 | Yes — `init_db()` called at startup (line 538) | VERIFIED |
| `MoltGrid/main.py` | `GET /v1/agents/{target_agent_id}/memory/{key}` endpoint | Yes | Yes — lines 1990-2022 with full implementation | Yes — registered with `@app.get` decorator | VERIFIED |
| `MoltGrid/main.py` | `PATCH /v1/memory/{key}/visibility` endpoint | Yes | Yes — lines 2027-2049 | Yes — registered with `@app.patch` decorator | VERIFIED |
| `MoltGrid/main.py` | `_log_memory_access()` calls in memory_set, memory_get, memory_cross_agent_get | Yes | Yes — write (2073), read (2092), cross_agent_read (2011), delete (2105) | Yes — all calls outside `with get_db()` per fire-and-forget contract | VERIFIED |
| `MoltGrid/main.py` | 5 dashboard endpoints (memory-list, memory-entry, memory-entry/visibility, memory-bulk-visibility, memory-access-log) | Yes | Yes — all 5 endpoints present at lines 1160, 1196, 1222, 1249, 1290 | Yes — all registered with `@app.*` decorators, JWT user auth | VERIFIED |
| `MoltGrid/test_main.py` | `TestMemoryVisibilitySchema` test class | Yes (3,232 lines) | Yes — 22 tests at lines 2443-2749 | Yes — class imported and runs in pytest | VERIFIED |
| `MoltGrid/test_main.py` | `TestMemoryVisibilityEndpoint` and `TestMemoryAuditLog` test classes | Yes | Yes — 5 + 5 = 10 tests at lines 2750-2989 | Yes | VERIFIED |
| `MoltGrid/test_main.py` | `TestMemoryDashboardEndpoints` test class | Yes | Yes — 9 tests at lines 2990+ | Yes | VERIFIED |
| `dashboard.html` | `visBadge()`, `renderTabMemory()`, `showMemoryDetailModal()` with correct badge colors | Yes (2,399 lines) | Yes — all three functions present with full implementations | Yes — wired to backend endpoints via `api()` calls | VERIFIED |

---

### Key Link Verification

#### Plan 01-01 Key Links

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `GET /v1/agents/{target_agent_id}/memory/{key}` | `_check_memory_visibility()` | Function call before returning value | WIRED | `main.py:2008` — `allowed = _check_memory_visibility(db, target_agent_id, namespace, key, agent_id)` |
| `POST /v1/memory` | memory table visibility column | INSERT stores `req.visibility` and `json.dumps(req.shared_agents)` | WIRED | `main.py:2061-2069` — `vis = req.visibility if req.visibility in (...)`, INSERT includes both columns |
| `_check_memory_visibility()` | `HTTPException(403)` | Raises 403 when visibility check fails | WIRED | `main.py:2014` — `raise HTTPException(403, "Access denied...")` when `allowed=False` |

#### Plan 01-02 Key Links

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `PATCH /v1/memory/{key}/visibility` | memory table UPDATE | `UPDATE memory SET visibility=?, shared_agents=?` | WIRED | `main.py:2040-2044` — full UPDATE with agent_id, namespace, key filter |
| `PATCH /v1/memory/{key}/visibility` | `_log_memory_access()` | Called after UPDATE with old/new visibility | WIRED | `main.py:2045-2048` — `_log_memory_access("visibility_changed", ..., old_visibility=..., new_visibility=...)` |
| `memory_set()` | `_log_memory_access()` | Called after INSERT OR REPLACE | WIRED | `main.py:2073` — `_log_memory_access("write", agent_id, req.namespace, req.key, actor_agent_id=agent_id)` |

#### Plan 01-03 Key Links

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `dashboard.html renderTabMemory()` | `GET /v1/user/agents/{id}/memory-list` | fetch call rendering vis-badge for each row's visibility | WIRED | `dashboard.html:1007` — `api("GET", "/v1/user/agents/" + agentId + "/memory-list" + qs)`; `dashboard.html:1035` — `visBadge(m.visibility)` |
| `dashboard.html showMemoryDetailModal()` | `PATCH /v1/user/agents/{id}/memory-entry/visibility` | PATCH call on form submit | WIRED | `dashboard.html:1184` — `api("PATCH", "/v1/user/agents/" + agentId + "/memory-entry/visibility", {...})` |
| `dashboard.html bulk action bar` | `POST /v1/user/agents/{id}/memory-bulk-visibility` | POST call with selected keys and target visibility | WIRED | `dashboard.html:1252` — `api("POST", "/v1/user/agents/" + agentId + "/memory-bulk-visibility", {...})` |
| `GET /v1/user/agents/{id}/memory-access-log` | memory_access_log table | SELECT query ordered by created_at DESC with agent_id filter | WIRED | `main.py:1306,1310` — `SELECT ... FROM memory_access_log WHERE {cond} ORDER BY created_at DESC` |
| `dashboard.html .vis-badge.shared CSS` | `#00aaff` (blue) | Direct CSS rule targeting `.vis-badge.shared` | WIRED | `dashboard.html:281` — `.vis-badge.shared { background:rgba(0,170,255,0.12); color:#00aaff; }` |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| MEM-01 | 01-01 | Agent owner can add `visibility` field via DB migration | SATISFIED | `main.py:505-513` — idempotent migration adds `visibility TEXT DEFAULT 'private'` + backfill |
| MEM-02 | 01-01 | Private memory only accessible to owning agent and dashboard owner; others get 403 | SATISFIED | `main.py:1966-1980,2008-2014` — private check + 403 raise; user dashboard uses ownership verify |
| MEM-03 | 01-01 | Public memory readable by any authenticated agent | SATISFIED | `main.py:1974-1976` — `if vis == "public": return True` in `_check_memory_visibility()` |
| MEM-04 | 01-01 | Shared memory readable by specified list of agent IDs in `shared_with` column | SATISFIED | `main.py:1977-1979` — JSON array parsed, requester checked against list; stored as `shared_agents` column (JSON array) |
| MEM-05 | 01-02 | Agent can change visibility via `PATCH /v1/memory/{key}/visibility` | SATISFIED | `main.py:2027-2049` — endpoint implemented and tested |
| MEM-06 | 01-01 | Unauthorized reads return 403 (not 404) | SATISFIED | `main.py:2014` — `raise HTTPException(403, ...)` confirmed not 404; `test_main.py:2694` — `test_cross_agent_read_private_not_404` |
| MEM-07 | 01-01 | `/v1/shared-memory` clearly differentiated from per-agent memory with visibility | SATISFIED | `main.py:1983-1988` — code comment block explicitly documents the distinction; two separate route sections |
| MEM-08 | 01-02 | All memory read/write/visibility-change events logged to memory_access_log | SATISFIED | write (2073), read (2092), cross_agent_read (2011), visibility_changed (2045, 1242, 1283), delete (2105) — all covered |
| MEM-09 | 01-03 | Dashboard Memory tab shows visibility badges (private=gray, public=green, shared=blue) | SATISFIED | `dashboard.html:279-281` — CSS for three badge types; `dashboard.html:990-992` — `visBadge()` renders correct class; `.vis-badge.shared` is blue (#00aaff) |
| MEM-10 | 01-03 | User can click visibility badge to open dropdown and change visibility | SATISFIED | `dashboard.html:1041` — row click opens `showMemoryDetailModal()`; `dashboard.html:1154-1157` — select with private/public/shared options, PATCH on submit |
| MEM-11 | 01-03 | User can select multiple keys and bulk-change visibility via action bar | SATISFIED | `dashboard.html:1094-1097` — bulk action bar with checkbox selection; `dashboard.html:1249-1260` — calls `memory-bulk-visibility` endpoint; `main.py:1249-1287` — server caps at 200 keys, logs each change |

**All 11 requirements (MEM-01 through MEM-11) are SATISFIED.**

No orphaned requirements — all 11 MEM-01..MEM-11 requirements appear in plan frontmatter and are traced to implementation.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `MoltGrid/main.py` | 3028 | `TODO: Add HNSW index (hnswlib) for >10K vectors.` | Info | Unrelated to memory privacy — pre-existing VectorMemory section comment |

No blocker or warning anti-patterns found in memory privacy code paths. The one TODO at line 3028 is in the VectorMemory section, unrelated to Phase 1 work.

---

### Human Verification Required

#### 1. Dashboard Memory Tab — Visual Badge Rendering

**Test:** Log into the dashboard, navigate to an agent detail page, click the Memory tab.
**Expected:** Memory keys display colored badges — gray for private, green for public, blue for shared. Clicking a badge opens a modal with a dropdown showing the three visibility options. Selecting "Shared" reveals an agent-ID input.
**Why human:** CSS rendering and modal open/close behavior cannot be verified programmatically.

#### 2. Bulk Visibility Action Bar — Multi-Select Flow

**Test:** In the Memory tab, check two or more memory key checkboxes, then click the "Change Visibility" button.
**Expected:** A dialog appears allowing selection of a new visibility level. On confirm, all selected keys update and the UI reflects the new badges.
**Why human:** UI state management, checkbox interaction, and overlay rendering require browser execution.

#### 3. Audit Log Display in Memory Modal

**Test:** Open the memory detail modal for a key that has been read and written multiple times. Expand the audit log section.
**Expected:** Audit log entries appear, showing action types (read, write, visibility_changed) with timestamps and old/new visibility where applicable.
**Why human:** Lazy-loading of the audit log within the modal and its rendering cannot be verified from static file analysis.

---

### Gaps Summary

No gaps. All 20 must-have truths verified, all key links confirmed wired, all 11 requirements satisfied by direct code evidence.

The phase goal — "Agents can control who reads their memory — private by default, publicly shareable, or delegated to specific agents — with full audit trail and dashboard UI to manage it" — is fully achieved.

---

### Commit Trail

All 7 commits are present in the inner `MoltGrid/` git repository:

| Commit | Plan | Phase | Description |
|--------|------|-------|-------------|
| `9c5135e` | 01-01 | RED | Failing TestMemoryVisibilitySchema tests |
| `7335f53` | 01-01 | GREEN | Memory visibility schema and access control implementation |
| `8275fa4` | 01-02 | RED | Failing tests for visibility endpoint and audit log |
| `01a8919` | 01-02 | GREEN | PATCH endpoint + audit log fixes |
| `e22a00f` | 01-03 | RED | Failing TestMemoryDashboardEndpoints tests |
| `d84662e` | 01-03 | GREEN | Bulk-visibility audit log fix + all dashboard tests pass |
| `d0e5464` | 01-03 | FEAT | .vis-badge.shared color orange → blue (#00aaff) |

---

_Verified: 2026-03-03T18:00:00Z_
_Verifier: Claude (gsd-verifier)_
