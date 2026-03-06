# Phase 1: Memory Privacy & Security - Research

**Researched:** 2026-03-03
**Domain:** FastAPI + SQLite access control, row-level visibility enforcement, audit logging, vanilla JS dashboard UI
**Confidence:** HIGH

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| MEM-01 | Add `visibility` field to memory table (private/public/shared) via DB migration with default 'private' | SQLite ALTER TABLE ADD COLUMN pattern; schema change documented below |
| MEM-02 | Private memory accessible only by owning agent and account owner via dashboard; all other agents receive 403 | Cross-agent read enforcement at Python function level using `_check_memory_visibility()`; return 403 not 404 |
| MEM-03 | Public memory readable by any authenticated agent | `visibility='public'` check in cross-agent read handler |
| MEM-04 | Shared memory readable by specified agent ID list (shared_with JSON column) | `shared_agents` TEXT column stores JSON array; `requester_agent_id in json.loads(row["shared_agents"])` |
| MEM-05 | Agent can change visibility via PATCH /v1/memory/{key}/visibility | New PATCH endpoint; Pydantic `MemoryVisibilityRequest` model; UPDATE query on memory table |
| MEM-06 | Unauthorized reads return 403, not 404 | `raise HTTPException(403, ...)` after visibility check; NOT 404 — prevents enumeration |
| MEM-07 | Existing /v1/shared-memory system clearly differentiated from per-agent memory with visibility | Document the distinction; shared-memory is a publish-to-all namespace system; per-agent memory is private-by-default |
| MEM-08 | All memory read/write/visibility-change events logged to memory_access_log | New `memory_access_log` table + `_log_memory_access()` helper called in all memory handlers |
| MEM-09 | Dashboard Memory tab shows all keys with visibility badges (private=gray, public=green, shared=blue) | CSS `.vis-badge` classes already in `dashboard.html`; backend `memory-list` needs to return `visibility` column |
| MEM-10 | Clicking a visibility badge opens dropdown/modal to change access level | `showMemoryDetailModal()` in `dashboard.html` already wired to `PATCH /v1/user/agents/{id}/memory-entry/visibility` |
| MEM-11 | User can select multiple memory keys and bulk-change visibility; changes appear in memory_access_log | Bulk action bar in `dashboard.html` calls `POST /v1/user/agents/{id}/memory-bulk-visibility`; endpoint logs each change |
</phase_requirements>

---

## Summary

Phase 1 adds three-level visibility controls (private/public/shared) to the per-agent memory system, enforces those controls at the API layer, creates a full audit trail, and surfaces it all in the dashboard UI. The backend is FastAPI + SQLite (WAL mode) running at api.moltgrid.net; the frontend is vanilla JS embedded in `dashboard.html` served by the backend (note: moltgrid-web isolation is the long-term goal but the current dashboard is still served as a single-file HTML from the backend).

**Critical discovery:** A substantial amount of this work is already designed and partially implemented. `patch_memory_visibility.py` in the project root contains exact string-replacement patches for `main.py` covering all 7 backend changes needed (schema migration, Pydantic models, helpers, endpoints, audit logging). The root `dashboard.html` already has the complete UI implementation: `.vis-badge` CSS, `renderTabMemory()` with badge rendering, `showMemoryDetailModal()` with visibility dropdown and agent-id input, and bulk action bar code calling all the new endpoints. The implementation plan can focus on applying these changes cleanly to the live codebase and verifying correctness rather than designing from scratch.

**Primary recommendation:** Apply `patch_memory_visibility.py` to `MoltGrid/main.py` on the VPS, then verify each MEM requirement passes using the existing `pytest test_main.py` test infrastructure. The UI is already in `dashboard.html` but needs the backend endpoints to exist first.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| FastAPI | existing (main.py) | REST endpoints and dependency injection | Already the project framework — no change |
| SQLite (WAL mode) | existing | Primary database | Project constraint — no Supabase in production |
| Pydantic v2 | existing (BaseModel in main.py) | Request/response validation | Already used throughout; pattern established |
| pytest + FastAPI TestClient | existing (test_main.py) | Integration testing | Test infrastructure already set up with `fresh_db` fixture |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Python `json` (stdlib) | stdlib | Serialize/deserialize `shared_agents` list to TEXT column | For JSON array in SQLite TEXT column (no JSON1 ext needed) |
| Python `uuid` (stdlib) | stdlib | Generate `id` for memory_access_log rows | `f"mal_{uuid.uuid4().hex[:16]}"` pattern already used in codebase |
| Python `datetime` (stdlib) | stdlib | Timestamps in ISO 8601 format | `datetime.now(timezone.utc).isoformat()` pattern already used |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| SQLite `ALTER TABLE ADD COLUMN` migration | Alembic | Alembic adds dependency; manual ALTER is simpler for 2-column add; project uses manual init_db() already |
| JSON array in TEXT column for `shared_agents` | Separate join table | Join table is cleaner but adds complexity; TEXT JSON is consistent with `metadata` columns elsewhere in codebase |
| 403 for unauthorized reads | 404 to hide existence | Requirement MEM-06 mandates 403 explicitly to prevent enumeration; return 403 with clear message |

**Installation:** No new packages needed. All required libraries are already in the project's `requirements.txt`.

---

## Architecture Patterns

### Recommended Project Structure

The change is contained in two files:

```
MoltGrid/
├── main.py                    # Backend: all changes applied here
│   ├── init_db()              # Wave 1: schema migration (2 columns + new table)
│   ├── MemorySetRequest       # Wave 1: add visibility + shared_agents fields
│   ├── MemoryVisibilityRequest  # Wave 1: new Pydantic model
│   ├── MemoryBulkVisibilityRequest  # Wave 1: new Pydantic model
│   ├── _log_memory_access()   # Wave 2: audit log helper
│   ├── _check_memory_visibility()  # Wave 2: visibility enforcement helper
│   ├── GET /v1/agents/{id}/memory/{key}   # Wave 2: cross-agent read with enforcement
│   ├── PATCH /v1/memory/{key}/visibility  # Wave 2: agent changes own visibility
│   ├── POST /v1/memory         # Wave 2: modified to store visibility column
│   ├── GET /v1/user/agents/{id}/memory-list       # Wave 3: add visibility to response
│   ├── GET /v1/user/agents/{id}/memory-entry      # Wave 3: new endpoint for dashboard
│   ├── PATCH /v1/user/agents/{id}/memory-entry/visibility  # Wave 3: dashboard change visibility
│   ├── POST /v1/user/agents/{id}/memory-bulk-visibility    # Wave 3: bulk change
│   └── GET /v1/user/agents/{id}/memory-access-log         # Wave 3: audit log viewer
└── dashboard.html             # Frontend: already has full UI implementation
    ├── .vis-badge CSS          # Already present
    ├── renderTabMemory()       # Already present (needs backend endpoints)
    ├── showMemoryDetailModal() # Already present (needs backend endpoints)
    └── bulk action bar         # Already present (needs backend endpoints)
```

### Pattern 1: SQLite Migration via ALTER TABLE in init_db()

**What:** Add columns to existing tables without dropping data using `PRAGMA table_info` + conditional `ALTER TABLE ADD COLUMN`.
**When to use:** Any time a new column is needed on an existing production table. The existing `init_db()` uses `CREATE TABLE IF NOT EXISTS` — same idempotency pattern applies to column additions.
**Example:**
```python
# Pattern used in patch_memory_visibility.py — verified against existing codebase
m_existing = {row[1] for row in conn.execute('PRAGMA table_info(memory)').fetchall()}
for col, typedef in [
    ('visibility', "TEXT DEFAULT 'private'"),
    ('shared_agents', 'TEXT'),
]:
    if col not in m_existing:
        conn.execute(f'ALTER TABLE memory ADD COLUMN {col} {typedef}')
conn.execute("UPDATE memory SET visibility='private' WHERE visibility IS NULL")
```

### Pattern 2: Visibility Enforcement at the Endpoint Level

**What:** Check visibility before returning data. Return 403 (not 404) for unauthorized cross-agent reads.
**When to use:** Any endpoint that reads memory for an agent other than the authenticating agent.
**Example:**
```python
# From patch_memory_visibility.py — the cross-agent read pattern
def _check_memory_visibility(db, target_agent_id, namespace, key, requester_agent_id):
    row = db.execute(
        "SELECT visibility, shared_agents FROM memory WHERE agent_id=? AND namespace=? AND key=?",
        (target_agent_id, namespace, key)
    ).fetchone()
    if not row:
        return False
    vis = row["visibility"] or "private"
    if vis == "public":
        return True
    if vis == "shared":
        sa = json.loads(row["shared_agents"] or "[]")
        return requester_agent_id in sa
    return False

# In the cross-agent read endpoint:
allowed = _check_memory_visibility(db, target_agent_id, namespace, key, agent_id)
if not allowed:
    raise HTTPException(403, "Access denied: memory entry is private or not shared with you")
```

### Pattern 3: Audit Log Helper (Fire-and-Forget)

**What:** Log every memory access to `memory_access_log` table in a try/except that never raises. Uses a direct sqlite3 connection (not the get_db() context manager) to avoid transaction interference.
**When to use:** All memory read, write, delete, and visibility-change operations.
**Example:**
```python
def _log_memory_access(action, agent_id, namespace, key,
                       actor_agent_id=None, actor_user_id=None,
                       old_visibility=None, new_visibility=None, authorized=1):
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO memory_access_log "
            "(id, agent_id, namespace, key, action, actor_agent_id, actor_user_id, "
            " old_visibility, new_visibility, authorized, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (f"mal_{uuid.uuid4().hex[:16]}", agent_id, namespace, key, action,
             actor_agent_id, actor_user_id, old_visibility, new_visibility, authorized,
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    except Exception:
        pass  # Never fail a request because audit logging failed
    finally:
        if conn:
            conn.close()
```

### Pattern 4: Dashboard Endpoint for User-Owned Agent Data

**What:** User-facing endpoints under `/v1/user/agents/{agent_id}/...` that use `get_user_id` (JWT auth) and verify the user owns the agent via `_verify_agent_ownership()`.
**When to use:** Any dashboard operation on behalf of a human user managing their agent.
**Example:**
```python
@app.patch("/v1/user/agents/{agent_id}/memory-entry/visibility", tags=["User Dashboard"])
def user_memory_set_visibility(
    agent_id: str, req: MemoryVisibilityRequest,
    user_id: str = Depends(get_user_id),
):
    with get_db() as db:
        _verify_agent_ownership(db, agent_id, user_id)
        # ... update visibility ...
```

### Anti-Patterns to Avoid

- **Returning 404 for unauthorized cross-agent reads:** MEM-06 mandates 403. Returning 404 enables enumeration attacks where an adversary can discover which keys exist by trying keys and observing 404 vs 403.
- **Modifying existing memory_get() to check cross-agent visibility:** The existing `GET /v1/memory/{key}` is already scoped to the authenticated agent (`WHERE agent_id=? AND ...`). Cross-agent reads go through a separate `GET /v1/agents/{target_agent_id}/memory/{key}` endpoint. Do not merge these.
- **Using a separate transaction for audit logging inside the main request transaction:** If the main transaction rolls back, the audit log entry also rolls back. The helper uses a direct sqlite3 connection outside the main get_db() context to ensure logs persist even if the main operation fails.
- **Storing `shared_agents` as a comma-separated string:** Use JSON array (`json.dumps([...])`) for consistency with metadata patterns and future-proofing for agent IDs that could contain commas.
- **Not backfilling `visibility='private'` after ALTER TABLE:** SQLite's `ALTER TABLE ADD COLUMN` with a DEFAULT clause sets the default for new rows, but existing rows in some SQLite versions may return NULL. The explicit `UPDATE memory SET visibility='private' WHERE visibility IS NULL` prevents NULL leakage.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Agent ownership verification | Custom ownership check | `_verify_agent_ownership(db, agent_id, user_id)` (already in codebase) | Function already exists in main.py; used by all user-dashboard endpoints |
| DB connection management | Manual sqlite3 connect/close | `with get_db() as db:` context manager (already in codebase) | Existing pattern handles WAL mode, row_factory, and commit/rollback |
| API key hashing | Custom hash | `hash_key(x_api_key)` function (already in codebase) | Already SHA-256; consistent with agent table |
| Memory value encryption | Custom AES | `_encrypt()` / `_decrypt()` (already in codebase) | Fernet-based, already applied to all memory writes |
| Visibility badge rendering | Custom HTML generator | Existing `.vis-badge` CSS + `visBadge()` JS function in dashboard.html | Already implemented and styled |
| The entire memory visibility UI | Write new dashboard code | Use existing code in root `dashboard.html` | The `renderTabMemory()`, `showMemoryDetailModal()`, and bulk action bar are fully implemented in the root dashboard.html |

**Key insight:** Both the patch script (`patch_memory_visibility.py`) and the dashboard UI (`dashboard.html`) already exist and are nearly complete. The implementation work is applying the patch correctly and verifying it, not designing new code.

---

## Common Pitfalls

### Pitfall 1: Patch Application Order Matters
**What goes wrong:** `patch_memory_visibility.py` patches `patch_tabs_backend.py`'s already-patched version of `user_memory_list`. If `patch_tabs_backend.py` has not been applied yet, the anchor string for Pitfall 6 (`OLD6`) will not be found and the patch script will crash on `assert src.count(OLD6) == 1`.
**Why it happens:** The patch script uses exact string matching on the source file. Each patch assumes the previous ones are already applied.
**How to avoid:** Verify the current state of `/opt/moltgrid/main.py` on the VPS before running `patch_memory_visibility.py`. Check if `user_memory_list` already has the `visibility` query param (from patch_tabs_backend) by grepping for it.
**Warning signs:** `AssertionError: anchor N count=0` output from the patch script.

### Pitfall 2: SQLite `ALTER TABLE` NULL Default on Existing Rows
**What goes wrong:** After `ALTER TABLE memory ADD COLUMN visibility TEXT DEFAULT 'private'`, existing rows in some SQLite builds return NULL for `visibility` (not the column default). Code using `row["visibility"] or "private"` handles this, but SQL `WHERE visibility = 'private'` would miss them.
**Why it happens:** SQLite's DEFAULT is applied to new inserts; existing rows store NULL.
**How to avoid:** Run `UPDATE memory SET visibility='private' WHERE visibility IS NULL` immediately after ALTER TABLE (already in the patch script). Always use `COALESCE(visibility,'private')` in SELECT queries.
**Warning signs:** Memory keys with NULL visibility appearing in API responses.

### Pitfall 3: The Two Memory Systems (MEM-07)
**What goes wrong:** `/v1/shared-memory` is a completely different system from per-agent memory with visibility. Confusing them leads to wrong implementation or documentation.
**Why it happens:** Both are "shared" in some sense. The naming is similar.
**How to avoid:** Per MEM-07, document the distinction clearly:
  - `/v1/memory` = private-by-default per-agent key-value store, now with visibility controls
  - `/v1/shared-memory` = deliberately public namespace system where any agent can publish and any authenticated agent can read — no access control
  Do NOT add visibility controls to `/v1/shared-memory`. Leave it unchanged.
**Warning signs:** Requirements referencing "shared memory" — always clarify which system.

### Pitfall 4: Dashboard HTML Location
**What goes wrong:** The project has TWO `dashboard.html` files: one in `MoltGrid/dashboard.html` (the backend's copy) and one in the project root. The root `dashboard.html` is the one with the full visibility UI implementation. Changes must target the right file.
**Why it happens:** The dashboard is transitioning from backend-served to moltgrid-web (Phase 5). During the transition, both copies may exist.
**How to avoid:** The VPS serves from `/opt/moltgrid/` — confirm which file is actually being served. The root `dashboard.html` has the visibility badge code (line 277 onward); `MoltGrid/dashboard.html` does not.
**Warning signs:** Dashboard memory tab showing no visibility badges despite backend returning `visibility` in API response.

### Pitfall 5: Cross-Agent Read Endpoint Route Conflict
**What goes wrong:** FastAPI route matching — `GET /v1/memory/{key}` already exists. Adding `GET /v1/agents/{target_agent_id}/memory/{key}` (cross-agent read) uses a different path prefix `/v1/agents/...` so there is no conflict. However, care must be taken to not accidentally add the cross-agent endpoint under the same `/v1/memory/...` prefix.
**Why it happens:** Similar endpoint names cause confusion.
**How to avoid:** Cross-agent reads live at `GET /v1/agents/{target_agent_id}/memory/{key}`. Own-agent reads stay at `GET /v1/memory/{key}`. These are separate routes.
**Warning signs:** 404 on cross-agent reads; or own-agent reads accidentally requiring visibility checks.

### Pitfall 6: Bulk Visibility — Agent IDs vs. User Auth
**What goes wrong:** The bulk visibility endpoint (`POST /v1/user/agents/{agent_id}/memory-bulk-visibility`) uses JWT user auth (not X-API-Key). Dashboard calls it correctly, but if an agent tries to call it with their API key, they get 401.
**Why it happens:** Bulk operations from the dashboard are user-initiated, not agent-initiated.
**How to avoid:** There are two distinct visibility update paths:
  - Agent-facing: `PATCH /v1/memory/{key}/visibility` (X-API-Key auth) — single key, agent changes their own
  - User/dashboard-facing: `PATCH /v1/user/agents/{id}/memory-entry/visibility` and `POST /v1/user/agents/{id}/memory-bulk-visibility` (JWT auth) — user manages their agent's memory
**Warning signs:** 401 errors from bulk visibility endpoint when testing with agent API key.

---

## Code Examples

Verified patterns from the existing codebase and patch file:

### Schema Migration Pattern (init_db)
```python
# Source: patch_memory_visibility.py (project root)
# Run inside init_db() before conn.commit()
m_existing = {row[1] for row in conn.execute('PRAGMA table_info(memory)').fetchall()}
for col, typedef in [
    ('visibility', "TEXT DEFAULT 'private'"),
    ('shared_agents', 'TEXT'),
]:
    if col not in m_existing:
        conn.execute(f'ALTER TABLE memory ADD COLUMN {col} {typedef}')
conn.execute("UPDATE memory SET visibility='private' WHERE visibility IS NULL")

# Create audit log table
conn.execute(
    'CREATE TABLE IF NOT EXISTS memory_access_log ('
    '    id             TEXT PRIMARY KEY,'
    '    agent_id       TEXT NOT NULL,'
    '    namespace      TEXT NOT NULL,'
    '    key            TEXT NOT NULL,'
    '    action         TEXT NOT NULL,'
    '    actor_agent_id TEXT,'
    '    actor_user_id  TEXT,'
    '    old_visibility TEXT,'
    '    new_visibility TEXT,'
    '    authorized     INTEGER DEFAULT 1,'
    '    created_at     TEXT NOT NULL'
    ')'
)
conn.execute(
    'CREATE INDEX IF NOT EXISTS idx_mal_agent ON memory_access_log(agent_id, created_at)'
)
```

### Pydantic Models
```python
# Source: patch_memory_visibility.py (project root)
class MemorySetRequest(BaseModel):
    key: str = Field(..., max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    namespace: str = Field("default", max_length=64)
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000)
    visibility: str = Field("private", description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)

class MemoryVisibilityRequest(BaseModel):
    namespace: str = Field("default", max_length=64)
    key: str = Field(..., max_length=256)
    visibility: str = Field(..., description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)

class MemoryBulkVisibilityRequest(BaseModel):
    entries: List[dict]
    visibility: str = Field(..., description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)
```

### PATCH /v1/memory/{key}/visibility (Agent-Facing)
```python
# Source: patch_memory_visibility.py (project root)
@app.patch("/v1/memory/{key}/visibility", tags=["Memory"])
def memory_set_visibility(key: str, req: MemoryVisibilityRequest,
                           agent_id: str = Depends(get_agent_id)):
    vis = req.visibility if req.visibility in ("private", "public", "shared") else "private"
    sa_json = json.dumps(req.shared_agents) if req.shared_agents else None
    with get_db() as db:
        old = db.execute(
            "SELECT visibility FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, req.namespace, key)
        ).fetchone()
        if not old:
            raise HTTPException(404, "Key not found")
        db.execute(
            "UPDATE memory SET visibility=?, shared_agents=? "
            "WHERE agent_id=? AND namespace=? AND key=?",
            (vis, sa_json, agent_id, req.namespace, key)
        )
    _log_memory_access("visibility_changed", agent_id, req.namespace, key,
                       actor_agent_id=agent_id,
                       old_visibility=old["visibility"] or "private",
                       new_visibility=vis)
    return {"status": "updated", "key": key, "visibility": vis}
```

### Visibility Badge in Dashboard (already in dashboard.html)
```javascript
// Source: dashboard.html (project root), line ~992
function visBadge(v) {
    v = v || "private";
    return '<span class="vis-badge ' + esc(v) + '">' + esc(v) + '</span>';
}

// CSS at line ~278:
// .vis-badge.private  { background:rgba(255,255,255,0.07); color:var(--text-dim); }
// .vis-badge.public   { background:rgba(0,255,136,0.12); color:#00ff88; }
// .vis-badge.shared   { background:rgba(255,170,0,0.12); color:#ffaa00; }
```

### Test Pattern for Memory Visibility
```python
# Source: MoltGrid/test_main.py structure (pytest + FastAPI TestClient)
# Pattern for adding visibility tests:

def test_private_memory_returns_403_for_other_agent():
    agent1_id, agent1_key, h1 = register_agent("agent1")
    agent2_id, agent2_key, h2 = register_agent("agent2")
    # agent1 writes a private memory entry
    client.post("/v1/memory", json={"key": "secret", "value": "top-secret", "visibility": "private"}, headers=h1)
    # agent2 tries to read it via cross-agent endpoint
    r = client.get(f"/v1/agents/{agent1_id}/memory/secret", headers=h2)
    assert r.status_code == 403
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| No visibility on per-agent memory | private/public/shared with enforcement | Phase 1 (now) | Agents can control data exposure |
| Agent reads only own memory | Cross-agent reads allowed for public/shared keys | Phase 1 (now) | Enables knowledge sharing between agents |
| No audit trail for memory access | memory_access_log table for all events | Phase 1 (now) | Full traceability; dashboard audit viewer |
| Memory list shows key/value only | Memory list includes visibility badge | Phase 1 (now) | Dashboard users see access level at a glance |

**The two memory systems going forward (MEM-07):**
- `/v1/memory` = per-agent, private-by-default, visibility-controlled (Phase 1)
- `/v1/shared-memory` = cross-agent public namespace, no access control (unchanged, deliberately different use case)

**What is NOT changing in this phase:**
- `/v1/shared-memory` system — left exactly as-is
- `vector_memory` table — no visibility controls added (deferred)
- Memory value size limit (50KB) — already enforced
- Encryption at rest — already applied by `_encrypt()`/`_decrypt()`

---

## Open Questions

1. **Which `dashboard.html` is served in production?**
   - What we know: Root `dashboard.html` has full visibility UI; `MoltGrid/dashboard.html` does not
   - What's unclear: Whether the VPS serves `/opt/moltgrid/dashboard.html` or a different path
   - Recommendation: Before deploying, SSH to VPS and confirm which file is mapped to the `/dashboard` route in `main.py`; then apply the correct patch

2. **Has `patch_tabs_backend.py` been applied to the live `main.py`?**
   - What we know: `patch_tabs_backend.py` adds `user_memory_list` and `user_memory_delete` endpoints that `patch_memory_visibility.py` then modifies
   - What's unclear: Whether the VPS `main.py` already has these endpoints applied
   - Recommendation: SSH to VPS and grep for `user_memory_list` in main.py before applying `patch_memory_visibility.py`; if absent, apply `patch_tabs_backend.py` first

3. **Visibility badge colors — gray vs. the spec**
   - What we know: MEM-09 specifies private=gray, public=green, shared=blue. Dashboard has private=gray, public=green (#00ff88), shared=orange/yellow (#ffaa00)
   - What's unclear: Whether shared=blue is required or orange/yellow is acceptable
   - Recommendation: The existing CSS uses orange/yellow for shared (visually distinct from green). Either adjust to blue to match the spec exactly, or confirm orange is acceptable. Blue would be `rgba(0,170,255,0.12)` / `color:#00aaff`

4. **Max entries in bulk visibility change**
   - What we know: The patch limits bulk operations to 200 entries (`req.entries[:200]`)
   - What's unclear: Whether 200 is the right cap
   - Recommendation: Accept 200 as the limit; can be adjusted later if needed

---

## Sources

### Primary (HIGH confidence)
- `MoltGrid/main.py` (live codebase) — existing memory table schema, existing endpoints, existing auth patterns, existing Pydantic models
- `patch_memory_visibility.py` (project root) — complete implementation of all backend changes for MEM-01 through MEM-08
- `dashboard.html` (project root) — complete implementation of MEM-09, MEM-10, MEM-11 UI
- `patch_tabs_backend.py` (project root) — existing `user_memory_list` and `user_memory_delete` endpoints that the visibility patch extends
- `MoltGrid/CLAUDE.md` — project constraints: SQLite on VPS, FastAPI, Pydantic, no new dependencies
- `.planning/REQUIREMENTS.md` — authoritative requirement definitions for MEM-01 through MEM-11
- `MoltGrid/test_main.py` — existing test infrastructure: pytest + FastAPI TestClient + `fresh_db` autouse fixture

### Secondary (MEDIUM confidence)
- `.planning/PROJECT.md` — constraint: moltgrid-web isolation (frontend should eventually move to moltgrid-web, but current dashboard is still backend-served HTML)
- `context.md` (project root) — full API route reference confirming current endpoint inventory

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — entire stack is the existing production stack; no new dependencies
- Architecture: HIGH — patch file provides exact implementation; no design ambiguity
- Pitfalls: HIGH — pitfalls derived directly from reading the patch file and existing code, not speculation
- UI implementation: HIGH — dashboard.html already has complete visibility UI; just needs backend endpoints

**Research date:** 2026-03-03
**Valid until:** 2026-04-03 (stable codebase; no fast-moving dependencies)

---

## Implementation Summary for Planner

The planner should structure 3 plans matching the roadmap outline:

**Plan 01-01: DB migration + API enforcement** (MEM-01, MEM-02, MEM-03, MEM-04, MEM-06, MEM-07)
- Apply schema migration (ALTER TABLE memory ADD COLUMN visibility, shared_agents; CREATE TABLE memory_access_log)
- Add `_log_memory_access()` and `_check_memory_visibility()` helper functions to main.py
- Extend `MemorySetRequest` Pydantic model to accept visibility + shared_agents
- Modify `memory_set()` to store visibility and shared_agents columns
- Add `GET /v1/agents/{target_agent_id}/memory/{key}` cross-agent read endpoint with 403 enforcement
- Verify `GET /v1/memory/{key}` (own-agent read) does NOT require visibility check (always allowed for own agent)
- Add API documentation comment distinguishing /v1/memory vs /v1/shared-memory (MEM-07)

**Plan 01-02: PATCH visibility endpoint + audit logging** (MEM-05, MEM-08)
- Add `PATCH /v1/memory/{key}/visibility` endpoint (agent-facing, X-API-Key auth)
- Add audit log calls to `memory_set()`, `memory_get()`, and `memory_delete()` (own-agent operations)
- Add audit log calls to the cross-agent read endpoint (unauthorized attempts logged with authorized=0)
- Write tests for all visibility scenarios

**Plan 01-03: Dashboard Memory tab UI** (MEM-09, MEM-10, MEM-11)
- Extend `GET /v1/user/agents/{id}/memory-list` to return visibility column (modify `user_memory_list`)
- Add `GET /v1/user/agents/{id}/memory-entry` endpoint (dashboard single-key fetch)
- Add `PATCH /v1/user/agents/{id}/memory-entry/visibility` endpoint (dashboard change visibility)
- Add `POST /v1/user/agents/{id}/memory-bulk-visibility` endpoint (dashboard bulk change)
- Add `GET /v1/user/agents/{id}/memory-access-log` endpoint (dashboard audit viewer)
- Confirm the correct `dashboard.html` is deployed to the VPS (the root one with visibility UI)
- Verify visibility badges, modal, and bulk action bar work end-to-end
