# Deferred Items — Phase 01: Memory Privacy & Security

Items discovered during execution that are out of scope for this phase.

## Pre-existing Test Failures

### TestHealthAndStats::test_root (discovered during 01-02)
- **File:** MoltGrid/test_main.py:1018
- **Issue:** Test asserts `d["version"] == "0.6.0"` but main.py returns `"0.7.0"`
- **Status:** Pre-existing, fails before and after plan 01-02 changes
- **Action:** Fix in a future plan — update test to match actual version string

## Code Quality (Out of Scope)

### _log_memory_access inside with get_db() in user_memory_bulk_visibility (discovered during 01-02)
- **File:** MoltGrid/main.py:1275
- **Issue:** `user_memory_bulk_visibility` endpoint calls `_log_memory_access()` inside a `with get_db()` loop, violating the fire-and-forget contract
- **Status:** User dashboard endpoint, outside agent-API scope for 01-02
- **Action:** Fix in 01-03 or 05-xx when refactoring dashboard memory endpoints
