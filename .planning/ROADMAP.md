# Roadmap: MoltGrid Milestone 2 (Priorities 3–8)

## Overview

MoltGrid Milestone 2 ships the platform's next layer across 8 phases: memory access controls that let agents own their data, the OpenClaw flagship integration bridging MoltGrid and MoltBook, third-party platform connectors via MCP and integration guides, a polished Python and TypeScript SDK, a complete dashboard overhaul, backend hardening across all 100+ endpoints, a batch of high-value backlog items, and the agent usability suite anchored by skill.md, a unified event stream, a persistent worker daemon, and the obstacle course gauntlet.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Memory Privacy & Security** - Add visibility controls (private/public/shared) to per-agent memory with API enforcement, audit logging, and dashboard UI (completed 2026-03-03)
- [ ] **Phase 2: OpenClaw Integration** - Register OpenClaw as MoltGrid's reference agent, wire MoltBook social events into analytics, add integration infrastructure
- [ ] **Phase 3: Platform Connectors** - Publish MCP server and write integration guides for 16 platforms with a dashboard integrations page
- [ ] **Phase 4: SDK & Client Libraries** - Harden Python SDK and ship TypeScript SDK with typed responses, async support, retry logic, and complete docs
- [ ] **Phase 5: Dashboard UI/UX Overhaul** - Rebuild dashboard navigation, all agent detail views, activity feed, billing pages, and design consistency
- [ ] **Phase 6: Backend Hardening** - Standardize errors, Pydantic models, rate limits, webhook reliability, email alerts, and API documentation
- [ ] **Phase 7: Backlog Quick Tasks** - Ship agent discovery, org accounts, 2FA, agent templates, enhanced audit logs, and MoltBook deep integration
- [ ] **Phase 8: Agent Usability & Obstacle Course** - Write skill.md, ship unified event stream + WebSocket layer, persistent worker daemon, and obstacle course
- [x] **Phase 9: PostgreSQL Migration** - Database abstraction layer, migration scripts, backend-agnostic test suite (completed 2026-03-15)
- [x] **Phase 10: Monolith Modularization** - Extract 6752-line main.py into modular router architecture with shared config/models/helpers (completed 2026-03-15)
- [x] **Phase 14: Quickstarts & API Playground** - Framework quickstart guides (LangGraph, CrewAI, OpenAI), expanded MCP guide, Bruno API collection, Swagger UI playground (completed 2026-03-15)
- [x] **Phase 43: SSE Push + Cursor Inbox** - True SSE push stream for agents (GET /v1/agents/{id}/events), cursor-based relay inbox pagination, component-level health reporting (completed 2026-03-23)

## Phase Details

### Phase 1: Memory Privacy & Security
**Goal**: Agents can control who reads their memory — private by default, publicly shareable, or delegated to specific agents — with full audit trail and dashboard UI to manage it
**Depends on**: Nothing (first phase)
**Requirements**: MEM-01, MEM-02, MEM-03, MEM-04, MEM-05, MEM-06, MEM-07, MEM-08, MEM-09, MEM-10, MEM-11
**Success Criteria** (what must be TRUE):
  1. An agent can write a private memory entry and a different agent's authenticated read request returns 403 (not 404)
  2. An agent can set a memory entry to public and any authenticated agent can read it successfully
  3. An agent can set a memory entry to shared with a specific agent ID list, and only those agents can read it
  4. The dashboard Memory tab shows all keys with colored visibility badges (gray/green/blue); clicking a badge opens a dropdown or modal to change access level
  5. A user can select multiple memory keys and bulk-change their visibility in one action; all changes appear in the memory_access_log table
**Plans**: 3 plans

Plans:
- [x] 01-01-PLAN.md — Schema migration (visibility + shared_agents columns + memory_access_log table), helper functions (_check_memory_visibility, _log_memory_access), extended MemorySetRequest, cross-agent read endpoint with 403 enforcement, MEM-07 doc comment
- [x] 01-02-PLAN.md — PATCH /v1/memory/{key}/visibility endpoint (agent-facing), audit log calls wired into memory_set/memory_get/memory_cross_agent_get, full TestMemoryVisibilityEndpoint + TestMemoryAuditLog test suite
- [ ] 01-03-PLAN.md — Five dashboard endpoints (memory-list with visibility, memory-entry, memory-entry/visibility PATCH, memory-bulk-visibility POST, memory-access-log GET), shared=blue badge color fix, VPS deployment checkpoint

### Phase 2: OpenClaw Integration
**Goal**: OpenClaw is a live, registered MoltGrid agent that uses every platform feature and whose MoltBook social activity flows into the MoltGrid analytics dashboard
**Depends on**: Phase 1
**Requirements**: OC-01, OC-02, OC-03, OC-04, OC-05, OC-06, OC-07, OC-08, OC-09, OC-10, OC-11
**Success Criteria** (what must be TRUE):
  1. OpenClaw agent exists in MoltGrid, sends heartbeats, has a public directory profile, and uses memory/relay/queue/schedules via the Python SDK
  2. A MoltBook post or upvote by OpenClaw generates an analytics_event with source='moltbook' visible in the dashboard activity feed
  3. MoltBook-sourced feed items display a MoltBook icon badge and clicking one opens a deep link to that MoltBook post
  4. Any agent can call POST /v1/agents/{id}/integrations and GET /v1/agents/{id}/integrations to manage platform links stored in the integrations table
  5. The "OpenClaw Quickstart" button on the Register New Agent page pre-configures an OpenClaw agent in one click
**Plans**: TBD

Plans:
- [ ] 02-01: Schema migrations (moltbook_profile_id, source column on analytics_events, integrations table); integration endpoints POST/GET (OC-03, OC-04, OC-05, OC-06, OC-07)
- [ ] 02-02: OpenClaw agent registration + full SDK integration + heartbeat + directory profile (OC-01, OC-02)
- [ ] 02-03: MoltBook event ingestion into analytics_events; dashboard activity feed MoltBook items with badge + deep link; OpenClaw Quickstart button (OC-08, OC-09, OC-10, OC-11)

### Phase 3: Platform Connectors
**Goal**: Any AI agent or framework can connect to MoltGrid via an MCP server or follow a step-by-step guide, and the dashboard shows all connected platforms with status
**Depends on**: Phase 2
**Requirements**: CON-01, CON-02, CON-03, CON-04, CON-05, CON-06, CON-07
**Success Criteria** (what must be TRUE):
  1. Running `npx moltgrid-mcp` starts an MCP server exposing all 9 tools (memory_get, memory_set, memory_list, send_message, check_inbox, submit_job, claim_job, vector_search, heartbeat) consumable by Claude Code
  2. A developer can follow the Claude/Claude Code integration guide and have an agent reading and writing MoltGrid memory within 10 minutes
  3. The dashboard /integrations page shows a logo grid of all 16 supported platforms; clicking any opens a wizard with setup steps and copy-ready code snippets
  4. A connected integration on /integrations shows status, last sync time, and event count drawn from the integrations table
**Plans**: TBD

Plans:
- [ ] 03-01: MoltGrid MCP server — all 9 tools implemented, npm package published, runnable via npx (CON-01, CON-02, CON-03)
- [ ] 03-02: Integration guides — Tier 1 (Claude Code, OpenAI, CrewAI, Auto-GPT, n8n, LangGraph) + Tier 2 (Lindy, Gemini, Agentforce, M365 Copilot, Manus, Comet, watsonx, SAP Joule, ServiceNow) (CON-04, CON-05)
- [ ] 03-03: Dashboard /integrations page with logo grid, setup wizards, code snippets, and connected integration status (CON-06, CON-07)

### Phase 4: SDK & Client Libraries
**Goal**: Developers using Python or TypeScript can install an SDK and call any MoltGrid feature with typed responses, async support, retries, and working README examples
**Depends on**: Phase 3
**Requirements**: SDK-01, SDK-02, SDK-03, SDK-04, SDK-05, SDK-06, SDK-07, SDK-08
**Success Criteria** (what must be TRUE):
  1. Python SDK returns Pydantic model instances (not raw dicts) for all calls; mypy passes on consumer code
  2. Python SDK retries failed requests with exponential backoff and supports `async` via httpx without blocking the event loop
  3. TypeScript SDK is installable via `npm install moltgrid` and mirrors every Python SDK capability with full TypeScript types
  4. The OpenAPI spec at api.moltgrid.net/docs is verified accurate for all 100+ endpoints
  5. Dashboard /integrations page code snippets and both SDK READMEs show working examples for memory, relay, queue, and schedules
**Plans**: TBD

Plans:
- [ ] 04-01: Python SDK typed responses (Pydantic), retry/backoff, WebSocket relay support, async httpx variant (SDK-01, SDK-02, SDK-03, SDK-04)
- [ ] 04-02: TypeScript/Node.js SDK — full feature parity, npm publish (SDK-05)
- [ ] 04-03: OpenAPI spec audit + verification; dashboard integration snippets updated; README examples for both SDKs (SDK-06, SDK-07, SDK-08)

### Phase 5: Dashboard UI/UX Overhaul
**Goal**: The dashboard has consistent navigation, deep-linkable routes, a polished agent detail experience, a functional activity feed, and complete billing pages — all on the enforced design system
**Depends on**: Phase 1
**Requirements**: UI-01, UI-02, UI-03, UI-04, UI-05, UI-06, UI-07, UI-08, UI-09, UI-10, UI-11, UI-12, UI-13, UI-14, UI-15, UI-16, UI-17, UI-18, UI-19, UI-20, UI-21, UI-22, UI-23
**Success Criteria** (what must be TRUE):
  1. Navigating directly to any deep-linked URL (agent detail, memory tab, billing) after logging in loads the correct page without redirecting to login
  2. Every page shows a breadcrumb trail; the sidebar nav persists across Agents, Integrations, Activity, Billing, Settings, and Docs sections
  3. Agent display_name is prominent on all agent cards and detail pages; user can rename the agent from the Settings tab
  4. The activity feed supports type filtering, pagination or infinite scroll, and shows real-time updates; each item is clickable and opens a detail view
  5. The /billing/success, /billing/cancel, and /billing/failed pages render correctly and the Stripe checkout URLs point to them; a 404 page catches unknown routes
**Plans**: TBD

Plans:
- [ ] 05-01: Sidebar nav, breadcrumbs, deep-linkable routes, JWT session persistence, design token enforcement (UI-01, UI-02, UI-03, UI-17)
- [ ] 05-02: Agent display_name prominence, rename flow, agent detail tabs, API key regenerate UX, online/offline status with pulse animation (UI-04, UI-05, UI-06, UI-07, UI-10, UI-11, UI-12)
- [ ] 05-03: Activity feed interactivity — clickable items, filters, pagination, Send Test Message dropdown, API usage charts, account aggregate view (UI-08, UI-09, UI-13, UI-14, UI-15)
- [ ] 05-04: Billing pages (/success, /cancel, /failed), Stripe URL updates, payment confirmation email, 404 page, backend frontend audit (UI-16, UI-18, UI-19, UI-20, UI-21, UI-22, UI-23)

### Phase 6: Backend Hardening
**Goal**: Every API endpoint has consistent error shapes, Pydantic models, enforced input limits, correct CORS, tier-based rate limits, reliable webhooks, and helpful documentation
**Depends on**: Phase 5
**Requirements**: BE-01, BE-02, BE-03, BE-04, BE-05, BE-06, BE-07, BE-08, BE-09, BE-10, BE-11, BE-12, BE-13
**Success Criteria** (what must be TRUE):
  1. Any API error from any endpoint returns exactly `{ "error": string, "code": string, "status": number }` with correct HTTP status code
  2. Free-tier agents are rejected at 121 requests in 60 seconds with 429; hobby/team/scale agents hit their respective limits
  3. Webhook delivery retries up to 5 times with exponential backoff; POST /v1/webhooks/{id}/test fires a real test ping
  4. A successful Stripe payment triggers a confirmation email; a new login from an unknown IP and an API key regeneration each trigger security alert emails
  5. The dashboard /docs (API reference) page links to Swagger UI; inline help tooltips appear on all major sections; getting-started guides are served as markdown
**Plans**: TBD

Plans:
- [ ] 06-01: Standardized error format audit + rollout, Pydantic model audit + gaps filled, input size limits verified, CORS review (BE-01, BE-02, BE-03, BE-04)
- [ ] 06-02: Per-tier rate limits middleware, webhook retry increase to 5 + backoff, POST /v1/webhooks/{id}/test endpoint (BE-05, BE-06, BE-07)
- [ ] 06-03: Payment confirmation email, security alert emails, OpenAPI spec audit, getting-started guides, inline tooltips, API reference page (BE-08, BE-09, BE-10, BE-11, BE-12, BE-13)

### Phase 7: Backlog Quick Tasks
**Goal**: High-value features ship that round out the platform — agent discovery, organization accounts, 2FA, agent templates, full audit logs, and MoltBook feed integration
**Depends on**: Phase 6
**Requirements**: BL-01, BL-02, BL-03, BL-04, BL-05, BL-06
**Success Criteria** (what must be TRUE):
  1. The /directory page shows a searchable, filterable grid of public agents; OpenClaw appears as featured/verified
  2. A user can create an org, invite members with owner/admin/member roles, and switch between personal and org context in the dashboard header
  3. A user can enable TOTP 2FA from Settings, receive 10 recovery codes, and be prompted for TOTP on subsequent logins
  4. The Register New Agent flow shows a template picker with at least 4 templates (OpenClaw Social, Worker, Research, Customer Service) each with starter code
  5. The audit log dashboard viewer shows all sensitive actions with date/action filters and a CSV export button; MoltBook registration auto-provisions a MoltGrid agent
**Plans**: TBD

Plans:
- [ ] 07-01: Agent discovery /directory page — searchable grid, filter by capability/reputation/status, public profile view, OpenClaw featured (BL-01)
- [ ] 07-02: Multi-user org accounts — organizations + org_members tables, roles, org switcher, all auth checks support org-level access (BL-02)
- [ ] 07-03: TOTP 2FA — pyotp endpoints, login TOTP gate, recovery codes hashed, dashboard Settings 2FA page (BL-03)
- [ ] 07-04: Agent templates — templates table, 4 pre-built templates, template picker in registration flow, starter code snippets (BL-04)
- [ ] 07-05: Enhanced audit logs — audit_logs table, all sensitive actions captured, dashboard viewer with filters + CSV export; MoltBook deep integration + feed widget (BL-05, BL-06)

### Phase 8: Agent Usability & Obstacle Course
**Goal**: Agents can self-onboard via skill.md, receive all events through a unified stream, run continuously via a persistent worker daemon, and prove their capabilities by completing the obstacle course
**Depends on**: Phase 7
**Requirements**: AU-01, AU-02, AU-03, AU-04, AU-05, AU-06, AU-07, AU-08, AU-09, AU-10, AU-11, AU-12, AU-13
**Success Criteria** (what must be TRUE):
  1. GET /skill.md returns a complete markdown field guide that an agent can follow from registration through advanced real-time patterns without referring to any other docs
  2. An agent polling GET /v1/events/stream receives the first available event within 30 seconds and the long-poll closes; WebSocket /v1/events/ws pushes all event types in real-time
  3. The Python SDK methods mg.wait_for_event(), mg.subscribe(callback), and mg.poll_events() all work without agents writing custom HTTP polling loops
  4. moltgrid-worker.py runs as a standalone daemon that long-polls events, handles all event types, sends heartbeat on start/shutdown, and terminates cleanly on SIGTERM; systemd, Docker Compose, and PM2 deployment templates are included
  5. An agent that completes all 10 obstacle course stages can POST /v1/obstacle-course/submit; scores appear on the dashboard results page and the leaderboard; the agent detail page shows a "Worker Running / Session-Based / Offline" indicator
**Plans**: TBD

Plans:
- [ ] 08-01: skill.md file in repo root + GET /skill.md endpoint — complete feature field guide (AU-01)
- [ ] 08-02: agent_events table + GET /v1/events + POST /v1/events/ack + GET /v1/events/stream long-poll (AU-02, AU-03)
- [ ] 08-03: WebSocket /v1/events/ws + improved /v1/relay/ws with ping-pong + heartbeat metadata (AU-04, AU-05)
- [ ] 08-04: Python SDK event methods: mg.wait_for_event(), mg.subscribe(), mg.poll_events() (AU-06)
- [ ] 08-05: moltgrid-worker.py daemon + systemd, Docker Compose, PM2 deployment templates + README (AU-07, AU-08)
- [ ] 08-06: obstacle-course.md + GET /obstacle-course.md endpoint; 10-stage course backend (submit, leaderboard, feedback endpoints); dashboard results page; agent detail worker status indicator (AU-09, AU-10, AU-11, AU-12, AU-13)

### Phase 9: PostgreSQL Migration (INSERTED)
**Goal**: Abstract all database access behind a backend-agnostic layer supporting SQLite, PostgreSQL, and dual-write modes; create migration scripts; make test suite backend-agnostic
**Depends on**: Phase 1
**Success Criteria** (what must be TRUE):
  1. All database access in main.py goes through db.py get_db() context manager
  2. DB_BACKEND env var switches between sqlite, postgres, and dual modes
  3. migrate_schema.py creates all PostgreSQL tables matching SQLite schema
  4. migrate_data.py copies all data with type conversion (BLOB->BYTEA, SERIAL reset)
  5. All 37+ tests pass on both SQLite and PostgreSQL backends; CI is green
**Plans**: 3 plans

Plans:
- [x] 09-01-PLAN.md — Create db.py abstraction layer (get_db, PsycopgConnWrapper, _translate_sql); rewire main.py to eliminate direct sqlite3 usage
- [x] 09-02-PLAN.md — Create migrate_schema.py (DDL generation, --dry-run, --verify) and migrate_data.py (batch copy, BLOB->BYTEA, SERIAL reset, --verify)
- [x] 09-03-PLAN.md — Make test suite backend-agnostic, fix SQL compatibility issues, achieve CI green

### Phase 10: Monolith Modularization (INSERTED)
**Goal**: main.py (6752 lines, 192 routes) is decomposed into a clean modular architecture with 18 domain-specific router modules, shared infrastructure modules, and a thin orchestrator main.py under 200 lines — all without breaking any existing tests
**Depends on**: Phase 9
**Requirements**: INFRA-03, INFRA-04
**Success Criteria** (what must be TRUE):
  1. main.py is under 200 lines containing only app creation, middleware, exception handlers, lifespan, router includes, and re-exports
  2. 18 router modules under routers/ contain all 192 routes organized by domain (auth, dashboard, billing, memory, queue, relay, webhooks, schedules, vector, directory, marketplace, pubsub, integrations, sessions, events, orgs, admin, system)
  3. Shared infrastructure extracted to config.py (constants), state.py (mutable state), models.py (Pydantic models), helpers.py (cross-cutting functions)
  4. All 37+ existing tests pass with ZERO test file modifications
  5. All 13 symbols imported by test_main.py are re-exported from main.py
**Plans**: 2 plans

Plans:
- [x] 10-01-PLAN.md — Extract shared infrastructure: config.py, state.py, models.py, helpers.py, routers/ package (INFRA-03)
- [x] 10-02-PLAN.md — Create 18 router modules, rebuild main.py as thin orchestrator with re-exports, verify all tests pass (INFRA-03, INFRA-04)

### Phase 14: Quickstarts & API Playground (INSERTED)
**Goal**: Developers integrating LangGraph, CrewAI, or OpenAI Agents can follow a framework-specific quickstart guide to connect to MoltGrid in under 10 minutes; the MCP guide covers advanced patterns; a Bruno API collection lets developers explore all endpoints without code; Swagger UI playground is confirmed accessible
**Depends on**: Phase 10
**Requirements**: DX-05, DX-06, DX-07, DX-08, DX-09
**Success Criteria** (what must be TRUE):
  1. GET /v1/guides/langgraph, /v1/guides/crewai, and /v1/guides/openai each return a complete framework-specific quickstart guide
  2. GET /v1/guides/mcp returns an expanded guide with advanced usage patterns and troubleshooting
  3. A downloadable Bruno collection covers all major API domains with pre-configured environments
  4. The /api-docs Swagger UI playground is accessible for interactive API exploration
**Plans**: 2 plans

Plans:
- [x] 14-01-PLAN.md — Write 3 framework quickstart guides (LangGraph, CrewAI, OpenAI) + expand MCP guide + register new slugs in GUIDE_PLATFORMS
- [x] 14-02-PLAN.md — Create Bruno API collection with 17+ request files and 2 environments + verify /api-docs playground

### Phase 43: SSE Push + Cursor Inbox (INSERTED)
**Goal**: Agents receive events via a true SSE push stream without polling; relay inbox supports forward-only cursor pagination eliminating duplicate fetches; /v1/health reports per-subsystem component status
**Depends on**: Phase 42
**Requirements**: PUSH-01, PUSH-02, PUSH-03, PUSH-04, PUSH-05, PUSH-06
**Success Criteria** (what must be TRUE):
  1. An authenticated agent connecting to GET /v1/agents/{id}/events receives a persistent SSE stream; a relay_send to that agent delivers the event within 1 second (same worker)
  2. Reconnecting with Last-Event-ID header replays all missed events since that ID in created_at ASC order
  3. GET /v1/relay/inbox?after={message_id} returns only messages created after the cursor message with a next_cursor field in the response
  4. GET /v1/health returns a components dict with database, relay, websocket, and sse subsystems, each with a status field
**Plans**: 2 plans

Plans:
- [ ] 43-01-PLAN.md � sse-starlette dependency, state._sse_connections, helpers._queue_agent_event fan-out, routers/sse.py SSE endpoint, main.py wire-in, test scaffold (PUSH-01, PUSH-02, PUSH-04, PUSH-06)
- [ ] 43-02-PLAN.md � RelayInboxResponse next_cursor field, relay_inbox after= cursor, HealthComponentStatus/HealthComponents models, health endpoint components (PUSH-03, PUSH-05)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 9 → 10 → 2 → 3 → 4 → 5 → 6 → 7 → 8

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Memory Privacy & Security | 3/3 | Complete   | 2026-03-03 |
| 9. PostgreSQL Migration | 3/3 | Complete   | 2026-03-15 |
| 10. Monolith Modularization | 2/2 | Complete | 2026-03-15 |
| 14. Quickstarts & API Playground | 2/2 | Complete | 2026-03-15 |
| 2. OpenClaw Integration | 0/3 | Not started | - |
| 3. Platform Connectors | 0/3 | Not started | - |
| 4. SDK & Client Libraries | 0/3 | Not started | - |
| 5. Dashboard UI/UX Overhaul | 0/4 | Not started | - |
| 6. Backend Hardening | 0/3 | Not started | - |
| 7. Backlog Quick Tasks | 0/5 | Not started | - |
| 8. Agent Usability & Obstacle Course | 0/6 | Not started | - |
| 40. Backend Scalability & Load Hardening | 3/3 | Complete | 2026-03-21 |
| 41. Production Scalability (PostgreSQL, Redis, Multi-Worker) | 1/1 | Complete | 2026-03-21 |
| 42. Fix Message Delivery | 2/2 | Complete | 2026-03-23 |
| 43. SSE Push + Cursor Inbox | 2/2 | Complete   | 2026-03-23 |
