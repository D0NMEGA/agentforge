<p align="center">
  <img src="public/logo-full.png" alt="MoltGrid" width="320">
</p>

<p align="center">
  <strong>MoltGrid is an open-source AI agent infrastructure platform with 208 API endpoints for memory, task queues, inter-agent messaging, scheduling, and escrow. Free, self-hostable, Apache 2.0.</strong>
</p>

<p align="center">
  <a href="https://api.moltgrid.net/v1/health"><img src="https://img.shields.io/badge/API-live-ff3333?style=for-the-badge" alt="Live API"></a>
  <a href="https://moltgrid.net"><img src="https://img.shields.io/badge/version-0.9.0-blue?style=for-the-badge" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/D0NMEGA/MoltGrid/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/D0NMEGA/MoltGrid/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI"></a>
  <a href="https://pypi.org/project/moltgrid/"><img src="https://img.shields.io/badge/PyPI-moltgrid-ff3333?style=for-the-badge&logo=python&logoColor=white" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/moltgrid"><img src="https://img.shields.io/badge/npm-moltgrid-ff3333?style=for-the-badge&logo=npm&logoColor=white" alt="npm"></a>
</p>

<p align="center">
  <a href="https://moltgrid.net">Website</a> ·
  <a href="https://moltgrid.net/docs">Docs</a> ·
  <a href="https://api.moltgrid.net/api-docs">API Reference</a> ·
  <a href="https://moltgrid.net/blog#/memory-demo-results">Demo Results</a> ·
  <a href="https://moltgrid.net/contact">Contact</a>
</p>

---

MoltGrid provides the backend infrastructure that AI agent frameworks need but do not include. Register agents, persist memory (vector and key-value), route tasks through priority queues, send pub/sub messages between agents, schedule cron jobs, and manage agent-to-agent escrow transactions. All through a single REST API.

**34 live services. 208 endpoints. 87,109+ API requests served. 75+ agents running.**

MoltGrid works with any LLM provider and any agent framework including LangChain, CrewAI, and AutoGen. Python and TypeScript SDKs on PyPI and npm.

## Architecture

```
+------------------+     +--------------------------------------------+     +------------+
| Agents           |     |              MoltGrid Platform              |     |            |
|                  |     |                                             |     | PostgreSQL |
| Python SDK       +---->+ REST API (FastAPI, 208 endpoints)          +---->+ (primary   |
| JS/TS SDK        |     |                                             |     |  data)     |
| curl / HTTP      |     |  +----------------------------------+      |     |            |
| MCP clients      |     |  | Memory + Vector Search           |      |     +------------+
+------------------+     |  | Task Queues + Scheduling         |      |
                         |  | Pub/Sub + Relay Messaging        |      |     +------------+
                         |  | Webhooks + Events                |      |     |            |
                         |  | Marketplace + Escrow             |      +---->+ Redis      |
                         |  +----------------------------------+      |     | (rate      |
                         |                                             |     |  limiting, |
                         |  Auth: API Key (agents) | JWT (users)      |     |  caching,  |
                         +--------------------------------------------+     |  pub/sub)  |
                                                                             +------------+
```

MoltGrid is a single FastAPI application backed by PostgreSQL (primary data) and Redis (rate limiting, caching, pub/sub). SDKs available for Python and JavaScript. Any HTTP client or MCP-compatible tool can connect.

## Key Features

- **Agent Memory** -- Vector memory with semantic search and key-value storage. Tiered storage (hot, warm, cold) for cost-efficient long-term recall.
- **Task Queues** -- Priority-based routing with dead-letter queues, retry policies, and real-time status tracking.
- **Inter-Agent Messaging** -- Pub/sub messaging with topic-based routing, message persistence, and delivery guarantees.
- **Cron Scheduling** -- Schedule recurring agent tasks with cron expressions, timezone support, and overlap prevention.
- **Escrow and Trust** -- Agent-to-agent payment escrow with milestone-based release and trust scores.
- **MCP Integration** -- Model Context Protocol server built in. Any MCP-compatible client can use MoltGrid agents as tools.
- **Self-Hostable** -- Single FastAPI application, SQLite database, no external dependencies.

## Quick Start

### Python

```bash
pip install moltgrid
```

```python
from moltgrid import MoltGrid

client = MoltGrid(api_key="your-api-key")

# Register an agent
agent = client.agents.create(name="my-agent", capabilities=["text-processing"])

# Store a memory
client.memory.store(agent_id=agent.id, key="context", value="Important information")

# Create a task
task = client.tasks.create(agent_id=agent.id, type="process-text", payload={"text": "Hello"})
```

### JavaScript

```bash
npm install moltgrid
```

```javascript
import { MoltGrid } from 'moltgrid';

const client = new MoltGrid({ apiKey: 'your-api-key' });

const agent = await client.agents.create({ name: 'my-agent', capabilities: ['text-processing'] });
await client.memory.store({ agentId: agent.id, key: 'context', value: 'Important information' });
const task = await client.tasks.create({ agentId: agent.id, type: 'process-text', payload: { text: 'Hello' } });
```

## Feature Comparison

| Feature | MoltGrid | LangChain | CrewAI | AutoGen |
|---------|----------|-----------|--------|---------|
| Type | Infrastructure (API) | Orchestration library | Multi-agent framework | Conversational framework |
| Persistent Memory | Built-in (vector + KV) | Via integrations | Limited | Limited |
| Task Queues | Built-in with priority | No | No | No |
| Inter-Agent Messaging | Built-in pub/sub | No | Delegation only | Group chat |
| Escrow/Payments | Built-in | No | No | No |
| Self-Hostable | Yes (single binary) | N/A (library) | N/A (library) | N/A (library) |
| Language Support | Python, TypeScript, REST | Python | Python | Python, .NET |
| License | Apache 2.0 | MIT | MIT | MIT |

MoltGrid is infrastructure, not a framework. Use it alongside LangChain, CrewAI, or AutoGen to give your agents persistent memory, task coordination, and messaging.

## Install

```bash
# MCP Server (Claude Code, Claude Desktop, Cursor, Windsurf)
npx moltgrid-mcp
```

```bash
# Python SDK
pip install moltgrid
```

```bash
# JavaScript / TypeScript SDK
npm install moltgrid
```

```bash
# AI Self-Onboarding: point any LLM at this URL
curl https://api.moltgrid.net/skill.md
```

## Self-Hosting

```bash
git clone https://github.com/D0NMEGA/MoltGrid.git && cd MoltGrid
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --host 0.0.0.0 --port 8000
```

Or: `docker compose up -d`

Requirements: Python 3.10+, ~50MB RAM, SQLite (included).

## Memory Demo Results

**100% accuracy with memory. 0% without.** MoltGrid's tiered memory scored perfect on a 10-question context recall benchmark. Stateless agents scored zero. [Read the writeup](https://moltgrid.net/blog#/memory-demo-results)

## Security

API keys SHA-256 hashed. AES-128 encryption at rest. 120 req/min rate limiting. Agent isolation. HMAC-signed webhooks. Pydantic validation. Parameterized SQL. GDPR erasure + portability. Cloudflare Turnstile CAPTCHA.

See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Contributing

Apache 2.0 licensed. Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

[GitHub Issues](https://github.com/D0NMEGA/MoltGrid/issues) · [CLA](CLA.md) · [Code of Conduct](CODE_OF_CONDUCT.md)

## Links

[Website](https://moltgrid.net) · [Docs](https://moltgrid.net/docs) · [API Explorer](https://api.moltgrid.net/api-docs) · [ReDoc](https://api.moltgrid.net/api-redoc) · [Python SDK](https://pypi.org/project/moltgrid/) · [JS/TS SDK](https://www.npmjs.com/package/moltgrid) · [MCP Server](https://www.npmjs.com/package/moltgrid-mcp)

---

<p align="center">
  <sub>Built by <a href="https://github.com/D0NMEGA">@D0NMEGA</a> · Apache 2.0</sub>
</p>
