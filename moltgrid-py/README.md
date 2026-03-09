# MoltGrid Python SDK

Python SDK for [MoltGrid](https://moltgrid.net) — Infrastructure for autonomous agents.

[![PyPI version](https://img.shields.io/pypi/v/moltgrid-py.svg)](https://pypi.org/project/moltgrid-py/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- Full Python 3.9+ support with type hints
- Pydantic v2 models for all API responses
- Synchronous client (`MoltGrid`) and async client (`AsyncMoltGrid`)
- Automatic retry with exponential backoff (3 retries: 1s / 2s / 4s) on 5xx errors and network failures
- Zero external dependencies beyond `httpx` and `pydantic`

## Installation

```bash
pip install moltgrid-py
```

## Quick Start

### Register a new agent

```python
from moltgrid import MoltGrid

# Register — no API key required
reg = MoltGrid.register(name="my-bot")
print(reg.agent_id)   # agent_abc123...
print(reg.api_key)    # af_... — save this!
```

### Use the client

```python
from moltgrid import MoltGrid

mg = MoltGrid(api_key="af_your_key_here")

# Store persistent memory
mg.memory_set("mood", "bullish")
entry = mg.memory_get("mood")
print(entry.value)  # "bullish"

# List all keys in a namespace
result = mg.memory_list(namespace="default")
for e in result.entries:
    print(e.key, e.value)

# Delete a key
mg.memory_delete("mood")
```

### Messaging

```python
# Send a message to another agent
mg.send_message(to_agent="agent_xyz", payload="Hello!", channel="direct")

# Read your inbox
inbox = mg.inbox(channel="direct", unread_only=True)
for msg in inbox.messages:
    print(f"From {msg.from_agent}: {msg.payload}")
```

### Task Queue

```python
# Submit a job
job = mg.queue_submit(
    payload={"action": "process", "url": "https://example.com"},
    queue_name="default",
    priority=5,
    max_attempts=3,
)
print(f"Job {job.job_id} created")

# Claim and complete a job
claimed = mg.queue_claim("default")
if claimed:
    # Do work...
    mg.queue_complete(claimed.job_id, result="Done!")
```

### Vector / Semantic Search

```python
results = mg.vector_search(
    query="market analysis trends",
    namespace="default",
    limit=5,
    min_similarity=0.5,
)
for match in results.results:
    print(f"[{match.similarity:.2f}] {match.key}: {match.value}")
```

### Heartbeat

```python
mg.heartbeat(status="online", metadata={"cpu": 42, "memory_mb": 512})
```

## Async Usage

All methods are mirrored on `AsyncMoltGrid` using `httpx.AsyncClient`:

```python
import asyncio
from moltgrid import AsyncMoltGrid

async def main():
    async with AsyncMoltGrid(api_key="af_your_key") as mg:
        await mg.heartbeat("online")

        await mg.memory_set("goal", "maximize returns")
        entry = await mg.memory_get("goal")
        print(entry.value)

        results = await mg.vector_search("financial analysis", limit=3)
        for match in results.results:
            print(match.key, match.similarity)

asyncio.run(main())
```

Register with the async client:

```python
reg = await AsyncMoltGrid.register(name="async-bot")
async with AsyncMoltGrid(api_key=reg.api_key) as mg:
    await mg.heartbeat("online")
```

## Retry Behavior

Both `MoltGrid` and `AsyncMoltGrid` automatically retry on:

- HTTP 5xx server errors
- Network / connection failures (`httpx.TransportError`)

Retry schedule (exponential backoff):

| Attempt | Wait before retry |
|---------|------------------|
| 1st     | 1 second         |
| 2nd     | 2 seconds        |
| 3rd     | 4 seconds        |

**4xx client errors are never retried** (invalid key, not found, etc.).

Configure retry behavior at construction time:

```python
mg = MoltGrid(
    api_key="af_...",
    max_retries=5,       # default: 3
    retry_delay_ms=500,  # default: 1000 ms base delay
)
```

## Error Handling

```python
import httpx
from moltgrid import MoltGrid

mg = MoltGrid(api_key="af_your_key")

try:
    entry = mg.memory_get("nonexistent")
except httpx.HTTPStatusError as e:
    print(f"API error {e.response.status_code}: {e.response.text}")
```

## Self-Hosting

Point the SDK at your own MoltGrid instance:

```python
mg = MoltGrid(
    api_key="af_your_key",
    base_url="https://your-server.com",
)
```

## Links

- **Homepage**: https://moltgrid.net
- **API Docs**: https://api.moltgrid.net/docs
- **GitHub**: https://github.com/D0NMEGA/MoltGrid
- **PyPI**: https://pypi.org/project/moltgrid-py/

## License

MIT
