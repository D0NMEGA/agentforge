"""
AgentForge — Open-source toolkit API for autonomous agents.
Provides persistent memory, task queuing, message relay, and text utilities.
"""

import os
import json
import time
import uuid
import hashlib
import sqlite3
import asyncio
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from contextlib import asynccontextmanager, contextmanager

import httpx
from croniter import croniter
from fastapi import FastAPI, HTTPException, Header, Depends, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("agentforge")

# ─── Config ───────────────────────────────────────────────────────────────────
DB_PATH = os.getenv("AGENTFORGE_DB", "agentforge.db")
MAX_MEMORY_VALUE_SIZE = 50_000  # 50KB per value
MAX_QUEUE_PAYLOAD_SIZE = 100_000  # 100KB per job
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 120  # requests per window per agent

# ─── App ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    # Startup: launch scheduler background thread
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    logger.info("Scheduler background thread started")
    yield
    # Shutdown: nothing to clean up (daemon threads auto-exit)

app = FastAPI(
    title="AgentForge",
    description="Open-source toolkit API for autonomous agents. "
    "Persistent memory, task queues, message relay, and text utilities.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            api_key_hash TEXT NOT NULL,
            name TEXT,
            description TEXT,
            capabilities TEXT,
            public INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_seen TEXT,
            request_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS memory (
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            PRIMARY KEY (agent_id, namespace, key),
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );

        CREATE TABLE IF NOT EXISTS queue (
            job_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            queue_name TEXT NOT NULL DEFAULT 'default',
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            priority INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_queue_status ON queue(queue_name, status, priority DESC);

        CREATE TABLE IF NOT EXISTS relay (
            message_id TEXT PRIMARY KEY,
            from_agent TEXT NOT NULL,
            to_agent TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'direct',
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY (from_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_relay_to ON relay(to_agent, read_at);

        CREATE TABLE IF NOT EXISTS rate_limits (
            agent_id TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            count INTEGER DEFAULT 1,
            PRIMARY KEY (agent_id, window_start)
        );

        CREATE TABLE IF NOT EXISTS metrics (
            recorded_at TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            status_code INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            url TEXT NOT NULL,
            event_types TEXT NOT NULL,
            secret TEXT,
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_webhooks_agent ON webhooks(agent_id, active);

        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            cron_expr TEXT NOT NULL,
            queue_name TEXT NOT NULL DEFAULT 'default',
            payload TEXT NOT NULL,
            priority INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            next_run_at TEXT NOT NULL,
            last_run_at TEXT,
            run_count INTEGER DEFAULT 0,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sched_next ON scheduled_tasks(enabled, next_run_at);

        CREATE TABLE IF NOT EXISTS shared_memory (
            owner_agent TEXT NOT NULL,
            namespace TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            PRIMARY KEY (owner_agent, namespace, key),
            FOREIGN KEY (owner_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_shared_ns ON shared_memory(namespace);
    """)

    # Migrate existing agents table — add columns that v0.1.0 didn't have
    existing = {row[1] for row in conn.execute("PRAGMA table_info(agents)").fetchall()}
    for col, typedef in [("description", "TEXT"), ("capabilities", "TEXT"), ("public", "INTEGER DEFAULT 0")]:
        if col not in existing:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {typedef}")

    conn.commit()
    conn.close()

init_db()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

# ─── Auth Helpers ─────────────────────────────────────────────────────────────
def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def generate_api_key() -> str:
    return f"af_{uuid.uuid4().hex}"

async def get_agent_id(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id FROM agents WHERE api_key_hash = ?",
            (hash_key(x_api_key),)
        ).fetchone()
        if not row:
            raise HTTPException(401, "Invalid API key")

        now = datetime.now(timezone.utc).isoformat()
        # Rate limiting
        window = int(time.time()) // RATE_LIMIT_WINDOW
        db.execute("""
            INSERT INTO rate_limits (agent_id, window_start, count)
            VALUES (?, ?, 1)
            ON CONFLICT(agent_id, window_start) DO UPDATE SET count = count + 1
        """, (row["agent_id"], window))
        rl = db.execute(
            "SELECT count FROM rate_limits WHERE agent_id = ? AND window_start = ?",
            (row["agent_id"], window)
        ).fetchone()
        if rl and rl["count"] > RATE_LIMIT_MAX:
            raise HTTPException(429, f"Rate limit exceeded ({RATE_LIMIT_MAX}/min)")

        db.execute(
            "UPDATE agents SET last_seen = ?, request_count = request_count + 1 WHERE agent_id = ?",
            (now, row["agent_id"])
        )
        return row["agent_id"]


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=64, description="Display name for your agent")

class RegisterResponse(BaseModel):
    agent_id: str
    api_key: str
    message: str

@app.post("/v1/register", response_model=RegisterResponse, tags=["Auth"])
def register_agent(req: RegisterRequest):
    """Register a new agent and receive an API key. Free. No payment required."""
    agent_id = f"agent_{uuid.uuid4().hex[:12]}"
    api_key = generate_api_key()
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO agents (agent_id, api_key_hash, name, created_at) VALUES (?, ?, ?, ?)",
            (agent_id, hash_key(api_key), req.name, now)
        )

    return RegisterResponse(
        agent_id=agent_id,
        api_key=api_key,
        message="Store your API key securely. It cannot be recovered."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PERSISTENT MEMORY (Key-Value Store with Namespaces + TTL)
# ═══════════════════════════════════════════════════════════════════════════════

class MemorySetRequest(BaseModel):
    key: str = Field(..., max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    namespace: str = Field("default", max_length=64)
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000, description="Auto-expire after N seconds (60s–30d)")

class MemoryGetResponse(BaseModel):
    key: str
    value: str
    namespace: str
    updated_at: str
    expires_at: Optional[str]

@app.post("/v1/memory", tags=["Memory"])
def memory_set(req: MemorySetRequest, agent_id: str = Depends(get_agent_id)):
    """Store or update a key-value pair in persistent memory."""
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()

    with get_db() as db:
        db.execute("""
            INSERT INTO memory (agent_id, namespace, key, value, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, namespace, key)
            DO UPDATE SET value=?, updated_at=?, expires_at=?
        """, (agent_id, req.namespace, req.key, req.value, now.isoformat(), now.isoformat(), expires,
              req.value, now.isoformat(), expires))

    return {"status": "stored", "key": req.key, "namespace": req.namespace}

@app.get("/v1/memory/{key}", response_model=MemoryGetResponse, tags=["Memory"])
def memory_get(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Retrieve a value from persistent memory."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM memory WHERE agent_id=? AND namespace=? AND key=? AND (expires_at IS NULL OR expires_at > ?)",
            (agent_id, namespace, key, now)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Key not found or expired")
        return MemoryGetResponse(**dict(row))

@app.delete("/v1/memory/{key}", tags=["Memory"])
def memory_delete(key: str, namespace: str = "default", agent_id: str = Depends(get_agent_id)):
    """Delete a key from memory."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM memory WHERE agent_id=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found")
    return {"status": "deleted", "key": key}

@app.get("/v1/memory", tags=["Memory"])
def memory_list(
    namespace: str = "default",
    prefix: str = "",
    limit: int = Query(50, le=200),
    agent_id: str = Depends(get_agent_id)
):
    """List keys in a namespace, optionally filtered by prefix."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT key, LENGTH(value) as size_bytes, updated_at, expires_at FROM memory "
            "WHERE agent_id=? AND namespace=? AND key LIKE ? AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY updated_at DESC LIMIT ?",
            (agent_id, namespace, f"{prefix}%", now, limit)
        ).fetchall()
    return {"namespace": namespace, "keys": [dict(r) for r in rows], "count": len(rows)}


# ═══════════════════════════════════════════════════════════════════════════════
# TASK QUEUE (Priority Queue with Status Tracking)
# ═══════════════════════════════════════════════════════════════════════════════

class QueueSubmitRequest(BaseModel):
    payload: str = Field(..., max_length=MAX_QUEUE_PAYLOAD_SIZE)
    queue_name: str = Field("default", max_length=64)
    priority: int = Field(0, ge=0, le=10, description="Higher = processed first")

class QueueJobResponse(BaseModel):
    job_id: str
    status: str
    queue_name: str
    priority: int
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[str]

@app.post("/v1/queue/submit", tags=["Queue"])
def queue_submit(req: QueueSubmitRequest, agent_id: str = Depends(get_agent_id)):
    """Submit a job to the task queue."""
    job_id = f"job_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO queue (job_id, agent_id, queue_name, payload, priority, created_at) VALUES (?,?,?,?,?,?)",
            (job_id, agent_id, req.queue_name, req.payload, req.priority, now)
        )
    return {"job_id": job_id, "status": "pending", "queue_name": req.queue_name}

@app.get("/v1/queue/{job_id}", response_model=QueueJobResponse, tags=["Queue"])
def queue_status(job_id: str, agent_id: str = Depends(get_agent_id)):
    """Check job status."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM queue WHERE job_id=? AND agent_id=?", (job_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        return QueueJobResponse(**dict(row))

@app.post("/v1/queue/claim", tags=["Queue"])
def queue_claim(queue_name: str = "default", agent_id: str = Depends(get_agent_id)):
    """Claim the next pending job from a queue (for worker agents)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT job_id, payload, priority FROM queue WHERE queue_name=? AND status='pending' "
            "ORDER BY priority DESC, created_at ASC LIMIT 1",
            (queue_name,)
        ).fetchone()
        if not row:
            return {"status": "empty", "queue_name": queue_name}
        db.execute(
            "UPDATE queue SET status='processing', started_at=? WHERE job_id=?",
            (now, row["job_id"])
        )
        return {"job_id": row["job_id"], "payload": row["payload"], "priority": row["priority"]}

@app.post("/v1/queue/{job_id}/complete", tags=["Queue"])
def queue_complete(job_id: str, result: str = "", agent_id: str = Depends(get_agent_id)):
    """Mark a job as completed with optional result."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        # Get the job owner before updating so we can notify them
        job_row = db.execute("SELECT agent_id, queue_name FROM queue WHERE job_id=? AND status='processing'", (job_id,)).fetchone()
        if not job_row:
            raise HTTPException(404, "Job not found or not in processing state")
        db.execute(
            "UPDATE queue SET status='completed', completed_at=?, result=? WHERE job_id=?",
            (now, result, job_id)
        )

    _fire_webhooks(job_row["agent_id"], "job.completed", {
        "job_id": job_id, "queue_name": job_row["queue_name"],
        "result": result, "completed_at": now,
    })
    return {"job_id": job_id, "status": "completed"}

@app.get("/v1/queue", tags=["Queue"])
def queue_list(
    queue_name: str = "default",
    status: Optional[str] = None,
    limit: int = Query(20, le=100),
    agent_id: str = Depends(get_agent_id)
):
    """List jobs in a queue."""
    with get_db() as db:
        if status:
            rows = db.execute(
                "SELECT job_id, status, priority, created_at, completed_at FROM queue "
                "WHERE agent_id=? AND queue_name=? AND status=? ORDER BY created_at DESC LIMIT ?",
                (agent_id, queue_name, status, limit)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT job_id, status, priority, created_at, completed_at FROM queue "
                "WHERE agent_id=? AND queue_name=? ORDER BY created_at DESC LIMIT ?",
                (agent_id, queue_name, limit)
            ).fetchall()
    return {"queue_name": queue_name, "jobs": [dict(r) for r in rows], "count": len(rows)}


# ═══════════════════════════════════════════════════════════════════════════════
# MESSAGE RELAY (Bot-to-Bot Communication)
# ═══════════════════════════════════════════════════════════════════════════════

class RelayMessage(BaseModel):
    to_agent: str = Field(..., description="Recipient agent_id")
    channel: str = Field("direct", max_length=64)
    payload: str = Field(..., max_length=10_000)

@app.post("/v1/relay/send", tags=["Relay"])
def relay_send(msg: RelayMessage, agent_id: str = Depends(get_agent_id)):
    """Send a message to another agent."""
    message_id = f"msg_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        # Verify recipient exists
        recip = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (msg.to_agent,)).fetchone()
        if not recip:
            raise HTTPException(404, "Recipient agent not found")
        db.execute(
            "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
            (message_id, agent_id, msg.to_agent, msg.channel, msg.payload, now)
        )

    # Push to WebSocket connections
    async def _ws_push():
        if msg.to_agent in _ws_connections:
            push = {
                "event": "message.received", "message_id": message_id,
                "from_agent": agent_id, "channel": msg.channel,
                "payload": msg.payload, "created_at": now,
            }
            dead = set()
            for peer in _ws_connections[msg.to_agent]:
                try:
                    await peer.send_json(push)
                except Exception:
                    dead.add(peer)
            _ws_connections[msg.to_agent] -= dead

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_ws_push())
    except RuntimeError:
        pass

    # Fire webhook notifications for recipient
    _fire_webhooks(msg.to_agent, "message.received", {
        "message_id": message_id, "from_agent": agent_id,
        "channel": msg.channel, "payload": msg.payload,
    })

    return {"message_id": message_id, "status": "delivered"}

@app.get("/v1/relay/inbox", tags=["Relay"])
def relay_inbox(
    channel: str = "direct",
    unread_only: bool = True,
    limit: int = Query(20, le=100),
    agent_id: str = Depends(get_agent_id)
):
    """Check your message inbox."""
    with get_db() as db:
        if unread_only:
            rows = db.execute(
                "SELECT message_id, from_agent, channel, payload, created_at FROM relay "
                "WHERE to_agent=? AND channel=? AND read_at IS NULL ORDER BY created_at DESC LIMIT ?",
                (agent_id, channel, limit)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT message_id, from_agent, channel, payload, created_at, read_at FROM relay "
                "WHERE to_agent=? AND channel=? ORDER BY created_at DESC LIMIT ?",
                (agent_id, channel, limit)
            ).fetchall()
    return {"channel": channel, "messages": [dict(r) for r in rows], "count": len(rows)}

@app.post("/v1/relay/{message_id}/read", tags=["Relay"])
def relay_mark_read(message_id: str, agent_id: str = Depends(get_agent_id)):
    """Mark a message as read."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        r = db.execute(
            "UPDATE relay SET read_at=? WHERE message_id=? AND to_agent=? AND read_at IS NULL",
            (now, message_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Message not found or already read")
    return {"message_id": message_id, "status": "read"}


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class TextProcessRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    operation: str = Field(..., description="One of: word_count, char_count, extract_urls, extract_emails, tokenize_sentences, deduplicate_lines, hash_sha256, base64_encode, base64_decode")

@app.post("/v1/text/process", tags=["Text Utilities"])
def text_process(req: TextProcessRequest, agent_id: str = Depends(get_agent_id)):
    """Run a text processing operation. Useful for agents that need fast server-side text manipulation."""
    import re
    import base64

    ops = {
        "word_count": lambda t: {"word_count": len(t.split())},
        "char_count": lambda t: {"char_count": len(t), "char_count_no_spaces": len(t.replace(" ", ""))},
        "extract_urls": lambda t: {"urls": re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', t)},
        "extract_emails": lambda t: {"emails": re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', t)},
        "tokenize_sentences": lambda t: {"sentences": [s.strip() for s in re.split(r'(?<=[.!?])\s+', t) if s.strip()]},
        "deduplicate_lines": lambda t: {"lines": list(dict.fromkeys(t.splitlines())), "removed": len(t.splitlines()) - len(set(t.splitlines()))},
        "hash_sha256": lambda t: {"hash": hashlib.sha256(t.encode()).hexdigest()},
        "base64_encode": lambda t: {"encoded": base64.b64encode(t.encode()).decode()},
        "base64_decode": lambda t: {"decoded": base64.b64decode(t.encode()).decode()},
    }

    if req.operation not in ops:
        raise HTTPException(400, f"Unknown operation. Available: {list(ops.keys())}")

    try:
        result = ops[req.operation](req.text)
    except Exception as e:
        raise HTTPException(422, f"Operation failed: {str(e)}")

    return {"operation": req.operation, "result": result}


# ═══════════════════════════════════════════════════════════════════════════════
# WEBHOOK CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

WEBHOOK_EVENT_TYPES = {"message.received", "job.completed"}
WEBHOOK_TIMEOUT = 5.0  # seconds

class WebhookRegisterRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="HTTPS callback URL")
    event_types: List[str] = Field(..., description="Events to subscribe to: message.received, job.completed")
    secret: Optional[str] = Field(None, max_length=128, description="Shared secret for HMAC signature verification")

class WebhookResponse(BaseModel):
    webhook_id: str
    url: str
    event_types: List[str]
    active: bool
    created_at: str

@app.post("/v1/webhooks", response_model=WebhookResponse, tags=["Webhooks"])
def webhook_register(req: WebhookRegisterRequest, agent_id: str = Depends(get_agent_id)):
    """Register a webhook callback URL for event notifications."""
    for et in req.event_types:
        if et not in WEBHOOK_EVENT_TYPES:
            raise HTTPException(400, f"Invalid event type '{et}'. Valid: {sorted(WEBHOOK_EVENT_TYPES)}")

    webhook_id = f"wh_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO webhooks (webhook_id, agent_id, url, event_types, secret, created_at) VALUES (?,?,?,?,?,?)",
            (webhook_id, agent_id, req.url, json.dumps(req.event_types), req.secret, now)
        )
    return WebhookResponse(
        webhook_id=webhook_id, url=req.url,
        event_types=req.event_types, active=True, created_at=now
    )

@app.get("/v1/webhooks", tags=["Webhooks"])
def webhook_list(agent_id: str = Depends(get_agent_id)):
    """List your registered webhooks."""
    with get_db() as db:
        rows = db.execute(
            "SELECT webhook_id, url, event_types, active, created_at FROM webhooks WHERE agent_id=?",
            (agent_id,)
        ).fetchall()
    return {
        "webhooks": [
            {**dict(r), "event_types": json.loads(r["event_types"]), "active": bool(r["active"])}
            for r in rows
        ],
        "count": len(rows),
    }

@app.delete("/v1/webhooks/{webhook_id}", tags=["Webhooks"])
def webhook_delete(webhook_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a webhook."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM webhooks WHERE webhook_id=? AND agent_id=?", (webhook_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Webhook not found")
    return {"status": "deleted", "webhook_id": webhook_id}


def _fire_webhooks(agent_id: str, event_type: str, data: dict):
    """Fire webhooks for an agent in a background thread. Best-effort delivery."""
    import hmac as _hmac

    with get_db() as db:
        rows = db.execute(
            "SELECT webhook_id, url, secret, event_types FROM webhooks WHERE agent_id=? AND active=1",
            (agent_id,)
        ).fetchall()

    matching = []
    for r in rows:
        if event_type in json.loads(r["event_types"]):
            matching.append({"webhook_id": r["webhook_id"], "url": r["url"], "secret": r["secret"]})

    if not matching:
        return

    def deliver():
        body = json.dumps({"event": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
        for wh in matching:
            try:
                headers = {"Content-Type": "application/json", "X-AgentForge-Event": event_type}
                if wh["secret"]:
                    sig = _hmac.new(wh["secret"].encode(), body.encode(), hashlib.sha256).hexdigest()
                    headers["X-AgentForge-Signature"] = sig
                with httpx.Client(timeout=WEBHOOK_TIMEOUT) as client:
                    client.post(wh["url"], content=body, headers=headers)
            except Exception as e:
                logger.warning(f"Webhook delivery failed for {wh['webhook_id']}: {e}")

    threading.Thread(target=deliver, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULED TASKS
# ═══════════════════════════════════════════════════════════════════════════════

class ScheduledTaskRequest(BaseModel):
    cron_expr: str = Field(..., max_length=128, description="Cron expression (5-field: min hour dom mon dow)")
    queue_name: str = Field("default", max_length=64)
    payload: str = Field(..., max_length=MAX_QUEUE_PAYLOAD_SIZE)
    priority: int = Field(0, ge=0, le=10)

class ScheduledTaskResponse(BaseModel):
    task_id: str
    cron_expr: str
    queue_name: str
    payload: str
    priority: int
    enabled: bool
    next_run_at: str
    created_at: str

@app.post("/v1/schedules", response_model=ScheduledTaskResponse, tags=["Schedules"])
def schedule_create(req: ScheduledTaskRequest, agent_id: str = Depends(get_agent_id)):
    """Create a cron-style recurring job schedule."""
    try:
        cron = croniter(req.cron_expr, datetime.now(timezone.utc))
        next_run = cron.get_next(datetime).isoformat()
    except (ValueError, KeyError) as e:
        raise HTTPException(400, f"Invalid cron expression: {e}")

    task_id = f"sched_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO scheduled_tasks (task_id, agent_id, cron_expr, queue_name, payload, priority, created_at, next_run_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (task_id, agent_id, req.cron_expr, req.queue_name, req.payload, req.priority, now, next_run)
        )
    return ScheduledTaskResponse(
        task_id=task_id, cron_expr=req.cron_expr, queue_name=req.queue_name,
        payload=req.payload, priority=req.priority, enabled=True,
        next_run_at=next_run, created_at=now
    )

@app.get("/v1/schedules", tags=["Schedules"])
def schedule_list(agent_id: str = Depends(get_agent_id)):
    """List your scheduled tasks."""
    with get_db() as db:
        rows = db.execute(
            "SELECT task_id, cron_expr, queue_name, priority, enabled, next_run_at, last_run_at, run_count, created_at "
            "FROM scheduled_tasks WHERE agent_id=? ORDER BY created_at DESC",
            (agent_id,)
        ).fetchall()
    return {
        "schedules": [{**dict(r), "enabled": bool(r["enabled"])} for r in rows],
        "count": len(rows),
    }

@app.get("/v1/schedules/{task_id}", tags=["Schedules"])
def schedule_get(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Get details of a scheduled task."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Scheduled task not found")
    d = dict(row)
    d["enabled"] = bool(d["enabled"])
    return d

@app.patch("/v1/schedules/{task_id}", tags=["Schedules"])
def schedule_toggle(task_id: str, enabled: bool = True, agent_id: str = Depends(get_agent_id)):
    """Enable or disable a scheduled task."""
    with get_db() as db:
        # If re-enabling, recalculate next_run
        if enabled:
            row = db.execute("SELECT cron_expr FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)).fetchone()
            if not row:
                raise HTTPException(404, "Scheduled task not found")
            cron = croniter(row["cron_expr"], datetime.now(timezone.utc))
            next_run = cron.get_next(datetime).isoformat()
            db.execute(
                "UPDATE scheduled_tasks SET enabled=1, next_run_at=? WHERE task_id=? AND agent_id=?",
                (next_run, task_id, agent_id)
            )
        else:
            r = db.execute(
                "UPDATE scheduled_tasks SET enabled=0 WHERE task_id=? AND agent_id=?",
                (task_id, agent_id)
            )
            if r.rowcount == 0:
                raise HTTPException(404, "Scheduled task not found")
    return {"task_id": task_id, "enabled": enabled}

@app.delete("/v1/schedules/{task_id}", tags=["Schedules"])
def schedule_delete(task_id: str, agent_id: str = Depends(get_agent_id)):
    """Delete a scheduled task."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM scheduled_tasks WHERE task_id=? AND agent_id=?", (task_id, agent_id)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Scheduled task not found")
    return {"status": "deleted", "task_id": task_id}


def _run_scheduler_tick():
    """Execute due scheduled tasks. Called by the background scheduler loop."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    with get_db() as db:
        due = db.execute(
            "SELECT * FROM scheduled_tasks WHERE enabled=1 AND next_run_at <= ?",
            (now_iso,)
        ).fetchall()

        for task in due:
            # Create a job in the queue
            job_id = f"job_{uuid.uuid4().hex[:16]}"
            db.execute(
                "INSERT INTO queue (job_id, agent_id, queue_name, payload, priority, created_at) VALUES (?,?,?,?,?,?)",
                (job_id, task["agent_id"], task["queue_name"], task["payload"], task["priority"], now_iso)
            )

            # Advance next_run_at
            cron = croniter(task["cron_expr"], now)
            next_run = cron.get_next(datetime).isoformat()
            db.execute(
                "UPDATE scheduled_tasks SET next_run_at=?, last_run_at=?, run_count=run_count+1 WHERE task_id=?",
                (next_run, now_iso, task["task_id"])
            )


def _scheduler_loop():
    """Background thread that checks for due scheduled tasks every 30 seconds."""
    while True:
        try:
            _run_scheduler_tick()
        except Exception as e:
            logger.error(f"Scheduler tick error: {e}")
        time.sleep(30)


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED / PUBLIC MEMORY NAMESPACES
# ═══════════════════════════════════════════════════════════════════════════════

class SharedMemorySetRequest(BaseModel):
    namespace: str = Field(..., max_length=64, description="Public namespace name")
    key: str = Field(..., max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    description: Optional[str] = Field(None, max_length=256, description="Human-readable description of this entry")
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000)

@app.post("/v1/shared-memory", tags=["Shared Memory"])
def shared_memory_set(req: SharedMemorySetRequest, agent_id: str = Depends(get_agent_id)):
    """Publish a key-value pair to a shared namespace that other agents can read."""
    now = datetime.now(timezone.utc)
    expires = None
    if req.ttl_seconds:
        expires = (now + timedelta(seconds=req.ttl_seconds)).isoformat()

    with get_db() as db:
        db.execute("""
            INSERT INTO shared_memory (owner_agent, namespace, key, value, description, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_agent, namespace, key)
            DO UPDATE SET value=?, description=?, updated_at=?, expires_at=?
        """, (agent_id, req.namespace, req.key, req.value, req.description,
              now.isoformat(), now.isoformat(), expires,
              req.value, req.description, now.isoformat(), expires))
    return {"status": "published", "namespace": req.namespace, "key": req.key}

@app.get("/v1/shared-memory/{namespace}", tags=["Shared Memory"])
def shared_memory_list(
    namespace: str,
    prefix: str = "",
    limit: int = Query(50, le=200),
    agent_id: str = Depends(get_agent_id),
):
    """List keys in a shared namespace (readable by any agent)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT owner_agent, key, description, LENGTH(value) as size_bytes, updated_at, expires_at "
            "FROM shared_memory WHERE namespace=? AND key LIKE ? "
            "AND (expires_at IS NULL OR expires_at > ?) ORDER BY updated_at DESC LIMIT ?",
            (namespace, f"{prefix}%", now, limit)
        ).fetchall()
    return {"namespace": namespace, "entries": [dict(r) for r in rows], "count": len(rows)}

@app.get("/v1/shared-memory/{namespace}/{key}", tags=["Shared Memory"])
def shared_memory_get(namespace: str, key: str, agent_id: str = Depends(get_agent_id)):
    """Read a value from a shared namespace (any agent can read)."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM shared_memory WHERE namespace=? AND key=? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (namespace, key, now)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Key not found or expired")
    return dict(row)

@app.delete("/v1/shared-memory/{namespace}/{key}", tags=["Shared Memory"])
def shared_memory_delete(namespace: str, key: str, agent_id: str = Depends(get_agent_id)):
    """Delete a key from a shared namespace (only the owner can delete)."""
    with get_db() as db:
        r = db.execute(
            "DELETE FROM shared_memory WHERE owner_agent=? AND namespace=? AND key=?",
            (agent_id, namespace, key)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found or you are not the owner")
    return {"status": "deleted", "namespace": namespace, "key": key}

@app.get("/v1/shared-memory", tags=["Shared Memory"])
def shared_memory_namespaces(agent_id: str = Depends(get_agent_id)):
    """List all shared namespaces with entry counts."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT namespace, COUNT(*) as entry_count, COUNT(DISTINCT owner_agent) as contributor_count "
            "FROM shared_memory WHERE (expires_at IS NULL OR expires_at > ?) "
            "GROUP BY namespace ORDER BY entry_count DESC",
            (now,)
        ).fetchall()
    return {"namespaces": [dict(r) for r in rows], "count": len(rows)}


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT DIRECTORY
# ═══════════════════════════════════════════════════════════════════════════════

class DirectoryUpdateRequest(BaseModel):
    description: Optional[str] = Field(None, max_length=512, description="What your agent does")
    capabilities: Optional[List[str]] = Field(None, max_length=20, description="List of capabilities")
    public: bool = Field(False, description="Whether to list in the public directory")

@app.put("/v1/directory/me", tags=["Directory"])
def directory_update(req: DirectoryUpdateRequest, agent_id: str = Depends(get_agent_id)):
    """Update your agent's directory listing."""
    caps_json = json.dumps(req.capabilities) if req.capabilities else None
    with get_db() as db:
        db.execute(
            "UPDATE agents SET description=?, capabilities=?, public=? WHERE agent_id=?",
            (req.description, caps_json, int(req.public), agent_id)
        )
    return {"status": "updated", "agent_id": agent_id, "public": req.public}

@app.get("/v1/directory/me", tags=["Directory"])
def directory_me(agent_id: str = Depends(get_agent_id)):
    """Get your own directory profile."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id, name, description, capabilities, public, created_at FROM agents WHERE agent_id=?",
            (agent_id,)
        ).fetchone()
    d = dict(row)
    d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
    d["public"] = bool(d["public"])
    return d

@app.get("/v1/directory", tags=["Directory"])
def directory_list(
    capability: Optional[str] = None,
    limit: int = Query(50, le=200),
):
    """Browse the public agent directory. No auth required."""
    with get_db() as db:
        if capability:
            rows = db.execute(
                "SELECT agent_id, name, description, capabilities, created_at FROM agents "
                "WHERE public=1 AND capabilities LIKE ? ORDER BY created_at DESC LIMIT ?",
                (f"%{capability}%", limit)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT agent_id, name, description, capabilities, created_at FROM agents "
                "WHERE public=1 ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
    agents = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"]) if d["capabilities"] else []
        agents.append(d)
    return {"agents": agents, "count": len(agents)}


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET REAL-TIME RELAY
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory map: agent_id -> set of WebSocket connections
_ws_connections: dict[str, set[WebSocket]] = {}

async def _ws_auth(api_key: str) -> Optional[str]:
    """Validate API key and return agent_id, or None."""
    with get_db() as db:
        row = db.execute(
            "SELECT agent_id FROM agents WHERE api_key_hash = ?",
            (hash_key(api_key),)
        ).fetchone()
        return row["agent_id"] if row else None

@app.websocket("/v1/relay/ws")
async def relay_websocket(ws: WebSocket):
    """
    WebSocket endpoint for real-time message relay.
    Connect with ?api_key=<key>. Send JSON: {"to_agent": "...", "channel": "...", "payload": "..."}
    Receive JSON push when a message is sent to you.
    """
    api_key = ws.query_params.get("api_key")
    if not api_key:
        await ws.close(code=4001, reason="Missing api_key query parameter")
        return

    agent_id = await _ws_auth(api_key)
    if not agent_id:
        await ws.close(code=4003, reason="Invalid API key")
        return

    await ws.accept()

    # Register connection
    if agent_id not in _ws_connections:
        _ws_connections[agent_id] = set()
    _ws_connections[agent_id].add(ws)

    try:
        while True:
            data = await ws.receive_json()
            to_agent = data.get("to_agent")
            channel = data.get("channel", "direct")
            payload = data.get("payload", "")

            if not to_agent or not payload:
                await ws.send_json({"error": "to_agent and payload are required"})
                continue

            # Persist to relay table
            message_id = f"msg_{uuid.uuid4().hex[:16]}"
            now = datetime.now(timezone.utc).isoformat()
            with get_db() as db:
                recip = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (to_agent,)).fetchone()
                if not recip:
                    await ws.send_json({"error": "Recipient agent not found"})
                    continue
                db.execute(
                    "INSERT INTO relay (message_id, from_agent, to_agent, channel, payload, created_at) VALUES (?,?,?,?,?,?)",
                    (message_id, agent_id, to_agent, channel, payload, now)
                )

            # Confirm to sender
            await ws.send_json({"status": "delivered", "message_id": message_id})

            # Push to recipient if connected
            if to_agent in _ws_connections:
                push = {
                    "event": "message.received",
                    "message_id": message_id,
                    "from_agent": agent_id,
                    "channel": channel,
                    "payload": payload,
                    "created_at": now,
                }
                dead = set()
                for peer in _ws_connections[to_agent]:
                    try:
                        await peer.send_json(push)
                    except Exception:
                        dead.add(peer)
                _ws_connections[to_agent] -= dead

            # Fire webhooks for recipient
            _fire_webhooks(to_agent, "message.received", {
                "message_id": message_id, "from_agent": agent_id,
                "channel": channel, "payload": payload,
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error for {agent_id}: {e}")
    finally:
        _ws_connections.get(agent_id, set()).discard(ws)
        if agent_id in _ws_connections and not _ws_connections[agent_id]:
            del _ws_connections[agent_id]


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH / METRICS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/v1/health", tags=["System"])
def health():
    """Public health check — no auth required."""
    with get_db() as db:
        agent_count = db.execute("SELECT COUNT(*) as c FROM agents").fetchone()["c"]
        job_count = db.execute("SELECT COUNT(*) as c FROM queue").fetchone()["c"]
        memory_keys = db.execute("SELECT COUNT(*) as c FROM memory").fetchone()["c"]
        messages = db.execute("SELECT COUNT(*) as c FROM relay").fetchone()["c"]
        webhooks = db.execute("SELECT COUNT(*) as c FROM webhooks WHERE active=1").fetchone()["c"]
        schedules = db.execute("SELECT COUNT(*) as c FROM scheduled_tasks WHERE enabled=1").fetchone()["c"]
        shared_keys = db.execute("SELECT COUNT(*) as c FROM shared_memory").fetchone()["c"]
        public_agents = db.execute("SELECT COUNT(*) as c FROM agents WHERE public=1").fetchone()["c"]

    return {
        "status": "operational",
        "version": "0.2.0",
        "stats": {
            "registered_agents": agent_count,
            "public_agents": public_agents,
            "total_jobs": job_count,
            "memory_keys_stored": memory_keys,
            "shared_memory_keys": shared_keys,
            "messages_relayed": messages,
            "active_webhooks": webhooks,
            "active_schedules": schedules,
            "websocket_connections": sum(len(s) for s in _ws_connections.values()),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/v1/stats", tags=["System"])
def stats(agent_id: str = Depends(get_agent_id)):
    """Your agent's usage stats."""
    with get_db() as db:
        agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        mem_count = db.execute("SELECT COUNT(*) as c FROM memory WHERE agent_id=?", (agent_id,)).fetchone()["c"]
        job_count = db.execute("SELECT COUNT(*) as c FROM queue WHERE agent_id=?", (agent_id,)).fetchone()["c"]
        msg_sent = db.execute("SELECT COUNT(*) as c FROM relay WHERE from_agent=?", (agent_id,)).fetchone()["c"]
        msg_recv = db.execute("SELECT COUNT(*) as c FROM relay WHERE to_agent=?", (agent_id,)).fetchone()["c"]

        wh_count = db.execute("SELECT COUNT(*) as c FROM webhooks WHERE agent_id=? AND active=1", (agent_id,)).fetchone()["c"]
        sched_count = db.execute("SELECT COUNT(*) as c FROM scheduled_tasks WHERE agent_id=? AND enabled=1", (agent_id,)).fetchone()["c"]
        shared_count = db.execute("SELECT COUNT(*) as c FROM shared_memory WHERE owner_agent=?", (agent_id,)).fetchone()["c"]

    return {
        "agent_id": agent_id,
        "name": agent["name"],
        "created_at": agent["created_at"],
        "total_requests": agent["request_count"],
        "memory_keys": mem_count,
        "jobs_submitted": job_count,
        "messages_sent": msg_sent,
        "messages_received": msg_recv,
        "active_webhooks": wh_count,
        "active_schedules": sched_count,
        "shared_memory_keys": shared_count,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ROOT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["System"])
def root():
    return {
        "service": "AgentForge",
        "version": "0.2.0",
        "docs": "/docs",
        "description": "Open-source toolkit API for autonomous agents",
        "endpoints": {
            "register": "POST /v1/register",
            "memory": "/v1/memory",
            "shared_memory": "/v1/shared-memory",
            "queue": "/v1/queue",
            "schedules": "/v1/schedules",
            "relay": "/v1/relay",
            "relay_ws": "WS /v1/relay/ws",
            "webhooks": "/v1/webhooks",
            "directory": "/v1/directory",
            "text": "/v1/text/process",
            "health": "GET /v1/health",
        }
    }
