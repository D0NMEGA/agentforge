"""
MoltGrid Database Abstraction Layer.

Supports SQLite, PostgreSQL, and dual-write backends via DB_BACKEND env var.
All database access in main.py should go through get_db() and get_standalone_conn().
"""

import os
import json
import uuid
import queue
import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime, timezone

logger = logging.getLogger("moltgrid.db")

# ─── Config ──────────────────────────────────────────────────────────────────
DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")  # sqlite | postgres | dual
DB_PATH = os.getenv("MOLTGRID_DB", "moltgrid.db")
DATABASE_URL = os.getenv("DATABASE_URL", "")
_pg_pool = None


# ─── Pool Management ─────────────────────────────────────────────────────────
def init_pool():
    """Initialize psycopg connection pool when DB_BACKEND is postgres or dual."""
    global _pg_pool
    if DB_BACKEND not in ("postgres", "dual"):
        return
    if not DATABASE_URL:
        logger.error("DB_BACKEND=%s but DATABASE_URL not set — falling back to sqlite", DB_BACKEND)
        return
    try:
        from psycopg_pool import ConnectionPool
        from psycopg.rows import dict_row
        _pg_pool = ConnectionPool(
            DATABASE_URL,
            min_size=2,
            max_size=10,
            kwargs={"row_factory": dict_row},
        )
        logger.info("PostgreSQL connection pool initialized (min=2, max=10)")
    except Exception as e:
        logger.error("Failed to initialize PostgreSQL pool: %s", e)
        _pg_pool = None


def close_pool():
    """Close the PostgreSQL connection pool if it exists."""
    global _pg_pool
    if _pg_pool is not None:
        try:
            _pg_pool.close()
            logger.info("PostgreSQL connection pool closed")
        except Exception as e:
            logger.warning("Error closing PostgreSQL pool: %s", e)
        _pg_pool = None


# ─── Native Async Pool (asyncpg) ─────────────────────────────────────────────
try:
    import asyncpg
except ImportError:
    asyncpg = None  # type: ignore[assignment]

_asyncpg_pool = None


async def init_asyncpg_pool():
    """Initialize native async connection pool via asyncpg.

    Only activates when DB_BACKEND is 'postgres' or 'dual' and DATABASE_URL
    is set. Falls back gracefully (pool stays None) on import or connection
    errors so that SQLite local dev is never broken.
    """
    global _asyncpg_pool
    if DB_BACKEND not in ("postgres", "dual"):
        logger.info("asyncpg pool skipped (DB_BACKEND=%s)", DB_BACKEND)
        return
    if not DATABASE_URL:
        logger.error("DB_BACKEND=%s but DATABASE_URL not set; asyncpg pool not created", DB_BACKEND)
        return
    if asyncpg is None:
        logger.error("asyncpg package not installed; native async pool unavailable")
        return
    try:
        from config import ASYNCPG_MIN_SIZE, ASYNCPG_MAX_SIZE, ASYNCPG_COMMAND_TIMEOUT
        _asyncpg_pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=ASYNCPG_MIN_SIZE,
            max_size=ASYNCPG_MAX_SIZE,
            command_timeout=ASYNCPG_COMMAND_TIMEOUT,
        )
        logger.info(
            "asyncpg connection pool initialized (min=%d, max=%d, timeout=%ds)",
            ASYNCPG_MIN_SIZE, ASYNCPG_MAX_SIZE, ASYNCPG_COMMAND_TIMEOUT,
        )
    except Exception as e:
        logger.error("Failed to initialize asyncpg pool: %s", e)
        _asyncpg_pool = None


async def close_asyncpg_pool():
    """Close the asyncpg connection pool if it exists."""
    global _asyncpg_pool
    if _asyncpg_pool is not None:
        try:
            await _asyncpg_pool.close()
            logger.info("asyncpg connection pool closed")
        except Exception as e:
            logger.warning("Error closing asyncpg pool: %s", e)
        _asyncpg_pool = None


def _translate_sql_asyncpg(sql):
    """Translate SQLite SQL to asyncpg-compatible SQL.

    - Replace ? placeholders with $1, $2, $3 numbered params
    - Translate datetime() calls to CAST/interval expressions
    - Skip ? inside single-quoted string literals
    """
    # First, apply datetime translations (same as _translate_sql)
    sql = _RE_DATETIME_OFFSET.sub(
        r"(CAST(\1 AS TIMESTAMP) + INTERVAL '\2 seconds')", sql
    )
    sql = _RE_DATETIME_DYNAMIC_OFFSET.sub(
        r"(CAST(\1 AS TIMESTAMP) - (\2 || ' seconds')::INTERVAL)", sql
    )
    sql = _RE_DATETIME_SIMPLE.sub(r"CAST(\1 AS TIMESTAMP)", sql)

    # Replace ? with $N, skipping ? inside single-quoted strings
    result = []
    param_idx = 0
    in_string = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'" and not in_string:
            in_string = True
            result.append(ch)
        elif ch == "'" and in_string:
            # Handle escaped quotes ('')
            if i + 1 < len(sql) and sql[i + 1] == "'":
                result.append("''")
                i += 2
                continue
            in_string = False
            result.append(ch)
        elif ch == "?" and not in_string:
            param_idx += 1
            result.append(f"${param_idx}")
        else:
            result.append(ch)
        i += 1
    return "".join(result)


# ─── SQLite Connection Pool ──────────────────────────────────────────────────

class SQLitePool:
    """Thread-safe SQLite connection pool using queue.Queue.

    Pre-creates `pool_size` connections with WAL mode, busy_timeout, and
    synchronous=NORMAL for optimal concurrent read/write performance.
    """

    def __init__(self, db_path: str, pool_size: int = 5):
        self._pool = queue.Queue(maxsize=pool_size)
        for _ in range(pool_size):
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._pool.put(conn)

    @contextmanager
    def connection(self):
        """Borrow a connection from the pool, return it when done."""
        conn = self._pool.get(timeout=10)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.put(conn)

    def close(self):
        """Drain the queue and close all pooled connections."""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except queue.Empty:
                break
        logger.info("SQLite connection pool closed")


_sqlite_pool = None


def init_sqlite_pool():
    """Initialize the SQLite connection pool (called during app lifespan startup)."""
    global _sqlite_pool
    if DB_BACKEND == "sqlite":
        _sqlite_pool = SQLitePool(DB_PATH, pool_size=5)
        logger.info("SQLite connection pool initialized (size=5)")


def close_sqlite_pool():
    """Close the SQLite connection pool (called during app lifespan shutdown)."""
    global _sqlite_pool
    if _sqlite_pool is not None:
        _sqlite_pool.close()
        _sqlite_pool = None


# ─── SQL Translation ─────────────────────────────────────────────────────────
import re as _re

# Precompile patterns for SQLite-to-PostgreSQL SQL translation
_RE_DATETIME_OFFSET = _re.compile(
    r"datetime\(([^(),]+),\s*'(-?\d+)\s+seconds'\)",
    _re.IGNORECASE,
)
_RE_DATETIME_DYNAMIC_OFFSET = _re.compile(
    r"datetime\(([^(),]+),\s*'-'\s*\|\|\s*\((.+?)\)\s*\|\|\s*'\s*seconds'\)",
    _re.IGNORECASE,
)
_RE_DATETIME_SIMPLE = _re.compile(
    r"datetime\(([^()]+)\)",
    _re.IGNORECASE,
)


def _translate_sql(sql):
    """Translate SQLite SQL to PostgreSQL-compatible SQL.

    - Replace ? placeholders with %s
    - Translate datetime() calls to CAST/interval expressions
    """
    # datetime(col, '-300 seconds') -> (CAST(col AS TIMESTAMP) + INTERVAL '-300 seconds')
    sql = _RE_DATETIME_OFFSET.sub(
        r"(CAST(\1 AS TIMESTAMP) + INTERVAL '\2 seconds')", sql
    )
    # datetime(col, '-' || (expr) || ' seconds') -> (CAST(col AS TIMESTAMP) - (\2 || ' seconds')::INTERVAL)
    sql = _RE_DATETIME_DYNAMIC_OFFSET.sub(
        r"(CAST(\1 AS TIMESTAMP) - (\2 || ' seconds')::INTERVAL)", sql
    )
    # datetime(col) -> CAST(col AS TIMESTAMP)
    sql = _RE_DATETIME_SIMPLE.sub(r"CAST(\1 AS TIMESTAMP)", sql)
    # Placeholder translation
    sql = sql.replace("?", "%s")
    return sql


# ─── PsycopgConnWrapper ──────────────────────────────────────────────────────
class _PsycopgCursorWrapper:
    """Wraps a psycopg cursor to intercept execute calls and translate SQL."""

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=None):
        translated = _translate_sql(sql)
        if params is not None:
            return self._cursor.execute(translated, params)
        return self._cursor.execute(translated)

    def executemany(self, sql, params_seq):
        translated = _translate_sql(sql)
        return self._cursor.executemany(translated, params_seq)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    def __iter__(self):
        return iter(self._cursor)


class _PsycopgConnWrapper:
    """Wraps a psycopg3 connection to translate SQL placeholders and provide
    a sqlite3-compatible interface."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        translated = _translate_sql(sql)
        if params is not None:
            return self._conn.execute(translated, params)
        return self._conn.execute(translated)

    def executemany(self, sql, params_seq):
        translated = _translate_sql(sql)
        cur = self._conn.cursor()
        return cur.executemany(translated, params_seq)

    def executescript(self, sql):
        """Split on semicolons and execute each statement individually."""
        for statement in sql.split(";"):
            stmt = statement.strip()
            if stmt:
                self._conn.execute(stmt)

    def cursor(self):
        return _PsycopgCursorWrapper(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


# ─── Context Managers ─────────────────────────────────────────────────────────
@contextmanager
def get_db():
    """Yield a database connection based on DB_BACKEND.

    - sqlite: same as original main.py get_db() — connect, Row factory, yield, commit, close
    - postgres: use pool connection with wrapper
    - dual: write to both, read from postgres with fallback to sqlite
    """
    if DB_BACKEND == "sqlite":
        if _sqlite_pool is not None:
            with _sqlite_pool.connection() as conn:
                yield conn
        else:
            # Fallback: direct connection when pool is not initialized
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()
    elif DB_BACKEND == "postgres":
        if _pg_pool is None:
            raise RuntimeError("PostgreSQL pool not initialized. Call init_pool() first.")
        with _pg_pool.connection() as pg_conn:
            wrapper = _PsycopgConnWrapper(pg_conn)
            yield wrapper
            # Pool handles commit on clean exit
    elif DB_BACKEND == "dual":
        # Dual-write: write to both, read from postgres with sqlite fallback
        sqlite_conn = sqlite3.connect(DB_PATH)
        sqlite_conn.row_factory = sqlite3.Row
        pg_wrapper = None
        pg_ctx = None
        if _pg_pool is not None:
            try:
                pg_ctx = _pg_pool.connection()
                pg_conn = pg_ctx.__enter__()
                pg_wrapper = _PsycopgConnWrapper(pg_conn)
            except Exception as e:
                logger.warning("Dual-write: PostgreSQL connection failed, sqlite-only: %s", e)
                pg_wrapper = None
                pg_ctx = None

        dual = _DualWriteConn(sqlite_conn, pg_wrapper)
        try:
            yield dual
            sqlite_conn.commit()
            if pg_wrapper is not None:
                try:
                    pg_wrapper.commit()
                except Exception as e:
                    logger.warning("Dual-write: PostgreSQL commit failed: %s", e)
        finally:
            sqlite_conn.close()
            if pg_ctx is not None:
                try:
                    pg_ctx.__exit__(None, None, None)
                except Exception:
                    pass
    else:
        raise ValueError(f"Unknown DB_BACKEND: {DB_BACKEND}")


class _DualWriteConn:
    """Dual-write connection: writes go to both sqlite and postgres,
    reads come from postgres (with sqlite fallback)."""

    def __init__(self, sqlite_conn, pg_wrapper):
        self._sqlite = sqlite_conn
        self._pg = pg_wrapper

    def execute(self, sql, params=None):
        # Write to sqlite first (source of truth)
        if params is not None:
            result = self._sqlite.execute(sql, params)
        else:
            result = self._sqlite.execute(sql)
        # Write to postgres too
        if self._pg is not None:
            try:
                if params is not None:
                    self._pg.execute(sql, params)
                else:
                    self._pg.execute(sql)
            except Exception as e:
                logger.warning("Dual-write: PostgreSQL execute failed: %s", e)
        return result

    def executemany(self, sql, params_seq):
        params_list = list(params_seq)
        result = self._sqlite.executemany(sql, params_list)
        if self._pg is not None:
            try:
                self._pg.executemany(sql, params_list)
            except Exception as e:
                logger.warning("Dual-write: PostgreSQL executemany failed: %s", e)
        return result

    def executescript(self, sql):
        result = self._sqlite.executescript(sql)
        if self._pg is not None:
            try:
                self._pg.executescript(sql)
            except Exception as e:
                logger.warning("Dual-write: PostgreSQL executescript failed: %s", e)
        return result

    def commit(self):
        self._sqlite.commit()
        if self._pg is not None:
            try:
                self._pg.commit()
            except Exception as e:
                logger.warning("Dual-write: PostgreSQL commit failed: %s", e)

    def close(self):
        self._sqlite.close()

    def cursor(self):
        return self._sqlite.cursor()

    def __getattr__(self, name):
        return getattr(self._sqlite, name)


def get_standalone_conn():
    """Get an independent database connection (not from the pool).

    Used by fire-and-forget functions that need their own connection
    outside of request-scoped get_db() blocks.
    """
    if DB_BACKEND == "sqlite":
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    else:
        # postgres or dual — use direct psycopg connection
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=False)
        return _PsycopgConnWrapper(conn)


# ─── Column Discovery Helper ─────────────────────────────────────────────────
def _get_existing_columns(conn, table_name):
    """Get existing column names for a table.

    - SQLite: uses PRAGMA table_info
    - Postgres: uses information_schema.columns
    """
    if DB_BACKEND == "sqlite":
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row[1] for row in rows}
    else:
        # Postgres — conn is a _PsycopgConnWrapper, use translated SQL
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = ?",
            (table_name,)
        ).fetchall()
        return {row["column_name"] if isinstance(row, dict) else row[0] for row in rows}


# ─── Schema Initialization ───────────────────────────────────────────────────
def init_db(conn=None):
    """Initialize database schema. Supports both SQLite and PostgreSQL.

    If conn is None, creates a connection using the current backend.
    """
    own_conn = conn is None
    if own_conn:
        if DB_BACKEND == "sqlite":
            conn = sqlite3.connect(DB_PATH)
        else:
            import psycopg
            from psycopg.rows import dict_row
            conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=False)
            conn = _PsycopgConnWrapper(conn)

    # SQLite-only PRAGMAs
    if DB_BACKEND == "sqlite":
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")

    # Type mappings for postgres
    if DB_BACKEND in ("postgres", "dual"):
        _init_db_postgres(conn)
    else:
        _init_db_sqlite(conn)

    if own_conn:
        conn.commit()
        conn.close()


def _init_db_sqlite(conn):
    """SQLite schema initialization — original init_db() logic from main.py."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            api_key_hash TEXT NOT NULL,
            name TEXT,
            description TEXT,
            capabilities TEXT,
            public INTEGER DEFAULT 1,
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

        CREATE TABLE IF NOT EXISTS vector_memory (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            text TEXT NOT NULL,
            embedding BLOB NOT NULL,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
            UNIQUE(agent_id, namespace, key)
        );
        CREATE INDEX IF NOT EXISTS idx_vec_agent ON vector_memory(agent_id, namespace);

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
            max_attempts INTEGER DEFAULT 1,
            attempt_count INTEGER DEFAULT 0,
            retry_delay_seconds INTEGER DEFAULT 0,
            next_retry_at TEXT,
            failed_at TEXT,
            fail_reason TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_queue_status ON queue(queue_name, status, priority DESC);

        CREATE TABLE IF NOT EXISTS dead_letter (
            job_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            queue_name TEXT NOT NULL DEFAULT 'default',
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'failed',
            priority INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result TEXT,
            max_attempts INTEGER DEFAULT 1,
            attempt_count INTEGER DEFAULT 0,
            retry_delay_seconds INTEGER DEFAULT 0,
            failed_at TEXT,
            fail_reason TEXT,
            moved_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_dlq_agent ON dead_letter(agent_id, queue_name);

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

        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS uptime_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at TEXT NOT NULL,
            status TEXT NOT NULL,
            response_ms REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_uptime_at ON uptime_checks(checked_at);

        CREATE TABLE IF NOT EXISTS collaborations (
            collaboration_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            partner_agent TEXT NOT NULL,
            task_type TEXT,
            outcome TEXT NOT NULL,
            rating INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
            FOREIGN KEY (partner_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_collab_partner ON collaborations(partner_agent);
        CREATE INDEX IF NOT EXISTS idx_collab_agent ON collaborations(agent_id);

        CREATE TABLE IF NOT EXISTS marketplace (
            task_id TEXT PRIMARY KEY,
            creator_agent TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            requirements TEXT,
            reward_credits INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0,
            estimated_effort TEXT,
            tags TEXT,
            deadline TEXT,
            status TEXT DEFAULT 'open',
            claimed_by TEXT,
            claimed_at TEXT,
            delivered_at TEXT,
            result TEXT,
            rating INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (creator_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_market_status ON marketplace(status, category);
        CREATE INDEX IF NOT EXISTS idx_market_creator ON marketplace(creator_agent);
        CREATE INDEX IF NOT EXISTS idx_market_claimed ON marketplace(claimed_by);

        CREATE TABLE IF NOT EXISTS test_scenarios (
            scenario_id TEXT PRIMARY KEY,
            creator_agent TEXT NOT NULL,
            name TEXT,
            pattern TEXT NOT NULL,
            agent_count INTEGER NOT NULL,
            timeout_seconds INTEGER DEFAULT 60,
            success_criteria TEXT,
            status TEXT DEFAULT 'created',
            results TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (creator_agent) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_scenarios_creator ON test_scenarios(creator_agent);

        CREATE TABLE IF NOT EXISTS contact_submissions (
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT NOT NULL,
            subject TEXT,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            subscription_tier TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            usage_count INTEGER DEFAULT 0,
            max_agents INTEGER DEFAULT 1,
            max_api_calls INTEGER DEFAULT 10000,
            created_at TEXT NOT NULL,
            last_login TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_stripe ON users(stripe_customer_id);

        CREATE TABLE IF NOT EXISTS email_queue (
            id TEXT PRIMARY KEY,
            to_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_html TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            sent_at TEXT,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status, created_at);

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            title TEXT,
            messages TEXT NOT NULL DEFAULT '[]',
            metadata TEXT,
            token_count INTEGER DEFAULT 0,
            max_tokens INTEGER DEFAULT 128000,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);

        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            delivery_id TEXT PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            attempt_count INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 3,
            next_retry_at TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL,
            delivered_at TEXT,
            FOREIGN KEY (webhook_id) REFERENCES webhooks(webhook_id)
        );
        CREATE INDEX IF NOT EXISTS idx_webhook_del_status ON webhook_deliveries(status, next_retry_at);

        CREATE TABLE IF NOT EXISTS pubsub_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            subscribed_at TEXT NOT NULL,
            UNIQUE(agent_id, channel),
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_pubsub_channel ON pubsub_subscriptions(channel);

        CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS analytics_events (
            id TEXT PRIMARY KEY,
            event_name TEXT NOT NULL,
            user_id TEXT,
            agent_id TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_event ON analytics_events(event_name, created_at);

    """)

    # Migrate existing agents table — add columns that older versions didn't have
    existing = _get_existing_columns(conn, "agents")
    for col, typedef in [
        ("description", "TEXT"), ("capabilities", "TEXT"), ("public", "INTEGER DEFAULT 0"),
        ("available", "INTEGER DEFAULT 1"), ("looking_for", "TEXT"), ("busy_until", "TEXT"),
        ("reputation", "REAL DEFAULT 0.0"), ("reputation_count", "INTEGER DEFAULT 0"),
        ("credits", "INTEGER DEFAULT 0"),
        ("heartbeat_at", "TEXT"), ("heartbeat_interval", "INTEGER DEFAULT 60"),
        ("heartbeat_status", "TEXT DEFAULT 'unknown'"), ("heartbeat_meta", "TEXT"),
        ("owner_id", "TEXT"),
        ("onboarding_completed", "INTEGER DEFAULT 0"),
        ("moltbook_profile_id", "TEXT"),
        ("display_name", "TEXT"),
        ("featured", "INTEGER DEFAULT 0"),
        ("verified", "INTEGER DEFAULT 0"),
        ("skills", "TEXT"),
        ("interests", "TEXT"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {typedef}")

    # Migrate analytics_events — add source and moltbook_url columns
    ae_existing = _get_existing_columns(conn, "analytics_events")
    for col, typedef in [
        ("source", "TEXT DEFAULT 'moltgrid_api'"),
        ("moltbook_url", "TEXT"),
    ]:
        if col not in ae_existing:
            conn.execute(f"ALTER TABLE analytics_events ADD COLUMN {col} {typedef}")
    conn.execute("UPDATE analytics_events SET source='moltgrid_api' WHERE source IS NULL")

    # Create integrations table (OC-05)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            config TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_integrations_agent ON integrations(agent_id)")

    # Migrate existing users table — add columns for billing and notifications
    try:
        u_existing = _get_existing_columns(conn, "users")
        for col, typedef in [
            ("payment_failed", "INTEGER DEFAULT 0"),
            ("notification_preferences", "TEXT"),
            ("known_login_ips", "TEXT DEFAULT '[]'"),
            ("totp_secret", "TEXT"),
            ("totp_enabled", "INTEGER DEFAULT 0"),
            ("totp_recovery_codes", "TEXT"),
            ("promo_optin", "INTEGER DEFAULT 0"),
        ]:
            if col not in u_existing:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typedef}")
    except Exception:
        pass  # users table may not exist yet on first run

    # Migrate existing queue table — add retry/dead-letter columns
    q_existing = _get_existing_columns(conn, "queue")
    for col, typedef in [
        ("max_attempts", "INTEGER DEFAULT 1"), ("attempt_count", "INTEGER DEFAULT 0"),
        ("retry_delay_seconds", "INTEGER DEFAULT 0"), ("next_retry_at", "TEXT"),
        ("failed_at", "TEXT"), ("fail_reason", "TEXT"),
    ]:
        if col not in q_existing:
            conn.execute(f"ALTER TABLE queue ADD COLUMN {col} {typedef}")

    # Migrate memory table — add visibility / shared_agents
    m_existing = _get_existing_columns(conn, "memory")
    for col, typedef in [
        ('visibility', "TEXT DEFAULT 'private'"),
        ('shared_agents', 'TEXT'),
    ]:
        if col not in m_existing:
            conn.execute(f'ALTER TABLE memory ADD COLUMN {col} {typedef}')
    conn.execute("UPDATE memory SET visibility='private' WHERE visibility IS NULL")

    # Create memory audit log table
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

    # Audit logs table (BL-05)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT,
            agent_id TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, created_at)")

    # Agent templates table (BL-04)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS templates (
            template_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            starter_code TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Seed 5 built-in templates — INSERT OR IGNORE so re-seeding is always safe
    _templates_seed = [
        (
            "tmpl_openclaw_social",
            "OpenClaw Social Agent",
            "An agent that posts to MoltBook and tracks social engagement via MoltGrid analytics.",
            "social",
            '{"memory_keys": ["moltbook_profile_id", "last_post_id", "follower_count"], "capabilities": ["moltbook_post", "moltbook_reply", "moltbook_upvote"], "starter_tasks": [{"action": "heartbeat", "interval": 60}, {"action": "poll_moltbook_events", "queue": "social"}], "example_post": "POST /v1/moltbook/events"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_openclaw",
            "OpenClaw Agent",
            "OpenClaw-compatible autonomous agent with messaging, memory, and scheduling capabilities.",
            "openclaw",
            '{"description": "OpenClaw-compatible autonomous agent", "capabilities": ["messaging", "memory", "scheduling"], "tags": ["openclaw", "autonomous", "multi-channel"], "is_public": true, "memory_keys": ["openclaw_config", "channel_list"], "auto_webhook": true}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_worker",
            "Background Worker Agent",
            "A general-purpose background worker that polls the job queue and processes tasks reliably.",
            "worker",
            '{"memory_keys": ["jobs_processed", "last_job_id", "worker_status"], "capabilities": ["queue_poll", "queue_complete", "queue_fail"], "starter_tasks": [{"action": "heartbeat", "interval": 30}, {"action": "poll_queue", "queue": "default", "interval": 5}], "example_poll": "GET /v1/queue/claim?queue=default"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_research",
            "Research Agent",
            "A research agent that stores findings in memory and uses vector search to avoid duplicate work.",
            "research",
            '{"memory_keys": ["research_topic", "findings_count", "last_query"], "capabilities": ["memory_write", "memory_vector_search", "shared_memory_read"], "starter_tasks": [{"action": "heartbeat", "interval": 120}, {"action": "vector_index_findings", "namespace": "research"}], "example_search": "POST /v1/vector/search"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_customer_service",
            "Customer Service Agent",
            "A customer service agent that handles inbound relay messages and routes them to the right queue.",
            "customer_service",
            '{"memory_keys": ["tickets_open", "tickets_resolved", "avg_response_time_s"], "capabilities": ["relay_inbox", "relay_send", "queue_submit"], "starter_tasks": [{"action": "heartbeat", "interval": 30}, {"action": "poll_inbox", "interval": 10}], "example_reply": "POST /v1/relay/send"}',
            "2026-01-01T00:00:00Z",
        ),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO templates (template_id, name, description, category, starter_code, created_at) VALUES (?,?,?,?,?,?)",
        _templates_seed,
    )

    # Multi-user org accounts (BL-02)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            org_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE,
            owner_user_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS org_members (
            org_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            PRIMARY KEY (org_id, user_id)
        )
    """)

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id)"
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_events (
            event_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL DEFAULT '{}',
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_events_agent_ack_time "
        "ON agent_events (agent_id, acknowledged, created_at)"
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_key_events (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL DEFAULT 'key_rotated',
            initiated_by TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_key_events_agent ON agent_key_events(agent_id)"
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS obstacle_course_submissions (
            submission_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            stages_completed TEXT NOT NULL DEFAULT '[]',
            score INTEGER NOT NULL DEFAULT 0,
            submitted_at TEXT NOT NULL,
            feedback TEXT NOT NULL DEFAULT ''
        )
    """)

    try:
        conn.execute("ALTER TABLE agents ADD COLUMN worker_status TEXT NOT NULL DEFAULT 'offline'")
    except Exception:
        pass  # column already exists

    # Migrate vector_memory — add importance and access_count for composite scoring
    vm_existing = _get_existing_columns(conn, "vector_memory")
    for col, typedef in [
        ('importance', 'REAL DEFAULT 0.5'),
        ('access_count', 'INTEGER DEFAULT 0'),
    ]:
        if col not in vm_existing:
            try:
                conn.execute(f'ALTER TABLE vector_memory ADD COLUMN {col} {typedef}')
            except Exception:
                pass

    # ── Phase 4: Account Settings tables ────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            jti TEXT NOT NULL UNIQUE,
            device TEXT DEFAULT 'Unknown',
            browser TEXT DEFAULT 'Unknown',
            ip_address TEXT,
            last_active TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_jti ON user_sessions(jti)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            key_hint TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used TEXT,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_keys_user ON user_keys(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_keys_hash ON user_keys(key_hash)")

    # Migrate users table — add timezone and avatar
    try:
        u_existing2 = _get_existing_columns(conn, "users")
        for col, typedef in [
            ("timezone", "TEXT DEFAULT 'America/Chicago'"),
            ("avatar_url", "TEXT"),
            ("deletion_requested_at", "TEXT"),
            ("last_username_change", "TEXT"),
        ]:
            if col not in u_existing2:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typedef}")
    except Exception:
        pass

    # Migrate email_queue table — add from_display for per-email FROM routing
    try:
        eq_existing = _get_existing_columns(conn, "email_queue")
        for col, typedef in [
            ("from_display", "TEXT"),
        ]:
            if col not in eq_existing:
                conn.execute(f"ALTER TABLE email_queue ADD COLUMN {col} {typedef}")
    except Exception:
        pass

    # Performance indexes — run AFTER all migrations so columns exist
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents(owner_id)",
        "CREATE INDEX IF NOT EXISTS idx_agents_heartbeat ON agents(heartbeat_at, heartbeat_status)",
        "CREATE INDEX IF NOT EXISTS idx_relay_unread ON relay(to_agent, read_at)",
        "CREATE INDEX IF NOT EXISTS idx_queue_agent ON queue(agent_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_sched_agent ON scheduled_tasks(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_analytics_agent ON analytics_events(agent_id, created_at)",
    ]:
        try:
            conn.execute(idx_sql)
        except Exception:
            pass


def _init_db_postgres(conn):
    """PostgreSQL schema initialization — CREATE TABLE IF NOT EXISTS with PG types.
    Skip PRAGMA migration loops; PG schema includes all columns from the start."""

    # Create all tables with PostgreSQL-compatible types
    # Note: TEXT for timestamps/JSON per research recommendation (no TIMESTAMPTZ/JSONB in Phase 9)
    # SERIAL PRIMARY KEY for uptime_checks.id and pubsub_subscriptions.id
    # DOUBLE PRECISION instead of REAL, BYTEA instead of BLOB

    tables_sql = [
        """CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            api_key_hash TEXT NOT NULL,
            name TEXT,
            description TEXT,
            capabilities TEXT,
            public INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_seen TEXT,
            request_count INTEGER DEFAULT 0,
            available INTEGER DEFAULT 1,
            looking_for TEXT,
            busy_until TEXT,
            reputation DOUBLE PRECISION DEFAULT 0.0,
            reputation_count INTEGER DEFAULT 0,
            credits INTEGER DEFAULT 0,
            heartbeat_at TEXT,
            heartbeat_interval INTEGER DEFAULT 60,
            heartbeat_status TEXT DEFAULT 'unknown',
            heartbeat_meta TEXT,
            owner_id TEXT,
            onboarding_completed INTEGER DEFAULT 0,
            moltbook_profile_id TEXT,
            display_name TEXT,
            featured INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            skills TEXT,
            interests TEXT,
            worker_status TEXT NOT NULL DEFAULT 'offline'
        )""",
        """CREATE TABLE IF NOT EXISTS memory (
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            visibility TEXT DEFAULT 'private',
            shared_agents TEXT,
            PRIMARY KEY (agent_id, namespace, key)
        )""",
        """CREATE TABLE IF NOT EXISTS vector_memory (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            text TEXT NOT NULL,
            embedding BYTEA NOT NULL,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            importance DOUBLE PRECISION DEFAULT 0.5,
            access_count INTEGER DEFAULT 0,
            UNIQUE(agent_id, namespace, key)
        )""",
        """CREATE TABLE IF NOT EXISTS queue (
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
            max_attempts INTEGER DEFAULT 1,
            attempt_count INTEGER DEFAULT 0,
            retry_delay_seconds INTEGER DEFAULT 0,
            next_retry_at TEXT,
            failed_at TEXT,
            fail_reason TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS dead_letter (
            job_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            queue_name TEXT NOT NULL DEFAULT 'default',
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'failed',
            priority INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result TEXT,
            max_attempts INTEGER DEFAULT 1,
            attempt_count INTEGER DEFAULT 0,
            retry_delay_seconds INTEGER DEFAULT 0,
            failed_at TEXT,
            fail_reason TEXT,
            moved_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS relay (
            message_id TEXT PRIMARY KEY,
            from_agent TEXT NOT NULL,
            to_agent TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'direct',
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS rate_limits (
            agent_id TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            count INTEGER DEFAULT 1,
            PRIMARY KEY (agent_id, window_start)
        )""",
        """CREATE TABLE IF NOT EXISTS metrics (
            recorded_at TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            latency_ms DOUBLE PRECISION NOT NULL,
            status_code INTEGER NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            url TEXT NOT NULL,
            event_types TEXT NOT NULL,
            secret TEXT,
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1
        )""",
        """CREATE TABLE IF NOT EXISTS scheduled_tasks (
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
            run_count INTEGER DEFAULT 0
        )""",
        """CREATE TABLE IF NOT EXISTS shared_memory (
            owner_agent TEXT NOT NULL,
            namespace TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            PRIMARY KEY (owner_agent, namespace, key)
        )""",
        """CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            expires_at DOUBLE PRECISION NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS uptime_checks (
            id SERIAL PRIMARY KEY,
            checked_at TEXT NOT NULL,
            status TEXT NOT NULL,
            response_ms DOUBLE PRECISION NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS collaborations (
            collaboration_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            partner_agent TEXT NOT NULL,
            task_type TEXT,
            outcome TEXT NOT NULL,
            rating INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS marketplace (
            task_id TEXT PRIMARY KEY,
            creator_agent TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            requirements TEXT,
            reward_credits INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0,
            estimated_effort TEXT,
            tags TEXT,
            deadline TEXT,
            status TEXT DEFAULT 'open',
            claimed_by TEXT,
            claimed_at TEXT,
            delivered_at TEXT,
            result TEXT,
            rating INTEGER,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS test_scenarios (
            scenario_id TEXT PRIMARY KEY,
            creator_agent TEXT NOT NULL,
            name TEXT,
            pattern TEXT NOT NULL,
            agent_count INTEGER NOT NULL,
            timeout_seconds INTEGER DEFAULT 60,
            success_criteria TEXT,
            status TEXT DEFAULT 'created',
            results TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS contact_submissions (
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT NOT NULL,
            subject TEXT,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            subscription_tier TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            usage_count INTEGER DEFAULT 0,
            max_agents INTEGER DEFAULT 1,
            max_api_calls INTEGER DEFAULT 10000,
            created_at TEXT NOT NULL,
            last_login TEXT,
            payment_failed INTEGER DEFAULT 0,
            notification_preferences TEXT,
            known_login_ips TEXT DEFAULT '[]',
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            totp_recovery_codes TEXT,
            promo_optin INTEGER DEFAULT 0,
            timezone TEXT DEFAULT 'America/Chicago',
            avatar_url TEXT,
            deletion_requested_at TEXT,
            last_username_change TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS email_queue (
            id TEXT PRIMARY KEY,
            to_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_html TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            sent_at TEXT,
            error TEXT,
            from_display TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            title TEXT,
            messages TEXT NOT NULL DEFAULT '[]',
            metadata TEXT,
            token_count INTEGER DEFAULT 0,
            max_tokens INTEGER DEFAULT 128000,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS webhook_deliveries (
            delivery_id TEXT PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            attempt_count INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 3,
            next_retry_at TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL,
            delivered_at TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS pubsub_subscriptions (
            id SERIAL PRIMARY KEY,
            agent_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            subscribed_at TEXT NOT NULL,
            UNIQUE(agent_id, channel)
        )""",
        """CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS analytics_events (
            id TEXT PRIMARY KEY,
            event_name TEXT NOT NULL,
            user_id TEXT,
            agent_id TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            source TEXT DEFAULT 'moltgrid_api',
            moltbook_url TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS memory_access_log (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            key TEXT NOT NULL,
            action TEXT NOT NULL,
            actor_agent_id TEXT,
            actor_user_id TEXT,
            old_visibility TEXT,
            new_visibility TEXT,
            authorized INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS audit_logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT,
            agent_id TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS templates (
            template_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            starter_code TEXT,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS organizations (
            org_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE,
            owner_user_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS org_members (
            org_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            PRIMARY KEY (org_id, user_id)
        )""",
        """CREATE TABLE IF NOT EXISTS agent_events (
            event_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL DEFAULT '{}',
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS agent_key_events (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL DEFAULT 'key_rotated',
            initiated_by TEXT,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS obstacle_course_submissions (
            submission_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            stages_completed TEXT NOT NULL DEFAULT '[]',
            score INTEGER NOT NULL DEFAULT 0,
            submitted_at TEXT NOT NULL,
            feedback TEXT NOT NULL DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            config TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS user_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            jti TEXT NOT NULL UNIQUE,
            device TEXT DEFAULT 'Unknown',
            browser TEXT DEFAULT 'Unknown',
            ip_address TEXT,
            last_active TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )""",
        """CREATE TABLE IF NOT EXISTS user_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            key_hint TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used TEXT,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )""",
    ]

    for sql in tables_sql:
        conn.execute(sql)

    # Create indexes
    indexes_sql = [
        "CREATE INDEX IF NOT EXISTS idx_vec_agent ON vector_memory(agent_id, namespace)",
        "CREATE INDEX IF NOT EXISTS idx_queue_status ON queue(queue_name, status, priority DESC)",
        "CREATE INDEX IF NOT EXISTS idx_dlq_agent ON dead_letter(agent_id, queue_name)",
        "CREATE INDEX IF NOT EXISTS idx_relay_to ON relay(to_agent, read_at)",
        "CREATE INDEX IF NOT EXISTS idx_webhooks_agent ON webhooks(agent_id, active)",
        "CREATE INDEX IF NOT EXISTS idx_sched_next ON scheduled_tasks(enabled, next_run_at)",
        "CREATE INDEX IF NOT EXISTS idx_shared_ns ON shared_memory(namespace)",
        "CREATE INDEX IF NOT EXISTS idx_uptime_at ON uptime_checks(checked_at)",
        "CREATE INDEX IF NOT EXISTS idx_collab_partner ON collaborations(partner_agent)",
        "CREATE INDEX IF NOT EXISTS idx_collab_agent ON collaborations(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_market_status ON marketplace(status, category)",
        "CREATE INDEX IF NOT EXISTS idx_market_creator ON marketplace(creator_agent)",
        "CREATE INDEX IF NOT EXISTS idx_market_claimed ON marketplace(claimed_by)",
        "CREATE INDEX IF NOT EXISTS idx_scenarios_creator ON test_scenarios(creator_agent)",
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
        "CREATE INDEX IF NOT EXISTS idx_users_stripe ON users(stripe_customer_id)",
        "CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_webhook_del_status ON webhook_deliveries(status, next_retry_at)",
        "CREATE INDEX IF NOT EXISTS idx_pubsub_channel ON pubsub_subscriptions(channel)",
        "CREATE INDEX IF NOT EXISTS idx_analytics_event ON analytics_events(event_name, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_mal_agent ON memory_access_log(agent_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_integrations_agent ON integrations(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_agent_events_agent_ack_time ON agent_events(agent_id, acknowledged, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_agent_key_events_agent ON agent_key_events(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_user_sessions_jti ON user_sessions(jti)",
        "CREATE INDEX IF NOT EXISTS idx_user_keys_user ON user_keys(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_user_keys_hash ON user_keys(key_hash)",
    ]

    for sql in indexes_sql:
        conn.execute(sql)

    # Seed 5 built-in templates with ON CONFLICT DO NOTHING (postgres equivalent of INSERT OR IGNORE)
    _templates_seed = [
        (
            "tmpl_openclaw_social",
            "OpenClaw Social Agent",
            "An agent that posts to MoltBook and tracks social engagement via MoltGrid analytics.",
            "social",
            '{"memory_keys": ["moltbook_profile_id", "last_post_id", "follower_count"], "capabilities": ["moltbook_post", "moltbook_reply", "moltbook_upvote"], "starter_tasks": [{"action": "heartbeat", "interval": 60}, {"action": "poll_moltbook_events", "queue": "social"}], "example_post": "POST /v1/moltbook/events"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_openclaw",
            "OpenClaw Agent",
            "OpenClaw-compatible autonomous agent with messaging, memory, and scheduling capabilities.",
            "openclaw",
            '{"description": "OpenClaw-compatible autonomous agent", "capabilities": ["messaging", "memory", "scheduling"], "tags": ["openclaw", "autonomous", "multi-channel"], "is_public": true, "memory_keys": ["openclaw_config", "channel_list"], "auto_webhook": true}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_worker",
            "Background Worker Agent",
            "A general-purpose background worker that polls the job queue and processes tasks reliably.",
            "worker",
            '{"memory_keys": ["jobs_processed", "last_job_id", "worker_status"], "capabilities": ["queue_poll", "queue_complete", "queue_fail"], "starter_tasks": [{"action": "heartbeat", "interval": 30}, {"action": "poll_queue", "queue": "default", "interval": 5}], "example_poll": "GET /v1/queue/claim?queue=default"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_research",
            "Research Agent",
            "A research agent that stores findings in memory and uses vector search to avoid duplicate work.",
            "research",
            '{"memory_keys": ["research_topic", "findings_count", "last_query"], "capabilities": ["memory_write", "memory_vector_search", "shared_memory_read"], "starter_tasks": [{"action": "heartbeat", "interval": 120}, {"action": "vector_index_findings", "namespace": "research"}], "example_search": "POST /v1/vector/search"}',
            "2026-01-01T00:00:00Z",
        ),
        (
            "tmpl_customer_service",
            "Customer Service Agent",
            "A customer service agent that handles inbound relay messages and routes them to the right queue.",
            "customer_service",
            '{"memory_keys": ["tickets_open", "tickets_resolved", "avg_response_time_s"], "capabilities": ["relay_inbox", "relay_send", "queue_submit"], "starter_tasks": [{"action": "heartbeat", "interval": 30}, {"action": "poll_inbox", "interval": 10}], "example_reply": "POST /v1/relay/send"}',
            "2026-01-01T00:00:00Z",
        ),
    ]
    conn.executemany(
        "INSERT INTO templates (template_id, name, description, category, starter_code, created_at) "
        "VALUES (?,?,?,?,?,?) ON CONFLICT (template_id) DO NOTHING",
        _templates_seed,
    )
