"""
MoltGrid Async Database Helpers.

Wraps synchronous get_db() calls in asyncio.to_thread() so that
database I/O does not block the FastAPI event loop.

Usage:
    rows = await async_db_fetchall("SELECT * FROM agents WHERE public=1 LIMIT ?", (50,))
    row  = await async_db_fetchone("SELECT COUNT(*) as c FROM memory", ())
    await async_db_execute("UPDATE agents SET heartbeat_at=? WHERE agent_id=?", (now, aid))
"""

import asyncio
from typing import Any, Optional, Sequence

from db import get_db


def _sync_fetchall(query: str, params: Optional[Sequence[Any]] = None) -> list[dict]:
    """Run a query synchronously and return all rows as dicts."""
    with get_db() as db:
        if params:
            rows = db.execute(query, params).fetchall()
        else:
            rows = db.execute(query).fetchall()
        return [dict(r) for r in rows]


def _sync_fetchone(query: str, params: Optional[Sequence[Any]] = None) -> Optional[dict]:
    """Run a query synchronously and return one row as dict (or None)."""
    with get_db() as db:
        if params:
            row = db.execute(query, params).fetchone()
        else:
            row = db.execute(query).fetchone()
        return dict(row) if row else None


def _sync_execute(query: str, params: Optional[Sequence[Any]] = None) -> None:
    """Run a write query synchronously (INSERT/UPDATE/DELETE)."""
    with get_db() as db:
        if params:
            db.execute(query, params)
        else:
            db.execute(query)


async def async_db_fetchall(query: str, params: Optional[Sequence[Any]] = None) -> list[dict]:
    """Execute a query off the event loop and return all rows as dicts."""
    return await asyncio.to_thread(_sync_fetchall, query, params)


async def async_db_fetchone(query: str, params: Optional[Sequence[Any]] = None) -> Optional[dict]:
    """Execute a query off the event loop and return one row as dict (or None)."""
    return await asyncio.to_thread(_sync_fetchone, query, params)


async def async_db_execute(query: str, params: Optional[Sequence[Any]] = None) -> None:
    """Execute a write query off the event loop."""
    return await asyncio.to_thread(_sync_execute, query, params)
