"""
MoltGrid Response Cache -- Redis-backed cache for cross-worker response caching.

Uses Redis for shared state across multiple Uvicorn workers. Falls back to
in-memory TTL cache when Redis is unavailable (graceful degradation).
"""

import json
import time
import threading
import functools
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("moltgrid.cache")


class LocalTTLCache:
    """Thread-safe in-memory cache with per-key TTL expiration (fallback)."""

    def __init__(self):
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """Return cached value if present and not expired, else None."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        """Store a value with TTL in seconds."""
        with self._lock:
            self._store[key] = (value, time.monotonic() + ttl_seconds)

    async def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache."""
        with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        """Remove all entries from the cache."""
        with self._lock:
            self._store.clear()

    def clear_sync(self) -> None:
        """Synchronous cache clear for use in test fixtures."""
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        """Return the number of entries (including possibly expired)."""
        with self._lock:
            return len(self._store)

    def cleanup(self) -> int:
        """Remove expired entries and return count removed."""
        now = time.monotonic()
        removed = 0
        with self._lock:
            expired_keys = [
                k for k, (_, exp) in self._store.items() if now > exp
            ]
            for k in expired_keys:
                del self._store[k]
                removed += 1
        return removed

    async def close(self) -> None:
        """No-op for local cache."""
        pass


class RedisCache:
    """Redis-backed cache with async interface for cross-worker sharing.

    Connects lazily on first use. If Redis is unavailable, all operations
    degrade gracefully (return None / skip silently) instead of crashing.
    """

    def __init__(self, redis_url: str, prefix: str = "moltgrid:cache:"):
        self._redis_url = redis_url
        self._prefix = prefix
        self._client = None
        self._connect_failed = False

    def _get_client(self):
        """Lazy-init Redis client. Returns None on connection failure."""
        if self._client is not None:
            return self._client
        if self._connect_failed:
            return None
        try:
            import redis.asyncio as aioredis
            self._client = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
                retry_on_timeout=True,
            )
            return self._client
        except Exception as e:
            logger.warning(f"Redis connection setup failed: {e}. Using no-cache mode.")
            self._connect_failed = False  # Allow retry on next call
            return None

    async def get(self, key: str) -> Optional[Any]:
        """GET prefix+key from Redis. Deserialize JSON. On error, return None."""
        client = self._get_client()
        if client is None:
            return None
        try:
            raw = await client.get(self._prefix + key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as e:
            logger.warning(f"Redis GET error for '{key}': {e}")
            return None

    async def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        """SETEX prefix+key with JSON-serialized value and TTL."""
        client = self._get_client()
        if client is None:
            return
        try:
            await client.set(
                self._prefix + key,
                json.dumps(value, default=str),
                ex=int(ttl_seconds),
            )
        except Exception as e:
            logger.warning(f"Redis SET error for '{key}': {e}")

    async def invalidate(self, key: str) -> None:
        """DEL prefix+key."""
        client = self._get_client()
        if client is None:
            return
        try:
            await client.delete(self._prefix + key)
        except Exception as e:
            logger.warning(f"Redis DEL error for '{key}': {e}")

    async def clear(self) -> None:
        """SCAN and DEL all keys matching prefix*."""
        client = self._get_client()
        if client is None:
            return
        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(cursor, match=self._prefix + "*", count=100)
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break
        except Exception as e:
            logger.warning(f"Redis CLEAR error: {e}")

    def clear_sync(self) -> None:
        """Synchronous no-op for Redis (used in test fixtures)."""
        pass

    def size(self) -> int:
        """Not critical for Redis -- return 0."""
        return 0

    def cleanup(self) -> int:
        """No-op for Redis (TTL handles expiration natively)."""
        return 0

    async def close(self) -> None:
        """Close Redis client connection if open."""
        if self._client is not None:
            try:
                await self._client.close()
            except Exception as e:
                logger.warning(f"Redis close error: {e}")
            self._client = None


# ---------------------------------------------------------------------------
# Global cache instance
# ---------------------------------------------------------------------------

def _create_cache():
    """Create the appropriate cache backend."""
    from config import REDIS_URL
    if REDIS_URL:
        logger.info(f"Using Redis cache backend ({REDIS_URL.split('@')[-1] if '@' in REDIS_URL else REDIS_URL})")
        return RedisCache(REDIS_URL)
    logger.info("No REDIS_URL configured, using local in-memory cache")
    return LocalTTLCache()


response_cache = _create_cache()


# ---------------------------------------------------------------------------
# Lifespan helpers (called from main.py)
# ---------------------------------------------------------------------------

async def init_redis() -> None:
    """Verify Redis connectivity at startup (non-fatal)."""
    if isinstance(response_cache, RedisCache):
        client = response_cache._get_client()
        if client:
            try:
                await client.ping()
                logger.info("Redis cache connected and healthy")
            except Exception as e:
                logger.warning(f"Redis ping failed at startup: {e}. Cache will retry on use.")


async def close_redis() -> None:
    """Close Redis connection on shutdown."""
    await response_cache.close()


# ---------------------------------------------------------------------------
# Decorator for cached responses
# ---------------------------------------------------------------------------

def cached_response(ttl_seconds: float, key_func: Optional[Callable] = None):
    """Decorator for FastAPI endpoint functions that caches JSON-serializable responses.

    Args:
        ttl_seconds: How long to cache the response.
        key_func: Optional callable(request) -> str to generate cache key.
                  If None, uses the endpoint function name as key.

    All cache operations are async (Redis or async-compatible LocalTTLCache).
    """

    def decorator(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            cache_key = key_func(*args, **kwargs) if key_func else func.__name__
            cached = await response_cache.get(cache_key)
            if cached is not None:
                return cached
            result = await func(*args, **kwargs)
            await response_cache.set(cache_key, result, ttl_seconds)
            return result

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        # For sync endpoints, wrap in async
        @functools.wraps(func)
        async def sync_to_async_wrapper(*args, **kwargs):
            cache_key = key_func(*args, **kwargs) if key_func else func.__name__
            cached = await response_cache.get(cache_key)
            if cached is not None:
                return cached
            result = func(*args, **kwargs)
            await response_cache.set(cache_key, result, ttl_seconds)
            return result
        return sync_to_async_wrapper

    return decorator
