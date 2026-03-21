"""
MoltGrid Leader Election -- Redis-based leader election for multi-worker Uvicorn.

Only one worker should run background threads (scheduler, uptime, liveness,
usage reset, email queue, webhook delivery). This module uses Redis SET NX
with a TTL to elect a single leader among workers.

Graceful fallback: if Redis is unavailable, assumes leadership so that
single-worker deployments continue to work without Redis.
"""

import os
import time
import threading
import logging

logger = logging.getLogger("moltgrid.leader")

# Unique worker ID based on PID (each Uvicorn worker has a different PID)
WORKER_ID = f"worker-{os.getpid()}"
LEADER_KEY = "moltgrid:leader"
LEADER_TTL = 30  # seconds
RENEW_INTERVAL = 15  # seconds

_is_leader = False
_renew_thread = None
_stop_event = threading.Event()


def _get_redis_client():
    """Get a synchronous Redis client for leader election.

    Uses a synchronous client (not async) because leader election runs
    in background threads and during startup before the event loop.
    """
    try:
        import redis
        from config import REDIS_URL
        if not REDIS_URL:
            return None
        client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        return client
    except Exception as e:
        logger.warning(f"Redis unavailable for leader election: {e}")
        return None


def _renew_loop():
    """Background thread that renews the leader TTL every RENEW_INTERVAL seconds."""
    global _is_leader
    while not _stop_event.is_set():
        try:
            client = _get_redis_client()
            if client is None:
                # Redis gone, keep leadership assumption for graceful degradation
                break
            current = client.get(LEADER_KEY)
            if current == WORKER_ID:
                client.expire(LEADER_KEY, LEADER_TTL)
            else:
                # Lost leadership (another worker took over or key expired)
                _is_leader = False
                logger.warning(f"Lost leadership to {current}")
                break
        except Exception as e:
            logger.error(f"Leader renewal error: {e}")
        _stop_event.wait(RENEW_INTERVAL)


def acquire_leadership() -> bool:
    """Try to become the leader worker. Returns True if this worker is now leader.

    If Redis is unavailable, returns True (fallback: assume single-worker mode).
    """
    global _is_leader, _renew_thread, WORKER_ID

    # Refresh worker ID in case PID changed (e.g. after fork)
    WORKER_ID = f"worker-{os.getpid()}"

    client = _get_redis_client()
    if client is None:
        logger.info(f"No Redis available. Worker {WORKER_ID} assumes leadership (single-worker fallback).")
        _is_leader = True
        return True

    try:
        # SET NX: only set if key does not exist
        acquired = client.set(LEADER_KEY, WORKER_ID, nx=True, ex=LEADER_TTL)
        if acquired:
            _is_leader = True
            logger.info(f"Worker {WORKER_ID} elected as leader.")
            # Start renewal thread
            _stop_event.clear()
            _renew_thread = threading.Thread(target=_renew_loop, daemon=True, name="leader-renew")
            _renew_thread.start()
            return True
        else:
            current = client.get(LEADER_KEY)
            _is_leader = False
            logger.info(f"Worker {WORKER_ID} is follower. Leader is {current}.")
            return False
    except Exception as e:
        logger.warning(f"Leader election failed: {e}. Assuming leadership (fallback).")
        _is_leader = True
        return True


def release_leadership() -> None:
    """Release leadership on shutdown. Only deletes the key if this worker owns it."""
    global _is_leader

    _stop_event.set()  # Stop the renewal thread

    if not _is_leader:
        return

    client = _get_redis_client()
    if client is None:
        _is_leader = False
        return

    try:
        # Only delete if we still own the key (atomic check-and-delete via Lua)
        lua_script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """
        client.eval(lua_script, 1, LEADER_KEY, WORKER_ID)
        logger.info(f"Worker {WORKER_ID} released leadership.")
    except Exception as e:
        logger.warning(f"Leader release error: {e}")
    finally:
        _is_leader = False


def is_leader() -> bool:
    """Check if the current worker is the leader."""
    return _is_leader
