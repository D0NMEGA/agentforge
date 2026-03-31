"""
Shared rate limiter instance for MoltGrid.

Both main.py and routers import from here to avoid circular imports.
Rate limiting is disabled when RATE_LIMIT_ENABLED=false (e.g. in tests).

Uses Redis storage when REDIS_URL is available for cross-worker rate limit
state sharing. Falls back to in-memory storage otherwise.
"""

import os
import re
import logging
import hashlib

from slowapi import Limiter
from slowapi.util import get_remote_address

from config import TIER_ENDPOINT_LIMITS, TIER_MULTIPLIERS, FIXED_CATEGORIES, TIER_AUTH_SIGNUP_LIMITS

logger = logging.getLogger("moltgrid.rate_limit")

_rate_limit_enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() != "false"
_redis_url = os.getenv("REDIS_URL", "")

# Build storage URI for slowapi/limits
# slowapi passes storage_uri to the limits library which handles Redis natively
_storage_uri = None
if _redis_url:
    _storage_uri = _redis_url
    logger.info(f"Rate limiter using Redis storage")
else:
    logger.info("Rate limiter using in-memory storage (no REDIS_URL)")


def _get_key_func(request):
    """Smart key function: returns 'tier:identifier' for tier-aware limiting.

    - Agent API key endpoints: key by tier + API key hash
    - JWT user endpoints: key by tier + Authorization header hash
    - Unauthenticated: key by tier + IP address (tier looked up from mg_token cookie)
    """
    tier = "free"

    # Try X-API-Key first (agent endpoints)
    api_key = request.headers.get("x-api-key")
    if api_key:
        api_key_stripped = api_key.strip()
        ident = hashlib.sha256(api_key_stripped.encode()).hexdigest()[:16]
        # Look up tier from DB
        try:
            from db import get_db
            with get_db() as db:
                row = db.execute(
                    "SELECT u.subscription_tier FROM users u "
                    "JOIN agents a ON a.owner_id = u.user_id "
                    "WHERE a.api_key_hash = ?",
                    (hashlib.sha256(api_key_stripped.encode()).hexdigest(),)
                ).fetchone()
                if row:
                    tier = row["subscription_tier"] or "free"
        except Exception as e:
            logger.warning("Rate limit tier lookup failed for X-API-Key: %s", e)
        request.state.subscription_tier = tier
        return f"{tier}:{ident}"

    # Try JWT Authorization header (dashboard/user endpoints)
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        ident = hashlib.sha256(auth_header.encode()).hexdigest()[:16]
        # JWT endpoints are dashboard -- set tier from token if available
        try:
            import jwt as pyjwt
            from config import JWT_SECRET, JWT_ALGORITHM
            token = auth_header[len("Bearer "):]
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            tier = payload.get("subscription_tier", "free") or "free"
        except Exception as e:
            logger.warning("Rate limit tier lookup failed for Bearer token: %s", e)
        request.state.subscription_tier = tier
        return f"{tier}:{ident}"

    # Fallback: IP address -- check mg_token cookie for tier (covers /v1/register
    # called from a browser session where the user is logged in but not sending
    # a Bearer header explicitly)
    ip = get_remote_address(request)
    mg_token = request.cookies.get("mg_token")
    if mg_token:
        try:
            import jwt as pyjwt
            from config import JWT_SECRET, JWT_ALGORITHM
            payload = pyjwt.decode(mg_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            tier = payload.get("subscription_tier", "free") or "free"
        except Exception:
            pass
    request.state.subscription_tier = tier
    return f"{tier}:{ip}"


def make_tier_limit(endpoint_category: str):
    """Factory: returns a dynamic limit function for the given endpoint category.

    Usage: @limiter.limit(make_tier_limit("agent_read"))

    Special handling for auth_signup: uses TIER_AUTH_SIGNUP_LIMITS (explicit per-tier
    values from RATE-01) instead of TIER_MULTIPLIERS.
    """
    if endpoint_category == "auth_signup":
        # auth_signup has explicit per-tier limits that don't follow multiplier pattern
        def _auth_signup_limit(key: str) -> str:
            tier = key.split(":")[0] if ":" in key else "free"
            return TIER_AUTH_SIGNUP_LIMITS.get(tier, TIER_AUTH_SIGNUP_LIMITS["free"])
        return _auth_signup_limit

    base_limit_str = TIER_ENDPOINT_LIMITS[endpoint_category]
    match = re.match(r"^(\d+)/(\w+)$", base_limit_str)
    if not match:
        raise ValueError(f"Invalid base limit format: {base_limit_str}")
    base_num = int(match.group(1))
    window = match.group(2)

    def _dynamic_limit(key: str) -> str:
        # key format is "tier:identifier" from _get_key_func
        tier = key.split(":")[0] if ":" in key else "free"
        if endpoint_category in FIXED_CATEGORIES:
            return base_limit_str
        multiplier = TIER_MULTIPLIERS.get(tier, 1)
        return f"{int(base_num * multiplier)}/{window}"

    return _dynamic_limit


limiter = Limiter(
    key_func=_get_key_func,
    default_limits=[],
    enabled=_rate_limit_enabled,
    storage_uri=_storage_uri,
)
