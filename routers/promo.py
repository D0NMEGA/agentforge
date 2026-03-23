"""Launch promo routes -- 50-person Scale giveaway + Teams fallback."""

import secrets
import json
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel, Field

from config import TIER_LIMITS, logger
from db import get_db
from rate_limit import limiter
from helpers import get_user_id, _track_event, _log_audit, _get_client_ip

router = APIRouter()

# ── Constants ─────────────────────────────────────────────────────────────────

PROMO_SCALE_LIMIT = 50          # first N redeemers get Scale
PROMO_DURATION_DAYS = 90        # 3 months
CODE_EXPIRY_HOURS = 48          # unredeemed codes expire
CODE_LENGTH = 16                # hex chars (8 bytes = 16 hex = 2^64 combinations)


# ── Request / Response Models ─────────────────────────────────────────────────

class GenerateCodeResponse(BaseModel):
    code: str
    tier_available: str = Field(description="scale or team -- what this code is worth")
    position: int = Field(description="how many codes have been redeemed so far")
    spots_remaining: int = Field(description="Scale spots remaining (0 = all gone)")
    expires_at: str

class PromoStatusResponse(BaseModel):
    total_redeemed: int
    scale_redeemed: int
    scale_limit: int
    spots_remaining: int
    tier_available: str

class RedeemCodeRequest(BaseModel):
    code: str = Field(min_length=8, max_length=32)

class RedeemCodeResponse(BaseModel):
    success: bool
    tier: str
    duration_days: int
    message: str
    position: int


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_code() -> str:
    """Generate a cryptographically random hex code with no pattern."""
    return secrets.token_hex(CODE_LENGTH // 2).upper()


def _get_promo_stats(db) -> dict:
    """Get current promo redemption counts."""
    row = db.execute(
        "SELECT COUNT(*) as total, "
        "SUM(CASE WHEN tier = 'scale' AND redeemed_at IS NOT NULL THEN 1 ELSE 0 END) as scale_redeemed "
        "FROM promo_codes WHERE redeemed_at IS NOT NULL"
    ).fetchone()
    total = row["total"] if row["total"] else 0
    scale_redeemed = row["scale_redeemed"] if row["scale_redeemed"] else 0
    spots_remaining = max(0, PROMO_SCALE_LIMIT - scale_redeemed)
    tier_available = "scale" if spots_remaining > 0 else "team"
    return {
        "total_redeemed": total,
        "scale_redeemed": scale_redeemed,
        "scale_limit": PROMO_SCALE_LIMIT,
        "spots_remaining": spots_remaining,
        "tier_available": tier_available,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/v1/promo/status", tags=["Promo"], response_model=PromoStatusResponse)
@limiter.limit("60/minute")
def promo_status(request: Request):
    """Check how many Scale spots remain. No auth required."""
    with get_db() as db:
        return _get_promo_stats(db)


@router.post("/v1/promo/generate", tags=["Promo"], response_model=GenerateCodeResponse)
@limiter.limit("3/hour")
def generate_promo_code(request: Request):
    """Generate a single-use promo code. Rate-limited by IP to prevent farming.

    - First 50 redeemers get 3 months free MoltGrid Scale ($99/mo).
    - After 50, codes grant 3 months free MoltGrid Teams ($25/mo).
    - Codes expire in 48 hours if not redeemed.
    - One active code per IP address.
    """
    client_ip = _get_client_ip(request)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=CODE_EXPIRY_HOURS)

    with get_db() as db:
        # Check if this IP already has an active unredeemed code
        existing = db.execute(
            "SELECT code, tier, expires_at FROM promo_codes "
            "WHERE generated_ip = ? AND redeemed_at IS NULL AND expires_at > ?",
            (client_ip, now.isoformat()),
        ).fetchone()

        if existing:
            stats = _get_promo_stats(db)
            return {
                "code": existing["code"],
                "tier_available": existing["tier"],
                "position": stats["total_redeemed"],
                "spots_remaining": stats["spots_remaining"],
                "expires_at": existing["expires_at"],
            }

        # Determine which tier this code will grant
        stats = _get_promo_stats(db)
        tier = stats["tier_available"]

        code = _generate_code()

        # Ensure uniqueness (astronomically unlikely collision, but be safe)
        while db.execute("SELECT 1 FROM promo_codes WHERE code = ?", (code,)).fetchone():
            code = _generate_code()

        db.execute(
            "INSERT INTO promo_codes (code, tier, generated_ip, generated_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (code, tier, client_ip, now.isoformat(), expires_at.isoformat()),
        )

    _track_event("promo.code_generated", metadata={"tier": tier, "ip": client_ip})
    logger.info(f"Promo code generated: tier={tier}, ip={client_ip}")

    return {
        "code": code,
        "tier_available": tier,
        "position": stats["total_redeemed"],
        "spots_remaining": stats["spots_remaining"],
        "expires_at": expires_at.isoformat(),
    }


@router.post("/v1/promo/redeem", tags=["Promo"], response_model=RedeemCodeResponse)
@limiter.limit("10/minute")
def redeem_promo_code(request: Request, req: RedeemCodeRequest, user_id: str = Depends(get_user_id)):
    """Redeem a promo code. Requires authentication.

    Applies the tier upgrade for 3 months. The user's subscription_tier is set
    and a promo_expires_at timestamp is stored. After expiry, a background job
    will downgrade them back to free.
    """
    code = req.code.strip().upper()
    now = datetime.now(timezone.utc)
    expires_subscription = now + timedelta(days=PROMO_DURATION_DAYS)

    with get_db() as db:
        # Check if user already redeemed a promo code
        already = db.execute(
            "SELECT code FROM promo_codes WHERE redeemed_by = ?",
            (user_id,),
        ).fetchone()
        if already:
            raise HTTPException(400, "You have already redeemed a promo code.")

        # Look up the code
        row = db.execute(
            "SELECT id, code, tier, redeemed_at, expires_at FROM promo_codes WHERE code = ?",
            (code,),
        ).fetchone()

        if not row:
            raise HTTPException(404, "Invalid promo code.")

        if row["redeemed_at"]:
            raise HTTPException(400, "This promo code has already been used.")

        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < now:
            raise HTTPException(400, "This promo code has expired.")

        tier = row["tier"]

        # Count position (how many redeemed before this one + 1)
        count_row = db.execute(
            "SELECT COUNT(*) as cnt FROM promo_codes WHERE redeemed_at IS NOT NULL"
        ).fetchone()
        position = (count_row["cnt"] if count_row["cnt"] else 0) + 1

        # If tier was assigned as "scale" but Scale slots filled since generation,
        # downgrade to team
        if tier == "scale":
            scale_count = db.execute(
                "SELECT COUNT(*) as cnt FROM promo_codes WHERE tier = 'scale' AND redeemed_at IS NOT NULL"
            ).fetchone()
            if (scale_count["cnt"] if scale_count["cnt"] else 0) >= PROMO_SCALE_LIMIT:
                tier = "team"

        # Mark code as redeemed
        db.execute(
            "UPDATE promo_codes SET redeemed_at = ?, redeemed_by = ?, tier = ? WHERE code = ?",
            (now.isoformat(), user_id, tier, code),
        )

        # Apply tier upgrade to user
        limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
        max_calls = limits["max_api_calls"] if limits["max_api_calls"] is not None else 999999999
        db.execute(
            "UPDATE users SET subscription_tier = ?, max_agents = ?, max_api_calls = ?, "
            "promo_tier = ?, promo_expires_at = ? WHERE user_id = ?",
            (tier, limits["max_agents"], max_calls, tier, expires_subscription.isoformat(), user_id),
        )

    _track_event("promo.code_redeemed", user_id=user_id, metadata={
        "code": code, "tier": tier, "position": position,
    })
    _log_audit("promo_redeem", user_id=user_id, details=json.dumps({
        "code": code, "tier": tier, "position": position,
        "expires": expires_subscription.isoformat(),
    }))
    logger.info(f"Promo redeemed: user={user_id}, tier={tier}, position={position}")

    if tier == "scale":
        message = f"You are #{position}! You have been upgraded to MoltGrid Scale for 3 months free."
    else:
        message = f"The Scale tier is full, but you have been upgraded to MoltGrid Teams for 3 months free."

    return {
        "success": True,
        "tier": tier,
        "duration_days": PROMO_DURATION_DAYS,
        "message": message,
        "position": position,
    }
