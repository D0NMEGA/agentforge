"""Billing + Templates routes (7 routes)."""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import stripe
from fastapi import APIRouter, HTTPException, Depends, Request

from config import (
    TIER_LIMITS, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_TIER_PRICES, logger,
)
from db import get_db
from helpers import get_user_id, _track_event, _log_audit, _queue_email, _branded_email

from models import (
    CheckoutRequest,
    PricingResponse, CheckoutResponse, PortalResponse,
    BillingStatusResponse, TemplateListResponse, TemplateDetailResponse,
)

from rate_limit import limiter, make_tier_limit

router = APIRouter()

def _get_queue_email():
    import main
    return main._queue_email



def _apply_tier(db, user_id: str, tier: str):
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    max_calls = limits["max_api_calls"] if limits["max_api_calls"] is not None else 999999999
    db.execute(
        "UPDATE users SET subscription_tier = ?, max_agents = ?, max_api_calls = ?, payment_failed = 0 WHERE user_id = ?",
        (tier, limits["max_agents"], max_calls, user_id),
    )

def _get_or_create_stripe_customer(db, user_id: str, email: str) -> str:
    row = db.execute("SELECT stripe_customer_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row and row["stripe_customer_id"]:
        return row["stripe_customer_id"]
    customer = stripe.Customer.create(email=email, metadata={"moltgrid_user_id": user_id})
    db.execute("UPDATE users SET stripe_customer_id = ? WHERE user_id = ?", (customer.id, user_id))
    return customer.id

def _tier_from_price(price_id: str) -> str:
    for tier, pid in STRIPE_TIER_PRICES.items():
        if pid and pid == price_id:
            return tier
    return "free"


@router.get("/v1/pricing", tags=["Billing"], response_model=PricingResponse)
@limiter.limit(make_tier_limit("billing"))
def get_pricing(request: Request):
    return {
        "tiers": {
            "free": {"name": "free", "price": 0, "max_agents": 1, "max_api_calls": 10000,
                     "features": ["Memory", "Queue", "Messaging", "Scheduling"]},
            "hobby": {"name": "hobby", "price": 5, "max_agents": 10, "max_api_calls": 1000000,
                      "features": ["Everything in Free", "Dead-letter queue", "Webhooks", "Marketplace", "Priority support"]},
            "team": {"name": "team", "price": 25, "max_agents": 50, "max_api_calls": 10000000,
                     "features": ["Everything in Hobby", "Team workspaces", "SSO (coming soon)", "SLA guarantee"]},
            "scale": {"name": "scale", "price": 99, "max_agents": 200, "max_api_calls": 999999999,
                      "features": ["Everything in Team", "Unlimited API calls", "Dedicated support", "Custom integrations"]},
        },
        "currency": "usd",
        "billing_period": "monthly",
    }

@router.post("/v1/billing/checkout", tags=["Billing"], response_model=CheckoutResponse)
@limiter.limit(make_tier_limit("billing"))
def billing_checkout(request: Request, req: CheckoutRequest, user_id: str = Depends(get_user_id)):
    if req.tier not in STRIPE_TIER_PRICES:
        raise HTTPException(400, f"Invalid tier '{req.tier}'. Must be: hobby, team, or scale")
    price_id = STRIPE_TIER_PRICES[req.tier]
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe is not configured on this server")
    if not price_id:
        raise HTTPException(503, f"Stripe price ID not configured for tier '{req.tier}'")
    with get_db() as db:
        user = db.execute("SELECT email, stripe_customer_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        customer_id = _get_or_create_stripe_customer(db, user_id, user["email"])
    session = stripe.checkout.Session.create(
        customer=customer_id, mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url="https://moltgrid.net/dashboard#/billing",
        cancel_url="https://moltgrid.net/dashboard#/billing",
        allow_promotion_codes=True,
        metadata={"moltgrid_user_id": user_id, "tier": req.tier},
    )
    _track_event("billing.checkout_started", user_id=user_id, metadata={"tier": req.tier})
    return {"checkout_url": session.url}

@router.post("/v1/billing/portal", tags=["Billing"], response_model=PortalResponse)
@limiter.limit(make_tier_limit("billing"))
def billing_portal(request: Request, user_id: str = Depends(get_user_id)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe is not configured on this server")
    with get_db() as db:
        user = db.execute("SELECT stripe_customer_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user or not user["stripe_customer_id"]:
            raise HTTPException(400, "No Stripe customer found. Subscribe first.")
    session = stripe.billing_portal.Session.create(
        customer=user["stripe_customer_id"],
        return_url="https://moltgrid.net/dashboard#/billing",
    )
    return {"portal_url": session.url}

@router.post("/v1/stripe/webhook", tags=["Billing"])
@limiter.limit(make_tier_limit("billing"))
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except stripe.error.SignatureVerificationError:
            raise HTTPException(400, "Invalid webhook signature")
        except Exception as e:
            raise HTTPException(400, f"Webhook error: {e}")
    else:
        try:
            event = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(400, "Invalid webhook payload")
    event_type = event.get("type", "") if isinstance(event, dict) else event.type
    data_obj = event.get("data", {}).get("object", {}) if isinstance(event, dict) else event.data.object
    _checkout_user_id = None; _checkout_tier = None
    with get_db() as db:
        if event_type == "checkout.session.completed":
            uid = (data_obj.get("metadata") or {}).get("moltgrid_user_id")
            tier = (data_obj.get("metadata") or {}).get("tier", "hobby")
            sub_id = data_obj.get("subscription")
            if uid:
                _apply_tier(db, uid, tier)
                db.execute("UPDATE users SET stripe_subscription_id = ? WHERE user_id = ?", (sub_id, uid))
                _track_event("billing.subscription_activated", user_id=uid, metadata={"tier": tier})
                _checkout_user_id = uid; _checkout_tier = tier
        elif event_type == "customer.subscription.updated":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                items = data_obj.get("items", {}).get("data", [])
                if items:
                    price_id = items[0].get("price", {}).get("id", "")
                    tier = _tier_from_price(price_id)
                    _apply_tier(db, user["user_id"], tier)
        elif event_type == "customer.subscription.deleted":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id, email FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                _apply_tier(db, user["user_id"], "free")
                db.execute("UPDATE users SET stripe_subscription_id = NULL WHERE user_id = ?", (user["user_id"],))
                _track_event("billing.subscription_cancelled", user_id=user["user_id"])
                cancel_body = (
                    '<p style="color:#e4e4ef;">Your MoltGrid subscription has been cancelled and your account is now on the <strong>Free</strong> tier.</p>'
                    '<p style="color:#e4e4ef;">Your agents and data are still here. You can re-subscribe anytime to unlock higher limits.</p>'
                    '<p style="margin-top:24px;text-align:center;">'
                    '<a href="https://moltgrid.net/dashboard#/billing" style="background:#ff3333;color:#fff;padding:14px 32px;text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;min-width:200px;text-align:center;">View Billing</a>'
                    '</p>'
                )
                _get_queue_email()(user["email"], "MoltGrid: subscription cancelled", _branded_email("Subscription cancelled", cancel_body), "transactional")
        elif event_type == "invoice.payment_failed":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id, email FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                db.execute("UPDATE users SET payment_failed = 1 WHERE user_id = ?", (user["user_id"],))
                logger.warning(f"Payment failed for user {user['user_id']}")
                failed_body = (
                    '<p style="color:#e4e4ef;">We were unable to process your latest MoltGrid subscription payment.</p>'
                    '<p style="color:#e4e4ef;">Please update your payment method so your agents keep running without interruption.</p>'
                    '<p style="margin-top:24px;text-align:center;">'
                    '<a href="https://moltgrid.net/dashboard#/billing" style="background:#ff3333;color:#fff;padding:14px 32px;text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;min-width:200px;text-align:center;">Update Payment</a>'
                    '</p>'
                )
                _get_queue_email()(user["email"], "MoltGrid: payment failed | action required", _branded_email("Payment failed", failed_body), "transactional")
    if _checkout_user_id:
        _log_audit("billing.tier_change", user_id=_checkout_user_id, details=_checkout_tier)
        with get_db() as email_db:
            email_user = email_db.execute("SELECT email FROM users WHERE user_id = ?", (_checkout_user_id,)).fetchone()
        if email_user:
            # Build a comparison table for the upgrade email
            tier_display = (_checkout_tier or "").capitalize()
            tier_info = TIER_LIMITS.get(_checkout_tier, TIER_LIMITS.get("free", {}))
            free_info = TIER_LIMITS.get("free", {})
            max_agents = tier_info.get("max_agents", "?")
            max_calls = tier_info.get("max_api_calls")
            max_calls_str = "Unlimited" if max_calls is None or max_calls >= 999999999 else f"{max_calls:,}"
            free_agents = free_info.get("max_agents", 1)
            free_calls = free_info.get("max_api_calls", 10000)
            free_calls_str = f"{free_calls:,}" if free_calls else "10,000"

            confirm_body = (
                f'<p style="color:#e4e4ef;">Welcome to the <strong>{tier_display}</strong> plan. '
                f'Your account has been upgraded and all new limits are active immediately.</p>'
                f'<p style="color:#e4e4ef;">Here is what changed:</p>'
                f'<table style="width:100%;border-collapse:collapse;margin:16px 0;">'
                f'<tr style="border-bottom:1px solid #2a2a3a;">'
                f'<td style="padding:10px 12px;color:#7a7a92;font-size:13px;"></td>'
                f'<td style="padding:10px 12px;color:#7a7a92;font-size:13px;font-weight:600;">Free</td>'
                f'<td style="padding:10px 12px;color:#ff3333;font-size:13px;font-weight:600;">{tier_display}</td>'
                f'</tr>'
                f'<tr style="border-bottom:1px solid #1a1a2e;">'
                f'<td style="padding:10px 12px;color:#e4e4ef;">Agents</td>'
                f'<td style="padding:10px 12px;color:#e4e4ef;">{free_agents}</td>'
                f'<td style="padding:10px 12px;color:#e4e4ef;font-weight:600;">{max_agents}</td>'
                f'</tr>'
                f'<tr style="border-bottom:1px solid #1a1a2e;">'
                f'<td style="padding:10px 12px;color:#e4e4ef;">API calls/month</td>'
                f'<td style="padding:10px 12px;color:#e4e4ef;">{free_calls_str}</td>'
                f'<td style="padding:10px 12px;color:#e4e4ef;font-weight:600;">{max_calls_str}</td>'
                f'</tr>'
                f'</table>'
                f'<p style="color:#e4e4ef;">Head to your dashboard to start using your expanded limits.</p>'
                f'<p style="margin-top:24px;text-align:center;">'
                f'<a href="https://moltgrid.net/dashboard#/billing" style="background:#ff3333;color:#fff;padding:14px 32px;'
                f'text-decoration:none;border-radius:6px;display:inline-block;font-weight:600;font-size:16px;'
                f'min-width:200px;text-align:center;">Open Dashboard</a>'
                f'</p>'
            )
            _get_queue_email()(email_user["email"], f"You're on the {tier_display} plan - here's what's unlocked", _branded_email(f"You're on the {tier_display} plan", confirm_body), "transactional")
    return {"received": True}

@router.get("/v1/billing/status", tags=["Billing"], response_model=BillingStatusResponse)
@limiter.limit(make_tier_limit("billing"))
def billing_status(request: Request, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
    result = {
        "tier": user["subscription_tier"] or "free",
        "active": (user["subscription_tier"] or "free") != "free",
        "usage_this_period": user["usage_count"],
        "payment_failed": bool(user["payment_failed"]) if user["payment_failed"] is not None else False,
        "stripe_subscription_id": user["stripe_subscription_id"],
        "current_period_end": None,
        "cancel_at_period_end": False,
    }
    if STRIPE_SECRET_KEY and user["stripe_subscription_id"]:
        try:
            sub = stripe.Subscription.retrieve(user["stripe_subscription_id"])
            result["current_period_end"] = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc).isoformat()
            result["cancel_at_period_end"] = sub.cancel_at_period_end
        except Exception:
            pass
    return result

@router.get("/v1/templates", tags=["Templates"], response_model=TemplateListResponse)
@limiter.limit(make_tier_limit("billing"))
def list_templates(request: Request):
    with get_db() as db:
        rows = db.execute("SELECT template_id, name, description, category, starter_code FROM templates ORDER BY name").fetchall()
    return {"templates": [{"template_id": r["template_id"], "name": r["name"], "description": r["description"], "category": r["category"], "starter_code": r["starter_code"]} for r in rows]}

@router.get("/v1/templates/{template_id}", tags=["Templates"], response_model=TemplateDetailResponse)
@limiter.limit(make_tier_limit("billing"))
def get_template(request: Request, template_id: str):
    with get_db() as db:
        row = db.execute("SELECT template_id, name, description, category, starter_code FROM templates WHERE template_id = ?", (template_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"template_id": row["template_id"], "name": row["name"], "description": row["description"], "category": row["category"], "starter_code": row["starter_code"]}
