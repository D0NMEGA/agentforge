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
from helpers import get_user_id, _track_event, _log_audit, _queue_email

from models import CheckoutRequest

router = APIRouter()


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


@router.get("/v1/pricing", tags=["Billing"])
def get_pricing():
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

@router.post("/v1/billing/checkout", tags=["Billing"])
def billing_checkout(req: CheckoutRequest, user_id: str = Depends(get_user_id)):
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
        success_url="https://api.moltgrid.net/dashboard#/billing",
        cancel_url="https://api.moltgrid.net/dashboard#/billing",
        metadata={"moltgrid_user_id": user_id, "tier": req.tier},
    )
    _track_event("billing.checkout_started", user_id=user_id, metadata={"tier": req.tier})
    return {"checkout_url": session.url}

@router.post("/v1/billing/portal", tags=["Billing"])
def billing_portal(user_id: str = Depends(get_user_id)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe is not configured on this server")
    with get_db() as db:
        user = db.execute("SELECT stripe_customer_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user or not user["stripe_customer_id"]:
            raise HTTPException(400, "No Stripe customer found. Subscribe first.")
    session = stripe.billing_portal.Session.create(
        customer=user["stripe_customer_id"],
        return_url="https://api.moltgrid.net/dashboard#/billing",
    )
    return {"portal_url": session.url}

@router.post("/v1/stripe/webhook", tags=["Billing"])
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
            user = db.execute("SELECT user_id FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                _apply_tier(db, user["user_id"], "free")
                db.execute("UPDATE users SET stripe_subscription_id = NULL WHERE user_id = ?", (user["user_id"],))
                _track_event("billing.subscription_cancelled", user_id=user["user_id"])
        elif event_type == "invoice.payment_failed":
            cust_id = data_obj.get("customer")
            user = db.execute("SELECT user_id FROM users WHERE stripe_customer_id = ?", (cust_id,)).fetchone()
            if user:
                db.execute("UPDATE users SET payment_failed = 1 WHERE user_id = ?", (user["user_id"],))
                logger.warning(f"Payment failed for user {user['user_id']}")
    if _checkout_user_id:
        _log_audit("billing.tier_change", user_id=_checkout_user_id, details=_checkout_tier)
        with get_db() as email_db:
            email_user = email_db.execute("SELECT email FROM users WHERE user_id = ?", (_checkout_user_id,)).fetchone()
        if email_user:
            confirm_html = (
                f"<h2>Your MoltGrid {_checkout_tier} plan is now active</h2>"
                f"<p>Thank you for your purchase. Your account has been upgraded to the <strong>{_checkout_tier}</strong> tier.</p>"
                "<p>Log in to your dashboard: <a href='https://moltgrid.net'>Open Dashboard</a></p>"
            )
            _queue_email(email_user["email"], f"MoltGrid: {_checkout_tier} plan activated", confirm_html)
    return {"received": True}

@router.get("/v1/billing/status", tags=["Billing"])
def billing_status(user_id: str = Depends(get_user_id)):
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

@router.get("/v1/templates", tags=["Templates"])
def list_templates():
    with get_db() as db:
        rows = db.execute("SELECT template_id, name, description, category, starter_code FROM templates ORDER BY name").fetchall()
    return {"templates": [{"template_id": r["template_id"], "name": r["name"], "description": r["description"], "category": r["category"], "starter_code": r["starter_code"]} for r in rows]}

@router.get("/v1/templates/{template_id}", tags=["Templates"])
def get_template(template_id: str):
    with get_db() as db:
        row = db.execute("SELECT template_id, name, description, category, starter_code FROM templates WHERE template_id = ?", (template_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail={"error": "Template not found", "code": "TEMPLATE_NOT_FOUND", "status": 404})
    return {"template_id": row["template_id"], "name": row["name"], "description": row["description"], "category": row["category"], "starter_code": row["starter_code"]}
