"""
MoltGrid Configuration — all constants and environment variable loading.
Extracted from main.py to serve as the shared config module for router modules.
"""

import os
import secrets
import logging

from cryptography.fernet import Fernet

logger = logging.getLogger("moltgrid")

# ─── Config ───────────────────────────────────────────────────────────────────
MAX_MEMORY_VALUE_SIZE = 50_000  # 50KB per value
MAX_QUEUE_PAYLOAD_SIZE = 100_000  # 100KB per job
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 120  # requests per window per agent (fallback / free-tier default)
TIER_RATE_LIMITS = {
    "free":  120,
    "hobby": 300,
    "team":  600,
    "scale": 1200,
}

# Subscription tier limits
TIER_LIMITS = {
    "free":  {"max_agents": 1,   "max_api_calls": 10_000},
    "hobby": {"max_agents": 10,  "max_api_calls": 1_000_000},
    "team":  {"max_agents": 50,  "max_api_calls": 10_000_000},
    "scale": {"max_agents": 200, "max_api_calls": None},  # unlimited
}

# Admin auth: load password hash from env (set on VPS only, never in code)
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
ADMIN_SESSION_TTL = 3600 * 24  # 24 hours

# Encrypted storage: set ENCRYPTION_KEY env var to enable AES encryption at rest
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
_fernet = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None

# JWT auth for user accounts
JWT_SECRET = os.getenv("JWT_SECRET", "")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)
    logger.warning("JWT_SECRET not set — using ephemeral key (sessions will not survive restarts)")

# MoltBook service-to-service auth
MOLTBOOK_SERVICE_KEY = os.getenv("MOLTBOOK_SERVICE_KEY", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7

# Stripe billing
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_HOBBY = os.getenv("STRIPE_PRICE_HOBBY", "")
STRIPE_PRICE_TEAM = os.getenv("STRIPE_PRICE_TEAM", "")
STRIPE_PRICE_SCALE = os.getenv("STRIPE_PRICE_SCALE", "")

import stripe as _stripe_module
if STRIPE_SECRET_KEY:
    _stripe_module.api_key = STRIPE_SECRET_KEY

STRIPE_TIER_PRICES = {
    "hobby": STRIPE_PRICE_HOBBY,
    "team":  STRIPE_PRICE_TEAM,
    "scale": STRIPE_PRICE_SCALE,
}

# SMTP config
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.hostinger.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_FROM = os.getenv("SMTP_FROM", "noreply@moltgrid.net")
SMTP_USER = os.getenv("SMTP_USER", os.getenv("SMTP_FROM", "noreply@moltgrid.net"))  # login username (Gmail address)
SMTP_TO = os.getenv("SMTP_TO", "contact@moltgrid.net")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

if not SMTP_FROM or not SMTP_TO or not SMTP_PASSWORD:
    logger.warning("SMTP environment variables not set — contact form will be disabled.")

# Google OAuth
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "https://api.moltgrid.net/v1/auth/google/callback")

# Cloudflare Turnstile CAPTCHA
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "")

# IP-based auth rate limiting (brute-force protection)
AUTH_RATE_LIMIT_MAX = 10      # max attempts per window
AUTH_RATE_LIMIT_WINDOW = 300  # 5-minute window (seconds)
