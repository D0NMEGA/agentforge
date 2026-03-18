"""
MoltGrid Pydantic Models — all request/response BaseModel subclasses.
Extracted from main.py to serve as the shared models module for router modules.
"""

import re
from typing import Optional, List, Dict, Union, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, validator

from config import MAX_MEMORY_VALUE_SIZE, MAX_QUEUE_PAYLOAD_SIZE


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH MODELS
# ═══════════════════════════════════════════════════════════════════════════════

def _validate_password_strength(v):
    """Shared password strength validator for signup, reset, and change flows."""
    if not re.search(r'[A-Z]', v):
        raise ValueError('Password must contain at least one uppercase letter')
    if not re.search(r'[0-9]', v):
        raise ValueError('Password must contain at least one number')
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', v):
        raise ValueError('Password must contain at least one special character')
    if not re.match(r'^[\x20-\x7E]+$', v):
        raise ValueError('Password must contain only standard ASCII characters')
    return v

class SignupRequest(BaseModel):
    email: str = Field(..., max_length=256)
    password: str = Field(..., min_length=8, max_length=128)
    display_name: Optional[str] = Field(None, max_length=30)
    promo_optin: bool = False
    turnstile_token: Optional[str] = None

    @validator('password')
    def password_strength(cls, v):
        return _validate_password_strength(v)

class LoginRequest(BaseModel):
    email: str = Field(..., max_length=256)
    password: str = Field(..., max_length=128)
    totp_code: Optional[str] = Field(None, max_length=16)
    turnstile_token: Optional[str] = None

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., max_length=256)

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @validator('new_password')
    def password_strength(cls, v):
        return _validate_password_strength(v)

class TOTP2FAVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

class TOTP2FADisableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=16)


# ═══════════════════════════════════════════════════════════════════════════════
# USER / DASHBOARD MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class NotificationPreferencesRequest(BaseModel):
    welcome: Optional[bool] = None
    quota_alerts: Optional[bool] = None
    weekly_digest: Optional[bool] = None

class MemoryVisibilityRequest(BaseModel):
    namespace: str = Field("default", max_length=64)
    key: Optional[str] = Field(None, max_length=256)
    visibility: str = Field(..., description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)

class MemoryBulkVisibilityRequest(BaseModel):
    entries: List[dict]
    visibility: str = Field(..., description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)

class TransferRequest(BaseModel):
    to_email: str = Field(..., max_length=256)

class UserScheduleRequest(BaseModel):
    cron_expr: str = Field(..., max_length=128)
    queue_name: str = Field("default", max_length=64)
    payload: str = Field("{}", max_length=100_000)
    priority: int = Field(0, ge=0, le=10)

class UserScheduleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    cron_expr: Optional[str] = Field(None, max_length=128)


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class IntegrationCreateRequest(BaseModel):
    platform: str = Field(..., max_length=64, description="Platform name, e.g. 'moltbook', 'slack'")
    config: Optional[dict] = Field(None, description="Platform-specific config JSON")
    status: str = Field("active", max_length=32)

class IntegrationStatusItem(BaseModel):
    integration_id: str
    agent_id: str
    platform: str
    status: str
    last_sync_at: str
    event_count: int

class IntegrationStatusResponse(BaseModel):
    integrations: List[IntegrationStatusItem]


# ═══════════════════════════════════════════════════════════════════════════════
# WEBHOOK MODELS
# ═══════════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════════
# BILLING MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class CheckoutRequest(BaseModel):
    tier: str = Field(..., description="Subscription tier: hobby, team, or scale")


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, description="Display name for your agent")
    template_id: Optional[str] = Field(None, max_length=64, description="Optional template ID to pre-load starter code into agent memory")

class RegisterResponse(BaseModel):
    agent_id: str
    api_key: str
    message: str


# ═══════════════════════════════════════════════════════════════════════════════
# MOLTBOOK MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class MoltBookEventRequest(BaseModel):
    event_type: str = Field(..., max_length=64, description="e.g. 'post', 'reply', 'upvote'")
    moltbook_url: Optional[str] = Field(None, max_length=512, description="Deep link to the MoltBook post")
    metadata: Optional[dict] = Field(None, description="Additional event metadata")

class MoltBookRegisterRequest(BaseModel):
    moltbook_user_id: str = Field(..., max_length=128)
    display_name: str = Field(..., max_length=64)


# ═══════════════════════════════════════════════════════════════════════════════
# ONBOARDING MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class OnboardingResponse(BaseModel):
    steps: List[dict]
    progress: int
    total: int
    reward: str


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT HEARTBEAT / LIVENESS MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class HeartbeatRequest(BaseModel):
    status: str = Field("online", description="Agent status: online, busy, idle")
    metadata: Optional[dict] = Field(None, description="Optional metadata blob (max 4KB)")


# ═══════════════════════════════════════════════════════════════════════════════
# MEMORY MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class MemorySetRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    namespace: str = Field("default", max_length=64)
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000, description="Auto-expire after N seconds (60s-30d)")
    visibility: str = Field("private", description="private | public | shared")
    shared_agents: List[str] = Field(default_factory=list)

class MemoryGetResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    key: str
    value: str
    namespace: str
    updated_at: str
    expires_at: Optional[str]

class MemoryKeyEntry(BaseModel):
    model_config = ConfigDict(extra='ignore')
    key: str
    size_bytes: int
    updated_at: str
    expires_at: Optional[str]

class MemoryListResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    namespace: str
    keys: List[MemoryKeyEntry]
    count: int


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH / STATS MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class HealthStatsResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    registered_agents: int
    public_agents: int
    total_jobs: int
    memory_keys_stored: int
    shared_memory_keys: int
    messages_relayed: int
    active_webhooks: int
    active_schedules: int
    websocket_connections: int

class HealthResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    status: str
    version: str
    stats: HealthStatsResponse
    timestamp: str


# ═══════════════════════════════════════════════════════════════════════════════
# QUEUE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class QueueJobEntry(BaseModel):
    model_config = ConfigDict(extra='ignore')
    job_id: str
    status: str
    priority: int
    created_at: str
    completed_at: Optional[str]

class QueueListResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    queue_name: str
    jobs: List[QueueJobEntry]
    count: int


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ScheduleEntry(BaseModel):
    model_config = ConfigDict(extra='ignore')
    task_id: str
    cron_expr: str
    queue_name: str
    priority: int
    enabled: bool
    next_run_at: Optional[str]
    last_run_at: Optional[str]
    run_count: Optional[int]
    created_at: str

class ScheduleListResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    schedules: List[ScheduleEntry]
    count: int

class QueueSubmitRequest(BaseModel):
    payload: Union[str, dict] = Field(..., description="Job payload (string or JSON object)")
    queue_name: str = Field("default", max_length=64)
    priority: int = Field(0, ge=0, le=10, description="Higher = processed first")
    max_attempts: int = Field(1, ge=1, le=10, description="Max retry attempts before dead-lettering")
    retry_delay_seconds: int = Field(0, ge=0, le=3600, description="Seconds to wait before retrying")

class QueueJobResponse(BaseModel):
    job_id: str
    status: str
    queue_name: str
    priority: int
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[str]

class QueueFailRequest(BaseModel):
    reason: str = Field("", max_length=1000, description="Why the job failed")


# ═══════════════════════════════════════════════════════════════════════════════
# RELAY MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class RelayMessage(BaseModel):
    to_agent: str = Field(..., description="Recipient agent_id")
    channel: str = Field("direct", max_length=64)
    payload: str = Field(..., min_length=1, max_length=10_000)


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT UTILITY MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class TextProcessRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    operation: str = Field(..., description="One of: word_count, char_count, extract_urls, extract_emails, tokenize_sentences, deduplicate_lines, hash_sha256, base64_encode, base64_decode")


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULED TASK MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ScheduledTaskRequest(BaseModel):
    cron_expr: str = Field(..., max_length=128, description="Cron expression (5-field: min hour dom mon dow)")
    queue_name: str = Field("default", max_length=64)
    payload: str = Field(..., min_length=1, max_length=MAX_QUEUE_PAYLOAD_SIZE)
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


# ═══════════════════════════════════════════════════════════════════════════════
# VECTOR MEMORY MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class VectorUpsertRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=256)
    text: str = Field(..., max_length=10000, description="Text to embed")
    namespace: str = Field("default", max_length=64)
    metadata: Optional[dict] = Field(None, description="Optional metadata (stored as JSON)")
    importance: float = Field(0.5, ge=0.0, le=1.0, description="Importance weight (0.0-1.0) for composite scoring")

class VectorSearchRequest(BaseModel):
    query: str = Field(..., max_length=10000, description="Search query to embed")
    namespace: str = Field("default", max_length=64)
    limit: int = Field(5, ge=1, le=100, description="Number of results to return")
    min_similarity: float = Field(0.0, ge=0.0, le=1.0, description="Minimum cosine similarity threshold")
    scoring: str = Field("cosine", description="Scoring mode: 'cosine' (similarity only) or 'composite' (0.4*recency + 0.2*importance + 0.4*cosine)")


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED MEMORY MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class SharedMemorySetRequest(BaseModel):
    namespace: str = Field(..., max_length=64, description="Public namespace name")
    key: str = Field(..., min_length=1, max_length=256)
    value: str = Field(..., max_length=MAX_MEMORY_VALUE_SIZE)
    description: Optional[str] = Field(None, max_length=256, description="Human-readable description of this entry")
    ttl_seconds: Optional[int] = Field(None, ge=60, le=2592000)


# ═══════════════════════════════════════════════════════════════════════════════
# DIRECTORY MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class DirectoryUpdateRequest(BaseModel):
    description: Optional[str] = Field(None, max_length=512, description="What your agent does")
    capabilities: Optional[List[str]] = Field(None, max_length=20, description="List of capabilities")
    skills: Optional[List[str]] = Field(None, max_length=20, description="Technical skills (e.g. python, data_analysis)")
    interests: Optional[List[str]] = Field(None, max_length=20, description="Topics/domains of interest (e.g. AI, finance)")
    public: bool = Field(False, description="Whether to list in the public directory")


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS / COLLABORATION MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class StatusUpdateRequest(BaseModel):
    available: Optional[bool] = Field(None, description="Whether agent is available for work")
    looking_for: Optional[List[str]] = Field(None, description="Capabilities this agent is seeking")
    busy_until: Optional[str] = Field(None, description="ISO timestamp when agent becomes free")

class CollaborationRequest(BaseModel):
    partner_agent: str = Field(..., description="Agent ID of the collaboration partner")
    task_type: Optional[str] = Field(None, max_length=128)
    outcome: str = Field(..., description="success, failure, or partial")
    rating: int = Field(..., ge=1, le=5, description="Rating 1-5 for the partner")


# ═══════════════════════════════════════════════════════════════════════════════
# MARKETPLACE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class MarketplaceCreateRequest(BaseModel):
    title: str = Field(..., max_length=256)
    description: Optional[str] = Field(None, max_length=5000)
    category: Optional[str] = Field(None, max_length=64)
    requirements: Optional[List[str]] = Field(None, description="Required capabilities")
    reward_credits: int = Field(0, ge=0, le=10000)
    priority: int = Field(0, ge=0, le=10)
    estimated_effort: Optional[str] = Field(None, max_length=128)
    tags: Optional[List[str]] = Field(None)
    deadline: Optional[str] = Field(None, description="ISO timestamp deadline")

class MarketplaceDeliverRequest(BaseModel):
    result: str = Field(..., max_length=50000)

class MarketplaceReviewRequest(BaseModel):
    accept: bool = Field(...)
    rating: Optional[int] = Field(None, ge=1, le=5)


# ═══════════════════════════════════════════════════════════════════════════════
# COORDINATION / SCENARIO MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ScenarioCreateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=128)
    pattern: str = Field(..., description="One of: leader_election, consensus, load_balancing, pub_sub_fanout, task_auction")
    agent_count: int = Field(..., ge=2, le=20)
    timeout_seconds: int = Field(60, ge=5, le=300)
    success_criteria: Optional[dict] = Field(None)


# ═══════════════════════════════════════════════════════════════════════════════
# PUBSUB MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class PubSubSubscribeRequest(BaseModel):
    channel: str = Field(..., min_length=1, max_length=128, description="Channel name to subscribe to")

class PubSubPublishRequest(BaseModel):
    channel: str = Field(..., min_length=1, max_length=128, description="Channel to publish to")
    payload: str = Field(..., min_length=1, max_length=50_000, description="Message payload")


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class AdminLoginRequest(BaseModel):
    password: str

class AdminEmailRequest(BaseModel):
    from_category: str = Field("transactional", description="transactional|support|marketing|founder")
    to_email: str = Field(..., max_length=256)
    subject: str = Field(..., max_length=256)
    title: str = Field(..., max_length=256)
    body_html: str = Field(...)
    send: bool = Field(False, description="If true, actually send. If false, just preview.")


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class SessionCreateRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=256)
    max_tokens: int = Field(128000, ge=1000, le=1000000)

class SessionAppendRequest(BaseModel):
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str = Field(..., min_length=1, max_length=1000000)


# ═══════════════════════════════════════════════════════════════════════════════
# CONTACT MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ContactForm(BaseModel):
    name: str = ""
    email: str
    subject: str = ""
    message: str
    turnstile_token: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# ORG MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class OrgCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    slug: Optional[str] = Field(None, max_length=64, pattern="^[a-z0-9-]+$")

class OrgInviteRequest(BaseModel):
    user_id: str = Field(..., max_length=64)
    role: str = Field("member", pattern="^(owner|admin|member)$")

class OrgRoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(owner|admin|member)$")


# ═══════════════════════════════════════════════════════════════════════════════
# EVENT STREAM MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class EventAckRequest(BaseModel):
    event_ids: List[str]

class ObstacleCourseSubmitRequest(BaseModel):
    stages_completed: List[int]
    proof: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE MODELS — Pydantic response_model declarations for OpenAPI spec
# ═══════════════════════════════════════════════════════════════════════════════

# --- Shared ---

class MessageResponse(BaseModel):
    message: str

class StatusResponse(BaseModel):
    status: str


# --- Auth Response Models ---

class AuthSignupResponse(BaseModel):
    user_id: str
    token: str
    message: str

class AuthLoginResponse(BaseModel):
    user_id: Optional[str] = None
    token: Optional[str] = None
    requires_2fa: Optional[bool] = None
    temp_token: Optional[str] = None

class AuthMeResponse(BaseModel):
    user_id: str
    email: str
    display_name: Optional[str]
    subscription_tier: Optional[str]
    max_agents: int
    max_api_calls: int
    usage_count: int
    agent_count: int
    created_at: str
    last_login: Optional[str]

class AuthRefreshResponse(BaseModel):
    user_id: str
    token: str

class AuthLogoutResponse(BaseModel):
    status: str

class Auth2FASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_url: str

class Auth2FAVerifyResponse(BaseModel):
    enabled: bool
    recovery_codes: List[str]

class Auth2FADisableResponse(BaseModel):
    disabled: bool

class NotificationPreferencesUpdateResponse(BaseModel):
    status: str
    preferences: dict

class NotificationPreferencesGetResponse(BaseModel):
    preferences: dict

class RotateKeyResponse(BaseModel):
    status: str
    agent_id: str
    api_key: str
    message: str


# --- Billing Response Models ---

class TierDetail(BaseModel):
    name: str
    price: int
    max_agents: int
    max_api_calls: int
    features: List[str]

class PricingResponse(BaseModel):
    tiers: Dict[str, TierDetail]
    currency: str
    billing_period: str

class CheckoutResponse(BaseModel):
    checkout_url: str

class PortalResponse(BaseModel):
    portal_url: str

class BillingStatusResponse(BaseModel):
    tier: str
    active: bool
    usage_this_period: int
    payment_failed: bool
    stripe_subscription_id: Optional[str]
    current_period_end: Optional[str]
    cancel_at_period_end: bool

class TemplateItem(BaseModel):
    template_id: str
    name: str
    description: Optional[str]
    category: Optional[str]
    starter_code: Optional[str]

class TemplateListResponse(BaseModel):
    templates: List[TemplateItem]

class TemplateDetailResponse(BaseModel):
    template_id: str
    name: str
    description: Optional[str]
    category: Optional[str]
    starter_code: Optional[str]


# --- Relay Response Models ---

class RelaySendResponse(BaseModel):
    message_id: str
    status: str

class RelayMessageItem(BaseModel):
    message_id: str
    from_agent: str
    channel: str
    payload: str
    created_at: str
    read_at: Optional[str] = None

class RelayInboxResponse(BaseModel):
    channel: str
    messages: List[RelayMessageItem]
    count: int

class RelayMarkReadResponse(BaseModel):
    message_id: str
    status: str


# --- Webhook Response Models ---

class WebhookListItem(BaseModel):
    webhook_id: str
    url: str
    event_types: List[str]
    active: bool
    created_at: str

class WebhookListResponse(BaseModel):
    webhooks: List[WebhookListItem]
    count: int

class WebhookDeleteResponse(BaseModel):
    status: str
    webhook_id: str

class WebhookTestResponse(BaseModel):
    delivery_id: str
    status: str
    error: Optional[str]


# --- Queue Response Models ---

class QueueSubmitResponse(BaseModel):
    job_id: str
    status: str
    queue_name: str
    max_attempts: int

class DeadLetterJobItem(BaseModel):
    model_config = ConfigDict(extra='ignore')
    job_id: str
    queue_name: str
    priority: int
    attempt_count: Optional[int]
    max_attempts: Optional[int]
    fail_reason: Optional[str]
    created_at: str
    failed_at: Optional[str]
    moved_at: Optional[str]

class DeadLetterListResponse(BaseModel):
    jobs: List[DeadLetterJobItem]
    count: int

class QueueClaimResponse(BaseModel):
    job_id: Optional[str] = None
    payload: Optional[str] = None
    priority: Optional[int] = None
    status: Optional[str] = None
    queue_name: Optional[str] = None

class QueueCompleteResponse(BaseModel):
    job_id: str
    status: str

class QueueFailResponse(BaseModel):
    job_id: str
    status: str
    attempts: int
    max_attempts: int
    next_retry_at: Optional[str] = None

class QueueReplayResponse(BaseModel):
    job_id: str
    status: str
    replayed_at: str


# --- Schedule Response Models ---

class ScheduleGetResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')
    task_id: str
    agent_id: str
    cron_expr: str
    queue_name: str
    payload: str
    priority: int
    enabled: bool
    next_run_at: Optional[str]
    last_run_at: Optional[str]
    run_count: Optional[int]
    created_at: str

class ScheduleToggleResponse(BaseModel):
    task_id: str
    enabled: bool

class ScheduleDeleteResponse(BaseModel):
    status: str
    task_id: str


# --- Events Response Models ---

class EventItem(BaseModel):
    event_id: str
    event_type: str
    payload: dict
    created_at: str

class EventAckResponse(BaseModel):
    acknowledged: int


# --- PubSub Response Models ---

class PubSubSubscribeResponse(BaseModel):
    channel: str
    status: str
    subscribed_at: Optional[str] = None

class PubSubUnsubscribeResponse(BaseModel):
    channel: str
    status: str

class PubSubSubscriptionItem(BaseModel):
    channel: str
    subscribed_at: str

class PubSubSubscriptionsResponse(BaseModel):
    subscriptions: List[PubSubSubscriptionItem]
    count: int

class PubSubPublishResponse(BaseModel):
    message_id: str
    channel: str
    subscribers_notified: int
    created_at: str

class PubSubChannelItem(BaseModel):
    channel: str
    subscriber_count: int

class PubSubChannelsResponse(BaseModel):
    channels: List[PubSubChannelItem]
    count: int


# --- Memory Response Models ---

class MemoryCrossAgentReadResponse(BaseModel):
    key: str
    value: str
    namespace: str
    visibility: str
    updated_at: str
    expires_at: Optional[str]

class MemoryVisibilityResponse(BaseModel):
    status: str
    key: str
    visibility: str

class MemorySetResponse(BaseModel):
    status: str
    key: str
    namespace: str
    visibility: str

class MemoryDeleteResponse(BaseModel):
    status: str
    key: str


# ═══════════════════════════════════════════════════════════════════════════════
# DIRECTORY RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class HeartbeatResponse(BaseModel):
    agent_id: str
    status: str
    heartbeat_at: str

class DirectoryUpdateResponse(BaseModel):
    status: str
    agent_id: str
    public: bool

class DirectoryAgentItem(BaseModel):
    model_config = ConfigDict(extra='allow')
    agent_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    available: bool = True

class DirectoryListResponse(BaseModel):
    agents: List[DirectoryAgentItem]
    count: int

class LeaderboardEntry(BaseModel):
    rank: int
    agent_id: str
    name: Optional[str] = None
    reputation: float = 0.0
    credits: int = 0
    tasks_completed: int = 0

class LeaderboardResponse(BaseModel):
    leaderboard: List[LeaderboardEntry]
    total_agents: int
    sort_by: str

class CapabilityItem(BaseModel):
    name: str
    count: int

class DirectoryStatsResponse(BaseModel):
    total_agents: int
    online_agents: int
    total_capabilities: List[str]
    top_capabilities: List[CapabilityItem]
    total_marketplace_tasks: int
    total_credits_distributed: int

class DirectorySearchResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    agents: List[DirectoryAgentItem]
    count: int

class DirectoryStatusUpdateResponse(BaseModel):
    status: str
    agent_id: str

class CollaborationResponse(BaseModel):
    collaboration_id: str
    agent_id: str
    partner_agent: str
    task_type: Optional[str] = None
    outcome: str
    rating: int
    partner_new_reputation: float
    created_at: str

class DirectoryMatchResponse(BaseModel):
    matches: List[DirectoryAgentItem]
    count: int
    need: str

class NetworkNode(BaseModel):
    model_config = ConfigDict(extra='allow')
    id: str
    name: Optional[str] = None
    status: str = "unknown"
    reputation: float = 0.0

class NetworkEdge(BaseModel):
    model_config = ConfigDict(extra='allow')
    source: str
    target: str
    type: str
    weight: int

class NetworkStats(BaseModel):
    total_agents: int
    online_agents: int
    total_edges: int

class DirectoryNetworkResponse(BaseModel):
    nodes: List[NetworkNode]
    edges: List[NetworkEdge]
    stats: NetworkStats

class DirectoryProfileResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    agent_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    reputation: float = 0.0
    reputation_count: int = 0
    credits: int = 0
    tasks_completed: int = 0
    uptime_pct: float = 99.0
    member_since: Optional[str] = None
    heartbeat_status: str = "unknown"
    featured: bool = False
    verified: bool = False
    recent_marketplace_activity: List[dict] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# MARKETPLACE RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class MarketplaceCreateResponse(BaseModel):
    task_id: str
    status: str
    created_at: str
    credits_deducted: int

class MarketplaceTaskItem(BaseModel):
    model_config = ConfigDict(extra='allow')
    task_id: str
    title: str
    status: str

class MarketplaceBrowseResponse(BaseModel):
    tasks: List[MarketplaceTaskItem]
    count: int

class MarketplaceClaimResponse(BaseModel):
    task_id: str
    status: str
    claimed_by: str

class MarketplaceDeliverResponse(BaseModel):
    task_id: str
    status: str

class MarketplaceReviewResponse(BaseModel):
    task_id: str
    status: str
    credits_awarded: int = 0

class ScenarioCreateResponse(BaseModel):
    scenario_id: str
    status: str
    pattern: str
    created_at: str

class ScenarioListResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    scenarios: List[dict]
    count: int

class ScenarioRunResponse(BaseModel):
    scenario_id: str
    status: str
    results: dict
    completed_at: str


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class SessionCreateResponse(BaseModel):
    session_id: str
    title: str
    created_at: str

class SessionListItem(BaseModel):
    model_config = ConfigDict(extra='ignore')
    session_id: str
    title: Optional[str] = None
    token_count: int = 0
    max_tokens: int = 128000
    created_at: str
    updated_at: str

class SessionListResponse(BaseModel):
    sessions: List[SessionListItem]

class SessionAppendResponse(BaseModel):
    status: str
    message_count: int
    token_count: int
    summarized: bool

class SessionSummarizeResponse(BaseModel):
    status: str
    original_message_count: int
    new_message_count: int
    token_count: int

class SessionDeleteResponse(BaseModel):
    status: str
    session_id: str


# ═══════════════════════════════════════════════════════════════════════════════
# VECTOR RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class VectorUpsertResponse(BaseModel):
    key: str
    namespace: str
    dimensions: int
    status: str

class VectorSearchResultItem(BaseModel):
    key: str
    text: str
    score: float
    similarity: float
    metadata: Optional[dict] = None

class VectorSearchResponse(BaseModel):
    results: List[VectorSearchResultItem]
    count: int
    scoring: str

class VectorGetResponse(BaseModel):
    key: str
    text: str
    metadata: Optional[dict] = None
    created_at: str
    updated_at: str

class VectorDeleteResponse(BaseModel):
    status: str
    key: str
    namespace: str

class VectorKeyItem(BaseModel):
    key: str
    created_at: str

class VectorListResponse(BaseModel):
    keys: List[VectorKeyItem]
    count: int
    namespace: str

class SharedMemorySetResponse(BaseModel):
    status: str
    namespace: str
    key: str

class SharedMemoryEntryItem(BaseModel):
    model_config = ConfigDict(extra='allow')
    owner_agent: str
    key: str
    description: Optional[str] = None
    size_bytes: int = 0
    updated_at: str
    expires_at: Optional[str] = None

class SharedMemoryListResponse(BaseModel):
    namespace: str
    entries: List[SharedMemoryEntryItem]
    count: int

class SharedMemoryDeleteResponse(BaseModel):
    status: str
    namespace: str
    key: str

class SharedMemoryNamespaceItem(BaseModel):
    namespace: str
    entry_count: int
    contributor_count: int

class SharedMemoryNamespacesResponse(BaseModel):
    namespaces: List[SharedMemoryNamespaceItem]
    count: int


# ═══════════════════════════════════════════════════════════════════════════════
# ORG RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class OrgCreateResponse(BaseModel):
    org_id: str
    name: str
    slug: Optional[str] = None
    owner_user_id: str
    created_at: str
    role: str

class OrgListItem(BaseModel):
    model_config = ConfigDict(extra='ignore')
    org_id: str
    name: str
    slug: Optional[str] = None
    owner_user_id: str
    created_at: str
    role: str

class OrgListResponse(BaseModel):
    orgs: List[OrgListItem]

class OrgMemberItem(BaseModel):
    user_id: str
    role: str
    joined_at: str

class OrgDetailResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    org_id: str
    name: str
    slug: Optional[str] = None
    owner_user_id: str
    created_at: str
    members: List[OrgMemberItem]

class OrgInviteResponse(BaseModel):
    org_id: str
    user_id: str
    role: str
    joined_at: str

class OrgMembersResponse(BaseModel):
    org_id: str
    members: List[OrgMemberItem]

class OrgRemoveResponse(BaseModel):
    removed: bool

class OrgRoleChangeResponse(BaseModel):
    org_id: str
    user_id: str
    role: str

class OrgSwitchResponse(BaseModel):
    active_org_id: str
    org_name: str


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class IntegrationCreateResponse(BaseModel):
    id: str
    agent_id: str
    platform: str
    status: str
    created_at: str

class IntegrationItem(BaseModel):
    model_config = ConfigDict(extra='allow')
    id: str
    platform: str
    config: Optional[dict] = None
    status: str
    created_at: str

class IntegrationListResponse(BaseModel):
    agent_id: str
    integrations: List[IntegrationItem]

class MoltBookEventResponse(BaseModel):
    id: str
    event_name: str
    source: str
    agent_id: str
    created_at: str

class MoltBookRegisterResponse(BaseModel):
    agent_id: str
    api_key: str
    display_name: str

class MoltBookFeedItem(BaseModel):
    model_config = ConfigDict(extra='allow')
    id: str
    type: str
    content: str
    timestamp: str
    moltbook_url: Optional[str] = None
    agent_id: str

class MoltBookFeedResponse(BaseModel):
    feed: List[MoltBookFeedItem]


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ContactSubmitResponse(BaseModel):
    status: str
    id: str

class SLAWindowItem(BaseModel):
    uptime_pct: float
    total_checks: int
    successful_checks: int
    avg_response_ms: float

class SLAResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    sla_target: str
    current_status: str
    windows: dict
    last_check: Optional[dict] = None
    check_interval_seconds: int
    encryption_enabled: bool

class AgentStatsResponse(BaseModel):
    model_config = ConfigDict(extra='allow')
    agent_id: str
    name: Optional[str] = None
    created_at: str
    total_requests: int
    memory_keys: int
    jobs_submitted: int
    messages_sent: int
    messages_received: int
    active_webhooks: int
    active_schedules: int
    shared_memory_keys: int
    credits: int = 0
    reputation: float = 0.0
    collaborations_given: int = 0
    collaborations_received: int = 0
    marketplace_tasks_created: int = 0
    marketplace_tasks_completed: int = 0

class TextProcessResponse(BaseModel):
    operation: str
    result: dict
    agent_id: str

class ObstacleSubmitResponse(BaseModel):
    submission_id: str
    score: int
    stages_completed: List[int]
    feedback: str

class ObstacleLeaderboardItem(BaseModel):
    submission_id: str
    agent_id: str
    display_name: str
    score: int
    stages_completed: List[int]
    submitted_at: str
    feedback: str

class ObstacleMyResultResponse(BaseModel):
    submission_id: str
    stages_completed: List[int]
    score: int
    submitted_at: str
    feedback: str

class RootResponse(BaseModel):
    service: str
    version: str
    docs: str
    description: str
    endpoints: dict


# ═══════════════════════════════════════════════════════════════════════════════
# EVENTS RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class EventStreamItem(BaseModel):
    event_id: str
    event_type: str
    payload: dict
    created_at: str

class EventPollResponse(BaseModel):
    """Wrapper for event poll list — not used as response_model since endpoint returns bare list."""
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# TIERED MEMORY MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class TieredStoreEventRequest(BaseModel):
    session_id: str = Field(..., max_length=64)
    data: Any = Field(..., description="Event content -- string or any JSON-serializable dict")
    role: str = Field("user", pattern="^(user|assistant|system)$")
    persist: bool = Field(False, description="If True, also write to mid-term notes (Tier 2)")
    note_key: Optional[str] = Field(None, max_length=256, description="Key for mid-term note (required if persist=True)")

class TieredStoreEventResponse(BaseModel):
    status: str
    session_id: str
    message_count: int
    token_count: int
    persisted: bool
    note_key: Optional[str] = None

class TieredRecallRequest(BaseModel):
    query: str = Field(..., max_length=10000)
    k: int = Field(5, ge=1, le=50, description="Number of results to return")
    namespace: str = Field("default", max_length=64, description="Namespace to search in Tier 2 and 3")
    tiers: List[Literal["mid", "long"]] = Field(["mid", "long"], description="Which tiers to search")
    min_similarity: float = Field(0.0, ge=0.0, le=1.0)

class TieredRecallResultItem(BaseModel):
    tier: str
    key: str
    text: str
    score: float
    metadata: Optional[dict] = None

class TieredRecallResponse(BaseModel):
    results: List[TieredRecallResultItem]
    count: int
    query: str

class TieredSummarizeResponse(BaseModel):
    status: str
    session_id: str
    original_message_count: int
    new_message_count: int
    token_count: int
    summary_text: str
    promoted: bool
    vector_key: str
    vector_namespace: str
