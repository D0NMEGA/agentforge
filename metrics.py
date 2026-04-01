"""
MoltGrid Metrics -- Prometheus-compatible metrics endpoint.

Collects platform metrics and returns them in Prometheus text exposition format.
Cached for 15 seconds to avoid excessive database queries.
"""

import time
import logging

logger = logging.getLogger("moltgrid.metrics")

# Process start time (set at module import)
_process_start_time = time.time()

APP_VERSION = "1.0.0"


def _prom_line(name: str, value, help_text: str = "", metric_type: str = "gauge", labels: dict = None) -> str:
    """Format a single Prometheus metric line with optional HELP and TYPE."""
    lines = []
    if help_text:
        lines.append(f"# HELP {name} {help_text}")
    if metric_type:
        lines.append(f"# TYPE {name} {metric_type}")

    label_str = ""
    if labels:
        pairs = ",".join(f'{k}="{v}"' for k, v in labels.items())
        label_str = f"{{{pairs}}}"

    lines.append(f"{name}{label_str} {value}")
    return "\n".join(lines)


async def collect_metrics() -> str:
    """Collect all platform metrics and return Prometheus text format."""
    from async_db import async_db_fetchone
    from state import _ws_connections

    lines = []

    # Process info
    lines.append(_prom_line(
        "moltgrid_info", 1,
        "MoltGrid server information",
        "gauge",
        {"version": APP_VERSION}
    ))
    lines.append(_prom_line(
        "moltgrid_process_start_time_seconds",
        f"{_process_start_time:.0f}",
        "Unix timestamp when the process started",
        "gauge"
    ))
    uptime = time.time() - _process_start_time
    lines.append(_prom_line(
        "moltgrid_process_uptime_seconds",
        f"{uptime:.0f}",
        "Seconds since process start",
        "gauge"
    ))

    # Agent metrics
    try:
        agents_total = (await async_db_fetchone("SELECT COUNT(*) as c FROM agents"))["c"]
        lines.append(_prom_line(
            "moltgrid_agents_total", agents_total,
            "Total registered agents", "gauge"
        ))
    except Exception:
        pass

    try:
        agents_online = (await async_db_fetchone(
            "SELECT COUNT(*) as c FROM agents WHERE heartbeat_status='online'"
        ))["c"]
        lines.append(_prom_line(
            "moltgrid_agents_online", agents_online,
            "Currently online agents", "gauge"
        ))
    except Exception:
        pass

    # Data metrics
    try:
        memory_keys = (await async_db_fetchone("SELECT COUNT(*) as c FROM memory"))["c"]
        lines.append(_prom_line(
            "moltgrid_memory_keys_total", memory_keys,
            "Total memory keys stored", "gauge"
        ))
    except Exception:
        pass

    try:
        queue_jobs = (await async_db_fetchone("SELECT COUNT(*) as c FROM queue"))["c"]
        lines.append(_prom_line(
            "moltgrid_queue_jobs_total", queue_jobs,
            "Total queue jobs", "gauge"
        ))
    except Exception:
        pass

    try:
        messages = (await async_db_fetchone("SELECT COUNT(*) as c FROM relay"))["c"]
        lines.append(_prom_line(
            "moltgrid_messages_total", messages,
            "Total messages relayed", "gauge"
        ))
    except Exception:
        pass

    try:
        webhooks = (await async_db_fetchone(
            "SELECT COUNT(*) as c FROM webhooks WHERE active=1"
        ))["c"]
        lines.append(_prom_line(
            "moltgrid_webhooks_active", webhooks,
            "Active webhook subscriptions", "gauge"
        ))
    except Exception:
        pass

    try:
        schedules = (await async_db_fetchone(
            "SELECT COUNT(*) as c FROM scheduled_tasks WHERE enabled=1"
        ))["c"]
        lines.append(_prom_line(
            "moltgrid_schedules_active", schedules,
            "Active scheduled tasks", "gauge"
        ))
    except Exception:
        pass

    # HTTP request totals (sum of all agent request_count)
    try:
        total_requests = (await async_db_fetchone(
            "SELECT COALESCE(SUM(request_count), 0) as c FROM agents"
        ))["c"]
        lines.append(_prom_line(
            "moltgrid_http_requests_total", total_requests,
            "Total HTTP requests processed (sum of agent request counts)", "counter"
        ))
    except Exception:
        pass

    # WebSocket connections
    try:
        ws_count = sum(len(s) for s in _ws_connections.values())
        lines.append(_prom_line(
            "moltgrid_websocket_connections_active", ws_count,
            "Active WebSocket connections", "gauge"
        ))
    except Exception:
        pass

    # Uptime ratio (30 day)
    try:
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        total_checks = (await async_db_fetchone(
            "SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ?", (cutoff,)
        ))["c"]
        up_checks = (await async_db_fetchone(
            "SELECT COUNT(*) as c FROM uptime_checks WHERE checked_at >= ? AND status='up'", (cutoff,)
        ))["c"]
        ratio = up_checks / total_checks if total_checks > 0 else 1.0
        lines.append(_prom_line(
            "moltgrid_uptime_ratio_30d", f"{ratio:.6f}",
            "Uptime ratio over 30 days (0.0-1.0)", "gauge"
        ))
    except Exception:
        pass

    # Marketplace
    try:
        marketplace = (await async_db_fetchone("SELECT COUNT(*) as c FROM marketplace"))["c"]
        lines.append(_prom_line(
            "moltgrid_marketplace_tasks_total", marketplace,
            "Total marketplace tasks", "gauge"
        ))
    except Exception:
        pass

    # User count
    try:
        users = (await async_db_fetchone("SELECT COUNT(*) as c FROM users"))["c"]
        lines.append(_prom_line(
            "moltgrid_users_total", users,
            "Total registered users", "gauge"
        ))
    except Exception:
        pass

    # Leader status
    try:
        from leader import is_leader
        lines.append(_prom_line(
            "moltgrid_worker_is_leader", 1 if is_leader() else 0,
            "Whether this worker is the leader (runs background threads)", "gauge"
        ))
    except Exception:
        pass

    lines.append("")  # trailing newline
    return "\n".join(lines)
