#!/usr/bin/env python3
"""
MoltGrid Batch Onboarding Tool

Onboards multiple agents across multiple accounts using a JSON config file.
Supports parallel execution via asyncio and an optional obstacle course.

Usage:
    python batch_onboard.py config.json
    python batch_onboard.py config.json --parallel
    python batch_onboard.py config.json --parallel --obstacle-course
    python batch_onboard.py config.json --base-url https://staging.api.moltgrid.net/v1
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://api.moltgrid.net/v1"
LOG_DIR = Path(__file__).parent / "logs"
TIMEOUT = 30.0

OBSTACLE_STAGES = [
    {"method": "POST", "path": "/heartbeat", "body": {"status": "online"}, "name": "heartbeat"},
    {"method": "GET", "path": "/directory/me", "body": None, "name": "identity_check"},
    {"method": "POST", "path": "/memory", "body": {"key": "obstacle_test", "value": "stage_2_passed"}, "name": "memory_write"},
    {"method": "GET", "path": "/memory", "body": None, "name": "memory_read"},
    {"method": "POST", "path": "/relay/send", "body": None, "name": "relay_send"},  # filled per agent
    {"method": "POST", "path": "/queue/submit", "body": {"payload": "obstacle_stage_5", "queue_name": "default"}, "name": "queue_submit"},
    {"method": "POST", "path": "/queue/claim?queue_name=default", "body": None, "name": "queue_claim"},
    {"method": "POST", "path": "/schedules", "body": {"cron_expr": "0 0 1 1 *", "payload": "obstacle_noop", "queue_name": "default"}, "name": "schedule_create"},
    {"method": "GET", "path": "/schedules", "body": None, "name": "schedule_list"},
    {"method": "GET", "path": "/onboarding/status", "body": None, "name": "onboarding_verify"},
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key, "Content-Type": "application/json"}


def _now_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Onboarding sequence
# ---------------------------------------------------------------------------


async def onboard_agent(
    client: httpx.AsyncClient,
    base_url: str,
    agent: dict[str, str],
    account_name: str,
) -> dict[str, Any]:
    """Run the full 7-step onboarding sequence for one agent."""

    agent_id = agent["agent_id"]
    api_key = agent["api_key"]
    agent_name = agent.get("name", agent_id)
    hdrs = _headers(api_key)
    result: dict[str, Any] = {
        "agent_id": agent_id,
        "account": account_name,
        "agent_name": agent_name,
        "onboarding": "pending",
        "obstacle_course": "skipped",
        "credits": None,
        "errors": [],
        "responses": [],
    }

    steps = [
        ("POST", "/heartbeat", {"status": "online"}),
        ("POST", "/memory", {"key": "identity", "value": f"{agent_name} initialized via batch onboard"}),
        ("POST", "/relay/send", {"to_agent": agent_id, "payload": "batch_onboard_ping", "channel": "direct"}),
        ("POST", "/queue/submit", {"payload": "batch_onboard_task", "queue_name": "default"}),
        ("POST", "/schedules", {"cron_expr": "0 */6 * * *", "payload": "batch_scheduled_ping", "queue_name": "default"}),
        ("PUT", "/directory/me", {
            "display_name": agent_name,
            "description": f"Agent {agent_name} onboarded via batch tool",
            "tags": ["batch-onboarded"],
            "status": "active",
        }),
        ("GET", "/onboarding/status", None),
    ]

    for method, path, body in steps:
        url = f"{base_url}{path}"
        try:
            if method == "GET":
                resp = await client.get(url, headers=hdrs, timeout=TIMEOUT)
            elif method == "POST":
                resp = await client.post(url, headers=hdrs, json=body, timeout=TIMEOUT)
            elif method == "PUT":
                resp = await client.put(url, headers=hdrs, json=body, timeout=TIMEOUT)
            else:
                continue

            entry = {
                "step": path,
                "method": method,
                "status": resp.status_code,
                "body": _safe_json(resp),
            }
            result["responses"].append(entry)

            if resp.status_code >= 400:
                result["errors"].append(f"{method} {path} -> {resp.status_code}")

            # Capture onboarding completion from final step
            if path == "/onboarding/status" and resp.status_code == 200:
                data = resp.json()
                completed = data.get("completed_steps", 0)
                total = data.get("total_steps", 7)
                result["onboarding"] = f"{completed}/{total}"
                result["credits"] = data.get("credits_balance", data.get("credits", "N/A"))

        except httpx.RequestError as exc:
            result["errors"].append(f"{method} {path} -> {type(exc).__name__}: {exc}")
            result["responses"].append({
                "step": path,
                "method": method,
                "status": "error",
                "body": str(exc),
            })

    if not result["errors"]:
        if result["onboarding"] == "pending":
            result["onboarding"] = "done (no status endpoint)"

    return result


# ---------------------------------------------------------------------------
# Obstacle course
# ---------------------------------------------------------------------------


async def run_obstacle_course(
    client: httpx.AsyncClient,
    base_url: str,
    agent: dict[str, str],
    result: dict[str, Any],
) -> None:
    """Run the 10-stage obstacle course for one agent."""

    agent_id = agent["agent_id"]
    api_key = agent["api_key"]
    hdrs = _headers(api_key)
    passed = 0
    total = len(OBSTACLE_STAGES)

    for stage in OBSTACLE_STAGES:
        method = stage["method"]
        path = stage["path"]
        body = stage["body"]
        url = f"{base_url}{path}"

        # Fill in agent-specific relay body
        if stage["name"] == "relay_send":
            body = {"to_agent": agent_id, "payload": "obstacle_relay_test", "channel": "direct"}

        try:
            if method == "GET":
                resp = await client.get(url, headers=hdrs, timeout=TIMEOUT)
            elif method == "POST":
                resp = await client.post(url, headers=hdrs, json=body, timeout=TIMEOUT)
            else:
                continue

            entry = {
                "obstacle_stage": stage["name"],
                "method": method,
                "path": path,
                "status": resp.status_code,
                "body": _safe_json(resp),
            }
            result["responses"].append(entry)

            if resp.status_code < 400:
                passed += 1
            else:
                result["errors"].append(f"obstacle:{stage['name']} -> {resp.status_code}")

        except httpx.RequestError as exc:
            result["errors"].append(f"obstacle:{stage['name']} -> {type(exc).__name__}")
            result["responses"].append({
                "obstacle_stage": stage["name"],
                "status": "error",
                "body": str(exc),
            })

    result["obstacle_course"] = f"{passed}/{total}"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text[:500]


def print_summary(results: list[dict[str, Any]]) -> None:
    """Print a formatted summary table."""

    header = f"{'Agent ID':<20} {'Account':<16} {'Onboarding':<14} {'Obstacle':<14} {'Credits':<10} {'Errors'}"
    print()
    print("=" * len(header))
    print("  BATCH ONBOARDING SUMMARY")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for r in results:
        agent_id = r["agent_id"][:18]
        account = r["account"][:14]
        onboard = str(r["onboarding"])[:12]
        obstacle = str(r["obstacle_course"])[:12]
        credits = str(r["credits"] if r["credits"] is not None else "N/A")[:8]
        errors = "; ".join(r["errors"][:3]) if r["errors"] else "none"
        print(f"{agent_id:<20} {account:<16} {onboard:<14} {obstacle:<14} {credits:<10} {errors}")

    print("=" * len(header))
    total = len(results)
    ok = sum(1 for r in results if not r["errors"])
    print(f"Total: {total}  |  Success: {ok}  |  Failed: {total - ok}")
    print()


def save_log(results: list[dict[str, Any]], tag: str) -> Path:
    """Write full API response log to tools/logs/."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"batch_onboard_{tag}.json"
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    return log_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def run(config_path: str, base_url: str, parallel: bool, obstacle_course: bool) -> None:
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    accounts = config.get("accounts", [])
    if not accounts:
        print("No accounts found in config file.")
        sys.exit(1)

    # Build flat list of (account_name, agent_dict)
    tasks_list: list[tuple[str, dict[str, str]]] = []
    for acct in accounts:
        acct_name = acct.get("name", "unnamed")
        for agent in acct.get("agents", []):
            tasks_list.append((acct_name, agent))

    total = len(tasks_list)
    print(f"Batch onboarding {total} agent(s) across {len(accounts)} account(s)")
    print(f"Base URL: {base_url}")
    print(f"Parallel: {parallel}  |  Obstacle course: {obstacle_course}")
    print()

    results: list[dict[str, Any]] = []
    tag = _now_tag()

    async with httpx.AsyncClient() as client:
        if parallel:
            # Run all agents concurrently
            coros = [
                _process_agent(client, base_url, acct_name, agent, obstacle_course)
                for acct_name, agent in tasks_list
            ]
            results = await asyncio.gather(*coros)
        else:
            # Run sequentially
            for i, (acct_name, agent) in enumerate(tasks_list, 1):
                print(f"[{i}/{total}] Onboarding {agent.get('name', agent['agent_id'])}...")
                r = await _process_agent(client, base_url, acct_name, agent, obstacle_course)
                results.append(r)

    # Output
    print_summary(results)
    log_path = save_log(results, tag)
    print(f"Full log saved to: {log_path}")


async def _process_agent(
    client: httpx.AsyncClient,
    base_url: str,
    acct_name: str,
    agent: dict[str, str],
    obstacle_course: bool,
) -> dict[str, Any]:
    """Onboard a single agent and optionally run obstacle course."""
    result = await onboard_agent(client, base_url, agent, acct_name)
    if obstacle_course:
        await run_obstacle_course(client, base_url, agent, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MoltGrid Batch Onboarding Tool. Onboards multiple agents from a JSON config."
    )
    parser.add_argument(
        "config",
        help="Path to JSON config file with accounts and agents",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run onboarding concurrently using asyncio",
    )
    parser.add_argument(
        "--obstacle-course",
        action="store_true",
        help="Also run the 10-stage obstacle course for each agent",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.config):
        print(f"Config file not found: {args.config}")
        sys.exit(1)

    asyncio.run(run(args.config, args.base_url, args.parallel, args.obstacle_course))


if __name__ == "__main__":
    main()
