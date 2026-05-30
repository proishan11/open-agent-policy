#!/usr/bin/env python3
"""Deterministic OAP enforcement walkthrough.

This script is intentionally not an AI agent. It proves the security flow
without LLM nondeterminism. Run llm_agent.py for an actual LLM-backed agent.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
SDK_PATH = ROOT / "sdk" / "python"
if SDK_PATH.exists():
    sys.path.insert(0, str(SDK_PATH))

from open_agent_policy import OAPClient  # noqa: E402


AGENT_ID = "agent://demo/customer-assistant"
ACTOR_ID = os.environ.get("OAP_ACTOR_ID", "user:alice@example.com")
OAP_SERVER_URL = os.environ.get("OAP_SERVER_URL", "http://127.0.0.1:8181")
RESOURCE_API_URL = os.environ.get("RESOURCE_API_URL", "http://127.0.0.1:9191")


def get_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    req = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def print_step(title: str) -> None:
    print(f"\n== {title}")


def main() -> int:
    client = OAPClient(server_url=OAP_SERVER_URL, agent_id=AGENT_ID)

    print("Minimal OAP Enforcement Demo")
    print(f"Agent:       {AGENT_ID}")
    print(f"Actor:       {ACTOR_ID}")
    print(f"OAP:         {OAP_SERVER_URL}")
    print(f"Resource API:{RESOURCE_API_URL}")

    print_step("1. Direct resource call without a grant is blocked")
    status, body = get_json(f"{RESOURCE_API_URL}/customers/C-100")
    print(f"GET /customers/C-100 -> {status} {body}")
    if status != 401:
        print("expected direct call to be rejected")
        return 1

    print_step("2. Agent asks OAP for customer.read on C-100")
    decision = client.authorize(
        action="customer.read",
        resource_type="crm.customer",
        resource_id="C-100",
        actor_type="user",
        actor_id=ACTOR_ID,
        context={"run_id": "run-minimal-demo"},
    )
    print(f"decision={decision.decision} constraints={decision.constraints}")
    if not decision.is_allowed or decision.grant is None:
        print(f"expected allow with grant, got {decision.decision}: {decision.reason}")
        return 1

    status, customer = get_json(
        f"{RESOURCE_API_URL}/customers/C-100",
        headers={"X-OAP-Grant-Token": decision.grant.token},
    )
    print(f"GET /customers/C-100 with grant -> {status}")
    print(json.dumps(customer, indent=2))
    if status != 200 or customer.get("tax_identifier") != "<redacted>":
        print("expected protected API to return redacted customer data")
        return 1

    print_step("3. Same grant cannot be replayed against C-200")
    status, replay_body = get_json(
        f"{RESOURCE_API_URL}/customers/C-200",
        headers={"X-OAP-Grant-Token": decision.grant.token},
    )
    print(f"GET /customers/C-200 with C-100 grant -> {status} {replay_body}")
    if status != 403:
        print("expected wrong-resource grant replay to be rejected")
        return 1

    print_step("4. External message requires approval")
    approval_decision = client.authorize(
        action="message.send",
        resource_type="slack.channel",
        resource_id="slack:#external-customers",
        resource_owner="channel:external",
        actor_type="user",
        actor_id=ACTOR_ID,
    )
    print(
        "decision="
        f"{approval_decision.decision} approvers="
        f"{approval_decision.approval.get('approvers', [])}"
    )
    if not approval_decision.requires_approval:
        print("expected external message to require approval")
        return 1

    print_step("5. Destructive customer.delete is denied")
    delete_decision = client.authorize(
        action="customer.delete",
        resource_type="crm.customer",
        resource_id="C-100",
        actor_type="user",
        actor_id=ACTOR_ID,
    )
    print(f"decision={delete_decision.decision} reason={delete_decision.reason}")
    if not delete_decision.is_denied:
        print("expected customer.delete to be denied")
        return 1

    print("\nDemo complete: grants, constraints, approval, and deny all behaved as expected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
