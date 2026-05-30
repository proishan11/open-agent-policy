#!/usr/bin/env python3
"""Minimal LLM-backed agent protected by OAP.

This script calls a local Ollama model to choose a tool, then executes that
tool through OAP authorization and resource-side grant validation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
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
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OAP_LLM_MODEL", "llama3.2")


TOOLS = {
    "read_customer": {
        "description": "Read a customer record by customer_id.",
        "args": {"customer_id": "C-100"},
    },
    "send_message": {
        "description": "Send a message to a Slack-like channel.",
        "args": {
            "channel_id": "slack:#external-customers",
            "owner": "channel:external",
        },
    },
    "delete_customer": {
        "description": "Delete a customer by customer_id.",
        "args": {"customer_id": "C-100"},
    },
}


def post_json(url: str, body: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    payload = json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    req = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError(f"LLM did not return JSON: {text}") from None
        return json.loads(match.group(0))


def choose_tool(task: str) -> dict[str, Any]:
    system_prompt = (
        "You are a minimal customer-support AI agent. Choose exactly one tool "
        "for the user task. Return JSON only with this shape: "
        '{"tool":"read_customer|send_message|delete_customer","args":{...}}. '
        "Use customer_id C-100 unless the task names another customer. "
        "Use channel_id slack:#external-customers and owner channel:external "
        "for external messages. Available tools: "
        f"{json.dumps(TOOLS, sort_keys=True)}"
    )
    body = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task},
        ],
        "format": "json",
        "stream": False,
    }
    try:
        response = post_json(f"{OLLAMA_URL}/api/chat", body)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(
            "Could not reach Ollama. Start it with `ollama serve` and pull a "
            f"model with `ollama pull {OLLAMA_MODEL}`."
        ) from exc

    content = response.get("message", {}).get("content", "")
    choice = extract_json(content)
    if choice.get("tool") not in TOOLS:
        raise ValueError(f"LLM chose unsupported tool: {choice}")
    if not isinstance(choice.get("args"), dict):
        raise ValueError(f"LLM returned invalid args: {choice}")
    return choice


def summarize_result(task: str, choice: dict[str, Any], result: dict[str, Any]) -> str:
    system_prompt = (
        "You are a customer-support AI agent. Produce a concise final answer "
        "for the user based only on the tool result. Do not invent redacted "
        "values. If the tool result says pending_approval or blocked, explain "
        "that the action was not performed."
    )
    body = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": task,
                        "tool_call": choice,
                        "tool_result": result,
                    },
                    sort_keys=True,
                ),
            },
        ],
        "stream": False,
    }
    response = post_json(f"{OLLAMA_URL}/api/chat", body)
    return response.get("message", {}).get("content", "").strip()


def read_customer(client: OAPClient, customer_id: str) -> dict[str, Any]:
    decision = client.authorize(
        action="customer.read",
        resource_type="crm.customer",
        resource_id=customer_id,
        actor_type="user",
        actor_id=ACTOR_ID,
        context={"run_id": "run-minimal-llm-demo"},
    )
    if not decision.is_allowed or decision.grant is None:
        return {"status": decision.decision, "reason": decision.reason}

    status, body = get_json(
        f"{RESOURCE_API_URL}/customers/{customer_id}",
        headers={"X-OAP-Grant-Token": decision.grant.token},
    )
    return {
        "status": "ok" if status == 200 else "resource_error",
        "http_status": status,
        "decision": decision.decision,
        "constraints": decision.constraints,
        "body": body,
    }


def send_message(client: OAPClient, channel_id: str, owner: str) -> dict[str, Any]:
    normalized_owner = owner
    if normalized_owner in {"external", "customer", "public"}:
        normalized_owner = "channel:external"
    elif normalized_owner in {"internal", "private"}:
        normalized_owner = "channel:internal"

    decision = client.authorize(
        action="message.send",
        resource_type="slack.channel",
        resource_id=channel_id,
        resource_owner=normalized_owner,
        actor_type="user",
        actor_id=ACTOR_ID,
    )
    if decision.requires_approval:
        return {
            "status": "pending_approval",
            "decision": decision.decision,
            "approvers": decision.approval.get("approvers", []),
            "reason": decision.reason,
        }
    if decision.is_denied:
        return {
            "status": "blocked",
            "decision": decision.decision,
            "reason": decision.reason,
        }
    return {"status": "sent", "decision": decision.decision, "channel_id": channel_id}


def delete_customer(client: OAPClient, customer_id: str) -> dict[str, Any]:
    decision = client.authorize(
        action="customer.delete",
        resource_type="crm.customer",
        resource_id=customer_id,
        actor_type="user",
        actor_id=ACTOR_ID,
    )
    if decision.is_denied:
        return {
            "status": "blocked",
            "decision": decision.decision,
            "reason": decision.reason,
        }
    return {"status": "would_delete", "decision": decision.decision}


def execute_tool(client: OAPClient, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    if tool == "read_customer":
        return read_customer(client, str(args.get("customer_id", "C-100")))
    if tool == "send_message":
        return send_message(
            client,
            str(args.get("channel_id", "slack:#external-customers")),
            str(args.get("owner", "channel:external")),
        )
    if tool == "delete_customer":
        return delete_customer(client, str(args.get("customer_id", "C-100")))
    return {"status": "unsupported_tool", "tool": tool}


def run_task(client: OAPClient, task: str) -> None:
    print(f"\nUser task: {task}")
    choice = choose_tool(task)
    print(f"LLM selected: {json.dumps(choice, sort_keys=True)}")
    result = execute_tool(client, choice["tool"], choice["args"])
    print("Tool result:")
    print(json.dumps(result, indent=2, sort_keys=True))
    print("LLM final response:")
    print(summarize_result(task, choice, result))


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal LLM-backed OAP agent")
    parser.add_argument(
        "task",
        nargs="?",
        help="Task to ask the LLM agent to perform. If omitted, runs three demos.",
    )
    args = parser.parse_args()

    client = OAPClient(server_url=OAP_SERVER_URL, agent_id=AGENT_ID)
    print("Minimal OAP LLM Agent")
    print(f"Model:       {OLLAMA_MODEL} via {OLLAMA_URL}")
    print(f"Agent:       {AGENT_ID}")
    print(f"OAP:         {OAP_SERVER_URL}")
    print(f"Resource API:{RESOURCE_API_URL}")

    tasks = [args.task] if args.task else [
        "Read customer C-100 and summarize what data is visible.",
        "Send an update to the external customer channel.",
        "Delete customer C-100.",
    ]
    try:
        for task in tasks:
            run_task(client, task)
    except (RuntimeError, ValueError) as exc:
        print(f"LLM agent error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
