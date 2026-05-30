#!/usr/bin/env python3
"""Minimal LangChain agent protected by OAP.

The LLM is real: LangChain calls a local Ollama model, the model chooses a
tool, and each tool performs OAP authorization before any protected action.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
    from langchain_core.tools import tool
except ImportError as exc:
    print(
        "Missing LangChain dependencies. Install them with: "
        "pip install -e 'sdk/python[langchain]' langchain-ollama",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


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

OAP_CLIENT: OAPClient | None = None


SYSTEM_PROMPT = """You are a minimal customer-support AI agent.
Use tools when the user asks to read, message about, or delete customer data.
Your tools are protected by Open Agent Policy. If a tool says blocked or
pending_approval, explain that the requested action was not performed."""


def get_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    req = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def check_ollama() -> None:
    try:
        with urlopen(f"{OLLAMA_URL}/api/tags", timeout=3):
            return
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(
            "Could not reach Ollama. Start it with `ollama serve` and pull a "
            f"model with `ollama pull {OLLAMA_MODEL}`."
        ) from exc


def create_llm():
    try:
        from langchain_ollama import ChatOllama
    except ImportError as exc:
        raise RuntimeError(
            "Missing langchain-ollama. Install it with: pip install langchain-ollama"
        ) from exc
    return ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_URL, temperature=0)


def client() -> OAPClient:
    if OAP_CLIENT is None:
        raise RuntimeError("OAP client is not initialized")
    return OAP_CLIENT


@tool
def read_customer(customer_id: str = "C-100") -> str:
    """Read a customer record by customer ID. Sensitive fields are redacted."""
    decision = client().authorize(
        action="customer.read",
        resource_type="crm.customer",
        resource_id=customer_id,
        actor_type="user",
        actor_id=ACTOR_ID,
        context={"run_id": "run-minimal-langchain-demo"},
    )
    if not decision.is_allowed or decision.grant is None:
        return json.dumps({
            "status": decision.decision,
            "reason": decision.reason,
        })

    status, body = get_json(
        f"{RESOURCE_API_URL}/customers/{customer_id}",
        headers={"X-OAP-Grant-Token": decision.grant.token},
    )
    return json.dumps({
        "status": "ok" if status == 200 else "resource_error",
        "http_status": status,
        "oap_decision": decision.decision,
        "constraints": decision.constraints,
        "customer": body,
    }, sort_keys=True)


@tool
def send_external_message(channel_id: str = "slack:#external-customers") -> str:
    """Send an external customer-channel message. Policy may require approval."""
    decision = client().authorize(
        action="message.send",
        resource_type="slack.channel",
        resource_id=channel_id,
        resource_owner="channel:external",
        actor_type="user",
        actor_id=ACTOR_ID,
        context={"run_id": "run-minimal-langchain-demo"},
    )
    if decision.requires_approval:
        return json.dumps({
            "status": "pending_approval",
            "oap_decision": decision.decision,
            "approvers": decision.approval.get("approvers", []),
            "reason": decision.reason,
        }, sort_keys=True)
    if decision.is_denied:
        return json.dumps({
            "status": "blocked",
            "oap_decision": decision.decision,
            "reason": decision.reason,
        }, sort_keys=True)
    return json.dumps({
        "status": "sent",
        "oap_decision": decision.decision,
        "channel_id": channel_id,
    }, sort_keys=True)


@tool
def delete_customer(customer_id: str = "C-100") -> str:
    """Delete a customer record. OAP policy blocks this destructive action."""
    decision = client().authorize(
        action="customer.delete",
        resource_type="crm.customer",
        resource_id=customer_id,
        actor_type="user",
        actor_id=ACTOR_ID,
        context={"run_id": "run-minimal-langchain-demo"},
    )
    if decision.is_denied:
        return json.dumps({
            "status": "blocked",
            "oap_decision": decision.decision,
            "reason": decision.reason,
        }, sort_keys=True)
    return json.dumps({
        "status": "would_delete",
        "oap_decision": decision.decision,
    }, sort_keys=True)


def run_task(llm: Any, task: str) -> None:
    tools = [read_customer, send_external_message, delete_customer]
    tools_by_name = {item.name: item for item in tools}
    llm_with_tools = llm.bind_tools(tools)
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=task),
    ]

    print(f"\nUser task: {task}")
    ai_message = llm_with_tools.invoke(messages)
    tool_calls = getattr(ai_message, "tool_calls", []) or []
    if not tool_calls:
        print("LLM final response:")
        print(ai_message.content)
        return

    tool_call = tool_calls[0]
    tool_name = tool_call["name"]
    tool_args = tool_call.get("args", {})
    print(f"LangChain tool call: {tool_name}({json.dumps(tool_args, sort_keys=True)})")

    tool_result = tools_by_name[tool_name].invoke(tool_args)
    print("OAP-gated tool result:")
    print(tool_result)

    messages.append(ai_message)
    messages.append(
        ToolMessage(
            content=tool_result,
            tool_call_id=tool_call.get("id", f"call-{tool_name}"),
        )
    )
    final_message = llm.invoke(messages)
    print("LLM final response:")
    print(final_message.content)


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal LangChain OAP agent")
    parser.add_argument(
        "task",
        nargs="?",
        help="Task for the LangChain agent. If omitted, runs three demos.",
    )
    args = parser.parse_args()

    global OAP_CLIENT
    OAP_CLIENT = OAPClient(server_url=OAP_SERVER_URL, agent_id=AGENT_ID)

    print("Minimal OAP LangChain Agent")
    print(f"Model:       {OLLAMA_MODEL} via {OLLAMA_URL}")
    print(f"Agent:       {AGENT_ID}")
    print(f"OAP:         {OAP_SERVER_URL}")
    print(f"Resource API:{RESOURCE_API_URL}")

    try:
        check_ollama()
        llm = create_llm()
        tasks = [args.task] if args.task else [
            "Read customer C-100 and summarize what data is visible.",
            "Send an update to the external customer channel.",
            "Delete customer C-100.",
        ]
        for task in tasks:
            run_task(llm, task)
    except RuntimeError as exc:
        print(f"LangChain agent error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
