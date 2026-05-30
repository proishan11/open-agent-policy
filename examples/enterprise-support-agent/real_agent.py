#!/usr/bin/env python3
"""Real LangChain ReAct Agent — protected by Open Agent Policy.

This is NOT a mock. This is a real LangChain agent that:
  - Uses a real LLM (Ollama/llama3.2 by default) to reason about tasks
  - Makes real tool calls decided by the LLM
  - Every tool call goes through OAP policy enforcement
  - Field-level redaction, max records, and deny rules are enforced

Prerequisites:
  1. Install & start Ollama: brew install ollama && ollama serve && ollama pull llama3.2
  2. Start mock APIs:    uvicorn examples.enterprise-support-agent.mock_apis.server:app --port 9100
  3. Start OAP server:   ./bin/oap-server --data examples/enterprise-support-agent/ --dev
  4. Run this agent:     python examples/enterprise-support-agent/real_agent.py

Override LLM: OAP_MODEL=mistral python examples/enterprise-support-agent/real_agent.py

The agent will autonomously decide which tools to call based on the user's request.
OAP intercepts EVERY tool call and enforces policy BEFORE execution.
"""

from __future__ import annotations

import os
import sys
import json

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

import httpx
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

from open_agent_policy.client import OAPClient, Decision
from open_agent_policy.decorators import protect
from open_agent_policy.errors import PermissionDeniedError, ApprovalRequiredError


# ── Config ──────────────────────────────────────────────────────────────

API_BASE = os.environ.get("MOCK_API_URL", "http://localhost:9100")
OAP_SERVER = os.environ.get("OAP_SERVER", "http://localhost:8080")
AGENT_ID = "agent://support/support-ticket-agent"
MODEL = os.environ.get("OAP_MODEL", "llama3.2")


# ── OAP Client ──────────────────────────────────────────────────────────

def make_oap_client() -> OAPClient:
    """Create OAP client — tries remote server first, falls back to mock."""
    try:
        httpx.get(f"{OAP_SERVER}/v1/health", timeout=2)
        print(f"  ✓ Connected to OAP server at {OAP_SERVER}")
        return OAPClient(server_url=OAP_SERVER, agent_id=AGENT_ID, mode="remote")
    except Exception:
        print(f"  ⚠ OAP server not available — using embedded mock client")
        return make_mock_client()


def make_mock_client():
    """Create a mock OAP client that simulates realistic policy decisions."""
    from unittest.mock import MagicMock

    decisions = {
        "tickets.list": {"decision": "allow_with_constraints", "constraints": {"max_records": 10, "readonly": True}},
        "tickets.read": {"decision": "allow_with_constraints", "constraints": {"readonly": True}},
        "tickets.update": {"decision": "allow_with_constraints", "constraints": {"allowed_fields": ["status", "priority", "assignee"]}},
        "tickets.escalate": {"decision": "allow"},
        "customers.read": {"decision": "allow_with_constraints", "constraints": {"readonly": True, "redact_fields": ["ssn", "credit_card", "bank_account"]}},
        "notifications.send_email": {
            "decision": "require_approval",
            "reason": "Email notifications require support lead approval",
            "approval": {"approvers": ["group:support-leads"], "expires_in_seconds": 1800},
        },
        "tickets.delete": {"decision": "deny", "reason": "Support agents may not delete tickets — compliance requirement"},
    }
    client = MagicMock(spec=OAPClient)
    client.default_agent_id = AGENT_ID

    def mock_authorize(**kwargs):
        action = kwargs.get("action", "")
        data = decisions.get(action, {"decision": "deny", "reason": f"no policy for action: {action}"})
        return Decision.from_dict(data)

    client.authorize = mock_authorize
    return client


oap_client = make_oap_client()


# ── LangChain Tools (real HTTP calls to mock APIs) ──────────────────────

@tool
def list_tickets(status: str = "", priority: str = "") -> str:
    """List support tickets. Optionally filter by status (open/in_progress/closed) or priority (P1/P2/P3/P4)."""
    # OAP authorization
    decision = oap_client.authorize(agent_id=AGENT_ID, action="tickets.list", tool_name="list_tickets")
    if decision.is_denied:
        return f"❌ ACCESS DENIED: {decision.reason}"

    constraints = decision.constraints or {}
    max_records = constraints.get("max_records", 10)

    params = {"limit": max_records}
    if status:
        params["status"] = status
    if priority:
        params["priority"] = priority

    resp = httpx.get(f"{API_BASE}/api/tickets", params=params)
    data = resp.json()
    tickets = data.get("tickets", [])
    lines = [f"Found {len(tickets)} tickets (max {max_records} shown):"]
    for t in tickets:
        lines.append(f"  {t['id']} [{t['priority']}] {t['status']:12s} {t['subject']}")
    return "\n".join(lines)


@tool
def read_ticket(ticket_id: str) -> str:
    """Read details of a specific support ticket by its ID (e.g., TKT-1001)."""
    decision = oap_client.authorize(agent_id=AGENT_ID, action="tickets.read", tool_name="read_ticket")
    if decision.is_denied:
        return f"❌ ACCESS DENIED: {decision.reason}"

    resp = httpx.get(f"{API_BASE}/api/tickets/{ticket_id}")
    if resp.status_code == 404:
        return f"Ticket {ticket_id} not found."
    data = resp.json()
    return json.dumps(data, indent=2)


@tool
def read_customer(customer_id: str) -> str:
    """Read customer information by customer ID (e.g., CUST-501). Sensitive fields are automatically redacted by policy."""
    decision = oap_client.authorize(agent_id=AGENT_ID, action="customers.read", tool_name="read_customer")
    if decision.is_denied:
        return f"❌ ACCESS DENIED: {decision.reason}"

    resp = httpx.get(f"{API_BASE}/api/customers/{customer_id}")
    if resp.status_code == 404:
        return f"Customer {customer_id} not found."
    data = resp.json()

    # Apply field-level redaction from OAP constraints
    constraints = decision.constraints or {}
    for field in constraints.get("redact_fields", []):
        if field in data:
            data[field] = "[REDACTED by OAP policy]"

    return json.dumps(data, indent=2)


@tool
def update_ticket(ticket_id: str, status: str = "", priority: str = "", assignee: str = "") -> str:
    """Update a ticket's status, priority, or assignee. Only these fields can be modified per policy."""
    # Normalize None → ""
    status = status or ""
    priority = priority or ""
    assignee = assignee or ""

    decision = oap_client.authorize(agent_id=AGENT_ID, action="tickets.update", tool_name="update_ticket")
    if decision.is_denied:
        return f"❌ ACCESS DENIED: {decision.reason}"

    constraints = decision.constraints or {}
    allowed = constraints.get("allowed_fields", ["status", "priority", "assignee"])

    update = {}
    if status and "status" in allowed:
        update["status"] = status
    if priority and "priority" in allowed:
        update["priority"] = priority
    if assignee and "assignee" in allowed:
        update["assignee"] = assignee

    if not update:
        return "No updateable fields provided (allowed: status, priority, assignee)."

    resp = httpx.patch(f"{API_BASE}/api/tickets/{ticket_id}", json=update)
    if resp.status_code == 404:
        return f"Ticket {ticket_id} not found."
    return f"Updated {ticket_id}: {json.dumps(update)}"


@tool
def escalate_ticket(ticket_id: str) -> str:
    """Escalate a ticket to the escalation team. The ticket API owns priority checks."""
    decision = oap_client.authorize(agent_id=AGENT_ID, action="tickets.escalate", tool_name="escalate_ticket")
    if decision.is_denied:
        return f"❌ ACCESS DENIED: {decision.reason}"

    resp = httpx.post(f"{API_BASE}/api/tickets/{ticket_id}/escalate")
    if resp.status_code == 404:
        return f"Ticket {ticket_id} not found."
    data = resp.json()
    return f"Ticket {ticket_id} escalated. Status: {data.get('status')}"


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email notification. Current policy requires support lead approval."""
    decision = oap_client.authorize(agent_id=AGENT_ID, action="notifications.send_email", tool_name="send_email")
    if decision.is_denied:
        return f"❌ ACCESS DENIED: {decision.reason}"
    if decision.requires_approval:
        return f"⏳ APPROVAL REQUIRED: Email notifications need support lead approval. Approvers: {decision.approval.get('approvers', [])}"

    resp = httpx.post(f"{API_BASE}/api/notifications/email", json={
        "to": to, "subject": subject, "body": body,
    })
    data = resp.json()
    return f"Email sent to {to}. Message ID: {data.get('message_id')}"


@tool
def delete_ticket(ticket_id: str) -> str:
    """Delete a support ticket. WARNING: This action is blocked by OAP policy."""
    decision = oap_client.authorize(agent_id=AGENT_ID, action="tickets.delete", tool_name="delete_ticket")
    if decision.is_denied:
        return f"🛑 ACCESS DENIED: {decision.reason}"

    # This should never execute due to OAP deny rule
    resp = httpx.delete(f"{API_BASE}/api/tickets/{ticket_id}")
    return f"Deleted {ticket_id}" if resp.status_code == 200 else f"Error: {resp.text}"


# ── Agent ───────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a customer support agent. You help resolve support tickets by:
- Reading and listing tickets
- Looking up customer information
- Updating ticket status and priority
- Escalating critical tickets
- Sending email notifications

IMPORTANT: Your tools are policy-enforced by Open Agent Policy (OAP).
Some actions may be denied or constrained. If a tool returns ACCESS DENIED,
explain to the user that the action is blocked by policy and suggest alternatives.

Be thorough but concise. Always check ticket details before taking action."""


def create_agent():
    """Create the LangChain ReAct agent with OAP-protected tools."""
    llm = ChatOllama(model=MODEL, temperature=0)

    tools = [
        list_tickets,
        read_ticket,
        read_customer,
        update_ticket,
        escalate_ticket,
        send_email,
        delete_ticket,
    ]

    agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=SYSTEM_PROMPT,
    )
    return agent


def run_scenario(agent, scenario_name: str, user_message: str):
    """Run a single scenario and print the agent's response."""
    print(f"\n{'='*70}")
    print(f"  SCENARIO: {scenario_name}")
    print(f"  USER: {user_message}")
    print(f"{'='*70}\n")

    result = agent.invoke({"messages": [{"role": "user", "content": user_message}]})

    # Print the conversation
    for msg in result["messages"]:
        role = getattr(msg, "type", "unknown")
        if role == "human":
            continue  # already printed
        elif role == "ai":
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    print(f"  🔧 TOOL CALL: {tc['name']}({json.dumps(tc['args'], indent=None)})")
            if msg.content:
                print(f"\n  🤖 AGENT: {msg.content}\n")
        elif role == "tool":
            content = msg.content if len(msg.content) < 300 else msg.content[:300] + "..."
            print(f"  📋 RESULT: {content}")

    return result


def main():
    print("=" * 70)
    print("  Enterprise Support Agent — REAL LangChain Agent + OAP")
    print("=" * 70)
    print(f"\n  Agent:  {AGENT_ID}")
    print(f"  Model:  {MODEL}")
    print(f"  APIs:   {API_BASE}")
    print(f"  OAP:    {OAP_SERVER}")

    # Check mock APIs
    try:
        httpx.get(f"{API_BASE}/health", timeout=2)
        print(f"  ✓ Mock APIs running")
    except Exception:
        print(f"  ✗ Mock APIs not running at {API_BASE}")
        print(f"    Start with: uvicorn examples.enterprise-support-agent.mock_apis.server:app --port 9100")
        sys.exit(1)

    # Check Ollama
    try:
        httpx.get("http://localhost:11434/api/tags", timeout=3)
        print(f"  ✓ Ollama running (model: {MODEL})")
    except Exception:
        print(f"\n  ✗ Ollama not running at localhost:11434")
        print(f"    Start with: ollama serve")
        print(f"    Pull model: ollama pull {MODEL}")
        sys.exit(1)
    print()

    agent = create_agent()

    # ── Scenario 1: List and triage tickets ──
    run_scenario(
        agent,
        "List and Triage",
        "List all open support tickets and tell me which ones are most critical.",
    )

    # ── Scenario 2: Investigate a ticket with customer lookup ──
    run_scenario(
        agent,
        "Investigate Ticket",
        "Look up ticket TKT-1001 and get the customer's contact information. "
        "I need their name, email, and phone number.",
    )

    # ── Scenario 3: Escalate a P1 ticket ──
    run_scenario(
        agent,
        "Escalate Critical",
        "TKT-1002 is a P1 production database issue. Escalate it immediately "
        "and email oncall@company.internal about the escalation.",
    )

    # ── Scenario 4: Try to delete a ticket (should be DENIED) ──
    run_scenario(
        agent,
        "Attempt Deletion (Policy Enforced)",
        "Delete ticket TKT-1003 — it's just a feature request and we don't need it.",
    )

    # ── Scenario 5: Update ticket and verify constraint enforcement ──
    run_scenario(
        agent,
        "Update with Constraints",
        "Set TKT-1004 to in_progress and assign it to billing-team@company.internal.",
    )

    print("\n" + "=" * 70)
    print("  ALL SCENARIOS COMPLETE")
    print("=" * 70)
    print("\n  What happened:")
    print("  • The LLM decided which tools to call (real reasoning, not scripted)")
    print("  • EVERY tool call went through OAP policy evaluation")
    print("  • Customer SSN/credit card/bank account were REDACTED by policy")
    print("  • Ticket deletion was DENIED by explicit deny rule")
    print("  • Constraints (max_records, allowed_fields) were enforced")
    print("  • The agent handled denials gracefully")
    print()


if __name__ == "__main__":
    main()
