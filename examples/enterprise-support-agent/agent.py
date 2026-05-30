#!/usr/bin/env python3
"""Enterprise Support Agent — protected by Open Agent Policy.

This agent demonstrates OAP's zero-trust access control in a realistic scenario:
- 6 tools with different permission levels
- Field-level redaction (SSN, credit card, bank account)
- Max records constraint
- Explicit deny (delete tickets)
- Approval required (external emails)
- Full audit trail

Usage:
    # Terminal 1: Start mock APIs
    python -m examples.enterprise-support-agent.mock_apis.server

    # Terminal 2: Start OAP server
    ./bin/oap-server --data examples/enterprise-support-agent/ --dev

    # Terminal 3: Run the agent
    python examples/enterprise-support-agent/agent.py
"""

from __future__ import annotations

import sys
import json
import os

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))

from open_agent_policy.client import OAPClient, Decision
from open_agent_policy.decorators import protect
from open_agent_policy.errors import PermissionDeniedError, ApprovalRequiredError

# Import tools
sys.path.insert(0, os.path.dirname(__file__))
from tools import (
    read_ticket, list_tickets, update_ticket,
    escalate_ticket, read_customer, send_email, delete_ticket,
)


# ── Configuration ───────────────────────────────────────────────────────

OAP_SERVER = os.environ.get("OAP_SERVER", "http://localhost:8080")
AGENT_ID = "agent://support/support-ticket-agent"
ACTOR_ID = os.environ.get("OAP_ACTOR", "user:operator@company.internal")


# ── OAP Client ──────────────────────────────────────────────────────────

client = OAPClient(
    server_url=OAP_SERVER,
    agent_id=AGENT_ID,
    mode="remote",
)


# ── Protected tools ─────────────────────────────────────────────────────

@protect(client, agent_id=AGENT_ID, action="tickets.read")
def protected_read_ticket(ticket_id: str, **kwargs) -> dict:
    return read_ticket(ticket_id, **kwargs)

@protect(client, agent_id=AGENT_ID, action="tickets.list")
def protected_list_tickets(status=None, priority=None, **kwargs) -> dict:
    return list_tickets(status=status, priority=priority, **kwargs)

@protect(client, agent_id=AGENT_ID, action="tickets.update")
def protected_update_ticket(ticket_id: str, **kwargs) -> dict:
    return update_ticket(ticket_id, **kwargs)

@protect(client, agent_id=AGENT_ID, action="tickets.escalate")
def protected_escalate_ticket(ticket_id: str, **kwargs) -> dict:
    return escalate_ticket(ticket_id, **kwargs)

@protect(client, agent_id=AGENT_ID, action="customers.read")
def protected_read_customer(customer_id: str, **kwargs) -> dict:
    return read_customer(customer_id, **kwargs)

@protect(client, agent_id=AGENT_ID, action="notifications.send_email")
def protected_send_email(to: str, subject: str, body: str, **kwargs) -> dict:
    return send_email(to, subject, body, **kwargs)

@protect(client, agent_id=AGENT_ID, action="tickets.delete")
def protected_delete_ticket(ticket_id: str, **kwargs) -> dict:
    return delete_ticket(ticket_id, **kwargs)


# ── Agent simulation ────────────────────────────────────────────────────

def banner(text: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


def step(num: int, desc: str) -> None:
    print(f"\n{'─'*60}")
    print(f"  Step {num}: {desc}")
    print(f"{'─'*60}")


def run_demo_with_server():
    """Run the full demo against a live OAP server + mock API."""
    banner("Enterprise Support Agent — OAP Protected Demo")
    print(f"  Agent:  {AGENT_ID}")
    print(f"  Actor:  {ACTOR_ID}")
    print(f"  Server: {OAP_SERVER}")
    print()

    # Step 1: List open tickets (allowed, max 10 records)
    step(1, "List open tickets (allowed, max_records=10)")
    try:
        result = protected_list_tickets(status="open")
        print(f"  ✅ Found {len(result.get('tickets', []))} tickets")
        for t in result.get("tickets", []):
            print(f"     {t['id']} [{t['priority']}] {t['subject']}")
    except PermissionDeniedError as e:
        print(f"  ❌ Denied: {e}")

    # Step 2: Read a specific ticket
    step(2, "Read ticket TKT-1001 (allowed)")
    try:
        ticket = protected_read_ticket("TKT-1001")
        print(f"  ✅ {ticket['id']}: {ticket['subject']}")
        print(f"     Status: {ticket['status']}, Priority: {ticket['priority']}")
        print(f"     Customer: {ticket['customer_id']}")
    except PermissionDeniedError as e:
        print(f"  ❌ Denied: {e}")

    # Step 3: Read customer data (allowed, but SSN/CC/bank redacted)
    step(3, "Read customer CUST-501 (allowed, sensitive fields REDACTED)")
    try:
        customer = protected_read_customer("CUST-501")
        print(f"  ✅ Customer: {customer['name']} ({customer['company']})")
        print(f"     Email: {customer['email']}")
        print(f"     SSN: {customer.get('ssn', 'N/A')}")
        print(f"     Credit Card: {customer.get('credit_card', 'N/A')}")
        print(f"     Bank Account: {customer.get('bank_account', 'N/A')}")
        if "[REDACTED" in str(customer.get("ssn", "")):
            print(f"     ✅ Sensitive fields properly redacted by OAP constraints!")
    except PermissionDeniedError as e:
        print(f"  ❌ Denied: {e}")

    # Step 4: Update ticket status (allowed, constrained to status/priority/assignee)
    step(4, "Update TKT-1001 status to 'in_progress' (allowed)")
    try:
        result = protected_update_ticket("TKT-1001", status="in_progress")
        print(f"  ✅ Updated: status={result.get('status')}")
    except PermissionDeniedError as e:
        print(f"  ❌ Denied: {e}")

    # Step 5: Escalate P1 ticket (allowed; ticket API owns priority checks)
    step(5, "Escalate TKT-1002 (P1 — allowed)")
    try:
        result = protected_escalate_ticket("TKT-1002")
        print(f"  ✅ Escalated: {result.get('status')}")
    except PermissionDeniedError as e:
        print(f"  ❌ Denied: {e}")

    # Step 6: Send email (approval required)
    step(6, "Send email notification (approval required)")
    try:
        result = protected_send_email(
            to="oncall@company.internal",
            subject="TKT-1002 escalated",
            body="P1 ticket escalated to escalation team.",
        )
        print(f"  ✅ Email sent: {result.get('message_id')}")
    except PermissionDeniedError as e:
        print(f"  ❌ Denied: {e}")
    except ApprovalRequiredError as e:
        print(f"  ⏳ Approval required: {e}")

    # Step 7: Try to delete a ticket (DENIED — explicit deny)
    step(7, "Try to delete TKT-1003 (DENIED — explicit deny rule)")
    try:
        protected_delete_ticket("TKT-1003")
        print(f"  ❌ Should have been denied!")
    except PermissionDeniedError as e:
        print(f"  🛑 BLOCKED: {e}")
        print(f"     Policy enforced: support agents cannot delete tickets")

    # Summary
    banner("Demo Complete")
    print("  What happened:")
    print("  ✅ Step 1: Listed tickets (max 10 records enforced)")
    print("  ✅ Step 2: Read ticket (allowed)")
    print("  ✅ Step 3: Read customer (SSN, CC, bank account REDACTED)")
    print("  ✅ Step 4: Updated ticket status (constrained to allowed fields)")
    print("  ✅ Step 5: Escalated P1 ticket (allowed; API owns priority checks)")
    print("  ⏳ Step 6: Email required approval")
    print("  🛑 Step 7: Delete blocked (explicit deny rule)")
    print()
    print("  Every decision was authorized by OAP policy.")
    print("  Every decision was audited.")
    print("  The agent never self-enforced — OAP enforced from outside.")
    print()


def run_demo_offline():
    """Run the demo with mock OAP decisions (no server required)."""
    from unittest.mock import MagicMock

    banner("Enterprise Support Agent — Offline Demo (Mock OAP)")
    print("  Running without OAP server — using mock decisions")
    print("  To run with real server: start oap-server and mock APIs first")
    print()

    # Mock the OAP client with realistic decisions
    mock_decisions = {
        "tickets.read": {"decision": "allow_with_constraints", "constraints": {"max_records": 10, "readonly": True}},
        "tickets.list": {"decision": "allow_with_constraints", "constraints": {"max_records": 10, "readonly": True}},
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

    mock_client = MagicMock()
    def mock_authorize(**kwargs):
        action = kwargs.get("action", "")
        data = mock_decisions.get(action, {"decision": "deny", "reason": "no matching rule"})
        return Decision.from_dict(data)
    mock_client.authorize = mock_authorize
    mock_client.default_agent_id = AGENT_ID

    # Re-create protected tools with mock client
    @protect(mock_client, agent_id=AGENT_ID, action="tickets.list")
    def mock_list_tickets(**kwargs):
        constraints = kwargs.get("oap_constraints", {})
        max_rec = constraints.get("max_records", 10)
        tickets = [
            {"id": "TKT-1001", "priority": "P2", "subject": "Cannot access dashboard after password reset"},
            {"id": "TKT-1002", "priority": "P1", "subject": "Production database connection timeout"},
            {"id": "TKT-1003", "priority": "P4", "subject": "Feature request: dark mode in settings"},
        ]
        return {"tickets": tickets[:max_rec], "total": len(tickets)}

    @protect(mock_client, agent_id=AGENT_ID, action="tickets.read")
    def mock_read_ticket(ticket_id: str, **kwargs):
        return {"id": ticket_id, "subject": "Cannot access dashboard", "status": "open", "priority": "P2", "customer_id": "CUST-501"}

    @protect(mock_client, agent_id=AGENT_ID, action="customers.read")
    def mock_read_customer(customer_id: str, **kwargs):
        constraints = kwargs.get("oap_constraints", {})
        data = {
            "id": customer_id, "name": "Alice Johnson", "company": "Acme Corp",
            "email": "alice@acmecorp.com", "phone": "+1-555-0101",
            "ssn": "***-**-1234", "credit_card": "****-****-****-5678", "bank_account": "****6789",
        }
        for field in constraints.get("redact_fields", []):
            if field in data:
                data[field] = "[REDACTED by OAP policy]"
        return data

    @protect(mock_client, agent_id=AGENT_ID, action="tickets.update")
    def mock_update_ticket(ticket_id: str, **kwargs):
        return {"id": ticket_id, "status": "in_progress"}

    @protect(mock_client, agent_id=AGENT_ID, action="tickets.escalate")
    def mock_escalate_ticket(ticket_id: str, **kwargs):
        return {"status": "escalated", "ticket": {"id": ticket_id, "status": "escalated"}}

    @protect(mock_client, agent_id=AGENT_ID, action="notifications.send_email")
    def mock_send_email(to: str, subject: str, body: str, **kwargs):
        return {"status": "sent", "message_id": "MSG-0001"}

    @protect(mock_client, agent_id=AGENT_ID, action="tickets.delete")
    def mock_delete_ticket(ticket_id: str, **kwargs):
        return {"status": "deleted"}

    # Run the steps
    step(1, "List open tickets (allowed, max_records=10)")
    result = mock_list_tickets()
    print(f"  ✅ Found {len(result['tickets'])} tickets")
    for t in result["tickets"]:
        print(f"     {t['id']} [{t['priority']}] {t['subject']}")

    step(2, "Read ticket TKT-1001 (allowed)")
    ticket = mock_read_ticket("TKT-1001")
    print(f"  ✅ {ticket['id']}: {ticket['subject']}")
    print(f"     Status: {ticket['status']}, Priority: {ticket['priority']}")

    step(3, "Read customer CUST-501 (allowed, sensitive fields REDACTED)")
    customer = mock_read_customer("CUST-501")
    print(f"  ✅ Customer: {customer['name']} ({customer['company']})")
    print(f"     Email: {customer['email']}")
    print(f"     SSN: {customer['ssn']}")
    print(f"     Credit Card: {customer['credit_card']}")
    print(f"     Bank Account: {customer['bank_account']}")
    if "[REDACTED" in customer["ssn"]:
        print(f"     ✅ Sensitive fields properly redacted by OAP constraints!")

    step(4, "Update TKT-1001 status to 'in_progress' (allowed)")
    result = mock_update_ticket("TKT-1001", status="in_progress")
    print(f"  ✅ Updated: status={result.get('status')}")

    step(5, "Escalate TKT-1002 (P1 — allowed)")
    result = mock_escalate_ticket("TKT-1002")
    print(f"  ✅ Escalated: {result.get('status')}")

    step(6, "Send email notification (approval required)")
    try:
        result = mock_send_email("oncall@company.internal", "TKT-1002 escalated", "P1 ticket escalated.")
        print(f"  ✅ Email sent: {result.get('message_id')}")
    except ApprovalRequiredError as e:
        print(f"  ⏳ Approval required: {e}")

    step(7, "Try to delete TKT-1003 (DENIED — explicit deny rule)")
    try:
        mock_delete_ticket("TKT-1003")
        print(f"  ❌ Should have been denied!")
    except PermissionDeniedError as e:
        print(f"  🛑 BLOCKED: {e}")
        print(f"     Policy enforced: support agents cannot delete tickets")

    banner("Demo Complete — All 7 Steps Executed")
    print("  ✅ Steps 1-5: Allowed (with constraints where applicable)")
    print("  ⏳ Step 6: Approval required")
    print("  🛑 Step 7: Denied by explicit deny rule")
    print("  📋 Constraints enforced: max_records=10, field redaction, allowed_fields")
    print()
    print("  Key takeaway:")
    print("  The agent's tools were wrapped with @protect — each call goes through")
    print("  OAP policy evaluation BEFORE execution. The agent cannot bypass this.")
    print("  Field-level redaction happens automatically via constraint injection.")
    print()


if __name__ == "__main__":
    # Check if OAP server and mock APIs are running
    import httpx

    try:
        httpx.get(f"{OAP_SERVER}/v1/health", timeout=2)
        httpx.get("http://localhost:9100/health", timeout=2)
        print("✓ OAP server and mock APIs detected — running live demo")
        run_demo_with_server()
    except Exception:
        print("⚠ OAP server or mock APIs not running — running offline demo")
        run_demo_offline()
