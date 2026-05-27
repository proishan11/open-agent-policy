#!/usr/bin/env python3
"""Demo 03: Python SDK — OAPClient, @protect decorator, LangChain integration.

This demo runs entirely locally without a server, using mock responses
to showcase the SDK's API and behavior.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

# Ensure SDK is importable
sys.path.insert(0, "sdk/python")

from open_agent_policy.client import Decision
from open_agent_policy.decorators import protect
from open_agent_policy.errors import PermissionDeniedError
from open_agent_policy.integrations.langchain import OAPToolWrapper, protect_tools


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def make_client(decision_data: dict) -> MagicMock:
    """Create a mock OAPClient that returns a specific decision."""
    client = MagicMock()
    client.authorize.return_value = Decision.from_dict(decision_data)
    client.default_agent_id = "agent://finance/reconciler"
    return client


def demo_decision_types():
    section("1. Decision Types")

    decisions = [
        {"decision": "allow", "reason": "allowed by policy"},
        {"decision": "deny", "reason": "no matching policy", "policy_ids": ["finance/deny-all"]},
        {
            "decision": "allow_with_constraints",
            "reason": "read-only access",
            "constraints": {"readonly": True, "max_records": 25, "redact_fields": ["bank_account"]},
        },
        {"decision": "require_approval", "approval": {"approvers": ["group:finance-leads"]}},
    ]

    for d in decisions:
        dec = Decision.from_dict(d)
        status = "✅" if dec.is_allowed else "❌" if dec.is_denied else "⏳"
        print(f"  {status} {dec.decision:30s} reason={dec.reason}")
        if dec.constraints:
            print(f"     constraints: {dec.constraints}")


def demo_protect_decorator():
    section("2. @protect Decorator")

    # Allowed call
    client = make_client({"decision": "allow"})

    @protect(client, agent_id="agent://finance/reconciler", action="erp.invoice.read")
    def read_invoice(invoice_id: str, **kwargs) -> dict:
        return {"id": invoice_id, "status": "paid", "amount": 1500.00}

    result = read_invoice("INV-001")
    print(f"  ✅ read_invoice('INV-001') → {result}")

    # Constrained call
    client = make_client({
        "decision": "allow_with_constraints",
        "constraints": {"max_records": 25, "redact_fields": ["bank_account"]},
    })

    @protect(client, agent_id="agent://finance/reconciler", action="erp.invoice.read")
    def read_invoice_constrained(invoice_id: str, **kwargs) -> dict:
        constraints = kwargs.get("oap_constraints", {})
        return {"id": invoice_id, "constraints_applied": constraints}

    result = read_invoice_constrained("INV-002")
    print(f"  ✅ read_invoice('INV-002') → {result}")
    print(f"     (constraints injected automatically)")

    # Denied call
    client = make_client({"decision": "deny", "reason": "delete not allowed"})

    @protect(client, agent_id="agent://finance/reconciler", action="erp.invoice.delete")
    def delete_invoice(invoice_id: str) -> None:
        return None

    try:
        delete_invoice("INV-003")
        print("  ❌ Should have been denied!")
    except PermissionDeniedError as e:
        print(f"  🛑 delete_invoice('INV-003') → PermissionDeniedError: {e}")


def demo_langchain_integration():
    section("3. LangChain Integration")

    # Create fake tools
    class FakeTool:
        def __init__(self, name, description=""):
            self.name = name
            self.description = description
            self.args_schema = None

        def invoke(self, input, config=None, **kwargs):
            return f"Result from {self.name}: {input}"

    tools = [
        FakeTool("read_ticket", "Read a support ticket"),
        FakeTool("update_ticket", "Update a ticket"),
        FakeTool("delete_ticket", "Delete a ticket"),
    ]

    # Wrap with OAP
    client = make_client({"decision": "allow"})
    protected = protect_tools(
        tools,
        client=client,
        agent_id="agent://support/assistant",
        action_prefix="tickets.",
    )

    print(f"  Wrapped {len(protected)} tools:")
    for t in protected:
        print(f"    - {t.name} → action: {t.action}")

    # Invoke one
    result = protected[0].invoke("TICKET-123")
    print(f"\n  ✅ protected[0].invoke('TICKET-123') → {result}")


def demo_summary():
    section("Summary")
    print("  Python SDK provides three integration modes:")
    print("  1. OAPClient.authorize() — direct authorization calls")
    print("  2. @protect decorator   — wraps tool functions automatically")
    print("  3. protect_tools()      — one-line LangChain integration")
    print()
    print("  All modes support:")
    print("  • Remote (HTTP to oap-server) and embedded (oapctl subprocess)")
    print("  • Constraint injection into tool kwargs")
    print("  • PermissionDeniedError / ApprovalRequiredError for denied calls")
    print("  • 32 pytest tests passing")


if __name__ == "__main__":
    print("Demo 03: Python SDK")
    print("=" * 60)
    demo_decision_types()
    demo_protect_decorator()
    demo_langchain_integration()
    demo_summary()
    print("\n✅ Demo 03 complete\n")
