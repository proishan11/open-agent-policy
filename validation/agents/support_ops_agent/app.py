"""Support Operations Agent — production-like validation version.

Uses real Keycloak for authentication, real OAP server for authorization,
and real resource APIs for data. No mocks.

Usage:
    python app.py --user alice@company.test --task summarize --ticket T-100
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import httpx


# ── Configuration ─────────────────────────────────────────────────────

OAP_SERVER = os.environ.get("OAP_SERVER_URL", "http://oap-server:8080")
TICKET_API = os.environ.get("TICKET_API_URL", "http://ticket-api:9100")
CUSTOMER_API = os.environ.get("CUSTOMER_API_URL", "http://customer-api:9101")
APPROVAL_API = os.environ.get("APPROVAL_API_URL", "http://approval-api:9102")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "oap-validation")
CLIENT_ID = os.environ.get("AGENT_CLIENT_ID", "support-agent")
CLIENT_SECRET = os.environ.get("AGENT_CLIENT_SECRET", "support-agent-secret")

AGENT_ID = "agent://support/ticket-assistant"


# ── Keycloak auth ─────────────────────────────────────────────────────

def get_user_token(username: str, password: str) -> str:
    """Get a real IdP-issued token via resource owner password grant."""
    token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    resp = httpx.post(token_url, data={
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username": username,
        "password": password,
        "scope": "openid",
    })
    if resp.status_code != 200:
        print(f"Authentication failed: {resp.status_code} {resp.text}")
        sys.exit(1)
    return resp.json()["access_token"]


# ── OAP authorization ─────────────────────────────────────────────────

def authorize(actor_id: str, action: str, resource_type: str = "",
              resource_id: str = "", context: dict = None) -> dict:
    """Authorize an action through the real OAP server."""
    req = {
        "request_id": f"agent-{int(time.time() * 1000)}",
        "subject": {
            "type": "agent",
            "agent_id": AGENT_ID,
            "actor": actor_id,
        },
        "action": {"name": action},
        "resource": {"type": resource_type, "id": resource_id},
        "context": context or {},
    }
    resp = httpx.post(f"{OAP_SERVER}/v1/authorize", json=req, timeout=10.0)
    return resp.json()


# ── Protected tools ───────────────────────────────────────────────────

def read_ticket(actor_id: str, ticket_id: str) -> dict | None:
    """Read a ticket — authorized by OAP."""
    decision = authorize(actor_id, "ticket.read", "support.ticket", ticket_id)
    if decision.get("decision") not in ("allow", "allow_with_constraints"):
        print(f"  DENIED: {decision.get('reason', 'no reason')}")
        return None

    resp = httpx.get(f"{TICKET_API}/api/tickets/{ticket_id}")
    resp.raise_for_status()
    data = resp.json()

    # Apply redaction from constraints
    constraints = decision.get("constraints", {})
    for field in constraints.get("redact_fields", []):
        if field in data:
            data[field] = "[REDACTED by OAP]"

    return data


def read_customer(actor_id: str, customer_id: str) -> dict | None:
    """Read customer data — authorized by OAP with redaction."""
    decision = authorize(actor_id, "customer.read", "crm.customer", customer_id)
    if decision.get("decision") not in ("allow", "allow_with_constraints"):
        print(f"  DENIED: {decision.get('reason', 'no reason')}")
        return None

    resp = httpx.get(f"{CUSTOMER_API}/api/customers/{customer_id}")
    resp.raise_for_status()
    data = resp.json()

    constraints = decision.get("constraints", {})
    for field in constraints.get("redact_fields", []):
        if field in data:
            data[field] = "[REDACTED by OAP]"

    return data


def bulk_export(actor_id: str) -> dict | None:
    """Attempt bulk export — should be denied."""
    decision = authorize(actor_id, "ticket.bulk_export", "support.ticket")
    if decision.get("decision") not in ("allow", "allow_with_constraints"):
        print(f"  DENIED: {decision.get('reason', 'no reason')}")
        return None
    return {"error": "should not reach here"}


# ── Agent tasks ───────────────────────────────────────────────────────

def task_summarize(actor_id: str, ticket_id: str):
    """Summarize a ticket and its customer."""
    print(f"\nTask: Summarize ticket {ticket_id} for {actor_id}")
    print("=" * 60)

    print(f"\n1. Reading ticket {ticket_id}...")
    ticket = read_ticket(actor_id, ticket_id)
    if ticket:
        print(f"   Subject: {ticket.get('subject')}")
        print(f"   Status: {ticket.get('status')}")
        print(f"   Priority: {ticket.get('priority')}")
        print(f"   Assigned: {ticket.get('assigned_to')}")

        customer_id = ticket.get("customer_id")
        if customer_id:
            print(f"\n2. Reading customer {customer_id}...")
            customer = read_customer(actor_id, customer_id)
            if customer:
                print(f"   Name: {customer.get('name')}")
                print(f"   Company: {customer.get('company')}")
                print(f"   Region: {customer.get('region')}")
                print(f"   Tax ID: {customer.get('tax_identifier')}")
                print(f"   Bank: {customer.get('bank_account')}")

    print("\n3. Attempting bulk export (should be denied)...")
    bulk_export(actor_id)


def task_cross_user(actor_id: str, ticket_id: str):
    """Attempt to read another user's ticket."""
    print(f"\nTask: Read ticket {ticket_id} as {actor_id}")
    print("=" * 60)
    read_ticket(actor_id, ticket_id)


# ── Main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Support Operations Agent")
    parser.add_argument("--user", required=True, help="User email")
    parser.add_argument("--password", default="", help="User password")
    parser.add_argument("--task", required=True, choices=["summarize", "cross_user", "bulk_export"])
    parser.add_argument("--ticket", default="T-100", help="Ticket ID")
    args = parser.parse_args()

    # Authenticate with real IdP
    if args.password:
        print(f"Authenticating {args.user} via Keycloak...")
        token = get_user_token(args.user, args.password)
        print(f"  Token obtained ({len(token)} chars)")

    if args.task == "summarize":
        task_summarize(args.user, args.ticket)
    elif args.task == "cross_user":
        task_cross_user(args.user, args.ticket)
    elif args.task == "bulk_export":
        print(f"\nTask: Bulk export as {args.user}")
        print("=" * 60)
        bulk_export(args.user)


if __name__ == "__main__":
    main()
