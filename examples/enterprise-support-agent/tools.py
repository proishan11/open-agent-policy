"""Support agent tools — each wraps a mock API call.

These tools are designed to be wrapped by OAP's @protect decorator,
which authorizes each call before execution and injects constraints.
"""

from __future__ import annotations

import httpx
from typing import Any

API_BASE = "http://localhost:9100"


def read_ticket(ticket_id: str, **kwargs) -> dict:
    """Read a single support ticket by ID."""
    constraints = kwargs.get("oap_constraints", {})
    resp = httpx.get(f"{API_BASE}/api/tickets/{ticket_id}")
    resp.raise_for_status()
    data = resp.json()

    # Apply redaction constraints if present
    redact = constraints.get("redact_fields", [])
    for field in redact:
        if field in data:
            data[field] = "[REDACTED]"

    return data


def list_tickets(status: str | None = None, priority: str | None = None, **kwargs) -> dict:
    """List support tickets with optional filters."""
    constraints = kwargs.get("oap_constraints", {})
    max_records = constraints.get("max_records", 10)

    params: dict[str, Any] = {"limit": max_records}
    if status:
        params["status"] = status
    if priority:
        params["priority"] = priority

    resp = httpx.get(f"{API_BASE}/api/tickets", params=params)
    resp.raise_for_status()
    return resp.json()


def update_ticket(ticket_id: str, status: str | None = None,
                  priority: str | None = None, assignee: str | None = None,
                  **kwargs) -> dict:
    """Update a ticket's status, priority, or assignee."""
    constraints = kwargs.get("oap_constraints", {})
    allowed_fields = constraints.get("allowed_fields", [])

    update = {}
    if status and ("status" in allowed_fields or not allowed_fields):
        update["status"] = status
    if priority and ("priority" in allowed_fields or not allowed_fields):
        update["priority"] = priority
    if assignee and ("assignee" in allowed_fields or not allowed_fields):
        update["assignee"] = assignee

    if not update:
        return {"error": "no allowed fields to update"}

    resp = httpx.patch(f"{API_BASE}/api/tickets/{ticket_id}", json=update)
    resp.raise_for_status()
    return resp.json()


def escalate_ticket(ticket_id: str, **kwargs) -> dict:
    """Escalate a ticket to the escalation team."""
    resp = httpx.post(f"{API_BASE}/api/tickets/{ticket_id}/escalate")
    resp.raise_for_status()
    return resp.json()


def read_customer(customer_id: str, **kwargs) -> dict:
    """Read customer data. Sensitive fields are redacted per policy constraints."""
    constraints = kwargs.get("oap_constraints", {})
    resp = httpx.get(f"{API_BASE}/api/customers/{customer_id}")
    resp.raise_for_status()
    data = resp.json()

    # Apply field-level redaction from OAP constraints
    redact = constraints.get("redact_fields", [])
    for field in redact:
        if field in data:
            data[field] = "[REDACTED by OAP policy]"

    return data


def send_email(to: str, subject: str, body: str, **kwargs) -> dict:
    """Send an email notification."""
    resp = httpx.post(f"{API_BASE}/api/notifications/email", json={
        "to": to,
        "subject": subject,
        "body": body,
    })
    resp.raise_for_status()
    return resp.json()


def delete_ticket(ticket_id: str, **kwargs) -> dict:
    """Delete a ticket. This should always be blocked by OAP policy."""
    resp = httpx.delete(f"{API_BASE}/api/tickets/{ticket_id}")
    resp.raise_for_status()
    return resp.json()
