"""Mock ticketing and CRM APIs for the enterprise support agent demo.

Run with: uvicorn examples.enterprise-support-agent.mock_apis.server:app --port 9100
Or:       python -m examples.enterprise-support-agent.mock_apis.server
"""

from __future__ import annotations

import json
import uvicorn
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Mock Support APIs", version="1.0.0")

# ── In-memory data ──────────────────────────────────────────────────────

TICKETS = {
    "TKT-1001": {
        "id": "TKT-1001",
        "subject": "Cannot access dashboard after password reset",
        "customer_id": "CUST-501",
        "status": "open",
        "priority": "P2",
        "assignee": None,
        "created_at": "2026-05-20T10:30:00Z",
        "tags": ["access", "password", "dashboard"],
    },
    "TKT-1002": {
        "id": "TKT-1002",
        "subject": "Production database connection timeout",
        "customer_id": "CUST-502",
        "status": "open",
        "priority": "P1",
        "assignee": "oncall@company.internal",
        "created_at": "2026-05-27T08:15:00Z",
        "tags": ["database", "production", "critical"],
    },
    "TKT-1003": {
        "id": "TKT-1003",
        "subject": "Feature request: dark mode in settings",
        "customer_id": "CUST-503",
        "status": "open",
        "priority": "P4",
        "assignee": None,
        "created_at": "2026-05-25T14:00:00Z",
        "tags": ["feature-request", "ui"],
    },
    "TKT-1004": {
        "id": "TKT-1004",
        "subject": "Billing discrepancy on May invoice",
        "customer_id": "CUST-504",
        "status": "open",
        "priority": "P3",
        "assignee": None,
        "created_at": "2026-05-26T09:45:00Z",
        "tags": ["billing", "invoice"],
    },
    "TKT-1005": {
        "id": "TKT-1005",
        "subject": "SSO integration failing with Azure AD",
        "customer_id": "CUST-505",
        "status": "in_progress",
        "priority": "P2",
        "assignee": "identity-team@company.internal",
        "created_at": "2026-05-24T11:20:00Z",
        "tags": ["sso", "azure-ad", "integration"],
    },
}

CUSTOMERS = {
    "CUST-501": {
        "id": "CUST-501",
        "name": "Alice Johnson",
        "email": "alice@acmecorp.com",
        "company": "Acme Corp",
        "plan": "enterprise",
        "ssn": "***-**-1234",
        "credit_card": "****-****-****-5678",
        "bank_account": "****6789",
        "phone": "+1-555-0101",
    },
    "CUST-502": {
        "id": "CUST-502",
        "name": "Bob Chen",
        "email": "bob.chen@megacorp.io",
        "company": "MegaCorp",
        "plan": "enterprise",
        "ssn": "***-**-5678",
        "credit_card": "****-****-****-9012",
        "bank_account": "****3456",
        "phone": "+1-555-0202",
    },
    "CUST-503": {
        "id": "CUST-503",
        "name": "Carol Davis",
        "email": "carol@startup.dev",
        "company": "StartupDev",
        "plan": "pro",
        "ssn": "***-**-9012",
        "credit_card": "****-****-****-3456",
        "bank_account": "****7890",
        "phone": "+1-555-0303",
    },
    "CUST-504": {
        "id": "CUST-504",
        "name": "David Park",
        "email": "david.park@bigbank.com",
        "company": "BigBank Financial",
        "plan": "enterprise",
        "ssn": "***-**-3456",
        "credit_card": "****-****-****-7890",
        "bank_account": "****1234",
        "phone": "+1-555-0404",
    },
    "CUST-505": {
        "id": "CUST-505",
        "name": "Eve Martinez",
        "email": "eve.m@globaltech.com",
        "company": "GlobalTech Industries",
        "plan": "enterprise",
        "ssn": "***-**-7890",
        "credit_card": "****-****-****-1234",
        "bank_account": "****5678",
        "phone": "+1-555-0505",
    },
}

EMAILS_SENT: list[dict] = []


# ── Ticket endpoints ────────────────────────────────────────────────────

@app.get("/api/tickets")
def list_tickets(status: str | None = None, priority: str | None = None, limit: int = 10):
    tickets = list(TICKETS.values())
    if status:
        tickets = [t for t in tickets if t["status"] == status]
    if priority:
        tickets = [t for t in tickets if t["priority"] == priority]
    return {"tickets": tickets[:limit], "total": len(tickets)}


@app.get("/api/tickets/{ticket_id}")
def get_ticket(ticket_id: str):
    if ticket_id not in TICKETS:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    return TICKETS[ticket_id]


class TicketUpdate(BaseModel):
    status: str | None = None
    priority: str | None = None
    assignee: str | None = None


@app.patch("/api/tickets/{ticket_id}")
def update_ticket(ticket_id: str, update: TicketUpdate):
    if ticket_id not in TICKETS:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    ticket = TICKETS[ticket_id]
    if update.status:
        ticket["status"] = update.status
    if update.priority:
        ticket["priority"] = update.priority
    if update.assignee:
        ticket["assignee"] = update.assignee
    return ticket


@app.post("/api/tickets/{ticket_id}/escalate")
def escalate_ticket(ticket_id: str):
    if ticket_id not in TICKETS:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    ticket = TICKETS[ticket_id]
    ticket["status"] = "escalated"
    ticket["assignee"] = "escalation-team@company.internal"
    return {"status": "escalated", "ticket": ticket}


@app.delete("/api/tickets/{ticket_id}")
def delete_ticket(ticket_id: str):
    if ticket_id not in TICKETS:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    del TICKETS[ticket_id]
    return {"status": "deleted"}


# ── Customer endpoints ──────────────────────────────────────────────────

@app.get("/api/customers/{customer_id}")
def get_customer(customer_id: str):
    if customer_id not in CUSTOMERS:
        raise HTTPException(404, f"Customer {customer_id} not found")
    return CUSTOMERS[customer_id]


# ── Notification endpoints ──────────────────────────────────────────────

class EmailRequest(BaseModel):
    to: str
    subject: str
    body: str


@app.post("/api/notifications/email")
def send_email(email: EmailRequest):
    record = {
        "to": email.to,
        "subject": email.subject,
        "body": email.body,
        "sent_at": datetime.utcnow().isoformat() + "Z",
    }
    EMAILS_SENT.append(record)
    return {"status": "sent", "message_id": f"MSG-{len(EMAILS_SENT):04d}"}


@app.get("/api/notifications/emails")
def list_emails():
    return {"emails": EMAILS_SENT}


# ── Health ──────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "healthy", "tickets": len(TICKETS), "customers": len(CUSTOMERS)}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9100)
