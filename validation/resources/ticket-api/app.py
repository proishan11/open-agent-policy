"""Ticket API — real FastAPI service backed by PostgreSQL.

Provides CRUD for support tickets with assignment and classification enforcement.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import asyncpg
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from oap_guard import constrained_limit, ensure_allowed_fields, require_oap_grant


DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://oap:oap@postgres:5432/oap"
)

pool: asyncpg.Pool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    yield
    await pool.close()


app = FastAPI(title="Ticket API", version="1.0.0", lifespan=lifespan)


# ── Models ────────────────────────────────────────────────────────────

class TicketUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assignee: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM tickets")
    return {"status": "healthy", "tickets": count}


@app.get("/api/tickets")
async def list_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(default=25, le=100),
    x_oap_grant_token: Optional[str] = Header(default=None, alias="X-OAP-Grant-Token"),
):
    grant = await require_oap_grant(
        x_oap_grant_token,
        action="ticket.read",
        resource_type="support.ticket",
    )
    limit = constrained_limit(grant, limit)

    query = "SELECT * FROM tickets WHERE 1=1"
    params = []
    idx = 1
    if status:
        query += f" AND status = ${idx}"
        params.append(status)
        idx += 1
    if priority:
        query += f" AND priority = ${idx}"
        params.append(priority)
        idx += 1
    if assigned_to:
        query += f" AND assigned_to = ${idx}"
        params.append(assigned_to)
        idx += 1
    query += f" ORDER BY created_at DESC LIMIT ${idx}"
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return {"tickets": [dict(r) for r in rows], "total": len(rows)}


@app.get("/api/tickets/{ticket_id}")
async def get_ticket(
    ticket_id: str,
    x_oap_grant_token: Optional[str] = Header(default=None, alias="X-OAP-Grant-Token"),
):
    await require_oap_grant(
        x_oap_grant_token,
        action="ticket.read",
        resource_type="support.ticket",
        resource_id=ticket_id,
    )
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM tickets WHERE id = $1", ticket_id)
    if not row:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    return dict(row)


@app.patch("/api/tickets/{ticket_id}")
async def update_ticket(
    ticket_id: str,
    update: TicketUpdate,
    x_oap_grant_token: Optional[str] = Header(default=None, alias="X-OAP-Grant-Token"),
):
    grant = await require_oap_grant(
        x_oap_grant_token,
        action="ticket.update",
        resource_type="support.ticket",
        resource_id=ticket_id,
    )
    update_fields = update.model_dump(exclude_none=True).keys()
    ensure_allowed_fields(grant, update_fields)

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM tickets WHERE id = $1", ticket_id)
        if not row:
            raise HTTPException(404, f"Ticket {ticket_id} not found")
        sets = []
        params = []
        idx = 1
        if update.status is not None:
            sets.append(f"status = ${idx}")
            params.append(update.status)
            idx += 1
        if update.priority is not None:
            sets.append(f"priority = ${idx}")
            params.append(update.priority)
            idx += 1
        if update.assignee is not None:
            sets.append(f"assignee = ${idx}")
            params.append(update.assignee)
            idx += 1
        if not sets:
            return dict(row)
        sets.append(f"updated_at = ${idx}")
        params.append(datetime.utcnow())
        idx += 1
        params.append(ticket_id)
        query = f"UPDATE tickets SET {', '.join(sets)} WHERE id = ${idx} RETURNING *"
        updated = await conn.fetchrow(query, *params)
    return dict(updated)


@app.post("/api/tickets/{ticket_id}/escalate")
async def escalate_ticket(
    ticket_id: str,
    x_oap_grant_token: Optional[str] = Header(default=None, alias="X-OAP-Grant-Token"),
):
    await require_oap_grant(
        x_oap_grant_token,
        action="escalation.issue.create",
        resource_type="support.ticket",
        resource_id=ticket_id,
    )
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM tickets WHERE id = $1", ticket_id)
        if not row:
            raise HTTPException(404, f"Ticket {ticket_id} not found")
        updated = await conn.fetchrow(
            "UPDATE tickets SET status = 'escalated', assignee = 'escalation-team@company.internal', updated_at = $1 WHERE id = $2 RETURNING *",
            datetime.utcnow(), ticket_id,
        )
    return {"status": "escalated", "ticket": dict(updated)}


@app.delete("/api/tickets/{ticket_id}")
async def delete_ticket(
    ticket_id: str,
    x_oap_grant_token: Optional[str] = Header(default=None, alias="X-OAP-Grant-Token"),
):
    await require_oap_grant(
        x_oap_grant_token,
        action="ticket.delete",
        resource_type="support.ticket",
        resource_id=ticket_id,
    )
    async with pool.acquire() as conn:
        row = await conn.fetchrow("DELETE FROM tickets WHERE id = $1 RETURNING id", ticket_id)
    if not row:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    return {"status": "deleted", "id": ticket_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9100)
