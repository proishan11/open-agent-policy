"""Approval API — real FastAPI service backed by PostgreSQL.

Manages approval workflows for risky agent actions (e.g., external messaging).
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


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


app = FastAPI(title="Approval API", version="1.0.0", lifespan=lifespan)


# ── Models ────────────────────────────────────────────────────────────

class ApprovalRequest(BaseModel):
    agent_id: str
    actor_id: str
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    purpose: Optional[str] = None
    expires_in_minutes: int = 15


class ApprovalDecision(BaseModel):
    approver_id: str
    decision: str  # "approved" or "denied"


# ── Endpoints ─────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM approvals")
    return {"status": "healthy", "approvals": count}


@app.post("/api/approvals")
async def create_approval(req: ApprovalRequest):
    approval_id = f"APR-{uuid.uuid4().hex[:8]}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=req.expires_in_minutes)

    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO approvals (id, agent_id, actor_id, action, resource_type, resource_id, purpose, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
            approval_id, req.agent_id, req.actor_id, req.action,
            req.resource_type, req.resource_id, req.purpose, expires_at,
        )
    return {
        "id": approval_id,
        "status": "pending",
        "expires_at": expires_at.isoformat() + "Z",
    }


@app.get("/api/approvals/{approval_id}")
async def get_approval(approval_id: str):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM approvals WHERE id = $1", approval_id
        )
    if not row:
        raise HTTPException(404, f"Approval {approval_id} not found")
    record = dict(row)
    # Check expiry
    if record["status"] == "pending" and record["expires_at"] and record["expires_at"] < datetime.now(timezone.utc):
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE approvals SET status = 'expired' WHERE id = $1", approval_id
            )
        record["status"] = "expired"
    return record


@app.post("/api/approvals/{approval_id}/decide")
async def decide_approval(approval_id: str, decision: ApprovalDecision):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM approvals WHERE id = $1", approval_id
        )
        if not row:
            raise HTTPException(404, f"Approval {approval_id} not found")
        record = dict(row)
        if record["status"] != "pending":
            raise HTTPException(409, f"Approval already {record['status']}")
        if record["expires_at"] and record["expires_at"] < datetime.now(timezone.utc):
            await conn.execute(
                "UPDATE approvals SET status = 'expired' WHERE id = $1", approval_id
            )
            raise HTTPException(410, "Approval expired")

        new_status = decision.decision
        if new_status not in ("approved", "denied"):
            raise HTTPException(400, "Decision must be 'approved' or 'denied'")

        updated = await conn.fetchrow(
            """UPDATE approvals SET status = $1, approver_id = $2, approved_at = $3
               WHERE id = $4 RETURNING *""",
            new_status, decision.approver_id, datetime.now(timezone.utc), approval_id,
        )
    return dict(updated)


@app.get("/api/approvals")
async def list_approvals(
    agent_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    status: Optional[str] = None,
):
    query = "SELECT * FROM approvals WHERE 1=1"
    params = []
    idx = 1
    if agent_id:
        query += f" AND agent_id = ${idx}"
        params.append(agent_id)
        idx += 1
    if actor_id:
        query += f" AND actor_id = ${idx}"
        params.append(actor_id)
        idx += 1
    if status:
        query += f" AND status = ${idx}"
        params.append(status)
        idx += 1
    query += " ORDER BY created_at DESC LIMIT 100"

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return {"approvals": [dict(r) for r in rows]}


@app.post("/api/approvals/{approval_id}/validate")
async def validate_approval(approval_id: str, agent_id: str, actor_id: str, action: str, resource_id: Optional[str] = None):
    """Validate that an approval matches the requested scope."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM approvals WHERE id = $1", approval_id
        )
    if not row:
        return {"valid": False, "reason": "approval not found"}
    record = dict(row)

    if record["status"] != "approved":
        return {"valid": False, "reason": f"approval status is {record['status']}"}
    if record["expires_at"] and record["expires_at"] < datetime.now(timezone.utc):
        return {"valid": False, "reason": "approval expired"}
    if record["agent_id"] != agent_id:
        return {"valid": False, "reason": "agent_id mismatch"}
    if record["actor_id"] != actor_id:
        return {"valid": False, "reason": "actor_id mismatch"}
    if record["action"] != action:
        return {"valid": False, "reason": "action mismatch"}
    if resource_id and record["resource_id"] and record["resource_id"] != resource_id:
        return {"valid": False, "reason": "resource_id mismatch"}

    return {"valid": True, "approval": record}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9102)
