"""Customer API — real FastAPI service backed by PostgreSQL.

Provides read-only customer data with region and classification metadata.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Optional

import asyncpg
from fastapi import FastAPI, HTTPException, Query


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


app = FastAPI(title="Customer API", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM customers")
    return {"status": "healthy", "customers": count}


@app.get("/api/customers")
async def list_customers(
    region: Optional[str] = None,
    classification: Optional[str] = None,
    limit: int = Query(default=25, le=100),
):
    query = "SELECT * FROM customers WHERE 1=1"
    params = []
    idx = 1
    if region:
        query += f" AND region = ${idx}"
        params.append(region)
        idx += 1
    if classification:
        query += f" AND classification = ${idx}"
        params.append(classification)
        idx += 1
    query += f" ORDER BY created_at DESC LIMIT ${idx}"
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return {"customers": [dict(r) for r in rows], "total": len(rows)}


@app.get("/api/customers/{customer_id}")
async def get_customer(customer_id: str):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM customers WHERE id = $1", customer_id
        )
    if not row:
        raise HTTPException(404, f"Customer {customer_id} not found")
    return dict(row)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9101)
