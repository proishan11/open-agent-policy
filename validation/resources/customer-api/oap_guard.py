"""OAP grant enforcement helpers for validation resource APIs."""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any

import httpx
from fastapi import HTTPException


OAP_SERVER_URL = os.environ.get("OAP_SERVER_URL", "http://oap-server:8080").rstrip("/")
REQUIRE_GRANTS = os.environ.get("OAP_REQUIRE_GRANTS", "true").lower() not in {
    "0",
    "false",
    "no",
}
REDACTED = "<redacted>"


async def require_oap_grant(
    grant_token: str | None,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
) -> dict[str, Any]:
    if not REQUIRE_GRANTS:
        return {}
    if not grant_token:
        raise HTTPException(status_code=401, detail="X-OAP-Grant-Token is required")

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{OAP_SERVER_URL}/v1/grants/validate",
            json={"grant_token": grant_token},
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=403, detail="OAP grant validation failed")

    grant = resp.json()
    if grant.get("valid") is not True:
        raise HTTPException(status_code=403, detail="OAP grant is not valid")
    if grant.get("decision") not in ("allow", "allow_with_constraints"):
        raise HTTPException(status_code=403, detail="OAP grant decision is not allow")
    if grant.get("action") != action:
        raise HTTPException(status_code=403, detail="OAP grant action mismatch")
    if grant.get("resource_type") != resource_type:
        raise HTTPException(status_code=403, detail="OAP grant resource type mismatch")

    grant_resource_id = grant.get("resource_id") or ""
    if resource_id is not None and grant_resource_id != resource_id:
        raise HTTPException(status_code=403, detail="OAP grant resource id mismatch")
    return grant


def constrained_limit(grant: dict[str, Any], requested_limit: int) -> int:
    max_records = (grant.get("constraints") or {}).get("max_records")
    if isinstance(max_records, int) and max_records > 0:
        return min(requested_limit, max_records)
    return requested_limit


def ensure_allowed_fields(grant: dict[str, Any], fields: Iterable[str]) -> None:
    allowed_fields = (grant.get("constraints") or {}).get("allowed_fields")
    if not allowed_fields:
        return
    disallowed = sorted(set(fields) - set(allowed_fields))
    if disallowed:
        raise HTTPException(
            status_code=403,
            detail=f"OAP grant does not allow fields: {', '.join(disallowed)}",
        )


def redact_record(grant: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(record)
    for field in (grant.get("constraints") or {}).get("redact_fields") or []:
        if field in redacted:
            redacted[field] = REDACTED
    return redacted
