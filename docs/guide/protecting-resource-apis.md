# Protecting Resource APIs

This guide shows how a resource API should enforce OAP decisions. The key rule
is simple: **the resource API must validate an OAP grant before serving data or
performing a mutation**.

For a minimal runnable protected API, see
[examples/minimal-agent/resource_api.py](../../examples/minimal-agent/resource_api.py).

Do not trust:

- the agent's prompt
- the requested `agent_id`
- a client-side SDK decision alone
- a broad API key held by the agent

Trust only a valid, scoped, short-lived grant issued by OAP.

## Grant Flow

```text
Agent -> OAP /v1/authorize
  <- allow + grant token

Agent -> Resource API with X-OAP-Grant-Token
Resource API -> OAP /v1/grants/validate
  <- valid, agent_id, action, resource_type, resource_id, constraints

Resource API checks scope
Resource API applies constraints
Resource API serves or rejects the request
```

## Required Checks

Every protected resource handler should check:

| Check | Example |
|---|---|
| Grant exists | `X-OAP-Grant-Token` is present |
| Grant validates | `/v1/grants/validate` returns `valid: true` |
| Decision permits access | `decision` is `allow` or `allow_with_constraints` |
| Action matches | grant action is `ticket.read` for a read endpoint |
| Resource type matches | grant resource type is `support.ticket` |
| Resource ID matches | grant resource ID is `T-100` for `/tickets/T-100` |
| Constraints are enforced | redact fields, cap records, restrict update fields |

If any check fails, return `401` for missing grants and `403` for invalid or
mismatched grants.

## FastAPI Example

```python
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()
OAP_SERVER_URL = "http://localhost:8080"

async def require_oap_grant(
    grant_token: str | None,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
) -> dict[str, Any]:
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
        raise HTTPException(status_code=403, detail="OAP grant does not allow access")
    if grant.get("action") != action:
        raise HTTPException(status_code=403, detail="OAP grant action mismatch")
    if grant.get("resource_type") != resource_type:
        raise HTTPException(status_code=403, detail="OAP grant resource type mismatch")
    if resource_id is not None and (grant.get("resource_id") or "") != resource_id:
        raise HTTPException(status_code=403, detail="OAP grant resource id mismatch")

    return grant

def redact_record(grant: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(record)
    for field in (grant.get("constraints") or {}).get("redact_fields") or []:
        if field in redacted:
            redacted[field] = "<redacted>"
    return redacted

@app.get("/api/customers/{customer_id}")
async def get_customer(
    customer_id: str,
    x_oap_grant_token: str | None = Header(default=None, alias="X-OAP-Grant-Token"),
):
    grant = await require_oap_grant(
        x_oap_grant_token,
        action="customer.read",
        resource_type="crm.customer",
        resource_id=customer_id,
    )

    customer = await load_customer(customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="customer not found")

    return redact_record(grant, customer)
```

The validation APIs use this exact pattern in
`validation/resources/ticket-api/oap_guard.py` and
`validation/resources/customer-api/oap_guard.py`.

## Enforcing Constraints

OAP constraints are obligations on the enforcement point. Common examples:

### Max records

```python
def constrained_limit(grant: dict[str, Any], requested_limit: int) -> int:
    max_records = (grant.get("constraints") or {}).get("max_records")
    if isinstance(max_records, int) and max_records > 0:
        return min(requested_limit, max_records)
    return requested_limit
```

### Field redaction

```python
for field in grant.get("constraints", {}).get("redact_fields", []):
    record[field] = "<redacted>"
```

### Allowed update fields

```python
allowed_fields = set(grant.get("constraints", {}).get("allowed_fields", []))
requested_fields = set(update_payload.keys())
if allowed_fields and not requested_fields <= allowed_fields:
    raise HTTPException(status_code=403, detail="field update not allowed")
```

## Go Middleware

For Go services, use the grant middleware:

```go
mw := gateway.NewGrantMiddleware(gateway.GrantMiddlewareConfig{
    OAPServerURL: "http://oap-server:8080",
    HeaderName:   "X-OAP-Grant-Token",
    AllowMissing: false,
})

http.Handle("/api/", mw.Wrap(myAPIHandler))
```

The middleware validates the grant and adds verified headers such as:

```text
X-OAP-Verified-Agent-ID
X-OAP-Verified-Action
X-OAP-Verified-Decision
X-OAP-Run-ID
```

Your handler should still verify that the action and resource match the endpoint
you are serving.

## Testing A Protected Resource

Use the validation stack as a reference:

```bash
# Missing grant is rejected
curl -i http://localhost:9100/api/tickets/T-100
# -> 401

# Full e2e test suite
docker compose -f validation/docker-compose.yml --profile test run --rm e2e-tests
```

Recommended tests for your API:

- missing grant returns 401
- forged grant returns 403
- grant for another resource returns 403
- grant for another action returns 403
- allow grant returns data
- constrained grant applies redaction or record limits
- denied OAP decision never produces a usable grant

## Common Mistakes

- Calling OAP from the agent but leaving the API directly accessible without
  grant validation.
- Validating only that a grant is signed, without checking action and resource.
- Applying constraints in the agent instead of in the resource API.
- Using broad resource IDs such as `*` for endpoints that serve one record.
- Treating `require_approval` as an allow.
- Reusing one grant for multiple resource calls.

Next:

- [Building Agents With OAP](building-agents-with-oap.md)
- [Approval Workflows](approval-workflows.md)
- [Integration Guide](integration.md)
