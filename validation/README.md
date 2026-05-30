# OAP Production-Like Validation Environment

Production-like validation testbed for Open Agent Policy (OAP).
Proves OAP can govern a real agent application using real identity providers,
real APIs, real databases, and real audit — no mocks.

## Architecture

```
Human user (alice, bob, charlie, dana, eve)
  |
  | authenticates through Keycloak (real OIDC)
  v
Support Ops Agent (Python + OAP SDK)
  |
  | authorizes via OAP server
  v
OAP Policy Evaluation Layer (Go server)
  |
  | validates agent, actor, action, resource, context, policy
  | issues a short-lived scoped grant
  v
Protected Resource APIs (ticket-api, customer-api)
  |
  | require X-OAP-Grant-Token and call /v1/grants/validate
  |
  v
PostgreSQL (synthetic data)
  |
  v
Audit sink (JSONL + Postgres audit table)
```

## Quick Start

```bash
# 1. Start the full environment
docker compose --profile test build
docker compose up -d

# 2. Wait for services to be healthy
docker compose ps

# 3. Run the E2E test suite
docker compose --profile test run --rm e2e-tests

# 4. View OAP audit logs
docker compose exec postgres psql -U oap -d oap -c "SELECT id, agent_id, action, decision, created_at FROM oap_audit_events ORDER BY created_at DESC LIMIT 20;"
```

Expected test result: `74 passed`.

## OPA Backend Profile

The `opa-test` profile validates the public `oap-server --policy-backend opa`
path with a real OPA sidecar, real Keycloak sessions, Postgres audit queries,
and resource APIs pointed at the OPA-backed OAP server.

```bash
docker compose --profile opa-test build \
  e2e-tests-opa oap-server-opa oap-server-opa-unavailable ticket-api-opa customer-api-opa
docker compose --profile opa-test run --rm e2e-tests-opa
```

Expected OPA profile result: `6 passed`.

This profile proves:

- OAP reports `policy_backend=opa` through `/v1/health`.
- OPA returns constrained allow decisions that still receive OAP grants.
- Ticket and customer APIs enforce grants and OPA-supplied constraints.
- Deny decisions from OPA do not issue grants and are queryable in audit.
- `require_approval` details returned by OPA are mapped into OAP decisions.
- An OPA-backed OAP server with an unavailable OPA URL denies fail-closed and
  still emits an audit event.

## What This Proves

- Resource APIs reject direct access without `X-OAP-Grant-Token`.
- OAP-issued grants unlock only their scoped action and resource.
- Grant replay against another ticket/customer is rejected.
- Customer redaction constraints are enforced by the resource API.
- External channel messaging returns `require_approval`.
- Approval replay with the wrong resource, agent, or actor is rejected.
- OAP rejects missing, forged, or spoofed agent identity.
- Allow, approval-required, and deny authorization decisions are queryable in
  durable audit storage by unique `request_id`.

## Services

| Service | Port | Description |
|---|---|---|
| keycloak | 8443 | Real IdP with OIDC/OAuth flows |
| postgres | 5432 | Data store for APIs + OAP + audit |
| oap-server | 8080 | OAP policy evaluation server |
| ticket-api | 9100 | Support ticket REST API protected by OAP grants |
| customer-api | 9101 | Customer/CRM REST API protected by OAP grants and redaction constraints |
| approval-api | 9102 | Approval workflow API |
| opa | 8181 | OPA sidecar used by the `opa-test` profile |
| oap-server-opa | 18080 | OAP server running `--policy-backend opa` |
| oap-server-opa-unavailable | 18081 | OAP server pointed at a dead OPA URL for fail-closed validation |
| ticket-api-opa | 19100 | Ticket API pointed at `oap-server-opa` |
| customer-api-opa | 19101 | Customer API pointed at `oap-server-opa` |
| support-agent | — | Python support ops agent |
| e2e-tests | — | Pytest E2E test runner |
| e2e-tests-opa | — | Pytest OPA backend validation runner |

## Test Users (Keycloak)

| User | Password | Role | Region |
|---|---|---|---|
| alice@company.test | alice123 | support_l1 | US |
| bob@company.test | bob123 | support_l2 | EU |
| charlie@company.test | charlie123 | support_manager | global |
| dana@company.test | dana123 | security_admin | global |
| eve@company.test | eve123 | suspended_user | — |

## Scenarios

15 scenarios covering: happy path, cross-user denial, region mismatch,
restricted customer, bulk export, internal/external messaging, approval
workflows, prompt injection, suspended user, revoked agent, unknown agent,
grant replay, direct bypass prevention, and privilege escalation.

See `scenarios/` for declarative YAML definitions.

## Running Individual Tests

```bash
# All E2E tests
pytest tests/e2e/ -v

# Security tests only
pytest tests/security/ -v

# Single scenario
pytest tests/e2e/test_keycloak_e2e.py::test_S001_happy_path -v
```
