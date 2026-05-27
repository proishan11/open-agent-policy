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
  v
Protected Resource APIs (ticket-api, customer-api, approval-api)
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
docker compose up -d

# 2. Wait for services to be healthy
docker compose ps

# 3. Run the E2E test suite
docker compose run --rm e2e-tests

# 4. View audit logs
docker compose exec postgres psql -U oap -d oap -c "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 20;"
```

## Services

| Service | Port | Description |
|---|---|---|
| keycloak | 8443 | Real IdP with OIDC/OAuth flows |
| postgres | 5432 | Data store for APIs + OAP + audit |
| oap-server | 8080 | OAP policy evaluation server |
| ticket-api | 9100 | Support ticket REST API |
| customer-api | 9101 | Customer/CRM REST API |
| approval-api | 9102 | Approval workflow API |
| support-agent | — | Python support ops agent |
| e2e-tests | — | Pytest E2E test runner |

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
grant replay, direct bypass, and privilege escalation.

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
