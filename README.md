# Open Agent Policy (OAP)

> Zero-trust authorization for AI agents, tools, and resource APIs.

[![CI](https://github.com/proishan11/open-agent-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/proishan11/open-agent-policy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-blue.svg)](https://conventionalcommits.org)

Open Agent Policy makes AI agents first-class security principals. It lets you register agents, bind them to real runtime identity, evaluate every tool or API action against policy, issue short-lived scoped grants, require human approval for risky actions, and audit what happened.

The important design point: **the agent does not self-enforce**. OAP makes the decision, and protected resource APIs accept only OAP grants scoped to the exact action and resource.

## Build With OAP

If you are building an autonomous agent, OAP fits into your stack in three
places:

1. **Agent/tool layer** - authorize each tool call with the SDK, decorator,
   LangChain wrapper, gateway, or MCP proxy.
2. **Policy layer** - define what actions the agent may perform, what requires
   approval, and what constraints apply.
3. **Resource layer** - validate OAP grant tokens before serving protected data
   or performing mutations.

Start here:

- [Minimal OAP Example](examples/minimal-agent/README.md) - deterministic walkthrough, Ollama agent, and LangChain agent
- [Auth Protocol Examples](examples/auth-protocols/README.md) - OIDC/OAuth, Kubernetes, SPIFFE, and WIMSE templates
- [Policy Backend Examples](examples/policy-backends/README.md) - OPA and Cedar server/backend examples
- [Building Agents With OAP](docs/guide/building-agents-with-oap.md) - end-to-end developer path for agent builders
- [Protecting Resource APIs](docs/guide/protecting-resource-apis.md) - how APIs validate grants and enforce constraints
- [Approval Workflows](docs/guide/approval-workflows.md) - how to handle `require_approval`
- [Integration Guide](docs/guide/integration.md) - SDK, decorator, LangChain, gateway, and MCP proxy patterns
- [Authentication Protocols](docs/guide/authentication-protocols.md) - OIDC/OAuth, Kubernetes, SPIFFE, WIMSE, sessions, and grants
- [Policy Backends](docs/guide/policy-backends.md) - built-in policy path plus OPA and Cedar server modes
- [Writing Policies](docs/guide/writing-policies.md) - policy vocabulary and examples

The shortest mental model is:

```text
agent wants to call a tool
  -> ask OAP
  -> if allowed, receive scoped grant
  -> call protected API with X-OAP-Grant-Token
  -> resource API validates grant and applies constraints
```

## What You Can Try Locally

The repository includes a local production-like validation environment:

- Keycloak for real OIDC tokens.
- Postgres for durable OAP state and audit records.
- OAP server with sessions, runs, scoped grants, and grant validation.
- Ticket and customer APIs that reject direct access without `X-OAP-Grant-Token`.
- Approval API for risky actions and replay/scope validation.
- Optional OPA sidecar profile that runs `oap-server --policy-backend opa`.
- Pytest suite covering identity spoofing, prompt injection attempts, grant replay, privilege escalation, resource-side redaction, and direct API bypass prevention.

This is meant for local development and evaluation, not a hardened deployment recipe.

## Local Quick Start

### Prerequisites

- Docker Desktop or Docker Engine with Compose.
- Go 1.25+.
- Python 3.11+.
- Make.

### 1. Clone and Build

```bash
git clone https://github.com/proishan11/open-agent-policy.git
cd open-agent-policy

make venv
source .venv/bin/activate
make build
```

### 2. Run the Local Validation Stack

```bash
docker compose -f validation/docker-compose.yml --profile test build
docker compose -f validation/docker-compose.yml up -d \
  postgres keycloak oap-server ticket-api customer-api approval-api
docker compose -f validation/docker-compose.yml --profile test run --rm e2e-tests
```

Expected result:

```text
74 passed
```

Optional OPA backend profile:

```bash
docker compose -f validation/docker-compose.yml --profile opa-test build \
  e2e-tests-opa oap-server-opa oap-server-opa-unavailable ticket-api-opa customer-api-opa
docker compose -f validation/docker-compose.yml --profile opa-test run --rm e2e-tests-opa
```

Expected result:

```text
6 passed
```

### 3. Confirm Resource APIs Are Protected

Direct resource access is blocked:

```bash
curl -i http://localhost:9100/api/tickets/T-100
# HTTP/1.1 401 Unauthorized
# X-OAP-Grant-Token is required
```

The e2e tests prove the full grant path:

1. Agent proves identity and creates an OAP session.
2. Agent requests authorization for an action such as `ticket.read` on `support.ticket/T-100`.
3. OAP returns `allow` or `allow_with_constraints` plus a short-lived grant.
4. The agent presents `X-OAP-Grant-Token` to the ticket/customer API.
5. The resource API validates the grant with OAP before returning data.
6. Wrong action, wrong resource, forged grant, or missing grant is rejected.

### 4. Inspect Audit Events

```bash
docker compose -f validation/docker-compose.yml exec postgres \
  psql -U oap -d oap \
  -c "SELECT id, agent_id, action, decision, created_at FROM oap_audit_events ORDER BY created_at DESC LIMIT 20;"
```

## Protect an Agent With the Python SDK

Install the SDK from this checkout:

```bash
pip install -e sdk/python
```

Authorize before a tool or API call:

```python
import requests
from open_agent_policy import OAPClient

client = OAPClient(
    server_url="http://localhost:8080",
    agent_id="agent://support/ticket-assistant",
    session_token="<session-id-from-/v1/runtime/session>",
)

decision = client.authorize(
    action="ticket.read",
    resource_type="support.ticket",
    resource_id="T-100",
    actor_type="user",
    actor_id="alice@company.test",
    context={"run_id": "run-123"},
)

if not decision.is_allowed:
    raise PermissionError(decision.reason)

response = requests.get(
    "http://localhost:9100/api/tickets/T-100",
    headers={"X-OAP-Grant-Token": decision.grant.token},
)
ticket = response.json()
```

Use the decorator for ordinary Python tools:

```python
from open_agent_policy import OAPClient, protect

client = OAPClient(
    server_url="http://localhost:8080",
    agent_id="agent://support/ticket-assistant",
    session_token="<session-id>",
)

@protect(
    client,
    action="customer.read",
    resource_type="crm.customer",
)
def read_customer(customer_id: str, *, oap_grant_token: str = "", **kwargs):
    response = requests.get(
        f"http://localhost:9101/api/customers/{customer_id}",
        headers={"X-OAP-Grant-Token": oap_grant_token},
    )
    response.raise_for_status()
    return response.json()
```

The decorator:

- Calls OAP before the tool runs.
- Raises `PermissionDeniedError` on deny.
- Raises `ApprovalRequiredError` on `require_approval`.
- Injects `oap_constraints` when policy returns constraints.
- Injects `oap_grant_token` when OAP issues a scoped grant and the function accepts it.

## Protect a Resource API

Resource APIs should validate grants, not trust the agent's claim. The validation ticket and customer APIs implement this pattern in `validation/resources/*/oap_guard.py`.

Minimal FastAPI shape:

```python
from fastapi import Header, HTTPException
from open_agent_policy import OAPClient

oap = OAPClient(server_url="http://localhost:8080")

def require_grant(
    grant_token: str | None,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
) -> dict:
    if not grant_token:
        raise HTTPException(401, "X-OAP-Grant-Token is required")

    grant = oap.validate_grant(grant_token)
    if not grant.get("valid"):
        raise HTTPException(403, "invalid OAP grant")
    if grant.get("action") != action:
        raise HTTPException(403, "grant action mismatch")
    if grant.get("resource_type") != resource_type:
        raise HTTPException(403, "grant resource type mismatch")
    if grant.get("resource_id") != resource_id:
        raise HTTPException(403, "grant resource id mismatch")
    return grant

@app.get("/api/tickets/{ticket_id}")
async def get_ticket(
    ticket_id: str,
    x_oap_grant_token: str | None = Header(default=None, alias="X-OAP-Grant-Token"),
):
    require_grant(
        x_oap_grant_token,
        action="ticket.read",
        resource_type="support.ticket",
        resource_id=ticket_id,
    )
    return load_ticket(ticket_id)
```

## Approval Flow

Policies can require approval instead of allowing an action immediately:

```yaml
- effect: require_approval
  actions:
    - message.send
  resources:
    types:
      - slack.channel
    owners:
      - channel:external
  approval:
    approvers:
      - group:support-managers
    minApprovals: 1
    expiresIn: 30m
  reason: "External customer updates require support manager approval"
```

The SDK exposes that result as `decision.requires_approval` or raises `ApprovalRequiredError` from `@protect` and LangChain wrappers. Your app should route that decision to an approval workflow, then only continue when the approval is valid for the same agent, actor, action, and resource scope.

The local validation stack includes an approval service and tests that reject approval replay against a different resource, agent, or actor.

## LangChain / LangGraph

Wrap tools before handing them to your agent:

```python
from open_agent_policy.integrations.langchain import protect_tools

protected_tools = protect_tools(
    tools,
    client=client,
    agent_id="agent://support/ticket-assistant",
    action_prefix="ticket.",
    resource_type="support.ticket",
)
```

For dict inputs, the wrapper injects `oap_constraints` and `oap_grant_token` so the tool can enforce limits and call protected APIs.

For a runnable LangChain example with real Ollama LLM calls, see
[examples/minimal-agent/langchain_agent.py](examples/minimal-agent/langchain_agent.py).

## Core Guarantees

OAP's current baseline is:

- Registered agents only.
- Deny by default.
- Explicit deny overrides allow.
- `require_approval` takes precedence over allow.
- Unknown policy vocabulary fails closed.
- OIDC, SPIFFE, and WIMSE-style workload identity bindings.
- Session and run tokens for runtime authorization.
- Scoped JWT grants for resource-side enforcement.
- Postgres-backed audit query and readiness checks.

See [Foundation Baseline](docs/guide/foundation-baseline.md) for the exact validated guarantees and remaining enterprise-readiness gaps.

## Repository Layout

```text
spec/               JSON Schemas and OpenAPI contract
engine/             Go evaluator, identity, sessions, grants, audit, stores
server/             OAP HTTP server
cli/                oapctl CLI
sdk/python/         Python SDK, decorators, LangChain integration
gateway/            HTTP gateway enforcement layer
proxy/              MCP proxy enforcement layer
validation/         Local production-like stack and e2e tests
examples/           Example agents and policies
docs/               Guides, ADRs, specs, and architecture
```

## Documentation

- [Getting Started](docs/guide/getting-started.md)
- [Building Agents With OAP](docs/guide/building-agents-with-oap.md)
- [Protecting Resource APIs](docs/guide/protecting-resource-apis.md)
- [Approval Workflows](docs/guide/approval-workflows.md)
- [Identity & Sessions](docs/guide/identity-and-sessions.md)
- [Authentication Protocols](docs/guide/authentication-protocols.md)
- [Policy Backends](docs/guide/policy-backends.md)
- [Writing Policies](docs/guide/writing-policies.md)
- [Foundation Baseline](docs/guide/foundation-baseline.md)
- [Runtime Authorization Flow](docs/flows/runtime-authorization.md)
- [Enterprise Roadmap](ENTERPRISE_ROADMAP.md)
- [Development Plan](DEVELOPMENT_PLAN.md)
- [Python SDK](sdk/python/README.md)
- [Validation Stack](validation/README.md)

## Development

```bash
make build
make test-go
make test-python
make test-conformance
make test
```

## Status

OAP is alpha software. It is ready for local evaluation, agent-builder experiments, SDK integration work, and security architecture feedback. Production deployment still needs the usual hardening around key management, network policy, operational monitoring, and packaged enforcement middleware.

## License

[MIT](LICENSE) - Copyright (c) 2026 Ishan Singh
