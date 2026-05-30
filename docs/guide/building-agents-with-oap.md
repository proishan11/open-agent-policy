# Building Agents With OAP

This guide shows how to use Open Agent Policy from an autonomous agent. It is
written for developers who already have an agent that calls tools, APIs, MCP
servers, or workflow functions, and want policy enforcement around those calls.

For a tiny runnable version of this guide, see
[examples/minimal-agent](../../examples/minimal-agent/README.md). It includes
both a deterministic enforcement walkthrough and an Ollama-backed LLM agent that
chooses tools before OAP gates them.

OAP does not replace your agent framework. It gives your agent a security
control plane:

```text
Agent decides to call a tool
  -> OAP authorizes agent + actor + action + resource
  -> OAP returns allow, deny, require_approval, or constraints
  -> allowed decisions include a scoped grant token
  -> protected resource API validates the grant before serving data
  -> OAP audits the decision
```

The agent can still reason, plan, and use tools normally. The difference is that
tool execution is gated by policy outside the model.

## Adoption Path

Use this sequence for a new or existing agent:

1. Define stable action names.
2. Define resource types and IDs.
3. Register the agent.
4. Write policies.
5. Add SDK authorization around tool calls.
6. Pass OAP grants to protected resource APIs.
7. Handle deny, constraints, and approval-required decisions.
8. Validate grants on the resource side.
9. Add tests for allowed, denied, approval, and replay cases.

## 1. Model Actions And Resources

Start by naming what the agent can do. Use stable, dot-namespaced action names:

```text
ticket.read
ticket.update
ticket.bulk_export
customer.read
message.send
repository.settings.modify
```

Then name resource types:

```text
support.ticket
crm.customer
slack.channel
github.repository
```

For each real call, the agent should know:

| Field | Example | Why it matters |
|---|---|---|
| `agent_id` | `agent://support/ticket-assistant` | Policy subject |
| `actor_id` | `alice@company.test` | Human or service on whose behalf the agent acts |
| `action` | `ticket.read` | What the agent wants to do |
| `resource_type` | `support.ticket` | What kind of thing is targeted |
| `resource_id` | `T-100` | Exact instance for scoped grants |
| `resource_owner` | `channel:external` | Optional selector for policy |
| `resource_classification` | `restricted` | Optional selector for policy |
| `context.run_id` | `run_123` | Correlates a sequence of actions |

Good action and resource names are the foundation. Avoid prompt-shaped names
such as `do whatever the user asked`. OAP policy should authorize concrete
operations.

## 2. Register The Agent

Create an agent manifest in your policy directory:

```yaml
apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: ticket-assistant
  namespace: support
spec:
  owner: group:support-platform
  type: workflow_agent
  riskTier: medium
  description: "Assists support agents with tickets and customer summaries."
  capabilities:
    - ticket.read
    - ticket.update
    - customer.read
    - message.send
  framework: langchain
```

For identity-backed environments, add identity bindings:

```yaml
spec:
  identityBindings:
    - type: oidc_client
      provider: keycloak
      issuer: "https://auth.company.com/realms/agents"
      subject: "support-agent"
```

See [Identity & Sessions](identity-and-sessions.md) for the identity model and
[Authentication Protocols](authentication-protocols.md) for OIDC, Kubernetes,
SPIFFE, and WIMSE setup examples.

## 3. Write Agent Policies

Example support policy:

```yaml
apiVersion: oap.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: support-ticket-agent-policy
  namespace: support
spec:
  subject:
    agent: "agent://support/ticket-assistant"

  rules:
    - effect: allow
      actions:
        - ticket.read
      constraints:
        maxRecords: 25
        redact:
          - payment_card
          - government_id

    - effect: allow
      actions:
        - customer.read
      constraints:
        redact:
          - tax_identifier
          - billing_account
          - bank_account

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

    - effect: deny
      actions:
        - ticket.bulk_export
        - customer.bulk_export
        - repository.settings.modify
      reason: "High-risk or administrative actions are prohibited"
```

Evaluation is fail-closed:

- no matching policy means deny
- explicit deny overrides allow
- require_approval takes precedence over allow
- unsupported policy vocabulary fails closed

See [Writing Policies](writing-policies.md) for the full policy vocabulary.

## 4. Start OAP For Local Development

For local development without runtime identity verification:

```bash
bin/oap-server --data ./my-agent-policy-dir --dev
```

For a production-like local stack with Keycloak, Postgres, grants, protected
resource APIs, and approval tests:

```bash
docker compose -f validation/docker-compose.yml --profile test build
docker compose -f validation/docker-compose.yml up -d \
  postgres keycloak oap-server ticket-api customer-api approval-api
docker compose -f validation/docker-compose.yml --profile test run --rm e2e-tests
```

## 5. Authorize Tool Calls With The SDK

Install the SDK:

```bash
pip install -e sdk/python
```

Direct SDK usage:

```python
import requests
from open_agent_policy import OAPClient

client = OAPClient(
    server_url="http://localhost:8080",
    agent_id="agent://support/ticket-assistant",
)

def read_ticket_with_oap(ticket_id: str) -> dict:
    decision = client.authorize(
        action="ticket.read",
        resource_type="support.ticket",
        resource_id=ticket_id,
        actor_type="user",
        actor_id="alice@company.test",
        context={"run_id": "run-support-123"},
    )

    if decision.is_denied:
        return {"error": decision.reason}

    if decision.requires_approval:
        return {
            "status": "pending_approval",
            "approvers": decision.approval.get("approvers", []),
        }

    response = requests.get(
        f"http://localhost:9100/api/tickets/{ticket_id}",
        headers={"X-OAP-Grant-Token": decision.grant.token},
    )
    response.raise_for_status()
    return response.json()
```

When OAP is configured with an issuer, use sessions:

```python
client = OAPClient(server_url="http://localhost:8080")

session = client.create_session(
    agent_id="agent://support/ticket-assistant",
    runtime_token=get_client_credentials_token(),
)

run = client.create_run(
    actor_type="user",
    actor_id="alice@company.test",
    purpose="summarize support ticket T-100",
)

decision = client.authorize(
    action="ticket.read",
    resource_type="support.ticket",
    resource_id="T-100",
    context={"run_id": run["run_id"]},
)
```

## 6. Use The Decorator For Tools

The decorator is the easiest path for Python function tools:

```python
import requests
from open_agent_policy import OAPClient, protect

client = OAPClient(
    server_url="http://localhost:8080",
    agent_id="agent://support/ticket-assistant",
)

@protect(client, action="customer.read", resource_type="crm.customer")
def read_customer(customer_id: str, *, oap_grant_token: str = "", **kwargs):
    response = requests.get(
        f"http://localhost:9101/api/customers/{customer_id}",
        headers={"X-OAP-Grant-Token": oap_grant_token},
    )
    response.raise_for_status()
    return response.json()
```

The decorator:

- calls OAP before the function executes
- raises `PermissionDeniedError` for deny
- raises `ApprovalRequiredError` for require_approval
- injects `oap_constraints` when the policy returns constraints
- injects `oap_grant_token` when OAP issues a grant and your function accepts it

## 7. Use LangChain Or LangGraph

Wrap tools before giving them to your agent:

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

For dict inputs, OAP injects `oap_constraints` and `oap_grant_token` into the
tool input. Your tool can use the grant token to call the protected API.

For a runnable version with real Ollama LLM calls, see
[examples/minimal-agent/langchain_agent.py](../../examples/minimal-agent/langchain_agent.py).

## 8. Handle Decisions In The Agent Loop

Autonomous agents should treat policy decisions as tool results:

| Decision | Agent behavior |
|---|---|
| `allow` | Execute the tool and pass grant token to the resource API. |
| `allow_with_constraints` | Execute the tool, honor constraints, pass grant token. |
| `deny` | Do not execute. Return or reason over a safe blocked-action result. |
| `require_approval` | Create or route an approval request. Do not execute yet. |
| `require_delegation` | Ask for delegation or stop. |

Do not ask the model to decide whether to enforce the policy. Enforcement should
happen before the tool or resource API call.

## 9. Test Your Agent

At minimum, add tests for:

- known allowed action returns data
- missing grant is rejected by the resource API
- wrong-resource grant is rejected
- explicit deny blocks execution
- approval-required action does not execute
- constraints are applied, such as redaction and max records
- spoofed `agent_id` is ignored when bearer/session identity is configured

The local validation stack is a reference implementation of these checks:

```bash
docker compose -f validation/docker-compose.yml --profile test run --rm e2e-tests
```

## Production Notes

For local experiments, the default compose stack is enough. For real deployment,
plan for:

- OIDC, SPIFFE, or WIMSE identity bindings
- short-lived OAP sessions
- stable run IDs for audit correlation
- resource-side grant validation
- key management for grant signing
- audit export to your SIEM or data lake
- tests that prove deny, approval, and replay behavior

Next:

- [Protecting Resource APIs](protecting-resource-apis.md)
- [Approval Workflows](approval-workflows.md)
- [Integration Guide](integration.md)
- [Identity & Sessions](identity-and-sessions.md)
