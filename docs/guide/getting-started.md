# Getting Started with Open Agent Policy

This guide walks you through setting up OAP, registering your first agent, writing policies, and protecting tool calls — in under 15 minutes.

---

## What is OAP?

Open Agent Policy is a zero-trust access control system for AI agents. It answers:

- **What can this agent do?** — Policies define allowed and denied actions
- **Who is this agent?** — Cryptographic identity verification (OIDC, K8s SA)
- **What did it do?** — Every decision is audited
- **Can I stop it?** — Agents can be revoked instantly

OAP sits between your agent and the resources it accesses. It evaluates every action against policy and returns allow, deny, or constrained decisions — without changing how you build agents.

---

## Prerequisites

- **Go 1.25+** — [install](https://go.dev/doc/install)
- **Python 3.11+** — [install](https://www.python.org/downloads/)
- **Docker** (optional) — for the full stack with Keycloak identity provider

---

## 1. Install

```bash
git clone https://github.com/proishan11/open-agent-policy.git
cd open-agent-policy

# Build Go binaries
make build

# Install Python SDK
make venv
source .venv/bin/activate
```

This gives you:
- `bin/oap-server` — the OAP HTTP server
- `bin/oapctl` — the CLI for simulation, testing, and management
- `open_agent_policy` — the Python SDK

---

## 2. Define your agent

Create an agent manifest. This tells OAP who your agent is, what it can do, and how to verify its identity.

```yaml
# my-agent/agents.yaml
apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: invoice-reader
  namespace: finance
spec:
  owner: "group:finance-platform"
  type: workflow_agent
  riskTier: low
  description: "Reads invoices from the ERP system"

  # What this agent claims it can do
  capabilities:
    - erp.invoice.read
    - erp.invoice.list

  # (Optional) Standards-compatible workload identity profile
  # workloadIdentity:
  #   id: spiffe://example.org/ns/finance/sa/invoice-reader
  #   type: spiffe
  #   trustDomain: example.org

  # (Optional) Identity binding for production
  # identityBindings:
  #   - type: oidc_client
  #     issuer: "https://auth.company.com/realms/agents"
  #     subject: "invoice-reader-client"
  #   - type: spiffe
  #     issuer: "https://spire.example.org"
  #     jwksUri: "https://spire.example.org/.well-known/jwks.json"
  #     subject: "spiffe://example.org/ns/finance/sa/invoice-reader"
  #     audience: "oap-server"

  framework: langchain
```

---

## 3. Write a policy

Policies define what actions are allowed, denied, or constrained.

```yaml
# my-agent/policies.yaml
apiVersion: oap.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: invoice-reader-policy
  namespace: finance
spec:
  subject:
    agent: "agent://finance/invoice-reader"

  rules:
    # Allow reading invoices, but with constraints
    - effect: allow
      actions:
        - erp.invoice.read
        - erp.invoice.list
      constraints:
        maxRecords: 50
        readonly: true
        redact:
          - bank_account
          - tax_id

    # Explicitly deny any write operations
    - effect: deny
      actions:
        - erp.invoice.create
        - erp.invoice.update
        - erp.invoice.delete
      reason: "Invoice reader is read-only"
```

### Key policy concepts

- **`effect: allow`** — Permits the action, optionally with constraints
- **`effect: deny`** — Blocks the action (always overrides allow)
- **`constraints`** — Limits applied to allowed actions (max records, field redaction, read-only)
- **`reason`** — Human-readable explanation for deny decisions

---

## 4. Test locally with the CLI

Create a sample authorization request:

```json
{
  "request_id": "req_getting_started_001",
  "subject": {
    "type": "agent",
    "agent_id": "agent://finance/invoice-reader"
  },
  "action": {
    "name": "erp.invoice.read"
  },
  "resource": {
    "type": "erp.invoice",
    "id": "INV-001"
  }
}
```

Save it as `my-agent/read-request.json`. Then simulate the request:

```bash
bin/oapctl simulate \
  --data my-agent/ \
  -f my-agent/read-request.json
# -> allow_with_constraints (readonly, max_records=50, redact bank_account+tax_id)
```

Create a denied request as `my-agent/delete-request.json`:

```json
{
  "request_id": "req_getting_started_002",
  "subject": {
    "type": "agent",
    "agent_id": "agent://finance/invoice-reader"
  },
  "action": {
    "name": "erp.invoice.delete"
  },
  "resource": {
    "type": "erp.invoice",
    "id": "INV-001"
  }
}
```

```bash
bin/oapctl simulate \
  --data my-agent/ \
  -f my-agent/delete-request.json
# -> deny (Invoice reader is read-only)

# Run conformance tests
bin/oapctl test --conformance
```

---

## 5. Start the OAP server

```bash
# Development mode — loads agents and policies from a directory
bin/oap-server --data my-agent/ --dev

# Server is now running at http://localhost:8080
# Try the health endpoint
curl http://localhost:8080/v1/health
```

### Server endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/v1/health` | GET | Process liveness check |
| `/v1/ready` | GET | Dependency readiness check |
| `/metrics` | GET | Prometheus text metrics |
| `/v1/authorize` | POST | Authorize an action |
| `/v1/simulate` | POST | Simulate (with evaluation trace) |
| `/v1/agents` | GET | List registered agents |
| `/v1/policies` | GET | List policies |
| `/v1/runtime/session` | POST | Create authenticated session |
| `/v1/runs` | POST | Create execution run |
| `/v1/grants/validate` | POST | Validate a grant token |

---

## 6. Integrate with your agent

For a runnable minimal example with both a deterministic walkthrough and an
Ollama-backed LLM agent, see
[examples/minimal-agent](../../examples/minimal-agent/README.md). For the
complete end-to-end agent builder guide, see
[Building Agents With OAP](building-agents-with-oap.md).

### Option A: Python SDK (recommended)

```python
from open_agent_policy import OAPClient

client = OAPClient(
    server_url="http://localhost:8080",
    agent_id="agent://finance/invoice-reader",
)

# Authorize before calling a tool
decision = client.authorize(
    action="erp.invoice.read",
    resource_type="erp.invoice",
    resource_id="INV-001",
)

if decision.is_allowed:
    # Respect constraints
    max_records = decision.constraints.get("max_records", 100)
    redact = decision.constraints.get("redact_fields", [])
    result = read_invoice("INV-001", max_records=max_records)
    # ... redact fields ...
elif decision.is_denied:
    print(f"Blocked: {decision.reason}")
```

### Option B: @protect decorator

```python
from open_agent_policy import OAPClient, protect

client = OAPClient(server_url="http://localhost:8080")

@protect(client, agent_id="agent://finance/invoice-reader", action="erp.invoice.read")
def read_invoice(invoice_id: str, **kwargs) -> dict:
    constraints = kwargs.get("oap_constraints", {})
    max_records = constraints.get("max_records", 100)
    return fetch_invoice(invoice_id, limit=max_records)

# Denied calls raise PermissionDeniedError automatically
# Constrained calls get oap_constraints injected into kwargs
```

### Option C: LangChain integration

```python
from open_agent_policy import OAPClient
from open_agent_policy.integrations.langchain import protect_tools

client = OAPClient(server_url="http://localhost:8080")

# Wrap all tools with OAP authorization
protected = protect_tools(
    tools=[read_invoice, list_invoices, delete_invoice],
    client=client,
    agent_id="agent://finance/invoice-reader",
)

# Use protected tools in your LangChain agent — denied tools are blocked transparently
```

### Option D: HTTP Gateway (no code changes)

```go
gw, _ := gateway.New(gateway.Config{
    AgentID:     "agent://finance/invoice-reader",
    UpstreamURL: "https://erp-api.internal",
    OAPServerURL: "http://localhost:8080",  // remote auth mode
    Routes: map[string]string{
        "GET /api/invoices":    "erp.invoice.read",
        "DELETE /api/invoices": "erp.invoice.delete",
    },
})
// Point your agent at the gateway instead of the real API
```

### Option E: MCP Proxy (no code changes)

```go
p := proxy.New(proxy.Config{
    AgentID:      "agent://support/ticket-assistant",
    UpstreamURL:  "http://mcp-server:8080",
    OAPServerURL: "http://localhost:8080",  // remote auth mode
})
// Point your MCP agent at the proxy instead of the real MCP server
```

---

## 7. Production setup with identity verification

In production, agents prove their identity via OIDC, Kubernetes ServiceAccount,
SPIFFE JWT-SVID, or WIMSE WIT+WPT proof-of-possession. This prevents agents from
impersonating each other.

For provider-specific setup, see
[Authentication Protocols](authentication-protocols.md).

### Step 1: Add identity binding to your agent

```yaml
spec:
  identityBindings:
    - type: oidc_client
      issuer: "https://auth.company.com/realms/agents"
      subject: "invoice-reader-client"
    - type: spiffe
      issuer: "https://spire.example.org"
      jwksUri: "https://spire.example.org/.well-known/jwks.json"
      subject: "spiffe://example.org/ns/finance/sa/invoice-reader"
      audience: "oap-server"
    - type: wimse
      issuer: "https://identity.example.org/workloads"
      jwksUri: "https://identity.example.org/workloads/jwks.json"
      subject: "wimse://example.org/service/invoice-reader"
      audience: "oap-server"
```

### Step 2: Configure the OAP server with an issuer

```bash
bin/oap-server \
  --data my-agent/ \
  --issuer "https://auth.company.com/realms/agents" \
  --grant-key "your-hmac-secret-key"
```

### Step 3: Agent authenticates and creates a session

```python
from open_agent_policy import OAPClient

client = OAPClient(server_url="http://localhost:8080")

# 1. Get a token from your identity provider (e.g., Keycloak, Okta)
jwt_token = get_oidc_token(client_id="invoice-reader-client", client_secret="...")

# 2. Create an OAP session (proves agent identity)
session = client.create_session(
    agent_id="agent://finance/invoice-reader",
    runtime_token=jwt_token,
)
# client now automatically uses the session token for all requests

# 3. Create a run (tracks execution context)
run = client.create_run(
    actor_type="user",
    actor_id="alice@company.com",
    purpose="Monthly invoice reconciliation",
)

# 4. Authorize — decisions now include scoped grant tokens
decision = client.authorize(
    action="erp.invoice.read",
    resource_type="erp.invoice",
    resource_id="INV-001",
)

if decision.is_allowed and decision.grant:
    # Present the grant token to the resource API
    headers = {"X-OAP-Grant-Token": decision.grant.token}
    response = requests.get("https://erp-api/invoices/INV-001", headers=headers)
```

### Step 4: Resource API validates the grant

```go
// On the resource API side
mw := gateway.NewGrantMiddleware(gateway.GrantMiddlewareConfig{
    OAPServerURL: "http://oap-server:8080",
})
http.Handle("/api/", mw.Wrap(myAPIHandler))
// Requests without valid grants are rejected (401/403)
// Valid requests get X-OAP-Verified-Agent-ID header set
```

---

## 8. Docker Compose (full stack)

For a complete environment with Keycloak identity provider:

```bash
cd validation
docker compose up -d

# This starts:
# - Keycloak (identity provider) on port 8180
# - PostgreSQL (storage) on port 5432
# - OAP server on port 8080
# - E2e test runner

# Run the full test suite
docker compose run --rm e2e-tests
```

---

## Next steps

- [Identity & Sessions](identity-and-sessions.md) — Identity bindings, supported providers, sessions, runs, grant tokens
- [Writing Policies](writing-policies.md) — Deep dive into policy authoring
- [Integration Guide](integration.md) — All integration patterns (SDK, gateway, proxy, middleware)
- [Architecture](../../architecture.md) — System design and end-to-end flows
- [Runtime Authorization Flow](../flows/runtime-authorization.md) — Mermaid sequence diagram
- [Enterprise Roadmap](../../ENTERPRISE_ROADMAP.md) — What's coming next
