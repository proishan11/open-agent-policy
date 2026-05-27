# OAP Integration Guide

This guide covers every way to integrate OAP with your agents and resource APIs — from the Python SDK to the HTTP gateway, MCP proxy, and resource-side grant validation.

---

## Integration overview

OAP supports five integration patterns. Choose based on your architecture:

| Pattern | Code changes? | Best for |
|---|---|---|
| **Python SDK** | Yes (minimal) | Python agents, full control |
| **@protect decorator** | Yes (one line) | Python tool functions |
| **LangChain middleware** | Yes (one line) | LangChain/LangGraph agents |
| **HTTP Gateway** | No | REST API agents, legacy agents |
| **MCP Proxy** | No | MCP protocol agents |

All patterns produce the same result: every action is authorized, constrained, and audited.

---

## 1. Python SDK — Direct integration

Full control over authorization flow. Best when you want to handle decisions in custom logic.

### Basic usage

```python
from open_agent_policy import OAPClient

client = OAPClient(
    server_url="http://oap-server:8080",
    agent_id="agent://finance/reconciler",
)

decision = client.authorize(
    action="erp.invoice.read",
    resource_type="erp.invoice",
    resource_id="INV-001",
)

if decision.is_allowed:
    # Apply constraints
    constraints = decision.constraints
    max_records = constraints.get("max_records", 100)
    redact = constraints.get("redact_fields", [])
    result = fetch_invoice("INV-001", limit=max_records)
    for field in redact:
        result.pop(field, None)
elif decision.is_denied:
    return {"error": f"Blocked: {decision.reason}"}
elif decision.requires_approval:
    return {"status": "pending_approval", "approvers": decision.approval.get("approvers")}
```

### With session authentication (production)

```python
from open_agent_policy import OAPClient

client = OAPClient(server_url="http://oap-server:8080")

# 1. Get OIDC token from your identity provider
jwt = get_client_credentials_token(
    token_url="https://auth.company.com/token",
    client_id="reconciler-client",
    client_secret=os.environ["CLIENT_SECRET"],
)

# 2. Create session (proves agent identity)
session = client.create_session(
    agent_id="agent://finance/reconciler",
    runtime_token=jwt,
)
# client.session_token is now set automatically

# 3. Create a run (execution context)
run = client.create_run(
    actor_type="user",
    actor_id="alice@company.com",
    purpose="Monthly reconciliation batch",
)

# 4. Authorize with grant token
decision = client.authorize(
    action="erp.invoice.read",
    resource_type="erp.invoice",
    resource_id="INV-001",
    context={"run_id": run["run_id"]},
)

# 5. Use grant token for resource API
if decision.is_allowed and decision.grant:
    response = requests.get(
        "https://erp-api/invoices/INV-001",
        headers={"X-OAP-Grant-Token": decision.grant.token},
    )
```

### Constructor options

| Parameter | Default | Description |
|---|---|---|
| `server_url` | `http://localhost:8080` | OAP server URL |
| `mode` | `remote` | `remote` (HTTP) or `embedded` (local oapctl) |
| `agent_id` | — | Default agent ID for all requests |
| `timeout` | `5.0` | HTTP timeout in seconds |
| `session_token` | — | Pre-existing session token |
| `headers` | — | Additional HTTP headers |

---

## 2. @protect decorator

Wraps a Python function with automatic authorization. Denied calls raise exceptions; constrained calls inject constraints into kwargs.

```python
from open_agent_policy import OAPClient, protect

client = OAPClient(
    server_url="http://oap-server:8080",
    agent_id="agent://finance/reconciler",
)

@protect(client, action="erp.invoice.read")
def read_invoice(invoice_id: str, **kwargs) -> dict:
    constraints = kwargs.get("oap_constraints", {})
    max_records = constraints.get("max_records", 100)
    return fetch_invoice(invoice_id, limit=max_records)

@protect(client, action="erp.invoice.delete", on_deny="return_none")
def delete_invoice(invoice_id: str) -> dict | None:
    return remove_invoice(invoice_id)
```

### Decorator options

| Parameter | Description |
|---|---|
| `client` | OAPClient instance |
| `agent_id` | Agent ID (falls back to client default) |
| `action` | OAP action name (defaults to function name) |
| `on_deny` | `"raise"` (default) or `"return_none"` |

### What happens on each decision

| Decision | Behavior |
|---|---|
| **allow** | Function executes normally |
| **allow_with_constraints** | `oap_constraints` dict injected into kwargs, then executes |
| **deny** | Raises `PermissionDeniedError` (or returns None) |
| **require_approval** | Raises `ApprovalRequiredError` |

---

## 3. LangChain integration

One-line integration for LangChain/LangGraph agents. Wraps all tools with transparent authorization.

```python
from open_agent_policy import OAPClient
from open_agent_policy.integrations.langchain import protect_tools

client = OAPClient(server_url="http://oap-server:8080")

# Original tools
tools = [read_ticket, update_ticket, send_message, delete_ticket]

# Wrap with OAP — denied tools are blocked, constrained tools get constraints injected
protected = protect_tools(
    tools,
    client=client,
    agent_id="agent://support/ticket-assistant",
    action_prefix="tickets.",  # read_ticket → "tickets.read_ticket"
)

# Use in your LangChain agent
agent = create_agent(llm=llm, tools=protected)
```

### How it works

1. Agent decides to call a tool (e.g., `read_ticket`)
2. `OAPToolWrapper` intercepts the call
3. Sends authorization request to OAP server
4. **Allow** → executes the tool, returns result
5. **Deny** → returns safe error message to the LLM
6. **Constrained** → injects constraints into tool input, then executes
7. Every decision is audited

---

## 4. HTTP Gateway (no code changes)

Deploy as a reverse proxy between your agent and an HTTP API. The agent changes its base URL to point at the gateway — no SDK needed.

### Setup

```go
gw, _ := gateway.New(gateway.Config{
    AgentID:     "agent://finance/reconciler",
    UpstreamURL: "https://erp-api.internal:443",

    // Remote mode: delegate auth to OAP server
    OAPServerURL: "http://oap-server:8080",

    // Route mapping: HTTP method+path → OAP action
    Routes: map[string]string{
        "GET /api/invoices":    "erp.invoice.list",
        "GET /api/invoices/*":  "erp.invoice.read",
        "POST /api/invoices":   "erp.invoice.create",
        "DELETE /api/invoices": "erp.invoice.delete",
    },

    ObserveMode: false,  // true = log only, don't block
})
http.ListenAndServe(":9090", gw.Handler())
```

### How it works

```
Agent → GET /api/invoices (to gateway:9090)
  │
  ├── Gateway maps "GET /api/invoices" → action "erp.invoice.list"
  ├── Gateway calls OAP server /v1/authorize (with Bearer session token)
  │     ├── allow → forward to upstream, inject X-OAP-Grant-Token header
  │     ├── deny → return 403 with structured JSON error
  │     └── OAP unreachable → return 403 (fail-closed)
  └── Upstream receives request + grant token
```

### Deployment modes

| Mode | Config | Use case |
|---|---|---|
| **Embedded** | `Store` + `AuditSink` set | Sidecar deployment, no network hop to OAP |
| **Remote** | `OAPServerURL` set | Centralized OAP server, session-aware |

### Agent sends session token

```bash
# Agent authenticates via the gateway
curl -H "Authorization: Bearer ags_abc123..." \
     http://gateway:9090/api/invoices
```

### Observe mode

Start with `ObserveMode: true` to log all decisions without blocking. Review audit logs, then switch to enforce mode.

---

## 5. MCP Proxy (no code changes)

Sits between an MCP agent and an MCP server. Intercepts `tools/list` and `tools/call` messages.

### Setup

```go
p := proxy.New(proxy.Config{
    AgentID:      "agent://support/ticket-assistant",
    UpstreamURL:  "http://mcp-server:8080",
    OAPServerURL: "http://oap-server:8080",  // remote auth mode
    ObserveMode:  false,
})
http.ListenAndServe(":7777", p.Handler())
```

### How it works

| MCP method | Proxy behavior |
|---|---|
| `initialize` | Respond with proxy capabilities |
| `tools/list` | Fetch from upstream, filter by agent's allowed actions |
| `tools/call` | Authorize action → allow (forward) or deny (MCP error -32001) |
| Other | Forward to upstream as-is |

### Agent connects to proxy

```python
# Instead of connecting to the real MCP server
# agent.connect("http://mcp-server:8080")

# Connect to the proxy
agent.connect("http://proxy:7777")
# Every tool call is now authorized by OAP
```

---

## 6. Resource-side grant validation

Resource APIs can verify that a request came from an authorized agent by checking the grant token.

### Using the Go middleware

```go
import "github.com/proishan11/open-agent-policy/gateway"

mw := gateway.NewGrantMiddleware(gateway.GrantMiddlewareConfig{
    OAPServerURL: "http://oap-server:8080",
    HeaderName:   "X-OAP-Grant-Token",  // default
    AllowMissing: false,                  // fail-closed
})

// Wrap your API handler
http.Handle("/api/", mw.Wrap(myAPIHandler))
```

### What the middleware does

1. Extracts `X-OAP-Grant-Token` from the request header
2. Calls OAP server `POST /v1/grants/validate` to verify the token
3. On success, sets verified identity headers on the request:
   - `X-OAP-Verified-Agent-ID` — the agent that was authorized
   - `X-OAP-Verified-Action` — the action that was allowed
   - `X-OAP-Verified-Decision` — `allow` or `allow_with_constraints`
   - `X-OAP-Run-ID` — the execution run ID (if present)
4. On failure, returns 401 (missing) or 403 (invalid)

### Using the API directly

If you can't use the Go middleware, call the validation endpoint directly:

```python
# Resource API validates the grant
response = requests.post(
    "http://oap-server:8080/v1/grants/validate",
    json={"grant_token": request.headers["X-OAP-Grant-Token"]},
)
claims = response.json()
if claims.get("valid"):
    agent_id = claims["agent_id"]
    action = claims["action"]
    # Serve the request knowing it's authorized
```

### Gradual rollout

Use `AllowMissing: true` to start validating grants without blocking requests that don't have them yet:

```go
mw := gateway.NewGrantMiddleware(gateway.GrantMiddlewareConfig{
    OAPServerURL: "http://oap-server:8080",
    AllowMissing: true,  // don't block requests without grants
})
```

---

## End-to-end flow summary

```
1. Agent → IdP (client_credentials) → runtime JWT
2. Agent → OAP POST /v1/runtime/session → ags_ session token
3. Agent → OAP POST /v1/runs → run_id
4. Agent → Gateway/Proxy/SDK (Bearer: ags_...) → OAP /v1/authorize
5. OAP evaluates policy → decision + scoped grant token (on allow)
6. Gateway injects X-OAP-Grant-Token into upstream request
7. Resource API → GrantMiddleware validates grant → verified identity headers
8. Every decision is audited
```

---

## Error handling

### Python SDK errors

```python
from open_agent_policy import (
    OAPError,              # Base class for all OAP errors
    PermissionDeniedError, # Action denied by policy
    ApprovalRequiredError, # Needs human approval
    ServerError,           # OAP server error
)

try:
    decision = client.authorize(action="customer.delete", ...)
except PermissionDeniedError as e:
    log.warning(f"Denied: {e.reason} (policies: {e.policy_ids})")
except ApprovalRequiredError as e:
    log.info(f"Needs approval from: {e.approvers}")
except ServerError as e:
    log.error(f"OAP server error: {e.status_code}")
except OAPError as e:
    log.error(f"OAP error: {e}")
```

### Gateway HTTP errors

| Status | Meaning |
|---|---|
| 200 | Request allowed, forwarded to upstream |
| 403 | Request denied by policy (JSON body with reason) |
| 502 | OAP server unreachable (fail-closed) |

### MCP Proxy errors

| Code | Meaning |
|---|---|
| -32001 | Tool call denied by OAP policy |
| -32002 | Tool call requires approval |

---

## Next steps

- [Getting Started](getting-started.md) — Setup and first agent
- [Identity & Sessions](identity-and-sessions.md) — Identity bindings, supported providers, sessions, runs, grant tokens
- [Writing Policies](writing-policies.md) — Policy authoring guide
- [Architecture](../../architecture.md) — System design
- [API Reference](../../spec/openapi/oap-server.openapi.yaml) — OpenAPI spec
