# Open Agent Policy — Python SDK

Python SDK for zero-trust access control for AI agents.

## Purpose

Provides a Python interface for authorizing agent tool calls against OAP policies. Supports session-based authentication, scoped grant tokens, and integrates with LangChain/LangGraph for transparent protection of agent tools.

## Architecture

```
sdk/python/open_agent_policy/
├── __init__.py          Package entry point, re-exports
├── client.py            OAPClient, Decision, Grant
├── decorators.py        @protect decorator for tool functions
├── errors.py            Error hierarchy (PermissionDeniedError, etc.)
└── integrations/
    ├── __init__.py
    └── langchain.py     OAPToolWrapper, protect_tools()
```

## Key Interfaces

### OAPClient — Basic usage

```python
from open_agent_policy import OAPClient

# Remote mode — talks to an OAP server
client = OAPClient(server_url="http://localhost:8080")

# Embedded mode — runs oapctl locally (no server needed)
client = OAPClient(mode="embedded", data_dir="./policies/")

decision = client.authorize(
    agent_id="agent://finance/reconciler",
    action="erp.invoice.read",
    resource_type="erp.invoice",
    resource_id="INV-001",
)

if decision.is_allowed:
    print("Go ahead!", decision.constraints)
elif decision.is_denied:
    print("Blocked:", decision.reason)
```

### OAPClient — Session authentication (production)

```python
from open_agent_policy import OAPClient

client = OAPClient(server_url="http://oap-server:8080")

# 1. Prove agent identity with an OIDC token
jwt = get_client_credentials_token(...)
session = client.create_session(
    agent_id="agent://finance/reconciler",
    runtime_token=jwt,
)
# client now automatically uses the session token

# 2. Create an execution run
run = client.create_run(
    actor_type="user",
    actor_id="alice@company.com",
    purpose="Monthly reconciliation",
)

# 3. Authorize — decisions include scoped grant tokens
decision = client.authorize(
    action="erp.invoice.read",
    resource_type="erp.invoice",
    resource_id="INV-001",
    context={"run_id": run["run_id"]},
)

# 4. Use grant token for resource API
if decision.is_allowed and decision.grant:
    headers = {"X-OAP-Grant-Token": decision.grant.token}
    response = requests.get("https://erp-api/invoices/INV-001", headers=headers)
```

### Decision and Grant objects

```python
from open_agent_policy import Decision, Grant

# Decision fields
decision.decision       # "allow", "deny", "allow_with_constraints", ...
decision.is_allowed     # True if allow or allow_with_constraints
decision.is_denied      # True if deny
decision.reason         # Human-readable explanation
decision.constraints    # Dict of constraints (max_records, redact_fields, etc.)
decision.policy_ids     # List of policy IDs that contributed
decision.grant          # Grant object (if allow decision)

# Grant fields (when present)
decision.grant.token    # JWT grant token to present to resource API
decision.grant.grant_id # Unique grant ID
decision.grant.expires_in_seconds  # Grant TTL
```

### @protect Decorator

```python
from open_agent_policy import OAPClient, protect

client = OAPClient(server_url="http://localhost:8080")

@protect(client, agent_id="agent://finance/reconciler", action="erp.invoice.read")
def read_invoice(invoice_id: str, **kwargs) -> dict:
    constraints = kwargs.get("oap_constraints", {})
    max_records = constraints.get("max_records", 100)
    # ... respect constraints ...
    return {"id": invoice_id}

# Denied calls raise PermissionDeniedError
# Constrained calls get oap_constraints injected into kwargs
```

### LangChain Integration

```python
from open_agent_policy.integrations.langchain import protect_tools

tools = [read_ticket, update_ticket, send_message]
protected_tools = protect_tools(
    tools,
    client=client,
    agent_id="agent://support/ticket-assistant",
    action_prefix="tickets.",
)
# Use protected_tools in your LangChain agent
```

### Grant Validation (resource-side)

```python
# On the resource API side
result = client.validate_grant(grant_token=request.headers["X-OAP-Grant-Token"])
if result.get("valid"):
    agent_id = result["agent_id"]
    action = result["action"]
    # Serve the request knowing it's authorized
```

## Data Flow

```
Tool invocation
  │
  ├── @protect / OAPToolWrapper intercepts the call
  ├── client.authorize() → OAP server (with Bearer session token)
  │     ├── allow → call the tool (grant token available)
  │     ├── allow_with_constraints → inject constraints, call the tool
  │     ├── deny → raise PermissionDeniedError
  │     └── require_approval → raise ApprovalRequiredError
  │
  └── Tool executes (or not)
```

## Configuration

| Param | Description | Default |
|---|---|---|
| `server_url` | OAP server URL (remote mode) | `http://localhost:8080` |
| `mode` | `"remote"` or `"embedded"` | `"remote"` |
| `data_dir` | Path to policies (embedded mode) | — |
| `agent_id` | Default agent ID | — |
| `timeout` | HTTP timeout (seconds) | `5.0` |
| `session_token` | Pre-existing session token | — |
| `headers` | Additional HTTP headers | — |

## Testing

```bash
cd sdk/python
pip install -e ".[dev]"
pytest -v
# 32 tests: Decision parsing, client validation, remote mode,
#           decorators, LangChain integration
```
