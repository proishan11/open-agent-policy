# Open Agent Policy — Python SDK

Python SDK for zero-trust access control for AI agents.

## Purpose

Provides a Python interface for authorizing agent tool calls against OAP policies. Integrates with LangChain/LangGraph for transparent protection of agent tools.

## Architecture

```
sdk/python/open_agent_policy/
├── __init__.py          Package entry point, re-exports
├── client.py            OAPClient — remote and embedded authorization
├── decorators.py        @protect decorator for tool functions
├── errors.py            Error hierarchy (PermissionDeniedError, etc.)
└── integrations/
    ├── __init__.py
    └── langchain.py     OAPToolWrapper, protect_tools()
```

## Key Interfaces

### OAPClient

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

## Data Flow

```
Tool invocation
  │
  ├── @protect / OAPToolWrapper intercepts the call
  ├── client.authorize() → OAP server (or local oapctl)
  │     ├── allow → call the tool
  │     ├── allow_with_constraints → inject constraints, call the tool
  │     ├── deny → raise PermissionDeniedError
  │     └── require_approval → raise ApprovalRequiredError
  │
  └── Tool executes (or not)
```

## Configuration

| Param | Description | Default |
|-------|-------------|---------|
| `server_url` | OAP server URL (remote mode) | `http://localhost:8080` |
| `mode` | `"remote"` or `"embedded"` | `"remote"` |
| `data_dir` | Path to policies (embedded mode) | — |
| `agent_id` | Default agent ID | — |
| `timeout` | HTTP timeout (seconds) | `5.0` |

## Testing

```bash
cd sdk/python
pip install -e ".[dev]"
pytest -v
```
