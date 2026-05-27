# HTTP Gateway

OAP HTTP reverse proxy — authorizes API requests based on policy.

## Purpose

Sits between an AI agent and an upstream HTTP API. The agent changes its API base URL to point at the gateway. Every request is mapped to an OAP action, authorized, and then forwarded or denied. No SDK integration needed.

## Architecture

```
gateway/
├── doc.go           Package documentation
├── gateway.go       HTTP gateway implementation
└── gateway_test.go  Integration tests (6 tests)
```

## Key Interfaces

```go
gw, _ := gateway.New(gateway.Config{
    AgentID:     "agent://finance/reconciler",
    UpstreamURL: "https://erp-api.internal",
    ObserveMode: false,
    Routes: map[string]string{
        "GET /api/invoices":    "erp.invoice.read",
        "POST /api/invoices":   "erp.invoice.create",
        "DELETE /api/invoices": "erp.invoice.delete",
    },
    Store:     store,
    AuditSink: sink,
})
http.ListenAndServe(":9090", gw.Handler())
```

## Data Flow

```
Agent sends HTTP request
  │
  ├── Map method + path → OAP action (explicit routes or derived)
  ├── Check X-OAP-Agent-ID header (optional override)
  ├── evaluator.Evaluate(request)
  │     ├── deny → return 403 with structured error
  │     ├── allow → forward to upstream via reverse proxy
  │     └── observe mode → log + forward regardless
  └── Emit audit event
```

## Route Resolution

1. **Explicit routes** — exact match from `Routes` map (`"GET /api/invoices" → "erp.invoice.read"`)
2. **Prefix match** — if method matches and path starts with pattern
3. **Derived** — `GET /users/123` → `users.123.read` (method mapped to verb)

## Configuration

| Field | Description |
|-------|-------------|
| `AgentID` | Default agent identity |
| `UpstreamURL` | Target API server URL |
| `ObserveMode` | Log decisions without blocking |
| `Routes` | Map of `"METHOD /path" → "action.name"` |
| `Store` | Registry store (agents + policies) |
| `AuditSink` | Audit event sink |

## Testing

```bash
go test -v ./gateway/
```
