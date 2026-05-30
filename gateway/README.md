# HTTP Gateway

OAP HTTP reverse proxy — authorizes API requests based on policy.

## Purpose

Sits between an AI agent and an upstream HTTP API. The agent changes its API base URL to point at the gateway. Every request is mapped to an OAP action, authorized, and then forwarded or denied. No SDK integration needed.

## Architecture

```
gateway/
├── doc.go              Package documentation
├── gateway.go          HTTP gateway implementation
├── grant_middleware.go  Resource-side grant validation middleware
└── gateway_test.go     Integration tests (13 tests)
```

## Deployment Modes

| Mode | Config | Use case |
|---|---|---|
| **Embedded** | `Store` + `AuditSink` | Sidecar deployment, local policy evaluation |
| **Remote** | `OAPServerURL` | Centralized OAP server, session-aware auth |

### Embedded mode (local evaluator)

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

### Remote mode (OAP server)

```go
gw, _ := gateway.New(gateway.Config{
    AgentID:      "agent://finance/reconciler",
    UpstreamURL:  "https://erp-api.internal",
    OAPServerURL: "http://oap-server:8080",  // delegates to OAP server
    Routes: map[string]string{
        "GET /api/invoices":    "erp.invoice.read",
        "DELETE /api/invoices": "erp.invoice.delete",
    },
})
```

In remote mode, the gateway:
1. Extracts the `Bearer` session token from incoming requests
2. Calls OAP server `POST /v1/authorize` with the token
3. On allow, injects the grant token as `X-OAP-Grant-Token` into the upstream request
4. On deny or OAP unreachable, returns 403 (fail-closed)

## Grant Middleware

Reusable middleware for resource APIs to validate OAP grant tokens:

```go
mw := gateway.NewGrantMiddleware(gateway.GrantMiddlewareConfig{
    OAPServerURL: "http://oap-server:8080",
    HeaderName:   "X-OAP-Grant-Token",  // default
    AllowMissing: false,                  // fail-closed
})
http.Handle("/api/", mw.Wrap(myAPIHandler))
```

On valid grant, sets headers on the request for the downstream handler:
- `X-OAP-Verified-Agent-ID` — the authorized agent
- `X-OAP-Verified-Action` — the allowed action
- `X-OAP-Verified-Decision` — `allow` or `allow_with_constraints`
- `X-OAP-Run-ID` — execution run ID (if present)

## Data Flow

```
Agent sends HTTP request (with Bearer session token)
  │
  ├── Map method + path → OAP action (explicit routes or derived)
  ├── Check X-OAP-Agent-ID header (optional override)
  │
  ├── [Embedded] evaluator.Evaluate(request) locally
  │   OR
  ├── [Remote] POST /v1/authorize to OAP server (with Bearer token)
  │
  │     ├── deny → return 403 with structured error
  │     ├── allow → inject X-OAP-Grant-Token, forward to upstream
  │     └── observe mode → log + forward regardless
  └── Emit audit event
```

## Route Resolution

1. **Explicit routes** — exact match from `Routes` map (`"GET /api/invoices" → "erp.invoice.read"`)
2. **Prefix match** — if method matches and path starts with pattern
3. **Derived** — `GET /users/123` → `users.123.read` (method mapped to verb)

## Configuration

| Field | Description | Required |
|---|---|---|
| `AgentID` | Default agent identity | Yes |
| `UpstreamURL` | Target API server URL | Yes |
| `OAPServerURL` | OAP server URL (remote mode) | For remote mode |
| `Store` | Policy store (embedded mode) | For embedded mode |
| `AuditSink` | Audit event sink | For embedded mode |
| `ObserveMode` | Log decisions without blocking | No (default: false) |
| `Routes` | Map of `"METHOD /path" → "action.name"` | No |

## Testing

```bash
go test -v ./gateway/
# 13 tests: allow, deny, observe, health, routes, agent override,
#           remote allow+grant injection, remote deny, OAP down,
#           grant middleware valid/missing/allow-missing/invalid
```
