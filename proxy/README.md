# MCP Proxy

OAP MCP proxy — intercepts MCP protocol messages and authorizes tool calls.

## Purpose

Sits between an AI agent and an MCP server. The agent connects to the proxy instead of the real MCP server. Every `tools/call` is authorized against OAP policy before forwarding. No code changes to the agent required.

## Architecture

```
proxy/
├── doc.go          Package documentation
├── proxy.go        MCP proxy implementation
└── proxy_test.go   Integration tests (8 tests)
```

## Deployment Modes

| Mode | Config | Use case |
|---|---|---|
| **Embedded** | `Store` + `AuditSink` | Sidecar deployment, local policy evaluation |
| **Remote** | `OAPServerURL` | Centralized OAP server, session-aware auth |

### Embedded mode (local evaluator)

```go
p := proxy.New(proxy.Config{
    AgentID:     "agent://support/ticket-assistant",
    UpstreamURL: "http://mcp-server:8080",
    ObserveMode: false,
    Store:       store,
    AuditSink:   sink,
})
http.ListenAndServe(":7777", p.Handler())
```

### Remote mode (OAP server)

```go
p := proxy.New(proxy.Config{
    AgentID:      "agent://support/ticket-assistant",
    UpstreamURL:  "http://mcp-server:8080",
    OAPServerURL: "http://oap-server:8080",  // delegates to OAP server
})
http.ListenAndServe(":7777", p.Handler())
```

In remote mode, the proxy:
1. Extracts the `Bearer` session token from incoming requests
2. Calls OAP server `POST /v1/authorize` with the token and tool name
3. On allow, forwards the tool call to the upstream MCP server
4. On deny or OAP unreachable, returns MCP error -32001 (fail-closed)

## Data Flow

```
Agent sends MCP JSON-RPC request (with Bearer session token)
  │
  ├── initialize → respond with proxy capabilities
  ├── tools/list → fetch from upstream, filter by policy
  ├── tools/call → authorize:
  │     ├── [Embedded] evaluator.Evaluate(request) locally
  │     │   OR
  │     ├── [Remote] POST /v1/authorize to OAP server
  │     │
  │     ├── deny → return MCP error (-32001)
  │     ├── allow → forward to upstream
  │     └── observe mode → log + forward regardless
  └── other methods → forward to upstream as-is
```

## Configuration

| Field | Description | Required |
|---|---|---|
| `AgentID` | Agent identity for all proxied calls | Yes |
| `UpstreamURL` | Upstream MCP server URL | Yes |
| `OAPServerURL` | OAP server URL (remote mode) | For remote mode |
| `Store` | Policy store (embedded mode) | For embedded mode |
| `AuditSink` | Audit event sink | For embedded mode |
| `ObserveMode` | Log decisions without blocking | No (default: false) |

## Testing

```bash
go test -v ./proxy/
# 8 tests: initialize, allow, deny, observe, health,
#          remote allow, remote deny, OAP down
```
