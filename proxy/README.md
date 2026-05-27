# MCP Proxy

OAP MCP proxy — intercepts MCP protocol messages and authorizes tool calls.

## Purpose

Sits between an AI agent and an MCP server. The agent connects to the proxy instead of the real MCP server. Every `tools/call` is authorized against OAP policy before forwarding. No code changes to the agent required.

## Architecture

```
proxy/
├── doc.go          Package documentation
├── proxy.go        MCP proxy implementation
└── proxy_test.go   Integration tests (5 tests)
```

## Key Interfaces

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

## Data Flow

```
Agent sends MCP JSON-RPC request
  │
  ├── initialize → respond with proxy capabilities
  ├── tools/list → fetch from upstream, filter by policy
  ├── tools/call → authorize, then:
  │     ├── deny → return MCP error (-32001)
  │     ├── allow → forward to upstream
  │     └── observe mode → log + forward regardless
  └── other methods → forward to upstream as-is
```

## Configuration

| Field | Description |
|-------|-------------|
| `AgentID` | Agent identity for all proxied calls |
| `UpstreamURL` | Upstream MCP server URL |
| `ObserveMode` | Log decisions without blocking |
| `Store` | Registry store (agents + policies) |
| `AuditSink` | Audit event sink |

## Testing

```bash
go test -v ./proxy/
```
