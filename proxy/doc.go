// Package proxy implements the OAP MCP proxy.
//
// The MCP proxy sits between an AI agent and an MCP server. It intercepts
// MCP protocol messages (tools/list and tools/call), authorizes each tool
// call against OAP policy, and forwards allowed calls to the upstream server.
//
// Key design:
//   - Agent connects to the proxy instead of the real MCP server
//   - tools/list responses are filtered to only show allowed tools
//   - tools/call requests are authorized before forwarding
//   - Denied calls return an MCP error without reaching upstream
//   - Observe mode logs decisions without blocking
//
// Data flow:
//
//	Agent → MCP Proxy (OAP) → Upstream MCP Server
//	         ├── Authorize tool call
//	         ├── Deny → return MCP error to agent
//	         ├── Allow → forward to upstream, return result
//	         └── Emit audit event
package proxy
