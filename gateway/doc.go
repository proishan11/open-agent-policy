// Package gateway implements the OAP HTTP reverse proxy with policy enforcement.
//
// The gateway sits between an AI agent and upstream HTTP APIs. It intercepts
// every HTTP request, maps it to an OAP action, evaluates policy, and either
// forwards the request or returns a structured denial.
//
// Key design:
//   - Agent changes API base URL to point at the gateway
//   - Gateway maps HTTP method + path → OAP action name via route config
//   - Allowed requests are forwarded with optional credential injection
//   - Denied requests return 403 with structured error
//   - Observe mode logs without blocking
//
// Data flow:
//
//	Agent → HTTP Gateway (OAP) → Upstream API
//	         ├── Map route to action
//	         ├── Authorize via evaluator
//	         ├── Deny → return 403 to agent
//	         ├── Allow → forward to upstream
//	         └── Emit audit event
package gateway
