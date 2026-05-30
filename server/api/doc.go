// Package api implements the OAP HTTP server handlers.
//
// This package provides the HTTP API defined in spec/openapi/oap-server.openapi.yaml.
// It wraps the evaluator library, registry store, and audit sink into a
// standard net/http server.
//
// Key endpoints:
//   - POST /v1/authorize  — runtime authorization (the hot path)
//   - POST /v1/simulate   — dry-run with evaluation trace
//   - POST /v1/agents     — register an agent
//   - GET  /v1/agents     — list agents
//   - POST /v1/policies   — apply a policy
//   - GET  /v1/policies   — list policies
//   - GET  /v1/audit      — query audit events
//   - GET  /v1/health     — process liveness
//   - GET  /v1/ready      — dependency readiness
//   - GET  /metrics       — Prometheus text metrics
//
// Data flow for POST /v1/authorize:
//
//	HTTP request (JSON body)
//	  → Parse into model.AuthorizationRequest
//	  → evaluator.Evaluate(ctx, request)
//	  → Build model.AuditEvent from request + decision
//	  → audit.Sink.Write(event)
//	  → Return model.AuthorizationDecision as JSON
package api
