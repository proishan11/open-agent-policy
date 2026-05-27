// Package model defines the core domain types for Open Agent Policy.
//
// These types are the Go representation of the canonical JSON Schemas in
// spec/v1alpha1/. They are used by the evaluator, registries, server, and CLI.
//
// Key types:
//   - AuthorizationRequest: a normalized request asking "can this agent do this?"
//   - AuthorizationDecision: the evaluator's response (allow/deny/constrain/etc.)
//   - Agent: a registered autonomous software actor
//   - Resource: a registered resource type with classification
//   - Tool: a registered tool mapping to an action and resource
//   - AgentPolicy: a set of rules governing what agents can do
//   - AuditEvent: a structured record of every authorization decision
//   - Grant: a short-lived, scoped permission token
//   - Delegation: actor-to-agent authority transfer
//
// All types use JSON tags matching the spec schema field names for direct
// serialization/deserialization.
package model
