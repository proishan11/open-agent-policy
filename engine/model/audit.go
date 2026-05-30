package model

import "time"

// AuditEvent is a structured record of an authorization decision or
// lifecycle event. Every evaluation produces exactly one audit event.
//
// This maps to spec/v1alpha1/audit-event.schema.json.
type AuditEvent struct {
	// EventID uniquely identifies this audit event.
	EventID string `json:"event_id" yaml:"event_id"`

	// EventType categorizes the event (e.g., "authorization.decision",
	// "agent.registered", "policy.applied", "grant.revoked").
	EventType string `json:"event_type" yaml:"event_type"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	// Decision is the evaluation result ("allow", "deny", etc.).
	Decision string `json:"decision" yaml:"decision"`

	// Subject identifies the agent involved.
	Subject *AuditSubject `json:"subject,omitempty" yaml:"subject,omitempty"`

	// Actor identifies the human or service (if present).
	Actor *AuditActor `json:"actor,omitempty" yaml:"actor,omitempty"`

	// Action is what was requested.
	Action string `json:"action" yaml:"action"`

	// Resource is the target of the action.
	Resource *AuditResource `json:"resource,omitempty" yaml:"resource,omitempty"`

	// PolicyIDs lists the policies that contributed to the decision.
	PolicyIDs []string `json:"policy_ids,omitempty" yaml:"policy_ids,omitempty"`

	// Constraints applied to the decision.
	Constraints map[string]interface{} `json:"constraints,omitempty" yaml:"constraints,omitempty"`

	// GrantID references the grant issued (if any).
	GrantID string `json:"grant_id,omitempty" yaml:"grant_id,omitempty"`

	// RequestID correlates to the authorization request.
	RequestID string `json:"request_id,omitempty" yaml:"request_id,omitempty"`

	// RunID identifies the agent's execution run.
	RunID string `json:"run_id,omitempty" yaml:"run_id,omitempty"`

	// TraceID for distributed tracing correlation.
	TraceID string `json:"trace_id,omitempty" yaml:"trace_id,omitempty"`

	// Reason is a human-readable explanation.
	Reason string `json:"reason" yaml:"reason"`
}

// AuditSubject identifies the agent in an audit event.
type AuditSubject struct {
	AgentID    string `json:"agent_id" yaml:"agent_id"`
	InstanceID string `json:"instance_id,omitempty" yaml:"instance_id,omitempty"`
}

// AuditActor identifies the actor in an audit event.
type AuditActor struct {
	Type string `json:"type" yaml:"type"`
	ID   string `json:"id" yaml:"id"`
}

// AuditResource identifies the resource in an audit event.
type AuditResource struct {
	Type           string `json:"type" yaml:"type"`
	ID             string `json:"id,omitempty" yaml:"id,omitempty"`
	Classification string `json:"classification,omitempty" yaml:"classification,omitempty"`
}
