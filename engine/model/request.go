package model

import "time"

// AuthorizationRequest is the normalized input to the policy evaluator.
// It captures who (subject + actor), what (action), on what (resource),
// via what (tool), and why (context).
//
// This maps to spec/v1alpha1/authorization-request.schema.json.
type AuthorizationRequest struct {
	// RequestID is a unique identifier for this authorization request.
	// Used for correlation across audit events, grants, and logs.
	RequestID string `json:"request_id" yaml:"request_id"`

	// Timestamp is when the request was made.
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	// Subject identifies the agent making the request.
	Subject Subject `json:"subject" yaml:"subject"`

	// Actor is the human or service on whose behalf the agent acts.
	// May be nil if the agent acts autonomously (no delegation).
	Actor *Actor `json:"actor,omitempty" yaml:"actor,omitempty"`

	// Action describes what the agent wants to do.
	Action Action `json:"action" yaml:"action"`

	// Resource identifies the target of the action.
	// May be nil for actions that don't target a specific resource.
	Resource *ResourceRef `json:"resource,omitempty" yaml:"resource,omitempty"`

	// Tool identifies the tool being used to perform the action.
	// May be nil if the action is not tool-mediated.
	Tool *ToolRef `json:"tool,omitempty" yaml:"tool,omitempty"`

	// Context carries additional metadata like purpose, run ID,
	// delegation ID, environment, and approval references.
	Context map[string]interface{} `json:"context,omitempty" yaml:"context,omitempty"`
}

// Subject identifies the agent in an authorization request.
type Subject struct {
	// Type is always "agent" in OAP.
	Type string `json:"type" yaml:"type"`

	// AgentID is the canonical agent URI, e.g. "agent://finance/invoice-reconciler".
	AgentID string `json:"agent_id" yaml:"agent_id"`

	// AgentVersion is the declared version of the agent.
	AgentVersion string `json:"agent_version,omitempty" yaml:"agent_version,omitempty"`

	// InstanceID identifies a specific running instance of the agent.
	InstanceID string `json:"instance_id,omitempty" yaml:"instance_id,omitempty"`

	// TrustLevel indicates how the agent's identity was verified.
	// One of: "unverified", "verified", "attested".
	TrustLevel string `json:"trust_level,omitempty" yaml:"trust_level,omitempty"`
}

// Actor represents the human or service on whose behalf the agent acts.
type Actor struct {
	// Type is one of: "user", "service", "agent".
	Type string `json:"type" yaml:"type"`

	// ID is the actor's identifier (e.g., user email, service account name).
	ID string `json:"id" yaml:"id"`

	// Groups the actor belongs to (e.g., "finance-team", "admin").
	Groups []string `json:"groups,omitempty" yaml:"groups,omitempty"`

	// Roles the actor holds.
	Roles []string `json:"roles,omitempty" yaml:"roles,omitempty"`

	// AuthStrength indicates how strongly the actor authenticated.
	// One of: "none", "password", "mfa", "phishing_resistant_mfa".
	AuthStrength string `json:"auth_strength,omitempty" yaml:"auth_strength,omitempty"`
}

// Action describes what the agent wants to do.
type Action struct {
	// Name is the action identifier, e.g. "erp.invoice.read".
	Name string `json:"name" yaml:"name"`

	// Risk is the assessed risk level of this action.
	// One of: "low", "medium", "high", "critical".
	Risk string `json:"risk,omitempty" yaml:"risk,omitempty"`
}

// ToolRef identifies the tool being used to perform an action.
type ToolRef struct {
	// Name is the tool name, e.g. "query_invoices".
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Protocol is how the tool is invoked.
	// One of: "mcp", "http", "function", "shell", "sdk".
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Server identifies the MCP server or API endpoint hosting the tool.
	Server string `json:"server,omitempty" yaml:"server,omitempty"`
}
