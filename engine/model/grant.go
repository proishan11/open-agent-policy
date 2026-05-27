package model

import "time"

// Grant is a short-lived, scoped permission token issued by OAP when
// an authorization decision is "allow" or "allow_with_constraints".
// Grants replace broad standing credentials with narrow, time-bound tokens.
//
// This maps to spec/v1alpha1/grant.schema.json.
type Grant struct {
	// GrantID uniquely identifies this grant.
	GrantID string `json:"grant_id" yaml:"grant_id"`

	// AgentID identifies the agent this grant was issued to.
	AgentID string `json:"agent_id" yaml:"agent_id"`

	// Action is the specific action this grant authorizes.
	Action string `json:"action" yaml:"action"`

	// Resource is the specific resource this grant is scoped to.
	Resource GrantResource `json:"resource" yaml:"resource"`

	// Constraints narrow the grant's scope.
	Constraints map[string]interface{} `json:"constraints,omitempty" yaml:"constraints,omitempty"`

	// IssuedAt is when the grant was created.
	IssuedAt time.Time `json:"issued_at" yaml:"issued_at"`

	// ExpiresAt is when the grant becomes invalid.
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`

	// Status is one of: "active", "expired", "revoked".
	Status string `json:"status" yaml:"status"`
}

// GrantResource identifies the resource a grant is scoped to.
type GrantResource struct {
	Type string `json:"type" yaml:"type"`
	ID   string `json:"id" yaml:"id"`
}

// IsExpired returns true if the grant has passed its expiration time.
func (g *Grant) IsExpired() bool {
	return time.Now().After(g.ExpiresAt)
}

// IsValid returns true if the grant is active and not expired.
func (g *Grant) IsValid() bool {
	return g.Status == "active" && !g.IsExpired()
}
