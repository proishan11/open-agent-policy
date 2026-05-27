package model

// Decision constants define the possible outcomes of policy evaluation.
// These map to the "decision" enum in authorization-decision.schema.json.
const (
	DecisionAllow              = "allow"
	DecisionAllowConstrained   = "allow_with_constraints"
	DecisionDeny               = "deny"
	DecisionRequireApproval    = "require_approval"
	DecisionRequireDelegation  = "require_delegation"
	DecisionRequireStepUpAuth  = "require_step_up_auth"
)

// AuthorizationDecision is the structured output of the policy evaluator.
// It tells the enforcement point exactly what to do: allow, deny, constrain,
// or require additional steps (approval, delegation, step-up auth).
//
// This maps to spec/v1alpha1/authorization-decision.schema.json.
type AuthorizationDecision struct {
	// DecisionID uniquely identifies this decision.
	DecisionID string `json:"decision_id" yaml:"decision_id"`

	// RequestID correlates back to the AuthorizationRequest.
	RequestID string `json:"request_id" yaml:"request_id"`

	// Decision is the evaluation result.
	Decision string `json:"decision" yaml:"decision"`

	// PolicyIDs lists the policies that contributed to this decision.
	// Useful for debugging and audit.
	PolicyIDs []string `json:"policy_ids,omitempty" yaml:"policy_ids,omitempty"`

	// Grant contains a short-lived, scoped token if the decision is allow.
	Grant *GrantRef `json:"grant,omitempty" yaml:"grant,omitempty"`

	// Constraints narrow what the agent can do within the allowed action.
	// Only present when Decision is "allow_with_constraints".
	Constraints *Constraints `json:"constraints,omitempty" yaml:"constraints,omitempty"`

	// Obligations are requirements the enforcement point must fulfil.
	Obligations *Obligations `json:"obligations,omitempty" yaml:"obligations,omitempty"`

	// Reason is a human-readable explanation of the decision.
	Reason string `json:"reason" yaml:"reason"`

	// Approval contains details when Decision is "require_approval".
	Approval *ApprovalRef `json:"approval,omitempty" yaml:"approval,omitempty"`
}

// GrantRef references a grant issued as part of an allow decision.
type GrantRef struct {
	GrantID          string   `json:"grant_id" yaml:"grant_id"`
	Token            string   `json:"token,omitempty" yaml:"token,omitempty"`
	ExpiresInSeconds int      `json:"expires_in_seconds,omitempty" yaml:"expires_in_seconds,omitempty"`
	Audience         string   `json:"audience,omitempty" yaml:"audience,omitempty"`
	Scope            []string `json:"scope,omitempty" yaml:"scope,omitempty"`
}

// Constraints narrow permitted actions. When multiple policies match,
// constraints are merged using "strictest wins" semantics:
// - Numeric fields: minimum value wins
// - Boolean fields: most restrictive wins (readonly=true wins)
// - Array fields: union (e.g., redact fields are combined)
type Constraints struct {
	MaxRecords        *int     `json:"max_records,omitempty" yaml:"max_records,omitempty"`
	RedactFields      []string `json:"redact_fields,omitempty" yaml:"redact_fields,omitempty"`
	ReadOnly          *bool    `json:"readonly,omitempty" yaml:"readonly,omitempty"`
	TimeWindowSeconds *int     `json:"time_window_seconds,omitempty" yaml:"time_window_seconds,omitempty"`

	// Extra holds any additional constraint key-value pairs not covered above.
	Extra map[string]interface{} `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// Obligations are requirements the enforcement point must fulfil after
// receiving the decision (e.g., emit audit event, notify approvers).
type Obligations struct {
	Audit          bool     `json:"audit,omitempty" yaml:"audit,omitempty"`
	LogFullRequest bool     `json:"log_full_request,omitempty" yaml:"log_full_request,omitempty"`
	Notify         []string `json:"notify,omitempty" yaml:"notify,omitempty"`
}

// ApprovalRef contains details when a decision requires human approval.
type ApprovalRef struct {
	ApprovalID       string   `json:"approval_id,omitempty" yaml:"approval_id,omitempty"`
	Approvers        []string `json:"approvers,omitempty" yaml:"approvers,omitempty"`
	ExpiresInSeconds int      `json:"expires_in_seconds,omitempty" yaml:"expires_in_seconds,omitempty"`
}
