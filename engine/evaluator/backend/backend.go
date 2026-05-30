package backend

import (
	"context"

	"github.com/proishan11/open-agent-policy/engine/model"
)

// Input is the normalized input sent to a policy backend for evaluation.
// It contains the OAP authorization request plus the matching policies
// that the OAP evaluator has already resolved for the agent.
type Input struct {
	// Request is the original OAP authorization request.
	Request model.AuthorizationRequest `json:"request"`

	// Agent is the resolved agent from the registry.
	Agent *model.Agent `json:"agent"`

	// Policies are the policies that match the agent (already resolved by OAP).
	Policies []*model.AgentPolicy `json:"policies"`
}

// Result is what a policy backend returns after rule evaluation.
type Result struct {
	// Decision is the evaluation outcome.
	Decision string `json:"decision"` // allow, deny, allow_with_constraints, require_approval

	// Reason is a human-readable explanation.
	Reason string `json:"reason"`

	// PolicyIDs that contributed to the decision.
	PolicyIDs []string `json:"policy_ids,omitempty"`

	// Constraints from matching allow rules (merged by the backend or by OAP).
	Constraints map[string]interface{} `json:"constraints,omitempty"`

	// Obligations to execute after allowing the action.
	Obligations *model.Obligations `json:"obligations,omitempty"`

	// Approval details (when decision is require_approval).
	Approval *model.ApprovalRef `json:"approval,omitempty"`
}

// Backend is the pluggable policy evaluation interface.
//
// OAP's evaluator handles agent lifecycle (registration, status, delegation).
// The backend handles ONLY rule evaluation: given a request and matching policies,
// which rules fire and what is the decision?
//
// Implementations:
//   - BuiltinBackend: OAP's native deny-overrides-allow (default)
//   - OPABackend: Delegates to Open Policy Agent via REST or embedded Rego
//   - CedarBackend: Delegates to AWS Cedar via REST
type Backend interface {
	// Evaluate processes the input and returns a rule evaluation result.
	// The backend MUST NOT perform agent lifecycle checks — OAP handles those.
	Evaluate(ctx context.Context, input Input) (*Result, error)

	// Name returns the backend identifier (e.g., "builtin", "opa", "cedar").
	Name() string
}
