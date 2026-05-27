package model

// Effect constants define the possible effects of a policy rule.
const (
	EffectAllow             = "allow"
	EffectDeny              = "deny"
	EffectRequireApproval   = "require_approval"
	EffectRequireDelegation = "require_delegation"
)

// AgentPolicy is a set of rules governing what agents can do.
// Policies are the core governance primitive in OAP.
//
// This maps to spec/v1alpha1/policy.schema.json.
type AgentPolicy struct {
	APIVersion string     `json:"apiVersion" yaml:"apiVersion"`
	Kind       string     `json:"kind" yaml:"kind"`
	Metadata   Metadata   `json:"metadata" yaml:"metadata"`
	Spec       PolicySpec `json:"spec" yaml:"spec"`
}

// PolicySpec defines the policy's subject selector and rules.
type PolicySpec struct {
	// Subject selects which agents this policy applies to.
	// If multiple fields are set, all must match.
	Subject PolicySubject `json:"subject" yaml:"subject"`

	// Rules are evaluated in order. The first matching rule determines the effect.
	// However, deny rules always win regardless of order (deny-overrides-allow).
	Rules []PolicyRule `json:"rules" yaml:"rules"`
}

// PolicySubject selects which agents a policy applies to.
// Exactly one of these fields should typically be set.
type PolicySubject struct {
	// Agent matches a specific agent by ID (e.g., "agent://finance/invoice-reconciler").
	Agent string `json:"agent,omitempty" yaml:"agent,omitempty"`

	// AgentType matches all agents of a given type (e.g., "workflow_agent").
	AgentType string `json:"agentType,omitempty" yaml:"agentType,omitempty"`

	// AgentNamespace matches all agents in a given namespace.
	AgentNamespace string `json:"agentNamespace,omitempty" yaml:"agentNamespace,omitempty"`

	// AllAgents matches every registered agent. Use with caution.
	AllAgents bool `json:"allAgents,omitempty" yaml:"allAgents,omitempty"`
}

// PolicyRule is a single evaluation rule within a policy.
type PolicyRule struct {
	// Effect is always explicit: "allow", "deny", "require_approval", "require_delegation".
	Effect string `json:"effect" yaml:"effect"`

	// Actions lists the action names this rule matches (e.g., ["erp.invoice.read"]).
	// Supports wildcards: ["*"] matches all actions.
	Actions []string `json:"actions" yaml:"actions"`

	// Resources narrows which resources this rule applies to.
	// If nil, the rule applies to all resources.
	Resources *PolicyResourceSelector `json:"resources,omitempty" yaml:"resources,omitempty"`

	// Conditions are boolean prerequisites — the rule does not match if they fail.
	// Keys are condition names; values are the expected values.
	Conditions map[string]interface{} `json:"conditions,omitempty" yaml:"conditions,omitempty"`

	// Constraints narrow what the agent can do within the allowed action.
	// Only meaningful for "allow" effect rules.
	Constraints map[string]interface{} `json:"constraints,omitempty" yaml:"constraints,omitempty"`

	// Obligations are requirements the enforcement point must fulfil.
	Obligations map[string]interface{} `json:"obligations,omitempty" yaml:"obligations,omitempty"`

	// Approval specifies approval requirements for "require_approval" rules.
	Approval *PolicyApproval `json:"approval,omitempty" yaml:"approval,omitempty"`

	// Reason is a human-readable explanation of why this rule exists.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`

	// FailMode determines behavior if a condition evaluation errors.
	// "closed" (default) means deny; "open" means skip this rule.
	FailMode string `json:"failMode,omitempty" yaml:"failMode,omitempty"`
}

// PolicyResourceSelector filters which resources a rule applies to.
type PolicyResourceSelector struct {
	Types             []string `json:"types,omitempty" yaml:"types,omitempty"`
	ClassificationMax string   `json:"classificationMax,omitempty" yaml:"classificationMax,omitempty"`
	Environments      []string `json:"environments,omitempty" yaml:"environments,omitempty"`
	Owners            []string `json:"owners,omitempty" yaml:"owners,omitempty"`
}

// PolicyApproval specifies who must approve and how long the approval window lasts.
type PolicyApproval struct {
	Approvers    []string `json:"approvers,omitempty" yaml:"approvers,omitempty"`
	MinApprovals int      `json:"minApprovals,omitempty" yaml:"minApprovals,omitempty"`
	ExpiresIn    string   `json:"expiresIn,omitempty" yaml:"expiresIn,omitempty"`
}

// ID returns a unique policy identifier: "<namespace>/<name>".
func (p *AgentPolicy) ID() string {
	return p.Metadata.Namespace + "/" + p.Metadata.Name
}

// MatchesAgent checks if this policy's subject selector matches the given agent.
// This is the first step in evaluation: does this policy even apply to this agent?
func (p *AgentPolicy) MatchesAgent(agent *Agent) bool {
	s := p.Spec.Subject

	// allAgents matches everything
	if s.AllAgents {
		return true
	}

	// Match by specific agent ID
	if s.Agent != "" && s.Agent == agent.ID() {
		return true
	}

	// Match by agent type
	if s.AgentType != "" && s.AgentType == agent.Spec.Type {
		return true
	}

	// Match by namespace
	if s.AgentNamespace != "" && s.AgentNamespace == agent.Metadata.Namespace {
		return true
	}

	return false
}
