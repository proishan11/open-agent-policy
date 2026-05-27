package evaluator

import (
	"context"
	"fmt"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store"
)

// Evaluator is the policy decision point (PDP). It holds a reference to the
// store and evaluates authorization requests against registered agents and
// policies.
type Evaluator struct {
	store store.Store
}

// New creates an Evaluator backed by the given store.
func New(s store.Store) *Evaluator {
	return &Evaluator{store: s}
}

// TraceStep records one step of the evaluation for simulation/explain mode.
type TraceStep struct {
	Step     string `json:"step"`
	Result   string `json:"result"`
	Detail   string `json:"detail"`
	PolicyID string `json:"policy_id,omitempty"`
}

// EvalResult bundles the decision with an optional trace for simulation.
type EvalResult struct {
	Decision model.AuthorizationDecision
	Trace    []TraceStep
}

// Evaluate processes an authorization request and returns a decision.
// This is the hot-path function called on every protected tool invocation.
//
// The evaluation follows the order specified in architecture.md §7.4.
func (e *Evaluator) Evaluate(ctx context.Context, req model.AuthorizationRequest) EvalResult {
	var trace []TraceStep
	now := time.Now().UTC()

	// Generate decision ID
	decisionID := fmt.Sprintf("dec-%d", now.UnixNano())
	baseDec := model.AuthorizationDecision{
		DecisionID: decisionID,
		RequestID:  req.RequestID,
	}

	// Step 1: Validate request — required fields
	if req.Subject.AgentID == "" {
		trace = append(trace, TraceStep{Step: "validate_request", Result: "fail", Detail: "missing subject.agent_id"})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "invalid request: missing subject.agent_id"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	if req.Action.Name == "" {
		trace = append(trace, TraceStep{Step: "validate_request", Result: "fail", Detail: "missing action.name"})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "invalid request: missing action.name"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	trace = append(trace, TraceStep{Step: "validate_request", Result: "pass", Detail: "request is valid"})

	// Step 2: Verify agent identity — is the agent registered and active?
	agent, err := e.store.GetAgent(ctx, req.Subject.AgentID)
	if err != nil {
		trace = append(trace, TraceStep{Step: "verify_agent", Result: "fail", Detail: "store error: " + err.Error()})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "internal error (fail-closed)"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	if agent == nil {
		trace = append(trace, TraceStep{Step: "verify_agent", Result: "fail", Detail: "agent not registered: " + req.Subject.AgentID})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "agent is unregistered"
		return EvalResult{Decision: baseDec, Trace: trace}
	}

	// Check if agent is revoked or suspended
	if agent.Status.State == model.AgentStateRevoked {
		trace = append(trace, TraceStep{Step: "verify_agent", Result: "fail", Detail: "agent is revoked"})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "agent is revoked"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	if agent.Status.State == model.AgentStateSuspended {
		trace = append(trace, TraceStep{Step: "verify_agent", Result: "fail", Detail: "agent is suspended"})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "agent is suspended"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	trace = append(trace, TraceStep{Step: "verify_agent", Result: "pass", Detail: "agent registered and active"})

	// Step 3: Find matching policies
	policies, err := e.store.PoliciesForAgent(ctx, agent)
	if err != nil {
		trace = append(trace, TraceStep{Step: "find_policies", Result: "fail", Detail: "store error: " + err.Error()})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "internal error (fail-closed)"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	if len(policies) == 0 {
		// Deny-by-default: no policies means no access
		trace = append(trace, TraceStep{Step: "find_policies", Result: "fail", Detail: "no matching policies found"})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "no matching policy (deny by default)"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	trace = append(trace, TraceStep{
		Step:   "find_policies",
		Result: "pass",
		Detail: fmt.Sprintf("found %d matching policies", len(policies)),
	})

	// Step 4: Check delegation scope if a delegation_id is present in context.
	// If the requested action is outside the delegation's allowed actions, deny.
	if req.Context != nil {
		if _, hasDelegation := req.Context["delegation_id"]; hasDelegation {
			if !e.delegationCoversAction(req) {
				trace = append(trace, TraceStep{
					Step:   "check_delegation_scope",
					Result: "fail",
					Detail: fmt.Sprintf("action %q is outside delegation scope", req.Action.Name),
				})
				baseDec.Decision = model.DecisionDeny
				baseDec.Reason = "action is outside delegation scope"
				return EvalResult{Decision: baseDec, Trace: trace}
			}
			trace = append(trace, TraceStep{Step: "check_delegation_scope", Result: "pass", Detail: "action within delegation scope"})
		}
	}

	// Step 5: Evaluate rules across all matching policies.
	// We collect all matching rules, then apply deny-overrides-allow semantics.
	return e.evaluateRules(baseDec, req, agent, policies, trace)
}

// evaluateRules applies the deny-overrides-allow algorithm across all matching policies.
//
// Algorithm:
//  1. Scan ALL rules in ALL matching policies for deny rules that match the action.
//     If any deny matches → deny immediately (deny overrides allow).
//  2. Scan for require_approval rules that match. If found → require_approval.
//  3. Scan for allow rules that match. Collect constraints from all matching allow rules.
//  4. Merge constraints using strictest-wins semantics.
//  5. If no allow rule matched → deny by default.
func (e *Evaluator) evaluateRules(
	baseDec model.AuthorizationDecision,
	req model.AuthorizationRequest,
	agent *model.Agent,
	policies []*model.AgentPolicy,
	trace []TraceStep,
) EvalResult {

	var (
		matchedDeny     []matchedRule
		matchedApproval []matchedRule
		matchedAllow    []matchedRule
	)

	// Track condition failures for better deny reasons
	var lastConditionFailReason string

	// Scan all rules in all matching policies
	for _, policy := range policies {
		for _, rule := range policy.Spec.Rules {
			if !actionMatches(rule.Actions, req.Action.Name) {
				continue
			}

			// Check conditions (boolean prerequisites)
			if !e.conditionsMet(rule, req, agent) {
				reason := e.conditionFailReason(rule, req)
				lastConditionFailReason = reason
				trace = append(trace, TraceStep{
					Step:     "evaluate_conditions",
					Result:   "skip",
					Detail:   fmt.Sprintf("%s (rule in %s)", reason, policy.ID()),
					PolicyID: policy.ID(),
				})
				continue
			}

			mr := matchedRule{policyID: policy.ID(), rule: rule}
			switch rule.Effect {
			case model.EffectDeny:
				matchedDeny = append(matchedDeny, mr)
			case model.EffectRequireApproval:
				matchedApproval = append(matchedApproval, mr)
			case model.EffectAllow:
				matchedAllow = append(matchedAllow, mr)
			case model.EffectRequireDelegation:
				// Check if delegation is present in context
				if req.Actor == nil {
					matchedDeny = append(matchedDeny, mr)
				}
			}
		}
	}

	// Deny overrides everything
	if len(matchedDeny) > 0 {
		policyIDs := collectPolicyIDs(matchedDeny)
		reason := "explicitly denied"
		if matchedDeny[0].rule.Reason != "" {
			reason = matchedDeny[0].rule.Reason
		}
		trace = append(trace, TraceStep{
			Step:     "deny_overrides",
			Result:   "match",
			Detail:   fmt.Sprintf("explicit deny from %s", policyIDs[0]),
			PolicyID: policyIDs[0],
		})
		baseDec.Decision = model.DecisionDeny
		baseDec.PolicyIDs = policyIDs
		baseDec.Reason = reason
		return EvalResult{Decision: baseDec, Trace: trace}
	}

	// Require approval takes precedence over allow
	if len(matchedApproval) > 0 {
		policyIDs := collectPolicyIDs(matchedApproval)
		reason := "requires approval"
		if matchedApproval[0].rule.Reason != "" {
			reason = matchedApproval[0].rule.Reason
		}
		trace = append(trace, TraceStep{
			Step:     "require_approval",
			Result:   "match",
			Detail:   fmt.Sprintf("approval required by %s", policyIDs[0]),
			PolicyID: policyIDs[0],
		})
		baseDec.Decision = model.DecisionRequireApproval
		baseDec.PolicyIDs = policyIDs
		baseDec.Reason = reason

		// Attach approval details from the first matching rule
		if matchedApproval[0].rule.Approval != nil {
			baseDec.Approval = &model.ApprovalRef{
				Approvers: matchedApproval[0].rule.Approval.Approvers,
			}
			if matchedApproval[0].rule.Approval.ExpiresIn != "" {
				// Parse duration for expires_in_seconds
				baseDec.Approval.ExpiresInSeconds = parseDurationSeconds(matchedApproval[0].rule.Approval.ExpiresIn)
			}
		}
		return EvalResult{Decision: baseDec, Trace: trace}
	}

	// Allow — merge constraints from all matching allow rules
	if len(matchedAllow) > 0 {
		policyIDs := collectPolicyIDs(matchedAllow)
		constraints := mergeConstraints(matchedAllow)
		trace = append(trace, TraceStep{
			Step:   "allow",
			Result: "match",
			Detail: fmt.Sprintf("allowed by %d rules from %d policies", len(matchedAllow), len(policyIDs)),
		})

		if constraints != nil {
			baseDec.Decision = model.DecisionAllowConstrained
			baseDec.Constraints = constraints
			baseDec.Reason = "allowed with constraints"
		} else {
			baseDec.Decision = model.DecisionAllow
			baseDec.Reason = "allowed"
		}
		baseDec.PolicyIDs = policyIDs

		// Collect obligations from all matching rules
		baseDec.Obligations = mergeObligations(matchedAllow)

		return EvalResult{Decision: baseDec, Trace: trace}
	}

	// No allow rule matched — deny by default.
	// If conditions were the reason, provide a more specific denial reason.
	reason := "no matching policy (deny by default)"
	if lastConditionFailReason != "" {
		reason = lastConditionFailReason
	}
	trace = append(trace, TraceStep{
		Step:   "deny_by_default",
		Result: "fail",
		Detail: "no allow rule matched the requested action",
	})
	baseDec.Decision = model.DecisionDeny
	baseDec.Reason = reason
	return EvalResult{Decision: baseDec, Trace: trace}
}

// matchedRule pairs a policy ID with the specific rule that matched.
type matchedRule struct {
	policyID string
	rule     model.PolicyRule
}

// conditionsMet evaluates the boolean conditions on a rule.
// Currently supports:
//   - actorRequired: true/false — checks if an actor is present in the request
//   - delegationRequired: true — checks if a delegation_id is in context
//
// Returns true if all conditions are met (or if there are no conditions).
// Also returns a human-readable reason if conditions are not met.
func (e *Evaluator) conditionsMet(rule model.PolicyRule, req model.AuthorizationRequest, agent *model.Agent) bool {
	if len(rule.Conditions) == 0 {
		return true
	}

	for key, val := range rule.Conditions {
		switch key {
		case "actorRequired":
			required, ok := val.(bool)
			if ok && required && req.Actor == nil {
				return false
			}
		case "delegationRequired":
			required, ok := val.(bool)
			if ok && required {
				if req.Context == nil {
					return false
				}
				if _, hasDelegation := req.Context["delegation_id"]; !hasDelegation {
					return false
				}
			}
		}
	}
	return true
}

// conditionFailReason returns a human-readable reason for why conditions failed.
// Used to provide better deny reasons when a rule's conditions are not met.
func (e *Evaluator) conditionFailReason(rule model.PolicyRule, req model.AuthorizationRequest) string {
	for key, val := range rule.Conditions {
		switch key {
		case "actorRequired":
			if required, ok := val.(bool); ok && required && req.Actor == nil {
				return "actor required but not present in request"
			}
		case "delegationRequired":
			if required, ok := val.(bool); ok && required {
				if req.Context == nil || req.Context["delegation_id"] == nil {
					return "delegation required but not present"
				}
			}
		}
	}
	return "conditions not met"
}

// delegationCoversAction checks whether the delegation scope in the request context
// includes the requested action. In v1alpha1, delegation scope is looked up from
// a "delegation_scope" key in context (set by the enforcement point after verifying
// the delegation). If no scope is found, deny by default (fail closed).
func (e *Evaluator) delegationCoversAction(req model.AuthorizationRequest) bool {
	if req.Context == nil {
		return false
	}

	// The enforcement point should set "delegation_scope" with the allowed actions
	scopeVal, ok := req.Context["delegation_scope"]
	if !ok {
		// No scope info means we can't verify → fail closed
		return false
	}

	// delegation_scope can be a []interface{} of action strings
	actions, ok := toStringSlice(scopeVal)
	if !ok {
		return false
	}

	for _, allowed := range actions {
		if allowed == "*" || allowed == req.Action.Name {
			return true
		}
	}
	return false
}

// actionMatches checks if an action name matches any of the patterns in the rule.
// Supports exact match and wildcard "*".
func actionMatches(ruleActions []string, actionName string) bool {
	for _, a := range ruleActions {
		if a == "*" || a == actionName {
			return true
		}
	}
	return false
}

// collectPolicyIDs extracts unique policy IDs from matched rules.
func collectPolicyIDs(matches []matchedRule) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, m := range matches {
		if !seen[m.policyID] {
			seen[m.policyID] = true
			ids = append(ids, m.policyID)
		}
	}
	return ids
}
