package evaluator

import (
	"context"
	"fmt"
	"strings"
	"time"

	policybackend "github.com/proishan11/open-agent-policy/engine/evaluator/backend"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store"
)

// Evaluator is the policy decision point (PDP). It holds a reference to the
// store and evaluates authorization requests against registered agents and
// policies.
type Evaluator struct {
	store   store.Store
	backend policybackend.Backend
}

// Option configures an Evaluator.
type Option func(*Evaluator)

// WithBackend delegates rule evaluation to an external policy backend.
//
// OAP still performs request validation, agent lifecycle checks, capability
// checks, policy resolution, delegation scope checks, grant issuance, and audit.
// The backend owns only the final rule decision across the resolved policies.
func WithBackend(backend policybackend.Backend) Option {
	return func(e *Evaluator) {
		e.backend = backend
	}
}

// New creates an Evaluator backed by the given store.
func New(s store.Store, opts ...Option) *Evaluator {
	e := &Evaluator{store: s}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// BackendName returns the active rule evaluation backend.
func (e *Evaluator) BackendName() string {
	if e.backend == nil {
		return "builtin"
	}
	return e.backend.Name()
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

	// Step 3: Check capabilities. Registration-time capabilities are an upper
	// bound on what policies may later authorize.
	if !agentCanPerform(agent, req.Action.Name) {
		trace = append(trace, TraceStep{
			Step:   "check_capabilities",
			Result: "fail",
			Detail: fmt.Sprintf("agent did not declare capability %q", req.Action.Name),
		})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = "agent capability does not include requested action"
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	trace = append(trace, TraceStep{Step: "check_capabilities", Result: "pass", Detail: "agent capability covers action"})

	// Step 4: Find matching policies
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

	// Step 5: Check delegation scope if a delegation_id is present in context.
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

	// Step 6: Evaluate rules across all matching policies.
	if e.backend != nil {
		return e.evaluateBackend(ctx, baseDec, req, agent, policies, trace)
	}

	// The built-in path collects all matching rules, then applies
	// deny-overrides-allow semantics.
	return e.evaluateRules(baseDec, req, agent, policies, trace)
}

type failOpenBackend interface {
	FailOpen() bool
}

func (e *Evaluator) evaluateBackend(
	ctx context.Context,
	baseDec model.AuthorizationDecision,
	req model.AuthorizationRequest,
	agent *model.Agent,
	policies []*model.AgentPolicy,
	trace []TraceStep,
) EvalResult {
	backendName := e.backend.Name()
	result, err := e.backend.Evaluate(ctx, policybackend.Input{
		Request:  req,
		Agent:    agent,
		Policies: policies,
	})
	if err != nil {
		if failOpen, ok := e.backend.(failOpenBackend); ok && failOpen.FailOpen() {
			trace = append(trace, TraceStep{
				Step:   "evaluate_backend",
				Result: "fallback",
				Detail: fmt.Sprintf("%s backend failed open; falling back to builtin evaluator: %v", backendName, err),
			})
			return e.evaluateRules(baseDec, req, agent, policies, trace)
		}

		trace = append(trace, TraceStep{
			Step:   "evaluate_backend",
			Result: "fail",
			Detail: fmt.Sprintf("%s backend error: %v", backendName, err),
		})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = fmt.Sprintf("%s backend error (fail-closed): %v", backendName, err)
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	if result == nil {
		trace = append(trace, TraceStep{
			Step:   "evaluate_backend",
			Result: "fail",
			Detail: fmt.Sprintf("%s backend returned no result", backendName),
		})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = fmt.Sprintf("%s backend returned no decision", backendName)
		return EvalResult{Decision: baseDec, Trace: trace}
	}

	if !supportedDecision(result.Decision) {
		trace = append(trace, TraceStep{
			Step:   "evaluate_backend",
			Result: "fail",
			Detail: fmt.Sprintf("%s backend returned unsupported decision %q", backendName, result.Decision),
		})
		baseDec.Decision = model.DecisionDeny
		baseDec.Reason = fmt.Sprintf("%s backend returned unsupported decision %q", backendName, result.Decision)
		return EvalResult{Decision: baseDec, Trace: trace}
	}

	constraints, err := constraintsFromBackendMap(result.Constraints)
	if err != nil {
		trace = append(trace, TraceStep{
			Step:   "evaluate_backend",
			Result: "fail",
			Detail: fmt.Sprintf("%s backend returned invalid constraints: %v", backendName, err),
		})
		baseDec.Decision = model.DecisionDeny
		baseDec.PolicyIDs = result.PolicyIDs
		baseDec.Reason = fmt.Sprintf("%s backend returned invalid constraints: %v", backendName, err)
		return EvalResult{Decision: baseDec, Trace: trace}
	}
	decision := result.Decision
	if decision == model.DecisionAllow && constraints != nil {
		decision = model.DecisionAllowConstrained
	}
	if decision == model.DecisionAllowConstrained && constraints == nil {
		trace = append(trace, TraceStep{
			Step:   "evaluate_backend",
			Result: "fail",
			Detail: fmt.Sprintf("%s backend returned allow_with_constraints without constraints", backendName),
		})
		baseDec.Decision = model.DecisionDeny
		baseDec.PolicyIDs = result.PolicyIDs
		baseDec.Reason = fmt.Sprintf("%s backend returned allow_with_constraints without constraints", backendName)
		return EvalResult{Decision: baseDec, Trace: trace}
	}

	baseDec.Decision = decision
	baseDec.PolicyIDs = result.PolicyIDs
	baseDec.Reason = result.Reason
	baseDec.Constraints = constraints
	baseDec.Obligations = result.Obligations
	baseDec.Approval = result.Approval
	if baseDec.Reason == "" {
		baseDec.Reason = fmt.Sprintf("decided by %s policy backend", backendName)
	}

	trace = append(trace, TraceStep{
		Step:   "evaluate_backend",
		Result: "match",
		Detail: fmt.Sprintf("%s backend returned %q", backendName, baseDec.Decision),
	})
	return EvalResult{Decision: baseDec, Trace: trace}
}

func supportedDecision(decision string) bool {
	switch decision {
	case model.DecisionAllow,
		model.DecisionAllowConstrained,
		model.DecisionDeny,
		model.DecisionRequireApproval,
		model.DecisionRequireDelegation,
		model.DecisionRequireStepUpAuth:
		return true
	default:
		return false
	}
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

			if err := validateResources(rule.Resources); err != nil {
				trace = append(trace, TraceStep{
					Step:     "validate_policy_rule",
					Result:   "fail",
					Detail:   fmt.Sprintf("%s (rule in %s)", err.Error(), policy.ID()),
					PolicyID: policy.ID(),
				})
				baseDec.Decision = model.DecisionDeny
				baseDec.PolicyIDs = []string{policy.ID()}
				baseDec.Reason = "policy evaluation failed: " + err.Error()
				return EvalResult{Decision: baseDec, Trace: trace}
			}
			if ok, reason := resourceMatches(rule.Resources, req); !ok {
				trace = append(trace, TraceStep{
					Step:     "match_resource",
					Result:   "skip",
					Detail:   fmt.Sprintf("%s (rule in %s)", reason, policy.ID()),
					PolicyID: policy.ID(),
				})
				continue
			}

			// Check conditions (boolean prerequisites)
			cond := e.conditionsMet(rule, req)
			if cond.err != "" {
				trace = append(trace, TraceStep{
					Step:     "evaluate_conditions",
					Result:   "fail",
					Detail:   fmt.Sprintf("%s (rule in %s)", cond.err, policy.ID()),
					PolicyID: policy.ID(),
				})
				baseDec.Decision = model.DecisionDeny
				baseDec.PolicyIDs = []string{policy.ID()}
				baseDec.Reason = "policy evaluation failed: " + cond.err
				return EvalResult{Decision: baseDec, Trace: trace}
			}
			if !cond.met {
				reason := cond.reason
				lastConditionFailReason = reason
				trace = append(trace, TraceStep{
					Step:     "evaluate_conditions",
					Result:   "skip",
					Detail:   fmt.Sprintf("%s (rule in %s)", reason, policy.ID()),
					PolicyID: policy.ID(),
				})
				continue
			}

			if err := validateConstraints(rule.Constraints); err != nil {
				trace = append(trace, TraceStep{
					Step:     "validate_policy_rule",
					Result:   "fail",
					Detail:   fmt.Sprintf("%s (rule in %s)", err.Error(), policy.ID()),
					PolicyID: policy.ID(),
				})
				baseDec.Decision = model.DecisionDeny
				baseDec.PolicyIDs = []string{policy.ID()}
				baseDec.Reason = "policy evaluation failed: " + err.Error()
				return EvalResult{Decision: baseDec, Trace: trace}
			}
			if err := validateObligations(rule.Obligations); err != nil {
				trace = append(trace, TraceStep{
					Step:     "validate_policy_rule",
					Result:   "fail",
					Detail:   fmt.Sprintf("%s (rule in %s)", err.Error(), policy.ID()),
					PolicyID: policy.ID(),
				})
				baseDec.Decision = model.DecisionDeny
				baseDec.PolicyIDs = []string{policy.ID()}
				baseDec.Reason = "policy evaluation failed: " + err.Error()
				return EvalResult{Decision: baseDec, Trace: trace}
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

type conditionResult struct {
	met    bool
	reason string
	err    string
}

// conditionsMet evaluates rule prerequisites. Unknown or malformed conditions
// are policy errors and fail closed; unmet known conditions simply make the rule
// not match.
func (e *Evaluator) conditionsMet(rule model.PolicyRule, req model.AuthorizationRequest) conditionResult {
	if len(rule.Conditions) == 0 {
		return conditionResult{met: true}
	}

	for key, val := range rule.Conditions {
		switch key {
		case "actorRequired":
			required, ok := val.(bool)
			if !ok {
				return conditionResult{err: fmt.Sprintf("condition %q must be boolean", key)}
			}
			if required && req.Actor == nil {
				return conditionResult{reason: "actor required but not present in request"}
			}
		case "actorType":
			expected, ok := val.(string)
			if !ok || expected == "" {
				return conditionResult{err: fmt.Sprintf("condition %q must be a non-empty string", key)}
			}
			if req.Actor == nil || req.Actor.Type != expected {
				return conditionResult{reason: fmt.Sprintf("actor type must be %q", expected)}
			}
		case "actorId":
			expected, ok := val.(string)
			if !ok || expected == "" {
				return conditionResult{err: fmt.Sprintf("condition %q must be a non-empty string", key)}
			}
			if req.Actor == nil || req.Actor.ID != expected {
				return conditionResult{reason: fmt.Sprintf("actor id must be %q", expected)}
			}
		case "actorGroups":
			groups, ok := toStringSlice(val)
			if !ok || len(groups) == 0 {
				return conditionResult{err: fmt.Sprintf("condition %q must be a non-empty string array", key)}
			}
			if req.Actor == nil || !hasAnyString(req.Actor.Groups, groups) {
				return conditionResult{reason: "actor is not in a required group"}
			}
		case "environment":
			expected, ok := val.(string)
			if !ok || expected == "" {
				return conditionResult{err: fmt.Sprintf("condition %q must be a non-empty string", key)}
			}
			if requestEnvironment(req) != expected {
				return conditionResult{reason: fmt.Sprintf("environment must be %q", expected)}
			}
		case "minAuthStrength":
			expected, ok := val.(string)
			if !ok || expected == "" {
				return conditionResult{err: fmt.Sprintf("condition %q must be a non-empty string", key)}
			}
			if authStrengthRank(expected) < 0 {
				return conditionResult{err: fmt.Sprintf("condition %q has unsupported value %q", key, expected)}
			}
			if req.Actor == nil || authStrengthRank(req.Actor.AuthStrength) < authStrengthRank(expected) {
				return conditionResult{reason: fmt.Sprintf("minimum auth strength is %q", expected)}
			}
		case "timeWindow":
			window, ok := val.(map[string]interface{})
			if !ok {
				return conditionResult{err: fmt.Sprintf("condition %q must be an object", key)}
			}
			if ok, reason, err := timeWindowMatches(window, time.Now().UTC()); err != nil {
				return conditionResult{err: err.Error()}
			} else if !ok {
				return conditionResult{reason: reason}
			}
		case "delegationRequired":
			required, ok := val.(bool)
			if !ok {
				return conditionResult{err: fmt.Sprintf("condition %q must be boolean", key)}
			}
			if required {
				if req.Context == nil {
					return conditionResult{reason: "delegation required but not present"}
				}
				if _, hasDelegation := req.Context["delegation_id"]; !hasDelegation {
					return conditionResult{reason: "delegation required but not present"}
				}
			}
		default:
			return conditionResult{err: fmt.Sprintf("unsupported condition %q", key)}
		}
	}
	return conditionResult{met: true}
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
// Supports exact match, wildcard "*", and prefix wildcards such as "ticket.*".
func actionMatches(ruleActions []string, actionName string) bool {
	for _, a := range ruleActions {
		if a == "*" || a == actionName {
			return true
		}
		if strings.HasSuffix(a, ".*") {
			prefix := strings.TrimSuffix(a, ".*")
			if strings.HasPrefix(actionName, prefix+".") {
				return true
			}
		}
	}
	return false
}

func agentCanPerform(agent *model.Agent, actionName string) bool {
	for _, capability := range agent.Spec.Capabilities {
		if capability == "*" || capability == actionName {
			return true
		}
		if strings.HasSuffix(capability, ".*") {
			prefix := strings.TrimSuffix(capability, ".*")
			if strings.HasPrefix(actionName, prefix+".") {
				return true
			}
		}
	}
	return false
}

func validateResources(selector *model.PolicyResourceSelector) error {
	if selector == nil {
		return nil
	}
	if selector.ClassificationMax != "" && classificationRank(selector.ClassificationMax) < 0 {
		return fmt.Errorf("unsupported resource classification %q", selector.ClassificationMax)
	}
	for _, env := range selector.Environments {
		switch env {
		case "development", "staging", "production":
		default:
			return fmt.Errorf("unsupported resource environment %q", env)
		}
	}
	return nil
}

func resourceMatches(selector *model.PolicyResourceSelector, req model.AuthorizationRequest) (bool, string) {
	if selector == nil {
		return true, ""
	}
	if len(selector.Types) > 0 {
		if req.Resource == nil {
			return false, "resource type required by policy"
		}
		if !containsString(selector.Types, req.Resource.Type) {
			return false, fmt.Sprintf("resource type %q does not match policy", req.Resource.Type)
		}
	}
	if selector.ClassificationMax != "" {
		if req.Resource == nil || req.Resource.Classification == "" {
			return false, "resource classification required by policy"
		}
		reqRank := classificationRank(req.Resource.Classification)
		if reqRank < 0 {
			return false, fmt.Sprintf("resource classification %q is unsupported", req.Resource.Classification)
		}
		if reqRank > classificationRank(selector.ClassificationMax) {
			return false, fmt.Sprintf("resource classification %q exceeds %q", req.Resource.Classification, selector.ClassificationMax)
		}
	}
	if len(selector.Environments) > 0 {
		env := requestEnvironment(req)
		if env == "" {
			return false, "resource environment required by policy"
		}
		if !containsString(selector.Environments, env) {
			return false, fmt.Sprintf("environment %q does not match policy", env)
		}
	}
	if len(selector.Owners) > 0 {
		owner := requestResourceOwner(req)
		if owner == "" {
			return false, "resource owner required by policy"
		}
		if !containsString(selector.Owners, owner) {
			return false, fmt.Sprintf("resource owner %q does not match policy", owner)
		}
	}
	return true, ""
}

func requestEnvironment(req model.AuthorizationRequest) string {
	if req.Resource != nil && req.Resource.Environment != "" {
		return req.Resource.Environment
	}
	if req.Context != nil {
		if env, ok := req.Context["environment"].(string); ok {
			return env
		}
	}
	return ""
}

func requestResourceOwner(req model.AuthorizationRequest) string {
	if req.Resource != nil && req.Resource.Owner != "" {
		return req.Resource.Owner
	}
	if req.Context != nil {
		if owner, ok := req.Context["resource_owner"].(string); ok {
			return owner
		}
	}
	return ""
}

func classificationRank(classification string) int {
	switch classification {
	case "public":
		return 0
	case "internal":
		return 1
	case "confidential":
		return 2
	case "restricted":
		return 3
	default:
		return -1
	}
}

func authStrengthRank(strength string) int {
	switch strength {
	case "", "none":
		return 0
	case "password":
		return 1
	case "mfa":
		return 2
	case "phishing_resistant_mfa":
		return 3
	default:
		return -1
	}
}

func timeWindowMatches(window map[string]interface{}, now time.Time) (bool, string, error) {
	for key, raw := range window {
		switch key {
		case "after":
			after, ok := raw.(string)
			if !ok {
				return false, "", fmt.Errorf("timeWindow.after must be a string")
			}
			cmp, err := compareClock(now, after)
			if err != nil {
				return false, "", err
			}
			if cmp < 0 {
				return false, fmt.Sprintf("current time is before %s", after), nil
			}
		case "before":
			before, ok := raw.(string)
			if !ok {
				return false, "", fmt.Errorf("timeWindow.before must be a string")
			}
			cmp, err := compareClock(now, before)
			if err != nil {
				return false, "", err
			}
			if cmp > 0 {
				return false, fmt.Sprintf("current time is after %s", before), nil
			}
		case "daysOfWeek":
			days, ok := toStringSlice(raw)
			if !ok {
				return false, "", fmt.Errorf("timeWindow.daysOfWeek must be a string array")
			}
			if !containsString(days, strings.ToLower(now.Weekday().String()[:3])) {
				return false, "current day is outside allowed time window", nil
			}
		default:
			return false, "", fmt.Errorf("unsupported timeWindow key %q", key)
		}
	}
	return true, "", nil
}

func compareClock(now time.Time, clock string) (int, error) {
	target, err := parseClock(clock)
	if err != nil {
		return 0, err
	}
	nowSeconds := now.Hour()*3600 + now.Minute()*60 + now.Second()
	targetSeconds := target.Hour()*3600 + target.Minute()*60 + target.Second()
	if nowSeconds < targetSeconds {
		return -1, nil
	}
	if nowSeconds > targetSeconds {
		return 1, nil
	}
	return 0, nil
}

func parseClock(clock string) (time.Time, error) {
	target, err := time.Parse("15:04:05", clock)
	if err == nil {
		return target, nil
	}
	target, err = time.Parse("15:04", clock)
	if err == nil {
		return target, nil
	}
	return time.Time{}, fmt.Errorf("time window clock %q must use HH:MM or HH:MM:SS", clock)
}

func hasAnyString(haystack, needles []string) bool {
	for _, item := range haystack {
		if containsString(needles, item) {
			return true
		}
	}
	return false
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
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
