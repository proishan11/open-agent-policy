// Package evaluator implements the OAP policy evaluation engine.
//
// The evaluator is the core decision-making component. It takes an
// AuthorizationRequest, looks up the agent in the registry, finds matching
// policies, evaluates rules, merges constraints, and returns a structured
// AuthorizationDecision.
//
// # Evaluation order (architecture.md §7.4)
//
//  1. Validate request (required fields present)
//  2. Verify agent identity (registered? active? not revoked?)
//  3. Verify actor identity (present if required by policy?)
//  4. Find matching policies (subject selector matches agent)
//  5. Evaluate deny rules first (explicit deny always overrides allow)
//  6. Evaluate allow/require_approval/require_delegation rules
//  7. Apply conditions (boolean prerequisites)
//  8. Merge constraints from all matching allow rules (strictest wins)
//  9. Determine final decision
//  10. Emit audit event
//
// # Key invariants
//
//   - Unregistered agents are denied
//   - Revoked agents are denied
//   - No matching allow rule means deny (deny-by-default)
//   - Explicit deny always overrides allow
//   - Constraints only become stricter, never weaker
//   - Every evaluation produces an audit event
//
// # Usage
//
//	store := registry.NewStore()
//	store.LoadDir("policies/")
//	eval := evaluator.New(store)
//	decision := eval.Evaluate(ctx, request)
package evaluator
