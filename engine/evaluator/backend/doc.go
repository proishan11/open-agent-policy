// Package backend defines the pluggable policy evaluation backend interface.
//
// OAP's evaluator handles agent lifecycle (registration, suspension, revocation),
// delegation scoping, constraint merging, and approval workflows. The backend
// is responsible ONLY for rule evaluation: given a request and a set of policies,
// which rules match and what is the effect?
//
// Three backends are provided:
//
//   - BuiltinBackend: OAP's native deny-overrides-allow evaluator (default)
//   - OPABackend: Delegates rule evaluation to Open Policy Agent (Rego policies)
//   - CedarBackend: Delegates rule evaluation to AWS Cedar
//
// The evaluator falls back to BuiltinBackend if no backend is configured.
//
// Architecture:
//
//	OAP Evaluator (always runs)
//	  ├── Agent lookup + lifecycle check
//	  ├── Delegation scope check
//	  ├── PolicyBackend.Evaluate()  ← pluggable
//	  │     ├── BuiltinBackend (default)
//	  │     ├── OPABackend (Rego)
//	  │     └── CedarBackend
//	  ├── Constraint merging (OAP-specific)
//	  └── Audit event emission
package backend
