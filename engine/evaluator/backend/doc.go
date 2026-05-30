// Package backend defines the pluggable policy evaluation backend interface.
//
// OAP's evaluator handles agent lifecycle (registration, suspension, revocation),
// capability bounds, policy resolution, delegation scoping, grant issuance, and
// audit. The backend is responsible ONLY for rule evaluation: given a request
// and a set of policies, which rules match and what is the effect?
//
// Two external backends are provided:
//
//   - OPABackend: Delegates rule evaluation to Open Policy Agent (Rego policies)
//   - CedarBackend: Delegates rule evaluation to AWS Cedar
//
// If no backend is configured, the evaluator uses OAP's native
// deny-overrides-allow evaluator. External backends can opt into fail-open
// fallback to that native evaluator, but production deployments should keep the
// default fail-closed behavior.
//
// Architecture:
//
//	OAP Evaluator (always runs)
//	  ├── Agent lookup + lifecycle check
//	  ├── Capability check
//	  ├── Matching policy resolution
//	  ├── Delegation scope check
//	  ├── Rule evaluation
//	  │     ├── Native evaluator (default)
//	  │     ├── OPABackend (Rego)
//	  │     └── CedarBackend
//	  ├── Constraint mapping
//	  ├── Grant issuance
//	  └── Audit event emission
package backend
