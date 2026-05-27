# ADR-004: Pluggable Policy Evaluation Backend (OPA, Cedar)

## Status

Accepted

## Context

Enterprises already run policy engines like OPA (Open Policy Agent) and AWS Cedar.
OAP must integrate with these rather than compete. The question is where the boundary
is between OAP's evaluator and the external policy engine.

## Decision

OAP's evaluator is split into two layers:

1. **OAP Evaluator (always runs)** — handles agent lifecycle, delegation, constraint
   merging, approval workflows, and audit. This is OAP-specific logic that external
   engines don't have.

2. **Policy Backend (pluggable)** — handles rule evaluation: given a request and
   matching policies, which rules fire and what is the effect? Three backends exist:
   - `BuiltinBackend` — OAP's native deny-overrides-allow evaluator (default)
   - `OPABackend` — delegates to Open Policy Agent via REST API
   - `CedarBackend` — delegates to AWS Cedar / Verified Permissions

The interface is:

```go
type Backend interface {
    Evaluate(ctx context.Context, input Input) (*Result, error)
    Name() string
}
```

### What OAP handles (not delegated)

- Agent registration check (unregistered → deny)
- Agent status check (suspended/revoked → deny)
- Policy-to-agent matching
- Delegation scope validation
- Constraint merging (strictest wins)
- Approval workflow orchestration
- Audit event emission

### What the backend handles (delegated)

- Rule evaluation (action matches, conditions, effects)
- Custom policy logic (Rego for OPA, Cedar policies)

### Fail behavior

- **fail-closed (default)**: if the backend is unreachable, deny the request
- **fail-open (configurable)**: return an error so the evaluator can fall back to BuiltinBackend

## Consequences

- Enterprises with existing OPA infrastructure write Rego policies that reference OAP concepts
- Enterprises using AWS Verified Permissions use Cedar policies natively
- OAP still enforces agent identity, constraints, and audit regardless of backend
- No vendor lock-in — the default BuiltinBackend requires no external services
- The backend interface is small (1 method) making new backends easy to add

## Alternatives Considered

1. **Replace OAP evaluator entirely with OPA** — rejected because OPA lacks agent
   lifecycle, constraints, approval workflows, and two-identity (agent+actor) semantics.

2. **Embedded OPA (go-rego)** — viable future optimization but REST-first is simpler
   and allows OPA to run as a sidecar (standard enterprise pattern).

3. **Policy translation (OAP YAML → Rego/Cedar at build time)** — rejected because
   enterprises want to write native Rego/Cedar, not learn OAP's YAML and convert.
