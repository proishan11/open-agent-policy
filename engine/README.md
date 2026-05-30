# Engine

The engine is the core of OAP — a pure Go library that evaluates authorization requests against policies.

## Purpose

The engine decides whether an agent is allowed to perform an action. It implements the deny-overrides-allow algorithm specified in `architecture.md §7.4` and passes all 10 conformance test cases.

**This is a library, not a server.** The same evaluation code runs embedded in SDKs, gateways, proxies, and behind the HTTP API. Zero network calls for embedded mode.

## Architecture

```
engine/
├── model/       Domain types (AuthorizationRequest, Decision, Agent, Policy, etc.)
├── store/       Pluggable stores for agents, resources, tools, policies
├── evaluator/   Policy evaluation engine (the decision point)
└── audit/       Audit event sinks and query contract
```

## Key Interfaces

### Evaluator

```go
eval := evaluator.New(store)
result := eval.Evaluate(ctx, request)
// result.Decision — the authorization decision
// result.Trace    — step-by-step evaluation trace (for simulate/explain)
```

### Registry Store

```go
s := memory.New()
store.LoadDir(ctx, s, "path/to/data/")  // loads Agents, Policies, Resources, Tools from YAML/JSON
s.RegisterAgent(ctx, &agent)
s.AddPolicy(ctx, &policy)
agent, _ := s.GetAgent(ctx, "agent://finance/invoice-reconciler")
policies, _ := s.PoliciesForAgent(ctx, agent)
```

### Audit Sink

```go
sink, _ := audit.NewJSONLSink("/var/log/oap/audit.jsonl")
sink.Write(event)
```

Queryable durable audit storage is provided by the Postgres audit sink in `engine/store/postgres`. The Postgres backend also owns ordered schema migrations with version, name, checksum, and advisory-lock metadata.

## Data Flow

```
AuthorizationRequest
  │
  ▼
Evaluator.Evaluate(ctx, request)
  │
  ├── 1. Validate request fields
  ├── 2. Look up agent in registry → deny if unregistered/revoked
  ├── 3. Find matching policies (subject selector)
  ├── 4. Check delegation scope (if delegation_id in context)
  ├── 5. Scan deny rules → deny overrides allow
  ├── 6. Scan require_approval rules
  ├── 7. Scan allow rules, check conditions
  ├── 8. Merge constraints (strictest wins)
  │
  ▼
AuthorizationDecision + Trace
```

## Key Invariants

- Unregistered agents → deny
- Revoked agents → deny
- No matching allow → deny (deny-by-default)
- Explicit deny overrides allow
- Constraints only become stricter, never weaker
- Every evaluation is deterministic (same input → same output)

## Configuration

The engine has no configuration — it's pure logic. Configuration happens at the server/CLI layer (which data to load, which audit sink to use).

## Testing

```bash
# Run evaluator tests (includes 10 conformance tests)
go test -v ./engine/evaluator/

# Run all engine tests
go test ./engine/...
```
