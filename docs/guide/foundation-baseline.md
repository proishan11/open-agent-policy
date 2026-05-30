# Foundation Baseline

**Status:** validated  
**Date:** 2026-05-30  
**Scope:** v1alpha1 policy semantics, evaluator behavior, schema contract, durable control-plane storage wiring, audit query, operational readiness checks, baseline metrics, and local validation gates.

This baseline defines the minimum security contract OAP must preserve before adding more enterprise features. It is intentionally narrower than "enterprise-grade." It answers one question: can a developer trust the current spec and evaluator to fail closed for the core authorization path?

## Baseline Guarantees

### Spec-first contract

OAP policy authoring is governed by the JSON Schema files under `spec/v1alpha1/` and the OpenAPI contract under `spec/openapi/`.

The current policy vocabulary is closed for:

- `conditions`
- `constraints`
- `obligations`

Unknown keys in these blocks are rejected by schema validation and fail closed during evaluation. This is important because ignoring an unsupported constraint can silently broaden access.

### Policy keys vs decision keys

Policy YAML uses Kubernetes-style camelCase:

```yaml
constraints:
  maxRecords: 25
  allowedFields:
    - status
  expiresIn: 5m
```

Authorization decisions use API-style snake_case:

```json
{
  "constraints": {
    "max_records": 25,
    "allowed_fields": ["status"],
    "expires_in_seconds": 300
  }
}
```

This split is deliberate: policies stay natural for manifests, while decisions stay natural for JSON enforcement points and SDKs.

## Evaluation Guarantees

The built-in evaluator now enforces the following order:

1. Validate required request fields.
2. Verify the agent is registered and active.
3. Check the requested action is within the agent's declared capabilities.
4. Find policies matching the agent.
5. Enforce delegation scope when delegation context is present.
6. Match rules by action and resource selector.
7. Evaluate supported conditions.
8. Validate constraints and obligations.
9. Apply deny-overrides semantics.
10. Return approval, allow, allow-with-constraints, or deny.

Capabilities are an upper bound. A policy cannot grant an action the agent did not declare.

Resource selectors are enforced for:

- `types`
- `classificationMax`
- `environments`
- `owners`

## Supported Conditions

The baseline evaluator supports:

| Condition | Meaning |
|---|---|
| `actorRequired` | Request must include an actor. |
| `actorType` | Actor type must match. |
| `actorId` | Actor ID must match. |
| `actorGroups` | Actor must belong to at least one required group. |
| `environment` | Request/resource environment must match. |
| `minAuthStrength` | Actor authentication strength must meet the minimum. |
| `timeWindow` | Current UTC time/day must be inside the policy window. |
| `delegationRequired` | Request must include verified delegation context. |

Unsupported examples such as `priorityIn`, `recipientDomain`, or arbitrary custom condition keys are not part of the baseline. They must be added through the spec-first workflow before policy authors can rely on them.

## Supported Constraints

The baseline evaluator supports:

| Policy key | Decision key | Merge behavior |
|---|---|---|
| `maxRecords` | `max_records` | Minimum wins. |
| `readonly` | `readonly` | `true` wins. |
| `redact` | `redact_fields` | Union wins. |
| `allowedFields` | `allowed_fields` | Intersection wins. |
| `timeWindowSeconds` | `time_window_seconds` | Minimum wins. |
| `expiresIn` | `expires_in_seconds` | Minimum duration wins. |

`expiresIn` also controls grant token TTL when a scoped grant is issued.

## Strict Input Handling

File loading rejects unknown typed fields for YAML and JSON manifests. HTTP handlers also reject unknown JSON fields on request bodies. This avoids a split-brain contract where local manifests are strict but direct API writes are permissive.

## Durable Storage And Audit Query

The server binary supports explicit storage backend selection:

- `--store memory` for local development and tests.
- `--store postgres --postgres-dsn ...` for durable agents, policies, resources, tools, and audit events.

In Postgres mode, authorization audit events are written to `oap_audit_events` and `GET /v1/audit` supports indexed filters for agent, actor, action, decision, request ID, run ID, resource, time range, limit, and offset. When `--audit-file` is also configured, audit events are written to both Postgres and JSONL while queries still read from Postgres.

Postgres schema changes are tracked as ordered migrations in `oap_schema_version` with migration names, SHA-256 checksums, and an advisory migration lock.

## Workload Identity Profile

The Agent spec supports:

- `spec.workloadIdentity` for a standards-compatible workload identifier such as a SPIFFE or WIMSE URI.
- `spec.identityBindings` for runtime credential verification through OIDC, Kubernetes ServiceAccount JWTs, SPIFFE JWT-SVIDs, or WIMSE WIT+WPT proof-of-possession.

The logical OAP agent ID remains `agent://<namespace>/<name>`. The workload identity profile records how that logical agent maps to the deployed workload identity.

## Operational Readiness

The server exposes separate operational surfaces:

- `GET /v1/health` is a process liveness check.
- `GET /v1/ready` verifies dependency readiness, including the configured store, with a bounded timeout.
- `GET /metrics` exposes Prometheus text counters for authorization requests, decision outcomes, audit query/write failures, and readiness failures.

## Validation Commands

Run these before claiming the baseline still holds:

```bash
go test ./...
python3 demos/demo-01-spec-and-conformance/validate.py
git diff --check
```

Expected result as of this baseline:

- Go test suite: passing
- Schema/conformance validation: `33/33 validations passed`
- Whitespace check: passing

## What This Baseline Does Not Claim

This checkpoint does not make OAP enterprise-grade. The following remain outside the foundation baseline:

- Full Cedar validation stack and external-backend operations. OPA now has Docker Compose e2e coverage with a sidecar and fail-closed outage case, but Cedar sidecar coverage, timeout/circuit-breaker guidance, and runbooks still need to be added.
- Enterprise audit operations. Basic durable audit query exists, but retention policies, immutable export, SIEM/OTEL integrations, and legal-hold workflows are still incomplete.
- Production database operations. Postgres is wired into the server path, but backup/restore, online migration discipline, HA, and disaster recovery runbooks are still roadmap work.
- Full approval lifecycle. Policies can return `require_approval`, but approval request state and completion flows are not yet production-grade.
- Arbitrary resource attribute conditions. Additions like ticket priority or email recipient domain need spec, conformance, evaluator, and enforcement work.
- Multi-tenancy, OAP admin RBAC, GitOps policy management, HA, distributed tracing, SIEM export, dashboards, alerts, and operational runbooks.

## Spec-Driven Rule For Future Changes

Any new policy capability must follow this order:

1. Update the JSON Schema and OpenAPI contract.
2. Add positive and negative conformance cases.
3. Implement evaluator semantics.
4. Add unit/security tests for fail-closed behavior.
5. Update examples and guides.
6. Run the full validation commands above.

Do not add example policy keys before the evaluator can enforce them.
