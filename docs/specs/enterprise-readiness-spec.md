# Enterprise Readiness Feature Specs

**Status:** draft  
**Date:** 2026-05-30  
**Scope:** Features required to move OAP from foundation-ready to enterprise-GA.

This document turns the enterprise gaps into spec tracks. Each track must follow
the foundation rule: update spec first, add validation/tests, implement narrowly,
then update docs and examples.

## Status Legend

| Status | Meaning |
|---|---|
| `baseline` | A working foundation exists, but enterprise hardening remains. |
| `spec-ready` | The target contract is documented and ready for implementation slices. |
| `in-progress` | Code has started for a narrow slice of the spec. |
| `blocked` | Needs external dependency, product decision, or larger design work. |

## Feature Tracks

| Track | Status | Developer value | Enterprise gate |
|---|---|---|---|
| WIMSE/SPIFFE workload identity | in-progress | Bind logical agents to workload identities without trusting headers. | First-class workload identity profile, SPIFFE/WIMSE identifier mapping, JWT-SVID verification tests, WIMSE WPT validation, shared replay cache. |
| OAuth-compatible grants and token exchange | spec-needed | Let resource APIs validate standard access/transaction tokens. | OAuth 2.0 token exchange profile, audience-bound grants, replay controls, discovery metadata. |
| Admin auth, RBAC, and tenancy | spec-needed | Protect management APIs and isolate teams. | Admin sessions, roles, namespace/tenant boundaries, API authorization policy. |
| Tamper-evident audit and retention | baseline | Make audit usable for investigation and compliance. | Hash-chained or signed audit records, retention policy, export cursors, legal hold. |
| Approval lifecycle | spec-needed | Make `require_approval` executable, not just a decision. | Approval request store, approver auth, expiration, revocation, audit events, grant issuance after approval. |
| Production database operations | in-progress | Make Postgres safe to operate over time. | Versioned migrations, migration locking, backup/restore docs, readiness under DB failure, HA runbook. |
| SIEM/OpenTelemetry observability | baseline | Feed enterprise monitoring stacks. | OTEL traces/metrics/logs, SIEM exporters, dashboards, alert rules. |

## Cross-Cutting Requirements

- Every security-relevant event must produce a structured audit event.
- Every issued credential or grant must be short-lived and audience-scoped.
- Every management operation must be attributable to an authenticated admin actor.
- Every new policy or API field must be represented in JSON Schema and OpenAPI.
- Any unsupported configuration must fail closed.
- Docs must separate foundation-ready, developer-preview, and enterprise-GA claims.

## Implementation Order

1. WIMSE/SPIFFE workload identity profile.
2. Production database migration discipline.
3. Approval lifecycle state machine.
4. Admin auth, RBAC, and tenancy.
5. OAuth-compatible grant/token exchange profile.
6. Tamper-evident audit retention and export.
7. OTEL/SIEM integrations and operational dashboards.

The order is intentional: identity and storage correctness become dependencies
for approval, admin RBAC, token exchange, audit integrity, and observability.
