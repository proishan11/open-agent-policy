# Policy Backends

OAP has two separate extension points that are easy to confuse:

- The default server path is the built-in OAP YAML evaluator.
- The `oap-server` binary can delegate rule evaluation to OPA or a
  Cedar-compatible service with `--policy-backend`.

OAP still performs the agent-native checks before any external policy call:
request validation, agent lifecycle, capability bounds, matching policy
resolution, delegation scope, grant issuance, and audit. External backends
answer only the final rule-evaluation question: given the normalized request,
resolved agent, and matching policies, what is the decision?

Important: even with OPA or Cedar, the agent must be registered and at least
one `AgentPolicy` must match the agent. If no policy matches, OAP denies by
default before calling the external backend.

## Support Matrix

| Backend | Server-supported today | Library adapter | Status |
|---|---:|---:|---|
| Built-in OAP YAML | Yes | Yes | Default and production-like validation path. |
| Open Policy Agent | Yes | Yes | REST server mode with fail-closed default and backend tests. |
| Cedar / Verified Permissions style service | Yes | Yes | REST server mode with fail-closed default and backend tests. |

Backend configuration is also exposed through environment variables:
`OAP_POLICY_BACKEND`, `OAP_OPA_URL`, `OAP_OPA_POLICY_PATH`, `OAP_CEDAR_URL`,
and `OAP_CEDAR_POLICY_STORE_ID`.

## Built-In OAP YAML

This is the supported server path:

```bash
./bin/oap-server \
  --data validation/policies \
  --store postgres \
  --postgres-dsn "$DATABASE_URL" \
  --issuer "$OIDC_ISSUER" \
  --grant-key "$OAP_GRANT_KEY"
```

Policy shape:

```yaml
apiVersion: oap.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: support-ticket-agent-policy
  namespace: support
spec:
  subject:
    agent: "agent://support/ticket-assistant"
  rules:
    - effect: allow
      actions:
        - ticket.read
      resources:
        types:
          - support.ticket
      constraints:
        readonly: true
        maxRecords: 25
    - effect: deny
      actions:
        - customer.bulk_export
      reason: "Bulk export is prohibited"
```

## OPA Server Backend

Run OPA with a policy package that returns `decision`, `reason`, `policy_ids`,
and optional `constraints`, then start OAP with the OPA backend:

```bash
opa run --server --addr :8181 examples/policy-backends/opa/policy.rego

./bin/oap-server \
  --data validation/policies \
  --policy-backend opa \
  --opa-url http://localhost:8181 \
  --opa-policy-path v1/data/oap/authz \
  --grant-key "$OAP_GRANT_KEY"
```

OPA is fail-closed by default. If OPA is unreachable or returns a non-200
response, OAP denies the request. For emergency compatibility testing only, you
can opt into built-in evaluator fallback:

```bash
./bin/oap-server --policy-backend opa --opa-url http://localhost:8181 --opa-fail-open
```

The OPA adapter posts this shape to:

```text
POST <opa-url>/<policy-path>
default policy path: v1/data/oap/authz
```

Request body:

```json
{
  "input": {
    "agent": {"metadata": {"name": "ticket-assistant", "namespace": "support"}},
    "request": {
      "subject": {"agent_id": "agent://support/ticket-assistant"},
      "action": {"name": "ticket.read"},
      "resource": {"type": "support.ticket", "id": "T-100"}
    },
    "policies": []
  }
}
```

OPA should return:

```json
{
  "result": {
    "decision": "allow_with_constraints",
    "reason": "ticket reads are allowed with readonly constraints",
    "policy_ids": ["opa/support-ticket-read"],
    "constraints": {
      "readonly": true,
      "max_records": 25
    }
  }
}
```

Minimal Rego:

```rego
package oap.authz

default decision := "deny"
default reason := "no matching OPA rule"

ticket_read if {
  input.request.subject.agent_id == "agent://support/ticket-assistant"
  input.request.action.name == "ticket.read"
  input.request.resource.type == "support.ticket"
}

bulk_export if {
  input.request.action.name == "customer.bulk_export"
}

decision := "allow_with_constraints" if {
  ticket_read
}

reason := "support agent may read tickets" if {
  ticket_read
}

policy_ids := ["opa/support-ticket-read"] if {
  ticket_read
}

constraints := {"readonly": true, "max_records": 25} if {
  ticket_read
}

decision := "deny" if {
  bulk_export
}

reason := "bulk export is prohibited" if {
  bulk_export
}

policy_ids := ["opa/no-bulk-export"] if {
  bulk_export
}
```

Library adapter usage in Go:

```go
package main

import (
    "context"

    "github.com/proishan11/open-agent-policy/engine/evaluator/backend"
)

func evaluateWithOPA(input backend.Input) (*backend.Result, error) {
    opa := backend.NewOPABackend(backend.OPAConfig{
        URL:        "http://localhost:8181",
        PolicyPath: "v1/data/oap/authz",
        FailOpen:   false,
    })
    return opa.Evaluate(context.Background(), input)
}
```

See [examples/policy-backends/opa](../../examples/policy-backends/opa) for a
complete OPA server example.

The validation stack includes an OPA sidecar profile:

```bash
docker compose -f validation/docker-compose.yml --profile opa-test build \
  e2e-tests-opa oap-server-opa oap-server-opa-unavailable ticket-api-opa customer-api-opa
docker compose -f validation/docker-compose.yml --profile opa-test run --rm e2e-tests-opa
```

That profile covers constrained allow, resource-side grant enforcement,
redaction constraints, deny-without-grant, approval mapping, audit query, and
backend-unavailable fail-closed behavior.

## Cedar Server Backend

Start OAP with a Cedar-compatible authorization endpoint:

```bash
./bin/oap-server \
  --data validation/policies \
  --policy-backend cedar \
  --cedar-url http://localhost:8180/v1/is_authorized \
  --cedar-policy-store-id "$CEDAR_POLICY_STORE_ID" \
  --grant-key "$OAP_GRANT_KEY"
```

Cedar is fail-closed by default. Use `--cedar-fail-open` only when you
explicitly want temporary built-in evaluator fallback during outages.

The Cedar adapter posts an entity-style request:

```json
{
  "principal": {"type": "OAP::Agent", "id": "agent://support/ticket-assistant"},
  "action": {"type": "OAP::Action", "id": "ticket.read"},
  "resource": {"type": "OAP::support.ticket", "id": "T-100"},
  "context": {
    "actor": {"type": "user", "id": "alice@example.com"},
    "agent_risk_tier": "medium",
    "agent_type": "chat_agent",
    "agent_capabilities": ["ticket.read"]
  },
  "policyStoreId": "ps-abc123"
}
```

The service should return:

```json
{
  "decision": "Allow",
  "diagnostics": {
    "reason": ["allowed by Cedar policy"]
  },
  "context": {
    "constraints": {
      "readonly": true
    }
  }
}
```

Minimal Cedar policy:

```cedar
permit(
  principal == OAP::Agent::"agent://support/ticket-assistant",
  action == OAP::Action::"ticket.read",
  resource
);

forbid(
  principal == OAP::Agent::"agent://support/ticket-assistant",
  action == OAP::Action::"customer.bulk_export",
  resource
);
```

Library adapter usage in Go:

```go
cedar := backend.NewCedarBackend(backend.CedarConfig{
    URL:           "http://localhost:8180/v1/is_authorized",
    PolicyStoreID: "ps-abc123",
    FailOpen:      false,
})
result, err := cedar.Evaluate(ctx, input)
```

See [examples/policy-backends/cedar](../../examples/policy-backends/cedar) for
the Cedar-compatible request and response contract.

## Enterprise Readiness Checklist

Before calling all external-backend support enterprise-ready, add:

- Cedar sidecar/service validation equivalent to the OPA profile.
- More OPA cases for high-volume policy bundles and backend latency.
- Operational guidance for backend timeouts, circuit breaking, and fail-open
  policy. The default should remain fail-closed.
