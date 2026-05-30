# Policy Backend Examples

These examples document the external policy-backend contracts implemented under
`engine/evaluator/backend` and exposed by `oap-server --policy-backend`.

| Example | Status |
|---|---|
| `opa/` | Runnable OPA policy contract and `oap-server --policy-backend opa` example. |
| `cedar/` | Cedar-compatible request/response contract and `oap-server --policy-backend cedar` example. |

The built-in OAP YAML policy path remains the default. Use external backends
when you already have Rego/Cedar policy infrastructure and want OAP to retain
agent identity, grants, and audit around it.

External backends still require an OAP `Agent` and at least one matching
`AgentPolicy`; OAP uses those to bind the backend decision to a registered
agent principal before issuing grants.

See [Policy Backends](../../docs/guide/policy-backends.md).
