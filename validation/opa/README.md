# OPA Validation Policy

This directory contains the Rego policy used by the validation stack's
`opa-test` profile.

Run the profile from the repository root:

```bash
docker compose -f validation/docker-compose.yml --profile opa-test build \
  e2e-tests-opa oap-server-opa oap-server-opa-unavailable ticket-api-opa customer-api-opa
docker compose -f validation/docker-compose.yml --profile opa-test run --rm e2e-tests-opa
```

The profile starts:

- `opa` with `policy.rego`
- `oap-server-opa` with `--policy-backend opa`
- `ticket-api-opa` and `customer-api-opa`, both validating OAP grants from the
  OPA-backed server
- `oap-server-opa-unavailable`, pointed at a dead OPA URL to prove fail-closed
  behavior
