# OPA Server Backend Example

This directory shows the Rego shape expected by `engine/evaluator/backend.OPABackend`
and by `oap-server --policy-backend opa`.

The OPA adapter posts to:

```text
POST http://opa:8181/v1/data/oap/authz
```

and expects OPA to return:

```json
{
  "result": {
    "decision": "allow_with_constraints",
    "reason": "support agent may read tickets",
    "policy_ids": ["opa/support-ticket-read"],
    "constraints": {"readonly": true, "max_records": 25}
  }
}
```

## Try With OPA CLI

From this directory:

```bash
opa eval --format pretty --data policy.rego --input input-allow.json 'data.oap.authz'
opa eval --format pretty --data policy.rego --input input-deny.json 'data.oap.authz'
```

## Try With OPA Server

```bash
opa run --server --addr :8181 policy.rego
```

In another shell:

```bash
python3 -c 'import json; print(json.dumps({"input": json.load(open("input-allow.json"))}))' \
  | curl -sS -X POST http://localhost:8181/v1/data/oap/authz \
      -H "Content-Type: application/json" \
      --data-binary @-
```

## Run OAP Against OPA

From the repository root, start OAP with OPA as the rule-evaluation backend:

```bash
./bin/oap-server \
  --data validation/policies \
  --policy-backend opa \
  --opa-url http://localhost:8181 \
  --opa-policy-path v1/data/oap/authz \
  --grant-key dev-grant-key \
  --dev
```

OAP still performs agent lookup, capability checks, delegation checks, grant
issuance, and audit. OPA only returns the rule decision. The default behavior is
fail-closed; use `--opa-fail-open` only for temporary fallback testing.
