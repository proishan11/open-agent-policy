# Cedar Server Backend Contract Example

This directory shows the request and response contract expected by
`engine/evaluator/backend.CedarBackend` and by
`oap-server --policy-backend cedar`.

The adapter maps OAP authorization input into Cedar-style entities:

- OAP agent -> `OAP::Agent::<agent_id>`
- OAP action -> `OAP::Action::<action_name>`
- OAP resource -> `OAP::<resource_type>::<resource_id>`
- OAP actor and request context -> Cedar context

Run OAP against a Cedar-compatible authorization endpoint:

```bash
./bin/oap-server \
  --data validation/policies \
  --policy-backend cedar \
  --cedar-url http://localhost:8180/v1/is_authorized \
  --cedar-policy-store-id "$CEDAR_POLICY_STORE_ID" \
  --grant-key dev-grant-key \
  --dev
```

OAP still performs agent lookup, capability checks, delegation checks, grant
issuance, and audit. Cedar only returns the rule decision. The default behavior
is fail-closed; use `--cedar-fail-open` only for temporary fallback testing.

Files:

- `policy.cedar` - example Cedar policy.
- `request-allow.json` - request sent by the OAP Cedar adapter.
- `response-allow.json` - allow response with constraints.
- `response-deny.json` - deny response.
