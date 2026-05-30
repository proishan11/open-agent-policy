# SPIFFE JWT-SVID

Use `spiffe` when the workload can obtain a SPIFFE JWT-SVID, usually from
SPIRE. OAP supports JWT-SVID verification. It does not yet validate X.509-SVIDs
or mTLS client certificates.

## Agent Binding

```yaml
apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: ticket-assistant
  namespace: support
spec:
  owner: group:support-platform
  type: chat_agent
  riskTier: medium
  capabilities:
    - ticket.read
  workloadIdentity:
    id: "spiffe://oap.local/ns/support/sa/ticket-assistant"
    type: spiffe
    trustDomain: oap.local
    attestationLevel: platform
  identityBindings:
    - type: spiffe
      provider: spire
      issuer: "https://spire.oap.local"
      jwksUri: "https://spire.oap.local/.well-known/jwks.json"
      subject: "spiffe://oap.local/ns/support/sa/ticket-assistant"
      audience: "oap-server"
```

For SPIFFE bindings, `audience` is required. OAP filters the fetched key set and
only accepts keys whose JWK `use` is `jwt-svid`.

## Fetch A JWT-SVID

The exact command depends on your SPIRE deployment. A common shape is:

```bash
RUNTIME_TOKEN="$(spire-agent api fetch jwt \
  -audience oap-server \
  -socketPath /run/spire/sockets/agent.sock \
  | awk '/SVID/ {getline; print}')"
```

If your platform exposes the JWT-SVID another way, pass that JWT as the
`runtime_token`.

## Create The Session

```bash
curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent://support/ticket-assistant",
    "runtime_token": "'"$RUNTIME_TOKEN"'",
    "environment": "production"
  }'
```

## Notes

- The JWT `sub` must equal the binding `subject`.
- The JWT `aud` must contain the binding `audience`.
- Configure an explicit `jwksUri` unless your SPIFFE issuer exposes OIDC
  discovery metadata.
- X.509-SVID and mTLS enforcement are planned separately; do not document them
  as supported for this release.
