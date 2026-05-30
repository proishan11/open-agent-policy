# OIDC And OAuth2 Client Credentials

Use `oidc_client` when an agent workload can obtain a JWT access token from an
OIDC/OAuth provider. OAP validates the token signature through JWKS, checks
issuer, expiry, optional audience, and matches the binding subject against
`sub`, `azp`, or `client_id`.

This supports providers such as Keycloak, Okta, Entra ID, Auth0, Cognito,
Google, and PingIdentity when they issue JWTs with discoverable JWKS.

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
  identityBindings:
    - type: oidc_client
      provider: keycloak
      issuer: "https://keycloak.company.com/realms/agents"
      subject: "support-agent"
      audience: "oap-server"
```

`audience` is optional. Use it when the IdP issues an audience claim for OAP.

If the token's `sub` is not stable but `azp` or `client_id` is, set:

```yaml
subject: "client_id:support-agent"
```

## Get A Token

Keycloak shape:

```bash
TOKEN_RESPONSE="$(curl -sS -X POST \
  https://keycloak.company.com/realms/agents/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=client_credentials \
  -d client_id=support-agent \
  -d client_secret="$CLIENT_SECRET" \
  -d audience=oap-server)"

RUNTIME_TOKEN="$(printf '%s' "$TOKEN_RESPONSE" | python3 -c \
  'import json, sys; print(json.load(sys.stdin)["access_token"])')"
```

Okta shape:

```yaml
identityBindings:
  - type: oidc_client
    provider: okta
    issuer: "https://company.okta.com/oauth2/default"
    subject: "0oa1abc2def3ghi4j5k6"
    audience: "api://oap"
```

Entra ID shape:

```yaml
identityBindings:
  - type: oidc_client
    provider: entra-id
    issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
    subject: "<application-client-id>"
    audience: "api://<oap-api-app-id>"
```

## Create An OAP Session

```bash
SESSION_RESPONSE="$(curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent://support/ticket-assistant",
    "runtime_token": "'"$RUNTIME_TOKEN"'",
    "environment": "production"
  }')"

OAP_SESSION_ID="$(printf '%s' "$SESSION_RESPONSE" | python3 -c \
  'import json, sys; print(json.load(sys.stdin)["session_id"])')"
```

Python SDK:

```python
from open_agent_policy import OAPClient

client = OAPClient(
    server_url="https://oap.company.com",
    agent_id="agent://support/ticket-assistant",
)
session = client.create_session(
    runtime_token=runtime_token,
    environment="production",
)

decision = client.authorize(
    action="ticket.read",
    resource_type="support.ticket",
    resource_id="T-100",
    actor_type="user",
    actor_id="alice@example.com",
)
```

## Raw JWT Compatibility

The server also supports raw JWT bearer auth when started with `--issuer`.
This mode validates the JWT and extracts the OAP agent ID from an `agent_id`
claim by default.

```bash
./bin/oap-server \
  --data validation/policies \
  --issuer "https://keycloak.company.com/realms/agents" \
  --audience "oap-server"
```

Prefer runtime sessions for new deployments because the session binds the
runtime token to a registered agent identity binding.

## Limits

- Opaque OAuth2 tokens are not supported because OAP does not call token
  introspection endpoints yet.
- End-user OAuth login is not treated as agent workload identity. Pass the
  human actor in the authorization request and keep the agent workload identity
  separate.
