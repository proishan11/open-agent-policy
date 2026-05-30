# Authentication Protocols

OAP makes authorization decisions for agent actions, but it must first know
which workload is really calling. Runtime authentication is handled through
agent identity bindings and short-lived OAP sessions.

This page is the protocol map. Use the linked guides for runnable setup shapes.

## Support Matrix

| Mechanism | Binding type | Status | Use for |
|---|---|---|---|
| OAuth2 client credentials with JWT access token | `oidc_client` | Supported and Keycloak e2e validated | Agents that already have an OIDC/OAuth workload client. |
| OIDC JWT from Okta, Entra ID, Auth0, Cognito, Google, Keycloak, or similar | `oidc_client` | Supported when the token is JWT/JWKS-verifiable | General workload identity. |
| Kubernetes projected ServiceAccount token | `kubernetes_service_account` | Supported by JWT validator | In-cluster agents using K8s workload identity. |
| SPIFFE JWT-SVID | `spiffe` | Supported for JWT-SVID only | SPIRE/SPIFFE workloads that can mint JWT-SVIDs. |
| WIMSE Workload Identity Token plus Workload Proof Token | `wimse` | Supported first slice | Proof-of-possession workload identity. |
| OAP runtime session token | `ags_...` | Supported | Bearer token returned by `/v1/runtime/session` for later OAP API calls. |
| Raw JWT bearer token on `/v1/authorize` | none; server `--issuer` mode | Backward-compatible path | Existing callers with a JWT that carries an OAP agent ID claim. |
| OAP grant token | n/a | Supported | Resource API authorization after OAP returns `allow`. Not an agent identity token. |

## Not Supported Yet

- Opaque OAuth2 tokens via introspection.
- OAuth authorization-code user consent as agent workload identity.
- SPIFFE X.509-SVID or generic mTLS client certificate authentication.
- WIMSE HTTP Message Signatures.
- Distributed WIMSE WPT replay cache for horizontally scaled OAP servers.
- Verifying the human actor from a separate end-user OAuth token. Today the
  actor is part of the authorization request context; agent workload identity is
  the cryptographically verified subject.

## Runtime Session Flow

The preferred path is:

```text
agent workload obtains runtime credential
  -> POST /v1/runtime/session with agent_id and credential
  -> OAP validates credential against spec.identityBindings
  -> OAP returns ags_... session token
  -> agent uses Authorization: Bearer ags_... on /v1/authorize
  -> OAP issues scoped grant token on allow decisions
  -> resource API validates grant token with /v1/grants/validate
```

Generic session request:

```bash
curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent://support/ticket-assistant",
    "runtime_token": "'"$RUNTIME_TOKEN"'",
    "environment": "production"
  }'
```

Authorize with the session:

```bash
curl -sS -X POST "$OAP_SERVER_URL/v1/authorize" \
  -H "Authorization: Bearer $OAP_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "req-123",
    "subject": {"type": "agent", "agent_id": "agent://support/ticket-assistant"},
    "actor": {"type": "user", "id": "alice@example.com"},
    "action": {"name": "ticket.read"},
    "resource": {"type": "support.ticket", "id": "T-100"}
  }'
```

Current server note: the HTTP auth middleware is enabled by `--issuer`, which
also enables raw-JWT compatibility. Session creation validates each agent's
registered identity bindings, but protected endpoints only require bearer tokens
when auth middleware is enabled. Future server hardening should separate
`--require-auth` from raw JWT issuer configuration.

## Guides

- [Auth Protocol Examples](../../examples/auth-protocols/README.md)
- [OIDC And OAuth2 Client Credentials](auth-oidc-oauth.md)
- [Kubernetes ServiceAccount JWTs](auth-kubernetes-service-account.md)
- [SPIFFE JWT-SVID](auth-spiffe-jwt-svid.md)
- [WIMSE WIT And WPT](auth-wimse.md)
- [Identity And Sessions](identity-and-sessions.md)
- [Protecting Resource APIs](protecting-resource-apis.md)
