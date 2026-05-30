# Auth Protocol Examples

These examples show how to register an agent identity binding and create an OAP
runtime session for each supported workload-authentication mechanism.

| Example | Binding type | What it demonstrates |
|---|---|---|
| `oidc-client/` | `oidc_client` | OAuth2 client credentials with a JWT access token. |
| `kubernetes-service-account/` | `kubernetes_service_account` | Projected Kubernetes ServiceAccount JWTs. |
| `spiffe-jwt-svid/` | `spiffe` | SPIFFE JWT-SVID session creation. |
| `wimse/` | `wimse` | WIMSE WIT plus WPT proof-of-possession session creation. |

Only the Keycloak/OIDC path is fully exercised by the local validation stack
today. The Kubernetes, SPIFFE, and WIMSE examples are concrete integration
templates that match the implemented verifier contract.

Start with:

- [Authentication Protocols](../../docs/guide/authentication-protocols.md)
- [Identity And Sessions](../../docs/guide/identity-and-sessions.md)

