// Package oidc provides a production-grade OIDC identity verifier for OAP.
//
// Unlike the prototype OIDCVerifier (which only decoded JWT claims without
// signature verification), this package performs full cryptographic validation:
//
//   - JWKS auto-discovery via .well-known/openid-configuration
//   - Background JWKS rotation with configurable TTL
//   - Force-refresh on unknown kid (key ID)
//   - RS256, RS384, RS512, ES256, ES384, PS256 signature verification
//   - Issuer, audience, and expiry validation with clock skew tolerance
//   - Configurable claim mapping (per-provider)
//
// Usage:
//
//	verifier, err := oidc.NewVerifier(oidc.Config{
//	    Issuer:   "https://company.okta.com",
//	    Audience: "oap-server",
//	})
//	identity, err := verifier.VerifyActor(ctx, token)
//
// Provider-specific configs are available via helper constructors:
//
//	verifier := oidc.ForKeycloak("https://keycloak.corp/realms/main", "oap-server")
//	verifier := oidc.ForOkta("https://company.okta.com", "oap-server")
//	verifier := oidc.ForAzureAD("tenant-id", "oap-server")
//	verifier := oidc.ForGoogle("oap-server", "company.com")
//	verifier := oidc.ForCognito("us-east-1", "us-east-1_abc123", "oap-server")
//	verifier := oidc.ForAuth0("company.auth0.com", "oap-server")
package oidc
