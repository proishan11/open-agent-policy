// Package identity implements pluggable identity verification for OAP.
//
// Identity verification has two sides:
//
// 1. Agent identity — confirming an agent is who it claims to be.
//    Methods: dev credentials, Kubernetes ServiceAccount tokens, SPIFFE SVIDs.
//
// 2. Actor identity — confirming the human or service on whose behalf
//    the agent acts. Method: OIDC JWT validation against an IdP's JWKS.
//
// All verifiers implement the Verifier interface:
//
//	type Verifier interface {
//	    VerifyAgent(ctx, credentials) → agentID, error
//	    VerifyActor(ctx, token) → actorIdentity, error
//	}
//
// The default DevVerifier accepts any credentials (for local development).
// Production deployments use OIDCVerifier and/or KubernetesVerifier.
package identity
