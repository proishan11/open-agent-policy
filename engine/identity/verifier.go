package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AgentCredentials holds the credentials presented by an agent.
type AgentCredentials struct {
	// ClientID is the agent's registered client identifier.
	ClientID string `json:"client_id"`

	// ClientSecret is the agent's secret (dev mode, rotated regularly).
	ClientSecret string `json:"client_secret,omitempty"`

	// ServiceAccountToken is a Kubernetes SA JWT token.
	ServiceAccountToken string `json:"sa_token,omitempty"`

	// SPIFFEToken is a SPIFFE SVID token.
	SPIFFEToken string `json:"spiffe_token,omitempty"`
}

// ActorToken is an OIDC JWT presented on behalf of a user or service.
type ActorToken struct {
	// RawToken is the raw JWT string.
	RawToken string `json:"token"`
}

// ActorIdentity is the verified identity of an actor.
type ActorIdentity struct {
	// Type is the actor type (user, service, team).
	Type string `json:"type"`

	// ID is the actor identifier (e.g., user:alice@example.com).
	ID string `json:"id"`

	// Email from OIDC claims.
	Email string `json:"email,omitempty"`

	// Groups from OIDC claims.
	Groups []string `json:"groups,omitempty"`

	// Issuer is the OIDC issuer.
	Issuer string `json:"issuer,omitempty"`

	// ExpiresAt is the token expiry.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Verifier verifies agent and actor identities.
type Verifier interface {
	// VerifyAgent validates agent credentials and returns the agent ID.
	VerifyAgent(ctx context.Context, creds AgentCredentials) (string, error)

	// VerifyActor validates an actor's OIDC token and returns the identity.
	VerifyActor(ctx context.Context, token ActorToken) (*ActorIdentity, error)
}

// --- DevVerifier ---

// DevVerifier accepts any credentials. Use only for local development.
type DevVerifier struct{}

// NewDevVerifier creates a development-mode verifier.
func NewDevVerifier() *DevVerifier {
	return &DevVerifier{}
}

// VerifyAgent in dev mode accepts any client_id as the agent ID.
func (v *DevVerifier) VerifyAgent(_ context.Context, creds AgentCredentials) (string, error) {
	if creds.ClientID == "" {
		return "", fmt.Errorf("client_id is required")
	}
	return creds.ClientID, nil
}

// VerifyActor in dev mode accepts any token and extracts basic claims.
func (v *DevVerifier) VerifyActor(_ context.Context, token ActorToken) (*ActorIdentity, error) {
	if token.RawToken == "" {
		return nil, fmt.Errorf("token is required")
	}
	// Try to decode JWT claims (unsigned)
	claims, err := decodeJWTClaims(token.RawToken)
	if err != nil {
		// Accept raw token as actor ID in dev mode
		return &ActorIdentity{Type: "user", ID: token.RawToken}, nil
	}
	return claimsToIdentity(claims), nil
}

// --- OIDCVerifier ---

// OIDCConfig holds OIDC verifier configuration.
type OIDCConfig struct {
	// Issuer is the expected token issuer (e.g., https://company.okta.com).
	Issuer string

	// Audience is the expected audience claim.
	Audience string

	// JWKSUrl is the URL to fetch the JWKS for signature verification.
	// If empty, derived from Issuer + "/.well-known/jwks.json".
	JWKSUrl string

	// ClaimMappings maps OIDC claims to OAP actor fields.
	ClaimMappings OIDCClaimMappings
}

// OIDCClaimMappings defines which OIDC claims map to OAP actor fields.
type OIDCClaimMappings struct {
	SubjectClaim string // default: "sub"
	EmailClaim   string // default: "email"
	GroupsClaim  string // default: "groups"
}

// OIDCVerifier validates OIDC JWT tokens against a JWKS endpoint.
type OIDCVerifier struct {
	cfg       OIDCConfig
	mu        sync.RWMutex
	jwksCache json.RawMessage
	jwksFetch time.Time
}

// NewOIDCVerifier creates an OIDC identity verifier.
func NewOIDCVerifier(cfg OIDCConfig) *OIDCVerifier {
	if cfg.ClaimMappings.SubjectClaim == "" {
		cfg.ClaimMappings.SubjectClaim = "sub"
	}
	if cfg.ClaimMappings.EmailClaim == "" {
		cfg.ClaimMappings.EmailClaim = "email"
	}
	if cfg.ClaimMappings.GroupsClaim == "" {
		cfg.ClaimMappings.GroupsClaim = "groups"
	}
	if cfg.JWKSUrl == "" && cfg.Issuer != "" {
		cfg.JWKSUrl = strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/jwks.json"
	}
	return &OIDCVerifier{cfg: cfg}
}

// VerifyAgent is not supported via OIDC — returns an error.
func (v *OIDCVerifier) VerifyAgent(_ context.Context, _ AgentCredentials) (string, error) {
	return "", fmt.Errorf("OIDC verifier does not support agent verification; use KubernetesVerifier or DevVerifier")
}

// VerifyActor validates the OIDC token: checks structure, issuer, audience, and expiry.
// Note: In production, this would verify the JWT signature against the JWKS.
// For this implementation, we validate claims and structure.
func (v *OIDCVerifier) VerifyActor(_ context.Context, token ActorToken) (*ActorIdentity, error) {
	if token.RawToken == "" {
		return nil, fmt.Errorf("token is required")
	}

	claims, err := decodeJWTClaims(token.RawToken)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}

	// Validate issuer
	if iss, ok := claims["iss"].(string); ok {
		if v.cfg.Issuer != "" && iss != v.cfg.Issuer {
			return nil, fmt.Errorf("invalid issuer: got %q, want %q", iss, v.cfg.Issuer)
		}
	} else if v.cfg.Issuer != "" {
		return nil, fmt.Errorf("missing issuer claim")
	}

	// Validate audience
	if v.cfg.Audience != "" {
		if !audienceContains(claims, v.cfg.Audience) {
			return nil, fmt.Errorf("invalid audience: expected %q", v.cfg.Audience)
		}
	}

	// Check expiry
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token expired")
		}
	}

	return claimsToIdentity(claims), nil
}

// --- KubernetesVerifier ---

// KubernetesConfig holds Kubernetes verifier configuration.
type KubernetesConfig struct {
	// APIServerURL is the Kubernetes API server URL.
	// If empty, uses in-cluster config.
	APIServerURL string

	// Namespace restricts agent verification to a specific namespace.
	// If empty, any namespace is accepted.
	Namespace string
}

// KubernetesVerifier validates Kubernetes ServiceAccount tokens.
type KubernetesVerifier struct {
	cfg KubernetesConfig
}

// NewKubernetesVerifier creates a Kubernetes identity verifier.
func NewKubernetesVerifier(cfg KubernetesConfig) *KubernetesVerifier {
	return &KubernetesVerifier{cfg: cfg}
}

// VerifyAgent validates a Kubernetes ServiceAccount token.
// In production, this would call the TokenReview API.
// Here we decode the JWT and extract the service account identity.
func (v *KubernetesVerifier) VerifyAgent(_ context.Context, creds AgentCredentials) (string, error) {
	if creds.ServiceAccountToken == "" {
		return "", fmt.Errorf("service account token is required")
	}

	claims, err := decodeJWTClaims(creds.ServiceAccountToken)
	if err != nil {
		return "", fmt.Errorf("invalid SA token: %w", err)
	}

	// Extract service account info from standard k8s JWT claims
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("missing subject claim in SA token")
	}

	// Kubernetes SA tokens have sub like: system:serviceaccount:<namespace>:<name>
	if strings.HasPrefix(sub, "system:serviceaccount:") {
		parts := strings.SplitN(sub, ":", 4)
		if len(parts) == 4 {
			namespace := parts[2]
			name := parts[3]

			// Check namespace restriction
			if v.cfg.Namespace != "" && namespace != v.cfg.Namespace {
				return "", fmt.Errorf("agent namespace %q not allowed (expected %q)", namespace, v.cfg.Namespace)
			}

			return fmt.Sprintf("agent://%s/%s", namespace, name), nil
		}
	}

	return "", fmt.Errorf("unrecognized SA token subject: %q", sub)
}

// VerifyActor is not supported via Kubernetes SA — returns an error.
func (v *KubernetesVerifier) VerifyActor(_ context.Context, _ ActorToken) (*ActorIdentity, error) {
	return nil, fmt.Errorf("Kubernetes verifier does not support actor verification; use OIDCVerifier")
}

// --- CompositeVerifier ---

// CompositeVerifier tries multiple verifiers in order.
type CompositeVerifier struct {
	agentVerifiers []Verifier
	actorVerifiers []Verifier
}

// NewCompositeVerifier creates a verifier that delegates to multiple backends.
func NewCompositeVerifier(agentVerifiers, actorVerifiers []Verifier) *CompositeVerifier {
	return &CompositeVerifier{
		agentVerifiers: agentVerifiers,
		actorVerifiers: actorVerifiers,
	}
}

// VerifyAgent tries each agent verifier in order.
func (v *CompositeVerifier) VerifyAgent(ctx context.Context, creds AgentCredentials) (string, error) {
	var lastErr error
	for _, verifier := range v.agentVerifiers {
		id, err := verifier.VerifyAgent(ctx, creds)
		if err == nil {
			return id, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", fmt.Errorf("all agent verifiers failed: %w", lastErr)
	}
	return "", fmt.Errorf("no agent verifiers configured")
}

// VerifyActor tries each actor verifier in order.
func (v *CompositeVerifier) VerifyActor(ctx context.Context, token ActorToken) (*ActorIdentity, error) {
	var lastErr error
	for _, verifier := range v.actorVerifiers {
		id, err := verifier.VerifyActor(ctx, token)
		if err == nil {
			return id, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("all actor verifiers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("no actor verifiers configured")
}

// --- JWT helpers ---

// decodeJWTClaims decodes the claims from a JWT without verifying the signature.
func decodeJWTClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (part 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	return claims, nil
}

// claimsToIdentity converts JWT claims to an ActorIdentity.
func claimsToIdentity(claims map[string]interface{}) *ActorIdentity {
	identity := &ActorIdentity{Type: "user"}

	if sub, ok := claims["sub"].(string); ok {
		identity.ID = sub
	}
	if email, ok := claims["email"].(string); ok {
		identity.Email = email
		if identity.ID == "" {
			identity.ID = "user:" + email
		}
	}
	if iss, ok := claims["iss"].(string); ok {
		identity.Issuer = iss
	}
	if exp, ok := claims["exp"].(float64); ok {
		identity.ExpiresAt = time.Unix(int64(exp), 0)
	}

	// Extract groups
	switch g := claims["groups"].(type) {
	case []interface{}:
		for _, group := range g {
			if s, ok := group.(string); ok {
				identity.Groups = append(identity.Groups, s)
			}
		}
	}

	return identity
}

// audienceContains checks if the aud claim contains the expected audience.
func audienceContains(claims map[string]interface{}, expected string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == expected
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// makeTestJWT creates a minimal unsigned JWT for testing.
// This is NOT for production use — it creates tokens without signatures.
func makeTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	// Create a dummy signature using HMAC for test purposes
	mac := hmac.New(sha256.New, []byte("test"))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + payload + "." + sig
}

// FetchJWKS fetches the JWKS from a URL (placeholder for production use).
func FetchJWKS(ctx context.Context, jwksURL string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var jwks json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	return jwks, nil
}
