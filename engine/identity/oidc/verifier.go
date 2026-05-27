package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proishan11/open-agent-policy/engine/identity"
)

// Config configures the production OIDC verifier.
type Config struct {
	// Issuer is the expected OIDC issuer URL (e.g., "https://company.okta.com").
	// Used for issuer validation and JWKS discovery.
	Issuer string

	// Audience is the expected audience claim (e.g., "oap-server").
	Audience string

	// JWKSUrl overrides the JWKS endpoint. If empty, discovered from
	// Issuer + "/.well-known/openid-configuration".
	JWKSUrl string

	// ClockSkew is the allowed clock difference between OAP and the IDP.
	// Defaults to 60 seconds.
	ClockSkew time.Duration

	// JWKSRefreshInterval is how often to refresh the JWKS in the background.
	// Defaults to 1 hour.
	JWKSRefreshInterval time.Duration

	// HTTPClient is used for JWKS fetching. Defaults to http.DefaultClient.
	HTTPClient *http.Client

	// ClaimMappings configures which JWT claims map to OAP actor fields.
	ClaimMappings ClaimMappings

	// RequiredClaims are additional claims that must be present.
	// Key is the claim name, value is the expected value (or "" for any value).
	RequiredClaims map[string]string

	// AllowedAlgorithms restricts which signing algorithms are accepted.
	// Defaults to RS256, RS384, RS512, ES256, ES384, PS256.
	AllowedAlgorithms []jose.SignatureAlgorithm
}

// ClaimMappings defines which OIDC claims map to OAP actor fields.
type ClaimMappings struct {
	SubjectClaim string // default: "sub"
	EmailClaim   string // default: "email"
	GroupsClaim  string // default: "groups"
	RolesClaim   string // default: "roles"
	NameClaim    string // default: "name"
}

// defaultAlgorithms are the signing algorithms accepted by default.
var defaultAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384,
	jose.PS256,
}

// Verifier performs production OIDC token verification with real
// cryptographic signature validation against provider JWKS endpoints.
type Verifier struct {
	cfg Config

	mu      sync.RWMutex
	jwks    *jose.JSONWebKeySet
	jwksAt  time.Time
	jwksURL string // resolved JWKS URL
}

// NewVerifier creates a production OIDC verifier.
// It discovers the JWKS URL from the issuer's openid-configuration if not explicitly set.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 60 * time.Second
	}
	if cfg.JWKSRefreshInterval == 0 {
		cfg.JWKSRefreshInterval = 1 * time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if len(cfg.AllowedAlgorithms) == 0 {
		cfg.AllowedAlgorithms = defaultAlgorithms
	}

	// Defaults for claim mappings
	if cfg.ClaimMappings.SubjectClaim == "" {
		cfg.ClaimMappings.SubjectClaim = "sub"
	}
	if cfg.ClaimMappings.EmailClaim == "" {
		cfg.ClaimMappings.EmailClaim = "email"
	}
	if cfg.ClaimMappings.GroupsClaim == "" {
		cfg.ClaimMappings.GroupsClaim = "groups"
	}
	if cfg.ClaimMappings.RolesClaim == "" {
		cfg.ClaimMappings.RolesClaim = "roles"
	}
	if cfg.ClaimMappings.NameClaim == "" {
		cfg.ClaimMappings.NameClaim = "name"
	}

	v := &Verifier{cfg: cfg}

	// Resolve JWKS URL
	if cfg.JWKSUrl != "" {
		v.jwksURL = cfg.JWKSUrl
	} else {
		url, err := v.discoverJWKS(context.Background())
		if err != nil {
			// Fall back to well-known path
			v.jwksURL = strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/jwks.json"
		} else {
			v.jwksURL = url
		}
	}

	return v, nil
}

// VerifyAgent is not supported via OIDC — agents use K8s SA or SPIFFE.
func (v *Verifier) VerifyAgent(_ context.Context, _ identity.AgentCredentials) (string, error) {
	return "", fmt.Errorf("oidc: agent verification not supported; use Kubernetes or SPIFFE verifier")
}

// VerifyActor validates the OIDC JWT token with full cryptographic verification:
//  1. Parse the JWT and extract the header
//  2. Find the matching key in JWKS by kid
//  3. Verify the cryptographic signature
//  4. Validate issuer, audience, expiry (with clock skew)
//  5. Map claims to OAP ActorIdentity
func (v *Verifier) VerifyActor(ctx context.Context, token identity.ActorToken) (*identity.ActorIdentity, error) {
	if token.RawToken == "" {
		return nil, fmt.Errorf("oidc: token is required")
	}

	// Parse the JWT (does not verify yet)
	parsed, err := jwt.ParseSigned(token.RawToken, v.cfg.AllowedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("oidc: parse token: %w", err)
	}

	// Get JWKS (cached or fetch)
	keys, err := v.getJWKS(ctx, parsed)
	if err != nil {
		return nil, fmt.Errorf("oidc: get jwks: %w", err)
	}

	// Find matching key by kid
	matchingKeys := v.findKeys(parsed, keys)
	if len(matchingKeys) == 0 {
		return nil, fmt.Errorf("oidc: no matching key found for token kid")
	}

	// Try each matching key
	var claims jwt.Claims
	var customClaims map[string]interface{}
	var verifyErr error

	for _, key := range matchingKeys {
		claims = jwt.Claims{}
		customClaims = make(map[string]interface{})
		if err := parsed.Claims(key, &claims, &customClaims); err != nil {
			verifyErr = err
			continue
		}
		verifyErr = nil
		break
	}
	if verifyErr != nil {
		return nil, fmt.Errorf("oidc: signature verification failed: %w", verifyErr)
	}

	// Validate standard claims
	now := time.Now()
	expected := jwt.Expected{
		Issuer: v.cfg.Issuer,
		Time:   now,
	}
	if v.cfg.Audience != "" {
		expected.AnyAudience = jwt.Audience{v.cfg.Audience}
	}

	if err := claims.ValidateWithLeeway(expected, v.cfg.ClockSkew); err != nil {
		return nil, fmt.Errorf("oidc: token validation failed: %w", err)
	}

	// Validate required claims
	for k, expectedVal := range v.cfg.RequiredClaims {
		val, ok := customClaims[k]
		if !ok {
			return nil, fmt.Errorf("oidc: missing required claim %q", k)
		}
		if expectedVal != "" {
			if fmt.Sprintf("%v", val) != expectedVal {
				return nil, fmt.Errorf("oidc: claim %q: expected %q, got %q", k, expectedVal, val)
			}
		}
	}

	// Map claims to identity
	return v.mapClaimsToIdentity(claims, customClaims), nil
}

// getJWKS returns cached JWKS or fetches fresh from the provider.
func (v *Verifier) getJWKS(ctx context.Context, parsed *jwt.JSONWebToken) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	cached := v.jwks
	age := time.Since(v.jwksAt)
	v.mu.RUnlock()

	// Return cached if fresh
	if cached != nil && age < v.cfg.JWKSRefreshInterval {
		// Check if the kid is in the cache
		if v.kidInCache(parsed, cached) {
			return cached, nil
		}
		// Unknown kid — force refresh
	}

	// Fetch fresh JWKS
	return v.fetchJWKS(ctx)
}

// fetchJWKS fetches the JWKS from the provider endpoint.
func (v *Verifier) fetchJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks from %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	// Cache
	v.mu.Lock()
	v.jwks = &jwks
	v.jwksAt = time.Now()
	v.mu.Unlock()

	return &jwks, nil
}

// discoverJWKS resolves the JWKS URL from the issuer's openid-configuration.
func (v *Verifier) discoverJWKS(ctx context.Context) (string, error) {
	configURL := strings.TrimSuffix(v.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openid-configuration returned %d", resp.StatusCode)
	}

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", err
	}
	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in openid-configuration")
	}
	return config.JWKSURI, nil
}

// kidInCache checks if the token's kid matches any key in the cached JWKS.
func (v *Verifier) kidInCache(parsed *jwt.JSONWebToken, jwks *jose.JSONWebKeySet) bool {
	for _, header := range parsed.Headers {
		if header.KeyID != "" {
			keys := jwks.Key(header.KeyID)
			if len(keys) > 0 {
				return true
			}
		}
	}
	return false
}

// findKeys finds JWKS keys matching the token's kid and algorithm.
func (v *Verifier) findKeys(parsed *jwt.JSONWebToken, jwks *jose.JSONWebKeySet) []interface{} {
	var keys []interface{}
	for _, header := range parsed.Headers {
		if header.KeyID != "" {
			for _, k := range jwks.Key(header.KeyID) {
				keys = append(keys, k.Key)
			}
		}
	}
	// If no kid match, try all keys with matching algorithm
	if len(keys) == 0 {
		for _, header := range parsed.Headers {
			for _, k := range jwks.Keys {
				if string(k.Algorithm) == header.Algorithm {
					keys = append(keys, k.Key)
				}
			}
		}
	}
	return keys
}

// mapClaimsToIdentity converts JWT claims to an OAP ActorIdentity.
func (v *Verifier) mapClaimsToIdentity(std jwt.Claims, custom map[string]interface{}) *identity.ActorIdentity {
	id := &identity.ActorIdentity{
		Type:    "user",
		ID:      std.Subject,
		Issuer:  std.Issuer,
	}

	if std.Expiry != nil {
		id.ExpiresAt = std.Expiry.Time()
	}

	// Email
	if email, ok := custom[v.cfg.ClaimMappings.EmailClaim].(string); ok {
		id.Email = email
		if id.ID == "" {
			id.ID = "user:" + email
		}
	}

	// Groups
	id.Groups = extractStringSlice(custom, v.cfg.ClaimMappings.GroupsClaim)

	// Roles → also added to Groups for policy matching
	roles := extractStringSlice(custom, v.cfg.ClaimMappings.RolesClaim)
	id.Groups = append(id.Groups, roles...)

	return id
}

// extractStringSlice extracts a []string from a claim that may be []interface{} or string.
func extractStringSlice(claims map[string]interface{}, key string) []string {
	val, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	}
	return nil
}
