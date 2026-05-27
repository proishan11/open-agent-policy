package session

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

	"github.com/proishan11/open-agent-policy/engine/model"
)

// TokenValidator validates JWTs against multiple identity providers.
// It caches JWKS per issuer URL to avoid repeated fetches.
type TokenValidator struct {
	mu        sync.RWMutex
	jwksCache map[string]*cachedJWKS
	client    *http.Client
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// NewTokenValidator creates a multi-issuer token validator.
func NewTokenValidator() *TokenValidator {
	return &TokenValidator{
		jwksCache: make(map[string]*cachedJWKS),
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// ValidateAgainstBindings validates a JWT against a set of identity bindings.
// It tries each binding: fetches the binding's issuer JWKS, verifies the JWT
// signature, validates standard claims, and checks the subject match.
// Returns nil if the token matches any binding.
func (v *TokenValidator) ValidateAgainstBindings(
	ctx context.Context,
	rawToken string,
	bindings []model.IdentityBinding,
) error {
	algs := []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.PS256,
	}
	parsed, err := jwt.ParseSigned(rawToken, algs)
	if err != nil {
		return fmt.Errorf("parse token: %w", err)
	}

	// Try each binding's issuer JWKS to verify the token
	var lastErr error
	for _, binding := range bindings {
		if err := v.tryBinding(ctx, parsed, binding); err != nil {
			lastErr = err
			continue
		}
		return nil // success
	}

	if lastErr != nil {
		return fmt.Errorf("no matching identity binding: %w", lastErr)
	}
	return fmt.Errorf("no matching identity binding")
}

// tryBinding attempts to validate the parsed JWT against a single identity binding.
func (v *TokenValidator) tryBinding(
	ctx context.Context,
	parsed *jwt.JSONWebToken,
	binding model.IdentityBinding,
) error {
	// 1. Fetch JWKS for the binding's issuer
	jwks, err := v.getJWKS(ctx, binding.Issuer)
	if err != nil {
		return fmt.Errorf("fetch jwks for %s: %w", binding.Issuer, err)
	}

	// 2. Find matching signing keys
	matchKeys := findKeysFromJWKS(parsed, jwks)
	if len(matchKeys) == 0 {
		return fmt.Errorf("no matching signing key for issuer %s", binding.Issuer)
	}

	// 3. Verify signature and extract claims
	var stdClaims jwt.Claims
	var customClaims map[string]interface{}
	verified := false

	for _, key := range matchKeys {
		stdClaims = jwt.Claims{}
		customClaims = make(map[string]interface{})
		if err := parsed.Claims(key, &stdClaims, &customClaims); err != nil {
			continue
		}
		verified = true
		break
	}
	if !verified {
		return fmt.Errorf("signature verification failed for issuer %s", binding.Issuer)
	}

	// 4. Validate standard claims (issuer, expiry, audience)
	expected := jwt.Expected{
		Issuer: binding.Issuer,
		Time:   time.Now(),
	}
	if binding.Audience != "" {
		expected.AnyAudience = jwt.Audience{binding.Audience}
	}
	if err := stdClaims.ValidateWithLeeway(expected, 60*time.Second); err != nil {
		return fmt.Errorf("claims validation: %w", err)
	}

	// 5. Match subject against binding
	azp, _ := customClaims["azp"].(string)
	clientID, _ := customClaims["client_id"].(string)

	if !subjectMatches(binding.Subject, stdClaims.Subject, azp, clientID) {
		return fmt.Errorf("subject mismatch: binding expects %q, token has sub=%q azp=%q",
			binding.Subject, stdClaims.Subject, azp)
	}

	return nil
}

// subjectMatches checks if any of the token's identity claims match the binding.
//
// Supported formats:
//   - Direct match against sub, azp, or client_id claims
//   - Prefixed: "client_id:support-agent" matches azp or client_id "support-agent"
func subjectMatches(bindingSubject, tokenSub, azp, clientID string) bool {
	// Direct match
	if bindingSubject == tokenSub ||
		(azp != "" && bindingSubject == azp) ||
		(clientID != "" && bindingSubject == clientID) {
		return true
	}

	// Prefixed match: "client_id:support-agent"
	if strings.HasPrefix(bindingSubject, "client_id:") {
		expected := strings.TrimPrefix(bindingSubject, "client_id:")
		return expected == azp || expected == clientID || expected == tokenSub
	}

	return false
}

// --- JWKS management ---

func (v *TokenValidator) getJWKS(ctx context.Context, issuerURL string) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	cached, ok := v.jwksCache[issuerURL]
	v.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < 1*time.Hour {
		return cached.jwks, nil
	}

	// Discover JWKS URL from OIDC discovery
	jwksURL, err := discoverJWKS(ctx, v.client, issuerURL)
	if err != nil {
		// Fallback: Keycloak-style path
		jwksURL = strings.TrimSuffix(issuerURL, "/") + "/protocol/openid-connect/certs"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint %s returned %d", jwksURL, resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	v.mu.Lock()
	v.jwksCache[issuerURL] = &cachedJWKS{jwks: &jwks, fetchedAt: time.Now()}
	v.mu.Unlock()

	return &jwks, nil
}

func discoverJWKS(ctx context.Context, client *http.Client, issuerURL string) (string, error) {
	configURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery returned %d", resp.StatusCode)
	}
	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", err
	}
	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in discovery")
	}
	return config.JWKSURI, nil
}

func findKeysFromJWKS(parsed *jwt.JSONWebToken, jwks *jose.JSONWebKeySet) []interface{} {
	var keys []interface{}
	// Match by key ID first
	for _, header := range parsed.Headers {
		if header.KeyID != "" {
			for _, k := range jwks.Key(header.KeyID) {
				keys = append(keys, k.Key)
			}
		}
	}
	// Fallback: match by algorithm
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
