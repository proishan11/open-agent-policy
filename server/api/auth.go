package api

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

	"github.com/proishan11/open-agent-policy/engine/session"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const (
	// ctxVerifiedAgentID is the context key for the cryptographically verified agent ID.
	ctxVerifiedAgentID contextKey = "verified_agent_id"

	// sessionTokenPrefix identifies OAP session tokens.
	sessionTokenPrefix = "ags_"
)

// AuthConfig configures the token-validation middleware.
type AuthConfig struct {
	// IssuerURL is the OIDC issuer for direct JWT validation (backward-compat).
	// When empty and no session manager, auth middleware is disabled.
	IssuerURL string

	// Audience is the expected audience claim (optional, for JWT mode).
	Audience string

	// AgentIDClaim is the JWT claim containing the OAP agent ID (default: "agent_id").
	AgentIDClaim string
}

// authMiddleware validates Bearer tokens and extracts the verified agent identity.
//
// It supports two token types:
//  1. Session tokens (prefix "ags_"): looked up in session manager → agent_id from session
//  2. Raw JWTs (backward compat): validated against --issuer JWKS → agent_id from claim
type authMiddleware struct {
	cfg       AuthConfig
	sessions  *session.Manager // may be nil if sessions not enabled
	mu        sync.RWMutex
	jwks      *jose.JSONWebKeySet
	jwksAt    time.Time
	jwksURL   string
	discovery sync.Once
}

// newAuthMiddleware creates a middleware instance.
func newAuthMiddleware(cfg AuthConfig, sessions *session.Manager) *authMiddleware {
	if cfg.AgentIDClaim == "" {
		cfg.AgentIDClaim = "agent_id"
	}
	return &authMiddleware{cfg: cfg, sessions: sessions}
}

// enabled returns true if auth enforcement is configured.
// Auth requires --issuer (for JWT validation) which also enables sessions.
func (m *authMiddleware) enabled() bool {
	return m.cfg.IssuerURL != ""
}

// wrap protects a handler with Bearer-token validation.
func (m *authMiddleware) wrap(next http.HandlerFunc) http.HandlerFunc {
	if !m.enabled() {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing_token",
				"Authorization: Bearer <token> required")
			return
		}

		agentID, err := m.resolveIdentity(r.Context(), token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), ctxVerifiedAgentID, agentID)
		next(w, r.WithContext(ctx))
	}
}

// resolveIdentity determines agent_id from either a session token or a raw JWT.
func (m *authMiddleware) resolveIdentity(ctx context.Context, token string) (string, error) {
	// Session token: look up in session manager
	if strings.HasPrefix(token, sessionTokenPrefix) {
		if m.sessions == nil {
			return "", fmt.Errorf("session tokens not enabled")
		}
		sess, err := m.sessions.GetSession(token)
		if err != nil {
			return "", fmt.Errorf("invalid session: %w", err)
		}
		return sess.AgentID, nil
	}

	// Raw JWT: validate against --issuer JWKS (backward compat)
	if m.cfg.IssuerURL == "" {
		return "", fmt.Errorf("raw JWT auth not configured (use session tokens)")
	}
	return m.verifyJWT(ctx, token)
}

// verifyJWT validates a raw JWT against the configured issuer's JWKS.
func (m *authMiddleware) verifyJWT(ctx context.Context, rawToken string) (string, error) {
	algs := []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.PS256,
	}
	parsed, err := jwt.ParseSigned(rawToken, algs)
	if err != nil {
		return "", fmt.Errorf("parse token: %w", err)
	}

	keys, err := m.getJWKS(ctx)
	if err != nil {
		return "", fmt.Errorf("jwks: %w", err)
	}

	matchKeys := findMatchingKeys(parsed, keys)
	if len(matchKeys) == 0 {
		return "", fmt.Errorf("no matching signing key found")
	}

	var stdClaims jwt.Claims
	var customClaims map[string]interface{}
	var verifyErr error

	for _, key := range matchKeys {
		stdClaims = jwt.Claims{}
		customClaims = make(map[string]interface{})
		if err := parsed.Claims(key, &stdClaims, &customClaims); err != nil {
			verifyErr = err
			continue
		}
		verifyErr = nil
		break
	}
	if verifyErr != nil {
		return "", fmt.Errorf("signature verification failed: %w", verifyErr)
	}

	expected := jwt.Expected{
		Issuer: m.cfg.IssuerURL,
		Time:   time.Now(),
	}
	if m.cfg.Audience != "" {
		expected.AnyAudience = jwt.Audience{m.cfg.Audience}
	}
	if err := stdClaims.ValidateWithLeeway(expected, 60*time.Second); err != nil {
		return "", fmt.Errorf("claims validation: %w", err)
	}

	agentID, ok := customClaims[m.cfg.AgentIDClaim].(string)
	if !ok || agentID == "" {
		return "", fmt.Errorf("missing %q claim in token", m.cfg.AgentIDClaim)
	}

	return agentID, nil
}

// --- JWKS management (for direct JWT mode) ---

func (m *authMiddleware) getJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	m.discovery.Do(func() {
		url, err := discoverJWKSURL(m.cfg.IssuerURL)
		if err != nil {
			m.jwksURL = strings.TrimSuffix(m.cfg.IssuerURL, "/") + "/protocol/openid-connect/certs"
		} else {
			m.jwksURL = url
		}
	})

	m.mu.RLock()
	cached := m.jwks
	age := time.Since(m.jwksAt)
	m.mu.RUnlock()

	if cached != nil && age < 1*time.Hour {
		return cached, nil
	}
	return m.fetchJWKS(ctx)
}

func (m *authMiddleware) fetchJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", m.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	m.mu.Lock()
	m.jwks = &jwks
	m.jwksAt = time.Now()
	m.mu.Unlock()

	return &jwks, nil
}

// --- Helpers ---

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func discoverJWKSURL(issuerURL string) (string, error) {
	configURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(configURL)
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
		return "", fmt.Errorf("jwks_uri not found")
	}
	return config.JWKSURI, nil
}

func findMatchingKeys(parsed *jwt.JSONWebToken, jwks *jose.JSONWebKeySet) []interface{} {
	var keys []interface{}
	for _, header := range parsed.Headers {
		if header.KeyID != "" {
			for _, k := range jwks.Key(header.KeyID) {
				keys = append(keys, k.Key)
			}
		}
	}
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

// VerifiedAgentID returns the cryptographically verified agent ID from context.
func VerifiedAgentID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ctxVerifiedAgentID).(string)
	return id, ok && id != ""
}
