package grant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
)

// Claims are the JWT claims embedded in a grant token.
type Claims struct {
	// Standard JWT claims
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`           // agent_id
	Audience  string `json:"aud,omitempty"` // target resource API
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`

	// OAP-specific claims
	Action       string             `json:"oap_action"`
	ResourceType string             `json:"oap_resource_type,omitempty"`
	ResourceID   string             `json:"oap_resource_id,omitempty"`
	Decision     string             `json:"oap_decision"`
	PolicyIDs    []string           `json:"oap_policy_ids,omitempty"`
	Constraints  *model.Constraints `json:"oap_constraints,omitempty"`
	RequestID    string             `json:"oap_request_id,omitempty"`
	RunID        string             `json:"oap_run_id,omitempty"`
}

// Issuer creates signed JWT grant tokens.
type Issuer struct {
	// signingKey is the HMAC-SHA256 key for signing tokens.
	signingKey []byte

	// issuerName is the "iss" claim (e.g., "oap-server").
	issuerName string

	// defaultTTL is the default grant lifetime.
	defaultTTL time.Duration
}

// IssuerConfig holds configuration for the grant issuer.
type IssuerConfig struct {
	// SigningKey is the HMAC-SHA256 secret. In production, use a KMS-backed key.
	SigningKey string

	// IssuerName is the "iss" claim.
	IssuerName string

	// DefaultTTL is the default grant lifetime (default: 15 minutes).
	DefaultTTL time.Duration
}

// NewIssuer creates a grant issuer.
func NewIssuer(cfg IssuerConfig) *Issuer {
	ttl := cfg.DefaultTTL
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	issuer := cfg.IssuerName
	if issuer == "" {
		issuer = "oap-server"
	}
	return &Issuer{
		signingKey: []byte(cfg.SigningKey),
		issuerName: issuer,
		defaultTTL: ttl,
	}
}

// GrantRequest contains the full context needed to issue a scoped grant.
type GrantRequest struct {
	AgentID      string
	Action       string
	ResourceType string
	ResourceID   string
	Audience     string // target API that will validate the grant
	RunID        string
	Decision     model.AuthorizationDecision
}

// Issue creates a signed JWT grant from an authorization decision.
func (iss *Issuer) Issue(agentID string, decision model.AuthorizationDecision) (string, error) {
	return iss.IssueScoped(GrantRequest{
		AgentID:  agentID,
		Decision: decision,
	})
}

// IssueScoped creates a signed JWT grant with full resource scoping.
func (iss *Issuer) IssueScoped(req GrantRequest) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Issuer:       iss.issuerName,
		Subject:      req.AgentID,
		Audience:     req.Audience,
		ExpiresAt:    now.Add(iss.defaultTTL).Unix(),
		IssuedAt:     now.Unix(),
		JWTID:        req.Decision.DecisionID,
		Action:       req.Action,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		Decision:     req.Decision.Decision,
		PolicyIDs:    req.Decision.PolicyIDs,
		Constraints:  req.Decision.Constraints,
		RequestID:    req.Decision.RequestID,
		RunID:        req.RunID,
	}

	return iss.sign(claims)
}

// Verify validates a grant token and returns the claims.
func (iss *Issuer) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	expectedSig := iss.computeHMAC([]byte(signingInput))
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid claims encoding")
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// sign creates a signed JWT token (HS256).
func (iss *Issuer) sign(claims Claims) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := iss.computeHMAC([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + sigB64, nil
}

// computeHMAC computes HMAC-SHA256.
func (iss *Issuer) computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, iss.signingKey)
	mac.Write(data)
	return mac.Sum(nil)
}
