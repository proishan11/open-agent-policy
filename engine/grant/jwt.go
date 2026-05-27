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
	Subject   string `json:"sub"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`

	// OAP-specific claims
	Action      string             `json:"oap_action"`
	Decision    string             `json:"oap_decision"`
	PolicyIDs   []string           `json:"oap_policy_ids,omitempty"`
	Constraints *model.Constraints `json:"oap_constraints,omitempty"`
	RequestID   string             `json:"oap_request_id,omitempty"`
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

// Issue creates a signed JWT grant from a decision.
func (iss *Issuer) Issue(agentID string, decision model.AuthorizationDecision) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Issuer:      iss.issuerName,
		Subject:     agentID,
		ExpiresAt:   now.Add(iss.defaultTTL).Unix(),
		IssuedAt:    now.Unix(),
		JWTID:       decision.DecisionID,
		Action:      decision.Reason, // We'd normally include the action separately
		Decision:    decision.Decision,
		PolicyIDs:   decision.PolicyIDs,
		Constraints: decision.Constraints,
		RequestID:   decision.RequestID,
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
