package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/proishan11/open-agent-policy/engine/identity"
)

// testIDPServer simulates a real OIDC Identity Provider with JWKS endpoint.
type testIDPServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	keyID      string
	issuer     string
}

func newTestIDP(t *testing.T) *testIDPServer {
	t.Helper()

	// Generate a real RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	idp := &testIDPServer{
		privateKey: key,
		keyID:      "test-key-1",
	}

	mux := http.NewServeMux()

	// JWKS endpoint — serves the real public key
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       &key.PublicKey,
					KeyID:     idp.keyID,
					Algorithm: string(jose.RS256),
					Use:       "sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	// OpenID Configuration endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   idp.issuer,
			"jwks_uri": idp.issuer + "/.well-known/jwks.json",
		})
	})

	idp.server = httptest.NewServer(mux)
	idp.issuer = idp.server.URL
	return idp
}

func (idp *testIDPServer) close() {
	idp.server.Close()
}

// signToken creates a real signed JWT with the IDP's private key.
func (idp *testIDPServer) signToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: idp.privateKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), idp.keyID).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}

	return token
}

// makeClaims creates standard OIDC claims for testing.
func (idp *testIDPServer) makeClaims(overrides map[string]interface{}) map[string]interface{} {
	claims := map[string]interface{}{
		"iss":    idp.issuer,
		"sub":    "user-123",
		"aud":    "oap-server",
		"email":  "alice@company.com",
		"name":   "Alice Smith",
		"groups": []string{"engineering", "platform"},
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
	}
	for k, v := range overrides {
		claims[k] = v
	}
	return claims
}

// ── Tests ──────────────────────────────────────────────────────────────

func TestVerifyActor_ValidToken(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	token := idp.signToken(t, idp.makeClaims(nil))
	actor, err := v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err != nil {
		t.Fatalf("verify actor: %v", err)
	}

	if actor.ID != "user-123" {
		t.Errorf("expected sub user-123, got %s", actor.ID)
	}
	if actor.Email != "alice@company.com" {
		t.Errorf("expected email alice@company.com, got %s", actor.Email)
	}
	if actor.Issuer != idp.issuer {
		t.Errorf("expected issuer %s, got %s", idp.issuer, actor.Issuer)
	}
	if len(actor.Groups) != 2 || actor.Groups[0] != "engineering" {
		t.Errorf("expected groups [engineering platform], got %v", actor.Groups)
	}
}

func TestVerifyActor_WrongIssuer(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   "https://wrong-issuer.com",
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	token := idp.signToken(t, idp.makeClaims(nil))
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestVerifyActor_WrongAudience(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "different-audience",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	token := idp.signToken(t, idp.makeClaims(nil))
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestVerifyActor_ExpiredToken(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:    idp.issuer,
		Audience:  "oap-server",
		JWKSUrl:   idp.issuer + "/.well-known/jwks.json",
		ClockSkew: 1 * time.Second, // tight clock skew
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	claims := idp.makeClaims(map[string]interface{}{
		"exp": time.Now().Add(-10 * time.Minute).Unix(),
		"iat": time.Now().Add(-20 * time.Minute).Unix(),
	})
	token := idp.signToken(t, claims)
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyActor_FutureToken(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:    idp.issuer,
		Audience:  "oap-server",
		JWKSUrl:   idp.issuer + "/.well-known/jwks.json",
		ClockSkew: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	claims := idp.makeClaims(map[string]interface{}{
		"nbf": time.Now().Add(10 * time.Minute).Unix(),
	})
	token := idp.signToken(t, claims)
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err == nil {
		t.Fatal("expected error for future token")
	}
}

func TestVerifyActor_WrongSigningKey(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	// Create a different key pair (attacker's key)
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	// Sign with attacker's key but use same kid
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: attackerKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), idp.keyID).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("create attacker signer: %v", err)
	}

	payload, _ := json.Marshal(idp.makeClaims(nil))
	jws, _ := signer.Sign(payload)
	token, _ := jws.CompactSerialize()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err == nil {
		t.Fatal("expected error for forged signature")
	}
}

func TestVerifyActor_AlgNone(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// Craft alg:none token (attack vector)
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{
		RawToken: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciJ9.",
	})
	if err == nil {
		t.Fatal("expected error for alg:none token")
	}
}

func TestVerifyActor_EmptyToken(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: ""})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestVerifyActor_RequiredClaims(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	// Require hosted domain claim (Google-style)
	v, err := NewVerifier(Config{
		Issuer:         idp.issuer,
		Audience:       "oap-server",
		JWKSUrl:        idp.issuer + "/.well-known/jwks.json",
		RequiredClaims: map[string]string{"hd": "company.com"},
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// Token WITH the required claim
	claims := idp.makeClaims(map[string]interface{}{"hd": "company.com"})
	token := idp.signToken(t, claims)
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err != nil {
		t.Fatalf("expected success with required claim: %v", err)
	}

	// Token WITHOUT the required claim
	claims2 := idp.makeClaims(nil)
	token2 := idp.signToken(t, claims2)
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token2})
	if err == nil {
		t.Fatal("expected error for missing required claim")
	}

	// Token with WRONG value
	claims3 := idp.makeClaims(map[string]interface{}{"hd": "evil.com"})
	token3 := idp.signToken(t, claims3)
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token3})
	if err == nil {
		t.Fatal("expected error for wrong required claim value")
	}
}

func TestVerifyActor_JWKSCaching(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// First call fetches JWKS
	token1 := idp.signToken(t, idp.makeClaims(nil))
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token1})
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}

	// Second call should use cached JWKS
	token2 := idp.signToken(t, idp.makeClaims(map[string]interface{}{"sub": "user-456"}))
	actor, err := v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token2})
	if err != nil {
		t.Fatalf("second verify (cached): %v", err)
	}
	if actor.ID != "user-456" {
		t.Errorf("expected sub user-456, got %s", actor.ID)
	}
}

func TestVerifyActor_KeyRotation(t *testing.T) {
	// Generate two key pairs
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	currentKeyID := "key-1"
	var currentKeys []jose.JSONWebKey

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: currentKeys}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Start with key1
	currentKeys = []jose.JSONWebKey{
		{Key: &key1.PublicKey, KeyID: "key-1", Algorithm: string(jose.RS256), Use: "sig"},
	}

	v, err := NewVerifier(Config{
		Issuer:   server.URL,
		Audience: "oap-server",
		JWKSUrl:  server.URL + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// Token signed with key1
	signer1, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key1},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "key-1").WithType("JWT"),
	)
	claims1, _ := json.Marshal(map[string]interface{}{
		"iss": server.URL, "sub": "user1", "aud": "oap-server",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	jws1, _ := signer1.Sign(claims1)
	tok1, _ := jws1.CompactSerialize()

	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: tok1})
	if err != nil {
		t.Fatalf("verify with key1: %v", err)
	}

	// Rotate: add key2, keep key1
	currentKeys = []jose.JSONWebKey{
		{Key: &key1.PublicKey, KeyID: "key-1", Algorithm: string(jose.RS256), Use: "sig"},
		{Key: &key2.PublicKey, KeyID: "key-2", Algorithm: string(jose.RS256), Use: "sig"},
	}
	_ = currentKeyID

	// Token signed with key2 (unknown kid forces JWKS refresh)
	signer2, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key2},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "key-2").WithType("JWT"),
	)
	claims2, _ := json.Marshal(map[string]interface{}{
		"iss": server.URL, "sub": "user2", "aud": "oap-server",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	jws2, _ := signer2.Sign(claims2)
	tok2, _ := jws2.CompactSerialize()

	actor, err := v.VerifyActor(context.Background(), identity.ActorToken{RawToken: tok2})
	if err != nil {
		t.Fatalf("verify with rotated key2: %v", err)
	}
	if actor.ID != "user2" {
		t.Errorf("expected sub user2, got %s", actor.ID)
	}
}

func TestVerifyActor_AudienceArray(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// Token with audience as array
	claims := idp.makeClaims(map[string]interface{}{
		"aud": []string{"oap-server", "other-app"},
	})
	token := idp.signToken(t, claims)
	_, err = v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err != nil {
		t.Fatalf("expected success with audience array: %v", err)
	}
}

func TestVerifyAgent_NotSupported(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
		JWKSUrl:  idp.issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	_, err = v.VerifyAgent(context.Background(), identity.AgentCredentials{ClientID: "test"})
	if err == nil {
		t.Fatal("expected error — OIDC doesn't support agent verification")
	}
}

func TestVerifyActor_OpenIDDiscovery(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	// Don't set JWKSUrl — let it discover from openid-configuration
	v, err := NewVerifier(Config{
		Issuer:   idp.issuer,
		Audience: "oap-server",
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	token := idp.signToken(t, idp.makeClaims(nil))
	actor, err := v.VerifyActor(context.Background(), identity.ActorToken{RawToken: token})
	if err != nil {
		t.Fatalf("verify with discovery: %v", err)
	}
	if actor.ID != "user-123" {
		t.Errorf("expected user-123, got %s", actor.ID)
	}
}

// ── Provider constructor tests ─────────────────────────────────────────

func TestForKeycloak(t *testing.T) {
	v, err := ForKeycloak("https://keycloak.corp.com/realms/main", "oap")
	if err != nil {
		t.Fatalf("ForKeycloak: %v", err)
	}
	if v.cfg.Issuer != "https://keycloak.corp.com/realms/main" {
		t.Errorf("wrong issuer: %s", v.cfg.Issuer)
	}
}

func TestForOkta(t *testing.T) {
	v, err := ForOkta("https://company.okta.com", "oap")
	if err != nil {
		t.Fatalf("ForOkta: %v", err)
	}
	if v.cfg.Issuer != "https://company.okta.com" {
		t.Errorf("wrong issuer: %s", v.cfg.Issuer)
	}
}

func TestForAzureAD(t *testing.T) {
	v, err := ForAzureAD("tenant-abc", "oap")
	if err != nil {
		t.Fatalf("ForAzureAD: %v", err)
	}
	if v.cfg.Issuer != "https://login.microsoftonline.com/tenant-abc/v2.0" {
		t.Errorf("wrong issuer: %s", v.cfg.Issuer)
	}
	if v.cfg.ClaimMappings.EmailClaim != "preferred_username" {
		t.Errorf("Azure AD should use preferred_username for email, got %s", v.cfg.ClaimMappings.EmailClaim)
	}
}

func TestForGoogle(t *testing.T) {
	v, err := ForGoogle("oap", "company.com")
	if err != nil {
		t.Fatalf("ForGoogle: %v", err)
	}
	if v.cfg.Issuer != "https://accounts.google.com" {
		t.Errorf("wrong issuer: %s", v.cfg.Issuer)
	}
	if v.cfg.RequiredClaims["hd"] != "company.com" {
		t.Error("expected hd required claim")
	}
}

func TestForCognito(t *testing.T) {
	v, err := ForCognito("us-east-1", "us-east-1_abc123", "oap")
	if err != nil {
		t.Fatalf("ForCognito: %v", err)
	}
	expected := "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123"
	if v.cfg.Issuer != expected {
		t.Errorf("wrong issuer: %s", v.cfg.Issuer)
	}
	if v.cfg.ClaimMappings.GroupsClaim != "cognito:groups" {
		t.Errorf("Cognito should use cognito:groups, got %s", v.cfg.ClaimMappings.GroupsClaim)
	}
}

func TestForAuth0(t *testing.T) {
	v, err := ForAuth0("company.auth0.com", "oap")
	if err != nil {
		t.Fatalf("ForAuth0: %v", err)
	}
	if v.cfg.Issuer != "https://company.auth0.com/" {
		t.Errorf("wrong issuer: %s", v.cfg.Issuer)
	}
}

func TestNewVerifier_MissingIssuer(t *testing.T) {
	_, err := NewVerifier(Config{})
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

// ── Ensure interface compliance ────────────────────────────────────────

var _ identity.Verifier = (*Verifier)(nil)
