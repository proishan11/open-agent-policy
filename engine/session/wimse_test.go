package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
)

const testWIMSESubject = "wimse://example.com/workload/payment"

type testWIMSETokens struct {
	binding     model.IdentityBinding
	workloadKey *ecdsa.PrivateKey
	wit         string
	wpt         string
	accessToken string
}

func TestValidateWIMSEProofToken(t *testing.T) {
	tokens := newTestWIMSETokens(t, testWIMSESubject, "oap-server", "")
	validator := NewTokenValidator()

	err := validator.ValidateAgainstBindings(context.Background(), tokens.wit, []model.IdentityBinding{tokens.binding}, ValidationContext{
		WorkloadProofToken: tokens.wpt,
		ProofContext:       &ProofContext{TargetURI: "http://oap.local/v1/runtime/session"},
	})
	if err != nil {
		t.Fatalf("ValidateAgainstBindings: %v", err)
	}

	err = validator.ValidateAgainstBindings(context.Background(), tokens.wit, []model.IdentityBinding{tokens.binding}, ValidationContext{
		WorkloadProofToken: tokens.wpt,
		ProofContext:       &ProofContext{TargetURI: "http://oap.local/v1/runtime/session"},
	})
	if err == nil {
		t.Fatal("expected replayed WPT jti to be rejected")
	}
}

func TestValidateWIMSEProofTokenRequired(t *testing.T) {
	tokens := newTestWIMSETokens(t, testWIMSESubject, "oap-server", "")
	validator := NewTokenValidator()

	err := validator.ValidateAgainstBindings(context.Background(), tokens.wit, []model.IdentityBinding{tokens.binding}, ValidationContext{})
	if err == nil {
		t.Fatal("expected missing WPT to fail")
	}
}

func TestValidateWIMSEProofTokenRejectsWTHMismatch(t *testing.T) {
	tokens := newTestWIMSETokens(t, testWIMSESubject, "oap-server", "")
	badWPT := newTestWPT(t, tokens.workloadKey, "oap-server", tokens.wit, "", "wrong-wth")
	validator := NewTokenValidator()

	err := validator.ValidateAgainstBindings(context.Background(), tokens.wit, []model.IdentityBinding{tokens.binding}, ValidationContext{
		WorkloadProofToken: badWPT,
		ProofContext:       &ProofContext{TargetURI: "http://oap.local/v1/runtime/session"},
	})
	if err == nil {
		t.Fatal("expected WPT wth mismatch to fail")
	}
}

func TestValidateWIMSEProofTokenChecksAccessTokenHash(t *testing.T) {
	tokens := newTestWIMSETokens(t, testWIMSESubject, "oap-server", "access-token-1")
	validator := NewTokenValidator()

	err := validator.ValidateAgainstBindings(context.Background(), tokens.wit, []model.IdentityBinding{tokens.binding}, ValidationContext{
		WorkloadProofToken: tokens.wpt,
		ProofContext:       &ProofContext{TargetURI: "http://oap.local/v1/runtime/session", AccessToken: "different-access-token"},
	})
	if err == nil {
		t.Fatal("expected ath mismatch to fail")
	}

	err = validator.ValidateAgainstBindings(context.Background(), tokens.wit, []model.IdentityBinding{tokens.binding}, ValidationContext{
		WorkloadProofToken: tokens.wpt,
		ProofContext:       &ProofContext{TargetURI: "http://oap.local/v1/runtime/session", AccessToken: tokens.accessToken},
	})
	if err != nil {
		t.Fatalf("ValidateAgainstBindings with matching ath: %v", err)
	}
}

func TestCreateSessionWithWIMSEProofToken(t *testing.T) {
	tokens := newTestWIMSETokens(t, testWIMSESubject, "oap-server", "")
	store := memory.New()
	agent := &model.Agent{
		APIVersion: "oap.dev/v1alpha1",
		Kind:       "Agent",
		Metadata:   model.Metadata{Name: "payment-agent", Namespace: "payments"},
		Spec: model.AgentSpec{
			Owner:            "payments",
			Type:             "workflow_agent",
			RiskTier:         "medium",
			Capabilities:     []string{"payments.read"},
			IdentityBindings: []model.IdentityBinding{tokens.binding},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	}
	if err := store.RegisterAgent(context.Background(), agent); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	manager := NewManager(store, ManagerConfig{})
	session, err := manager.CreateSession(context.Background(), CreateSessionRequest{
		AgentID:            agent.ID(),
		RuntimeToken:       tokens.wit,
		WorkloadProofToken: tokens.wpt,
		ProofContext:       &ProofContext{TargetURI: "http://oap.local/v1/runtime/session"},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if session.AgentID != agent.ID() {
		t.Fatalf("session agent = %q, want %q", session.AgentID, agent.ID())
	}
}

func newTestWIMSETokens(t *testing.T, subject, audience, accessToken string) testWIMSETokens {
	t.Helper()

	issuerKey := newECDSAKey(t)
	workloadKey := newECDSAKey(t)
	issuerJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &issuerKey.PublicKey,
		KeyID:     "issuer-key",
		Algorithm: string(jose.ES256),
	}}}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(issuerJWKS); err != nil {
			t.Errorf("encode jwks: %v", err)
		}
	}))
	t.Cleanup(idp.Close)

	now := time.Now().UTC()
	workloadJWK := jose.JSONWebKey{
		Key:       &workloadKey.PublicKey,
		Algorithm: string(jose.ES256),
	}
	witClaims := struct {
		jwt.Claims
		CNF struct {
			JWK jose.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}{
		Claims: jwt.Claims{
			Issuer:   idp.URL,
			Subject:  subject,
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
			ID:       "wit-" + tokenHash(subject+audience+time.Now().String()),
		},
	}
	witClaims.CNF.JWK = workloadJWK
	wit := signTestJWT(t, issuerKey, "issuer-key", "wit+jwt", jose.ES256, witClaims)

	wpt := newTestWPT(t, workloadKey, audience, wit, accessToken, tokenHash(wit))

	return testWIMSETokens{
		binding: model.IdentityBinding{
			Type:     "wimse",
			Provider: "test",
			Issuer:   idp.URL,
			JWKSURI:  idp.URL + "/jwks",
			Subject:  subject,
			Audience: audience,
		},
		workloadKey: workloadKey,
		wit:         wit,
		wpt:         wpt,
		accessToken: accessToken,
	}
}

func newTestWPT(t *testing.T, workloadKey *ecdsa.PrivateKey, audience, wit, accessToken, wth string) string {
	t.Helper()
	now := time.Now().UTC()
	claims := struct {
		jwt.Claims
		WTH string `json:"wth"`
		ATH string `json:"ath,omitempty"`
	}{
		Claims: jwt.Claims{
			Audience: jwt.Audience{audience},
			Expiry:   jwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt: jwt.NewNumericDate(now.Add(-time.Second)),
			ID:       "wpt-" + tokenHash(wit+accessToken+wth+now.String()),
		},
		WTH: wth,
	}
	if accessToken != "" {
		claims.ATH = tokenHash(accessToken)
	}
	return signTestJWT(t, workloadKey, "workload-key", "wpt+jwt", jose.ES256, claims)
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func signTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid string, typ string, alg jose.SignatureAlgorithm, claims interface{}) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(typ)).
		WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("serialize jwt: %v", err)
	}
	return raw
}
