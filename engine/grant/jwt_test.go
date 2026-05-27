package grant

import (
	"testing"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
)

func TestIssueAndVerify(t *testing.T) {
	issuer := NewIssuer(IssuerConfig{
		SigningKey:  "test-secret-key-at-least-32-bytes!",
		IssuerName: "test-server",
		DefaultTTL: 15 * time.Minute,
	})

	readOnly := true
	maxRec := 25
	decision := model.AuthorizationDecision{
		DecisionID: "dec-test-1",
		Decision:   model.DecisionAllowConstrained,
		PolicyIDs:  []string{"finance/readonly"},
		Constraints: &model.Constraints{
			ReadOnly:   &readOnly,
			MaxRecords: &maxRec,
		},
		RequestID: "req-test-1",
	}

	token, err := issuer.Issue("agent://finance/reconciler", decision)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Verify
	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if claims.Subject != "agent://finance/reconciler" {
		t.Errorf("subject = %q, want %q", claims.Subject, "agent://finance/reconciler")
	}
	if claims.Issuer != "test-server" {
		t.Errorf("issuer = %q, want %q", claims.Issuer, "test-server")
	}
	if claims.Decision != model.DecisionAllowConstrained {
		t.Errorf("decision = %q, want %q", claims.Decision, model.DecisionAllowConstrained)
	}
	if claims.Constraints == nil {
		t.Fatal("expected constraints, got nil")
	}
	if claims.Constraints.ReadOnly == nil || !*claims.Constraints.ReadOnly {
		t.Error("expected readonly=true")
	}
	if claims.Constraints.MaxRecords == nil || *claims.Constraints.MaxRecords != 25 {
		t.Errorf("maxRecords = %v, want 25", claims.Constraints.MaxRecords)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	issuer := NewIssuer(IssuerConfig{
		SigningKey:  "test-secret-key-at-least-32-bytes!",
		DefaultTTL: -1 * time.Hour, // already expired
	})

	decision := model.AuthorizationDecision{
		DecisionID: "dec-expired",
		Decision:   model.DecisionAllow,
	}

	token, err := issuer.Issue("agent://test/agent", decision)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = issuer.Verify(token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestVerifyTamperedToken(t *testing.T) {
	issuer := NewIssuer(IssuerConfig{
		SigningKey: "test-secret-key-at-least-32-bytes!",
	})

	decision := model.AuthorizationDecision{
		DecisionID: "dec-tamper",
		Decision:   model.DecisionAllow,
	}

	token, err := issuer.Issue("agent://test/agent", decision)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Tamper with the token
	tampered := token + "x"
	_, err = issuer.Verify(tampered)
	if err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	issuer1 := NewIssuer(IssuerConfig{SigningKey: "key-one-for-server-one-long-enough"})
	issuer2 := NewIssuer(IssuerConfig{SigningKey: "key-two-for-server-two-long-enough"})

	decision := model.AuthorizationDecision{
		DecisionID: "dec-wrongkey",
		Decision:   model.DecisionAllow,
	}

	token, _ := issuer1.Issue("agent://test/agent", decision)

	_, err := issuer2.Verify(token)
	if err == nil {
		t.Error("expected error when verifying with wrong key")
	}
}

func TestVerifyInvalidFormat(t *testing.T) {
	issuer := NewIssuer(IssuerConfig{SigningKey: "test-key"})

	_, err := issuer.Verify("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}
