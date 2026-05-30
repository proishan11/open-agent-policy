package identity

import (
	"context"
	"testing"
	"time"
)

func TestDevVerifierAgent(t *testing.T) {
	v := NewDevVerifier()
	ctx := context.Background()

	id, err := v.VerifyAgent(ctx, AgentCredentials{ClientID: "agent://test/agent"})
	if err != nil {
		t.Fatalf("VerifyAgent: %v", err)
	}
	if id != "agent://test/agent" {
		t.Errorf("got %q, want %q", id, "agent://test/agent")
	}
}

func TestDevVerifierAgentEmptyID(t *testing.T) {
	v := NewDevVerifier()
	_, err := v.VerifyAgent(context.Background(), AgentCredentials{})
	if err == nil {
		t.Error("expected error for empty client_id")
	}
}

func TestDevVerifierActor(t *testing.T) {
	v := NewDevVerifier()
	ctx := context.Background()

	token := makeTestJWT(map[string]interface{}{
		"sub":   "user:alice@example.com",
		"email": "alice@example.com",
		"iss":   "https://idp.example.com",
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	identity, err := v.VerifyActor(ctx, ActorToken{RawToken: token})
	if err != nil {
		t.Fatalf("VerifyActor: %v", err)
	}
	if identity.ID != "user:alice@example.com" {
		t.Errorf("id = %q, want %q", identity.ID, "user:alice@example.com")
	}
	if identity.Email != "alice@example.com" {
		t.Errorf("email = %q, want %q", identity.Email, "alice@example.com")
	}
}

func TestDevVerifierActorRawString(t *testing.T) {
	v := NewDevVerifier()
	identity, err := v.VerifyActor(context.Background(), ActorToken{RawToken: "user:bob"})
	if err != nil {
		t.Fatalf("VerifyActor: %v", err)
	}
	if identity.ID != "user:bob" {
		t.Errorf("id = %q, want %q", identity.ID, "user:bob")
	}
}

func TestOIDCVerifierValidToken(t *testing.T) {
	v := NewOIDCVerifier(OIDCConfig{
		Issuer:   "https://idp.example.com",
		Audience: "oap-platform",
	})

	token := makeTestJWT(map[string]interface{}{
		"sub":    "user:alice",
		"email":  "alice@example.com",
		"iss":    "https://idp.example.com",
		"aud":    "oap-platform",
		"exp":    float64(time.Now().Add(1 * time.Hour).Unix()),
		"groups": []interface{}{"engineering", "platform"},
	})

	identity, err := v.VerifyActor(context.Background(), ActorToken{RawToken: token})
	if err != nil {
		t.Fatalf("VerifyActor: %v", err)
	}
	if identity.ID != "user:alice" {
		t.Errorf("id = %q, want %q", identity.ID, "user:alice")
	}
	if len(identity.Groups) != 2 {
		t.Errorf("groups = %v, want 2", identity.Groups)
	}
	if identity.Issuer != "https://idp.example.com" {
		t.Errorf("issuer = %q", identity.Issuer)
	}
}

func TestOIDCVerifierWrongIssuer(t *testing.T) {
	v := NewOIDCVerifier(OIDCConfig{Issuer: "https://correct.example.com"})
	token := makeTestJWT(map[string]interface{}{
		"sub": "user:alice",
		"iss": "https://wrong.example.com",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	_, err := v.VerifyActor(context.Background(), ActorToken{RawToken: token})
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestOIDCVerifierWrongAudience(t *testing.T) {
	v := NewOIDCVerifier(OIDCConfig{Audience: "correct-aud"})
	token := makeTestJWT(map[string]interface{}{
		"sub": "user:alice",
		"aud": "wrong-aud",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	_, err := v.VerifyActor(context.Background(), ActorToken{RawToken: token})
	if err == nil {
		t.Error("expected error for wrong audience")
	}
}

func TestOIDCVerifierExpiredToken(t *testing.T) {
	v := NewOIDCVerifier(OIDCConfig{})
	token := makeTestJWT(map[string]interface{}{
		"sub": "user:alice",
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
	})

	_, err := v.VerifyActor(context.Background(), ActorToken{RawToken: token})
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestOIDCVerifierAgentNotSupported(t *testing.T) {
	v := NewOIDCVerifier(OIDCConfig{})
	_, err := v.VerifyAgent(context.Background(), AgentCredentials{ClientID: "test"})
	if err == nil {
		t.Error("expected error: OIDC does not support agent verification")
	}
}

func TestKubernetesVerifierValidSA(t *testing.T) {
	v := NewKubernetesVerifier(KubernetesConfig{})
	token := makeTestJWT(map[string]interface{}{
		"sub": "system:serviceaccount:finance:invoice-reconciler",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	id, err := v.VerifyAgent(context.Background(), AgentCredentials{ServiceAccountToken: token})
	if err != nil {
		t.Fatalf("VerifyAgent: %v", err)
	}
	if id != "agent://finance/invoice-reconciler" {
		t.Errorf("id = %q, want %q", id, "agent://finance/invoice-reconciler")
	}
}

func TestKubernetesVerifierNamespaceRestriction(t *testing.T) {
	v := NewKubernetesVerifier(KubernetesConfig{Namespace: "production"})
	token := makeTestJWT(map[string]interface{}{
		"sub": "system:serviceaccount:staging:my-agent",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	_, err := v.VerifyAgent(context.Background(), AgentCredentials{ServiceAccountToken: token})
	if err == nil {
		t.Error("expected error for wrong namespace")
	}
}

func TestKubernetesVerifierInvalidSubject(t *testing.T) {
	v := NewKubernetesVerifier(KubernetesConfig{})
	token := makeTestJWT(map[string]interface{}{
		"sub": "not-a-k8s-sa",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	_, err := v.VerifyAgent(context.Background(), AgentCredentials{ServiceAccountToken: token})
	if err == nil {
		t.Error("expected error for non-k8s subject")
	}
}

func TestKubernetesVerifierActorNotSupported(t *testing.T) {
	v := NewKubernetesVerifier(KubernetesConfig{})
	_, err := v.VerifyActor(context.Background(), ActorToken{RawToken: "test"})
	if err == nil {
		t.Error("expected error: K8s does not support actor verification")
	}
}

func TestCompositeVerifier(t *testing.T) {
	dev := NewDevVerifier()
	k8s := NewKubernetesVerifier(KubernetesConfig{})
	oidc := NewOIDCVerifier(OIDCConfig{Issuer: "https://idp.example.com"})

	composite := NewCompositeVerifier(
		[]Verifier{k8s, dev},  // agent: try k8s first, fall back to dev
		[]Verifier{oidc, dev}, // actor: try oidc first, fall back to dev
	)

	// Agent via dev (k8s will fail since no SA token)
	id, err := composite.VerifyAgent(context.Background(), AgentCredentials{ClientID: "agent://test/a"})
	if err != nil {
		t.Fatalf("composite agent verify: %v", err)
	}
	if id != "agent://test/a" {
		t.Errorf("id = %q", id)
	}

	// Actor via OIDC
	token := makeTestJWT(map[string]interface{}{
		"sub": "user:alice",
		"iss": "https://idp.example.com",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})
	actor, err := composite.VerifyActor(context.Background(), ActorToken{RawToken: token})
	if err != nil {
		t.Fatalf("composite actor verify: %v", err)
	}
	if actor.ID != "user:alice" {
		t.Errorf("actor id = %q", actor.ID)
	}
}

func TestAudienceContainsString(t *testing.T) {
	claims := map[string]interface{}{"aud": "oap-platform"}
	if !audienceContains(claims, "oap-platform") {
		t.Error("expected true for matching string audience")
	}
	if audienceContains(claims, "other") {
		t.Error("expected false for non-matching audience")
	}
}

func TestAudienceContainsArray(t *testing.T) {
	claims := map[string]interface{}{"aud": []interface{}{"app-1", "oap-platform"}}
	if !audienceContains(claims, "oap-platform") {
		t.Error("expected true for matching array audience")
	}
	if audienceContains(claims, "missing") {
		t.Error("expected false for non-matching array audience")
	}
}
