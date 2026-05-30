package session

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/proishan11/open-agent-policy/engine/model"
)

func TestSupportedBindingType(t *testing.T) {
	for _, bindingType := range []string{"oidc_client", "kubernetes_service_account", "spiffe", "wimse"} {
		if !supportedBindingType(bindingType) {
			t.Fatalf("supportedBindingType(%q) = false, want true", bindingType)
		}
	}

	for _, bindingType := range []string{"", "mtls", "spiffe_x509", "deployment_attestation"} {
		if supportedBindingType(bindingType) {
			t.Fatalf("supportedBindingType(%q) = true, want false", bindingType)
		}
	}
}

func TestSubjectMatchesClientIDPrefixOnlyAgainstClientClaims(t *testing.T) {
	if !subjectMatches("client_id:support-agent", "other-sub", "support-agent", "") {
		t.Fatal("expected client_id prefix to match azp")
	}
	if !subjectMatches("client_id:support-agent", "other-sub", "", "support-agent") {
		t.Fatal("expected client_id prefix to match client_id")
	}
	if subjectMatches("client_id:support-agent", "support-agent", "", "") {
		t.Fatal("client_id prefix must not match sub")
	}
	if subjectMatches("client_id:support-agent", "client_id:support-agent", "", "") {
		t.Fatal("client_id prefix must not match literal sub")
	}
}

func TestSubjectMatchesSPIFFEID(t *testing.T) {
	spiffeID := "spiffe://example.org/ns/finance/sa/invoice-reader"
	if !subjectMatches(spiffeID, spiffeID, "", "") {
		t.Fatal("expected SPIFFE ID subject to match JWT sub")
	}
	if subjectMatches(spiffeID, "spiffe://example.org/ns/finance/sa/other", "", "") {
		t.Fatal("expected different SPIFFE ID subject not to match")
	}
}

func TestSubjectMatchesWIMSEID(t *testing.T) {
	wimseID := "wimse://trust.example.com/service/payment"
	if !subjectMatches(wimseID, wimseID, "", "") {
		t.Fatal("expected WIMSE workload ID subject to match JWT sub")
	}
}

func TestBindingCacheKeyIncludesExplicitJWKSURI(t *testing.T) {
	base := model.IdentityBinding{Type: "spiffe", Issuer: "https://issuer.example"}
	first := base
	first.JWKSURI = "https://issuer.example/a/jwks.json"
	second := base
	second.JWKSURI = "https://issuer.example/b/jwks.json"
	if bindingCacheKey(first) == bindingCacheKey(second) {
		t.Fatal("expected explicit JWKS URI to separate cache entries")
	}
}

func TestJWKSURLsForBindingPrefersExplicitJWKSURI(t *testing.T) {
	binding := model.IdentityBinding{
		Type:    "spiffe",
		Issuer:  "https://unreachable.example",
		JWKSURI: "https://bundle.example/spiffe/jwks.json",
	}
	urls, err := jwksURLsForBinding(context.Background(), http.DefaultClient, binding)
	if err != nil {
		t.Fatalf("jwksURLsForBinding: %v", err)
	}
	if len(urls) != 1 || urls[0] != binding.JWKSURI {
		t.Fatalf("got urls %#v, want explicit JWKS URI only", urls)
	}
}

func TestNormalizeSPIFFEJWKSRequiresJWTSVIDKeys(t *testing.T) {
	binding := model.IdentityBinding{Type: "spiffe"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: "x509", Use: "x509-svid", Key: []byte("x509")},
		{KeyID: "jwt", Use: "jwt-svid", Key: []byte("jwt")},
	}}

	got, err := normalizeJWKSForBinding(binding, &jwks)
	if err != nil {
		t.Fatalf("normalizeJWKSForBinding: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != "jwt" {
		t.Fatalf("got keys %#v, want only jwt-svid key", got.Keys)
	}

	_, err = normalizeJWKSForBinding(binding, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: "x509", Use: "x509-svid", Key: []byte("x509")},
	}})
	if err == nil {
		t.Fatal("expected SPIFFE bundle without jwt-svid keys to fail closed")
	}
}
