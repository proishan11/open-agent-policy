package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
)

func setupGateway(t *testing.T, observe bool) (*Gateway, *httptest.Server, *audit.MemorySink) {
	t.Helper()

	// Fake upstream API
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"path":   r.URL.Path,
			"method": r.Method,
		})
	}))

	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "api-agent", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "team", Type: "workflow_agent", RiskTier: "low", Capabilities: []string{"api.invoices.read"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "api-policy", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://test/api-agent"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"api.invoices.read"}},
				{Effect: model.EffectDeny, Actions: []string{"api.invoices.delete"}},
			},
		},
	})

	sink := audit.NewMemorySink()
	gw, err := New(Config{
		AgentID:     "agent://test/api-agent",
		UpstreamURL: upstream.URL,
		ObserveMode: observe,
		Routes: map[string]string{
			"GET /api/invoices":    "api.invoices.read",
			"DELETE /api/invoices": "api.invoices.delete",
		},
		Store:     s,
		AuditSink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}

	return gw, upstream, sink
}

func TestGatewayAllowedRequest(t *testing.T) {
	gw, upstream, sink := setupGateway(t, false)
	defer upstream.Close()

	req := httptest.NewRequest("GET", "/api/invoices", nil)
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
}

func TestGatewayDeniedRequest(t *testing.T) {
	gw, upstream, sink := setupGateway(t, false)
	defer upstream.Close()

	req := httptest.NewRequest("DELETE", "/api/invoices", nil)
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "forbidden" {
		t.Errorf("expected error=forbidden, got %v", body["error"])
	}

	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
	if sink.Events[0].Decision != model.DecisionDeny {
		t.Errorf("audit decision = %q, want deny", sink.Events[0].Decision)
	}
}

func TestGatewayObserveMode(t *testing.T) {
	gw, upstream, sink := setupGateway(t, true)
	defer upstream.Close()

	req := httptest.NewRequest("DELETE", "/api/invoices", nil)
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	// Observe mode should forward even denied requests
	if w.Code != http.StatusOK {
		t.Errorf("observe mode: expected 200 (forwarded), got %d", w.Code)
	}

	// Audit should still record the deny
	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
	if sink.Events[0].Decision != model.DecisionDeny {
		t.Errorf("audit should record deny in observe mode, got %q", sink.Events[0].Decision)
	}
}

func TestGatewayHealth(t *testing.T) {
	gw, upstream, _ := setupGateway(t, false)
	defer upstream.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health: got %d, want 200", w.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "healthy" {
		t.Errorf("health status = %v, want healthy", body["status"])
	}
}

func TestResolveAction(t *testing.T) {
	gw, upstream, _ := setupGateway(t, false)
	defer upstream.Close()

	tests := []struct {
		method string
		path   string
		want   string
	}{
		{"GET", "/api/invoices", "api.invoices.read"},
		{"DELETE", "/api/invoices", "api.invoices.delete"},
		{"GET", "/users/123", "users.123.read"}, // derived
		{"POST", "/orders", "orders.create"},    // derived
		{"PUT", "/items/42", "items.42.update"}, // derived
	}

	for _, tt := range tests {
		got := gw.resolveAction(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("resolveAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestGatewayAgentIDOverride(t *testing.T) {
	gw, upstream, sink := setupGateway(t, false)
	defer upstream.Close()

	req := httptest.NewRequest("GET", "/api/invoices", nil)
	req.Header.Set("X-OAP-Agent-ID", "agent://test/unknown-agent")
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	// Unknown agent should be denied
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown agent, got %d", w.Code)
	}

	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
}

// --- Remote auth mode tests ---

func TestGatewayRemoteAuthAllow(t *testing.T) {
	// Fake OAP server that always allows
	oapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(model.AuthorizationDecision{
			Decision:  model.DecisionAllow,
			Reason:    "allowed by test policy",
			PolicyIDs: []string{"test-policy"},
			Grant: &model.GrantRef{
				GrantID:          "grant-123",
				Token:            "eyJ0ZXN0IjoiZ3JhbnQifQ",
				ExpiresInSeconds: 300,
			},
		})
	}))
	defer oapServer.Close()

	// Fake upstream API that captures the grant header
	var gotGrantHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGrantHeader = r.Header.Get("X-OAP-Grant-Token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer upstream.Close()

	gw, err := New(Config{
		AgentID:      "agent://test/api-agent",
		UpstreamURL:  upstream.URL,
		OAPServerURL: oapServer.URL,
		Routes:       map[string]string{"GET /api/invoices": "api.invoices.read"},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/invoices", nil)
	req.Header.Set("Authorization", "Bearer ags_test_session_token")
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Grant token should be injected into upstream request
	if gotGrantHeader != "eyJ0ZXN0IjoiZ3JhbnQifQ" {
		t.Errorf("expected grant token in upstream header, got %q", gotGrantHeader)
	}
}

func TestGatewayRemoteAuthDeny(t *testing.T) {
	oapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(model.AuthorizationDecision{
			Decision: model.DecisionDeny,
			Reason:   "policy denied",
		})
	}))
	defer oapServer.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for denied requests")
	}))
	defer upstream.Close()

	gw, err := New(Config{
		AgentID:      "agent://test/api-agent",
		UpstreamURL:  upstream.URL,
		OAPServerURL: oapServer.URL,
		Routes:       map[string]string{"DELETE /api/invoices": "api.invoices.delete"},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("DELETE", "/api/invoices", nil)
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestGatewayRemoteAuthOAPDown(t *testing.T) {
	// No OAP server running — should fail closed
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called when OAP is unreachable")
	}))
	defer upstream.Close()

	gw, err := New(Config{
		AgentID:      "agent://test/api-agent",
		UpstreamURL:  upstream.URL,
		OAPServerURL: "http://localhost:59999", // nothing listening
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/invoices", nil)
	w := httptest.NewRecorder()
	gw.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 (fail-closed) when OAP down, got %d", w.Code)
	}
}

// --- Grant middleware tests ---

func TestGrantMiddlewareValid(t *testing.T) {
	// Fake OAP grant validation endpoint
	oapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":         true,
			"agent_id":      "agent://test/api-agent",
			"action":        "api.invoices.read",
			"resource_type": "api.invoices",
			"resource_id":   "INV-001",
			"decision":      "allow",
			"expires_at":    9999999999,
		})
	}))
	defer oapServer.Close()

	mw := NewGrantMiddleware(GrantMiddlewareConfig{
		OAPServerURL: oapServer.URL,
	})

	var gotAgentID string
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentID = r.Header.Get("X-OAP-Verified-Agent-ID")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/invoices/INV-001", nil)
	req.Header.Set("X-OAP-Grant-Token", "valid-grant-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if gotAgentID != "agent://test/api-agent" {
		t.Errorf("expected verified agent_id, got %q", gotAgentID)
	}
}

func TestGrantMiddlewareMissing(t *testing.T) {
	mw := NewGrantMiddleware(GrantMiddlewareConfig{
		OAPServerURL: "http://localhost:8080",
	})

	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without grant")
	}))

	req := httptest.NewRequest("GET", "/api/invoices/INV-001", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing grant, got %d", w.Code)
	}
}

func TestGrantMiddlewareAllowMissing(t *testing.T) {
	mw := NewGrantMiddleware(GrantMiddlewareConfig{
		OAPServerURL: "http://localhost:8080",
		AllowMissing: true,
	})

	called := false
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/invoices/INV-001", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should be called when AllowMissing=true")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with AllowMissing, got %d", w.Code)
	}
}

func TestGrantMiddlewareInvalid(t *testing.T) {
	oapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"code":    "invalid_grant",
			"message": "signature verification failed",
		})
	}))
	defer oapServer.Close()

	mw := NewGrantMiddleware(GrantMiddlewareConfig{
		OAPServerURL: oapServer.URL,
	})

	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with invalid grant")
	}))

	req := httptest.NewRequest("GET", "/api/invoices/INV-001", nil)
	req.Header.Set("X-OAP-Grant-Token", "invalid-forged-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid grant, got %d", w.Code)
	}
}
