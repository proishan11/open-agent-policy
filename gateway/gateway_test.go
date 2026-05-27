package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/registry"
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

	store := registry.NewStore()
	store.RegisterAgent(&model.Agent{
		Metadata: model.Metadata{Name: "api-agent", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "team", Type: "workflow_agent", RiskTier: "low", Capabilities: []string{"api.invoices.read"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	store.AddPolicy(&model.AgentPolicy{
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
		Store:     store,
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
		{"GET", "/users/123", "users.123.read"},         // derived
		{"POST", "/orders", "orders.create"},             // derived
		{"PUT", "/items/42", "items.42.update"},          // derived
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
