package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/model"
)

// setupTestServer creates a test server with a memory audit sink.
func setupTestServer(t *testing.T) (*Server, *audit.MemorySink) {
	t.Helper()
	srv, err := NewServer(Config{DevMode: true})
	if err != nil {
		t.Fatal(err)
	}
	memSink := audit.NewMemorySink()
	srv.SetAuditSink(memSink)
	return srv, memSink
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health: got status %d, want 200", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "healthy" {
		t.Errorf("health: got status %v, want healthy", result["status"])
	}
}

func TestAuthorizeFlow(t *testing.T) {
	srv, memSink := setupTestServer(t)

	// Register an agent
	agent := model.Agent{
		APIVersion: "oap.dev/v1alpha1",
		Kind:       "Agent",
		Metadata:   model.Metadata{Name: "test-agent", Namespace: "test"},
		Spec: model.AgentSpec{
			Owner:        "test-team",
			Type:         "workflow_agent",
			RiskTier:     "low",
			Capabilities: []string{"db.read"},
		},
	}
	agentJSON, _ := json.Marshal(agent)
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(agentJSON))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register agent: got %d, want 201. Body: %s", w.Code, w.Body.String())
	}

	// Apply a policy
	policy := model.AgentPolicy{
		APIVersion: "oap.dev/v1alpha1",
		Kind:       "AgentPolicy",
		Metadata:   model.Metadata{Name: "allow-read", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://test/test-agent"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"db.read"}},
			},
		},
	}
	policyJSON, _ := json.Marshal(policy)
	req = httptest.NewRequest("POST", "/v1/policies", bytes.NewReader(policyJSON))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("apply policy: got %d, want 201. Body: %s", w.Code, w.Body.String())
	}

	// Authorize — should allow
	authReq := model.AuthorizationRequest{
		RequestID: "test-req-1",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://test/test-agent"},
		Action:    model.Action{Name: "db.read"},
	}
	authJSON, _ := json.Marshal(authReq)
	req = httptest.NewRequest("POST", "/v1/authorize", bytes.NewReader(authJSON))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	var decision model.AuthorizationDecision
	json.NewDecoder(w.Body).Decode(&decision)
	if decision.Decision != model.DecisionAllow {
		t.Errorf("authorize: got %q, want %q", decision.Decision, model.DecisionAllow)
	}

	// Verify audit event was emitted
	if memSink.Len() != 1 {
		t.Errorf("audit: got %d events, want 1", memSink.Len())
	}

	// Authorize unregistered agent — should deny
	authReq.Subject.AgentID = "agent://test/ghost"
	authJSON, _ = json.Marshal(authReq)
	req = httptest.NewRequest("POST", "/v1/authorize", bytes.NewReader(authJSON))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&decision)
	if decision.Decision != model.DecisionDeny {
		t.Errorf("authorize unregistered: got %q, want deny", decision.Decision)
	}
}

func TestSimulateEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)

	// Register agent and policy
	ctx := context.Background()
	srv.Store().RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "sim-agent", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "test", Type: "workflow_agent", RiskTier: "low", Capabilities: []string{"api.call"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	srv.Store().AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "allow-api", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://test/sim-agent"},
			Rules:   []model.PolicyRule{{Effect: model.EffectAllow, Actions: []string{"api.call"}}},
		},
	})

	authReq := model.AuthorizationRequest{
		RequestID: "sim-1",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://test/sim-agent"},
		Action:    model.Action{Name: "api.call"},
	}
	body, _ := json.Marshal(authReq)
	req := httptest.NewRequest("POST", "/v1/simulate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("simulate: got %d, want 200", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)

	// Should have both decision and trace
	if result["decision"] == nil {
		t.Error("simulate: missing decision")
	}
	if result["trace"] == nil {
		t.Error("simulate: missing trace")
	}
}
