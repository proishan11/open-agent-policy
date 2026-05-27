package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/model"
)

func makeTestInput() Input {
	return Input{
		Request: model.AuthorizationRequest{
			Subject: model.Subject{AgentID: "agent://test/agent"},
			Action:  model.Action{Name: "tickets.read"},
		},
		Agent: &model.Agent{
			Metadata: model.Metadata{
				Name:      "agent",
				Namespace: "test",
			},
			Spec: model.AgentSpec{
				RiskTier:     "medium",
				Type:         "chat_agent",
				Capabilities: []string{"tickets.read"},
			},
		},
		Policies: []*model.AgentPolicy{},
	}
}

// ── OPA Backend Tests ─────────────────────────────────────────────────

func TestOPABackend_Allow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify input was sent
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		input, ok := body["input"].(map[string]interface{})
		if !ok {
			t.Fatal("missing input field")
		}
		req, ok := input["request"].(map[string]interface{})
		if !ok {
			t.Fatal("missing request field")
		}
		action := req["action"].(map[string]interface{})
		if action["name"] != "tickets.read" {
			t.Errorf("expected action tickets.read, got %v", action["name"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"decision":   "allow",
				"reason":     "allowed by rego policy",
				"policy_ids": []string{"opa/tickets-policy"},
			},
		})
	}))
	defer server.Close()

	b := NewOPABackend(OPAConfig{URL: server.URL, PolicyPath: "v1/data/oap/authz"})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "allow" {
		t.Errorf("expected allow, got %s", result.Decision)
	}
	if result.Reason != "allowed by rego policy" {
		t.Errorf("expected reason, got %s", result.Reason)
	}
	if len(result.PolicyIDs) != 1 || result.PolicyIDs[0] != "opa/tickets-policy" {
		t.Errorf("unexpected policy IDs: %v", result.PolicyIDs)
	}
}

func TestOPABackend_Deny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"decision": "deny",
				"reason":   "denied by rego policy",
			},
		})
	}))
	defer server.Close()

	b := NewOPABackend(OPAConfig{URL: server.URL})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny, got %s", result.Decision)
	}
}

func TestOPABackend_WithConstraints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"decision": "allow_with_constraints",
				"reason":   "allowed with limits",
				"constraints": map[string]interface{}{
					"max_records": 10,
					"readonly":    true,
				},
			},
		})
	}))
	defer server.Close()

	b := NewOPABackend(OPAConfig{URL: server.URL})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "allow_with_constraints" {
		t.Errorf("expected allow_with_constraints, got %s", result.Decision)
	}
	if result.Constraints == nil {
		t.Fatal("expected constraints")
	}
	if result.Constraints["readonly"] != true {
		t.Errorf("expected readonly=true, got %v", result.Constraints["readonly"])
	}
}

func TestOPABackend_Unreachable_FailClosed(t *testing.T) {
	b := NewOPABackend(OPAConfig{URL: "http://127.0.0.1:1", FailOpen: false})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("fail-closed should not return error: %v", err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny (fail-closed), got %s", result.Decision)
	}
}

func TestOPABackend_Unreachable_FailOpen(t *testing.T) {
	b := NewOPABackend(OPAConfig{URL: "http://127.0.0.1:1", FailOpen: true})
	_, err := b.Evaluate(context.Background(), makeTestInput())
	if err == nil {
		t.Fatal("fail-open should return error so evaluator can fallback")
	}
}

func TestOPABackend_EmptyDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{},
		})
	}))
	defer server.Close()

	b := NewOPABackend(OPAConfig{URL: server.URL})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "deny" {
		t.Errorf("empty decision should default to deny, got %s", result.Decision)
	}
}

func TestOPABackend_Name(t *testing.T) {
	b := NewOPABackend(OPAConfig{})
	if b.Name() != "opa" {
		t.Errorf("expected name 'opa', got %s", b.Name())
	}
}

// ── Cedar Backend Tests ───────────────────────────────────────────────

func TestCedarBackend_Allow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Cedar-style request
		var body cedarRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.Principal.Type != "OAP::Agent" {
			t.Errorf("expected principal type OAP::Agent, got %s", body.Principal.Type)
		}
		if body.Principal.ID != "agent://test/agent" {
			t.Errorf("expected principal ID, got %s", body.Principal.ID)
		}
		if body.Action.Type != "OAP::Action" {
			t.Errorf("expected action type OAP::Action, got %s", body.Action.Type)
		}
		if body.Action.ID != "tickets.read" {
			t.Errorf("expected action ID tickets.read, got %s", body.Action.ID)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cedarResponse{
			Decision: "Allow",
		})
	}))
	defer server.Close()

	b := NewCedarBackend(CedarConfig{URL: server.URL})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "allow" {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

func TestCedarBackend_Deny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cedarResponse{
			Decision: "Deny",
			Diagnostics: cedarDiagnostics{
				Reason: []string{"no matching permit policy"},
			},
		})
	}))
	defer server.Close()

	b := NewCedarBackend(CedarConfig{URL: server.URL})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny, got %s", result.Decision)
	}
	if result.Reason != "no matching permit policy" {
		t.Errorf("expected reason from diagnostics, got %s", result.Reason)
	}
}

func TestCedarBackend_AllowWithConstraints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cedarResponse{
			Decision: "Allow",
			Context: map[string]interface{}{
				"constraints": map[string]interface{}{
					"max_records":   float64(5),
					"redact_fields": []interface{}{"ssn", "credit_card"},
				},
			},
		})
	}))
	defer server.Close()

	b := NewCedarBackend(CedarConfig{URL: server.URL})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "allow_with_constraints" {
		t.Errorf("expected allow_with_constraints, got %s", result.Decision)
	}
	if result.Constraints == nil {
		t.Fatal("expected constraints")
	}
}

func TestCedarBackend_WithActor(t *testing.T) {
	var capturedCtx map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body cedarRequest
		json.NewDecoder(r.Body).Decode(&body)
		capturedCtx = body.Context

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cedarResponse{Decision: "Allow"})
	}))
	defer server.Close()

	input := makeTestInput()
	input.Request.Actor = &model.Actor{Type: "user", ID: "alice@corp.com"}

	b := NewCedarBackend(CedarConfig{URL: server.URL})
	_, err := b.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actor, ok := capturedCtx["actor"].(map[string]interface{})
	if !ok {
		t.Fatal("expected actor in Cedar context")
	}
	if actor["id"] != "alice@corp.com" {
		t.Errorf("expected actor id alice@corp.com, got %v", actor["id"])
	}
}

func TestCedarBackend_Unreachable_FailClosed(t *testing.T) {
	b := NewCedarBackend(CedarConfig{URL: "http://127.0.0.1:1", FailOpen: false})
	result, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("fail-closed should not return error: %v", err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny (fail-closed), got %s", result.Decision)
	}
}

func TestCedarBackend_Unreachable_FailOpen(t *testing.T) {
	b := NewCedarBackend(CedarConfig{URL: "http://127.0.0.1:1", FailOpen: true})
	_, err := b.Evaluate(context.Background(), makeTestInput())
	if err == nil {
		t.Fatal("fail-open should return error so evaluator can fallback")
	}
}

func TestCedarBackend_Name(t *testing.T) {
	b := NewCedarBackend(CedarConfig{})
	if b.Name() != "cedar" {
		t.Errorf("expected name 'cedar', got %s", b.Name())
	}
}

func TestCedarBackend_PolicyStoreID(t *testing.T) {
	var capturedStoreID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body cedarRequest
		json.NewDecoder(r.Body).Decode(&body)
		capturedStoreID = body.PolicyStoreID

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cedarResponse{Decision: "Allow"})
	}))
	defer server.Close()

	b := NewCedarBackend(CedarConfig{URL: server.URL, PolicyStoreID: "ps-abc123"})
	_, err := b.Evaluate(context.Background(), makeTestInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedStoreID != "ps-abc123" {
		t.Errorf("expected policyStoreId ps-abc123, got %s", capturedStoreID)
	}
}
