package bundle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/registry"
)

func setupStore() *registry.Store {
	store := registry.NewStore()
	store.RegisterAgent(&model.Agent{
		Metadata: model.Metadata{Name: "agent-a", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "team", Type: "workflow_agent", RiskTier: "low"},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	store.AddPolicy(&model.AgentPolicy{
		Metadata: model.Metadata{Name: "policy-a", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://test/agent-a"},
			Rules:   []model.PolicyRule{{Effect: "allow", Actions: []string{"read"}}},
		},
	})
	return store
}

func TestServerGenerate(t *testing.T) {
	store := setupStore()
	srv := NewServer(store)
	bundle := srv.Generate()

	if bundle.Version != "v1" {
		t.Errorf("version = %q, want v1", bundle.Version)
	}
	if len(bundle.Agents) != 1 {
		t.Errorf("agents = %d, want 1", len(bundle.Agents))
	}
	if len(bundle.Policies) != 1 {
		t.Errorf("policies = %d, want 1", len(bundle.Policies))
	}
	if bundle.ETag == "" {
		t.Error("expected non-empty ETag")
	}
}

func TestServerETagStable(t *testing.T) {
	store := setupStore()
	srv := NewServer(store)

	b1 := srv.Generate()
	b2 := srv.Generate()

	if b1.ETag != b2.ETag {
		t.Errorf("ETag should be stable: %q != %q", b1.ETag, b2.ETag)
	}
}

func TestServerETagChanges(t *testing.T) {
	store := setupStore()
	srv := NewServer(store)

	b1 := srv.Generate()

	// Add another agent
	store.RegisterAgent(&model.Agent{
		Metadata: model.Metadata{Name: "agent-b", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "team", Type: "chat_agent", RiskTier: "low"},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})

	b2 := srv.Generate()

	if b1.ETag == b2.ETag {
		t.Error("ETag should change when content changes")
	}
}

func TestServerHTTPHandler(t *testing.T) {
	store := setupStore()
	srv := NewServer(store)

	req := httptest.NewRequest("GET", "/v1/bundles", nil)
	w := httptest.NewRecorder()
	srv.Handler()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var bundle Bundle
	json.NewDecoder(w.Body).Decode(&bundle)
	if len(bundle.Agents) != 1 {
		t.Errorf("agents = %d, want 1", len(bundle.Agents))
	}

	// Second request with ETag
	etag := w.Header().Get("ETag")
	req2 := httptest.NewRequest("GET", "/v1/bundles", nil)
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	srv.Handler()(w2, req2)

	if w2.Code != http.StatusNotModified {
		t.Errorf("expected 304, got %d", w2.Code)
	}
}

func TestClientSync(t *testing.T) {
	// Server store with data
	serverStore := setupStore()
	srv := NewServer(serverStore)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Empty client store
	clientStore := registry.NewStore()
	client := NewClient(ts.URL, clientStore, 0)

	err := client.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if len(clientStore.ListAgents()) != 1 {
		t.Errorf("client agents = %d, want 1", len(clientStore.ListAgents()))
	}
	if len(clientStore.ListPolicies()) != 1 {
		t.Errorf("client policies = %d, want 1", len(clientStore.ListPolicies()))
	}

	// Second sync — should use ETag and get 304
	err = client.Sync(context.Background())
	if err != nil {
		t.Fatalf("Second sync: %v", err)
	}
}
