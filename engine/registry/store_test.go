package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/model"
)

func TestRegisterAndGetAgent(t *testing.T) {
	store := NewStore()
	agent := &model.Agent{
		Metadata: model.Metadata{Name: "test-agent", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "team", Type: "workflow_agent", RiskTier: "low", Capabilities: []string{"read"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	}

	store.RegisterAgent(agent)

	got := store.GetAgent("agent://test/test-agent")
	if got == nil {
		t.Fatal("expected agent, got nil")
	}
	if got.ID() != "agent://test/test-agent" {
		t.Errorf("got %q, want %q", got.ID(), "agent://test/test-agent")
	}
}

func TestGetAgentNotFound(t *testing.T) {
	store := NewStore()
	if got := store.GetAgent("agent://test/ghost"); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestListAgents(t *testing.T) {
	store := NewStore()
	store.RegisterAgent(&model.Agent{
		Metadata: model.Metadata{Name: "a", Namespace: "ns"},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	store.RegisterAgent(&model.Agent{
		Metadata: model.Metadata{Name: "b", Namespace: "ns"},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})

	agents := store.ListAgents()
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestAddAndGetPolicy(t *testing.T) {
	store := NewStore()
	policy := &model.AgentPolicy{
		Metadata: model.Metadata{Name: "allow-read", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{AllAgents: true},
			Rules:   []model.PolicyRule{{Effect: "allow", Actions: []string{"read"}}},
		},
	}

	store.AddPolicy(policy)
	got := store.GetPolicy("test/allow-read")
	if got == nil {
		t.Fatal("expected policy, got nil")
	}
}

func TestPoliciesForAgent(t *testing.T) {
	store := NewStore()
	agent := &model.Agent{
		Metadata: model.Metadata{Name: "agent-a", Namespace: "ns"},
		Spec:     model.AgentSpec{Type: "workflow_agent"},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	}
	store.RegisterAgent(agent)

	// Policy that matches
	store.AddPolicy(&model.AgentPolicy{
		Metadata: model.Metadata{Name: "match", Namespace: "ns"},
		Spec:     model.PolicySpec{Subject: model.PolicySubject{Agent: "agent://ns/agent-a"}},
	})
	// Policy that doesn't match
	store.AddPolicy(&model.AgentPolicy{
		Metadata: model.Metadata{Name: "nomatch", Namespace: "ns"},
		Spec:     model.PolicySpec{Subject: model.PolicySubject{Agent: "agent://ns/other"}},
	})

	matched := store.PoliciesForAgent(agent)
	if len(matched) != 1 {
		t.Errorf("expected 1 matching policy, got %d", len(matched))
	}
}

func TestLoadDir(t *testing.T) {
	// Create a temp dir with test YAML files
	dir := t.TempDir()

	agentYAML := `apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: test-agent
  namespace: test
spec:
  owner: team
  type: workflow_agent
  riskTier: low
  capabilities:
    - read
`
	policyYAML := `apiVersion: oap.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: test-policy
  namespace: test
spec:
  subject:
    agent: agent://test/test-agent
  rules:
    - effect: allow
      actions:
        - read
`
	os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(agentYAML), 0644)
	os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(policyYAML), 0644)
	// Non-YAML file should be skipped
	os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignore me"), 0644)

	store := NewStore()
	if err := store.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	if len(store.ListAgents()) != 1 {
		t.Errorf("expected 1 agent, got %d", len(store.ListAgents()))
	}
	if len(store.ListPolicies()) != 1 {
		t.Errorf("expected 1 policy, got %d", len(store.ListPolicies()))
	}
}

func TestLoadDirSkipsUnknownKinds(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "unknown.yaml"), []byte("kind: SomethingElse\nname: foo\n"), 0644)

	store := NewStore()
	if err := store.LoadDir(dir); err != nil {
		t.Fatalf("expected no error for unknown kind, got: %v", err)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	store := NewStore()
	if err := store.LoadFile("/nonexistent/path.yaml"); err == nil {
		t.Error("expected error for nonexistent file")
	}
}
