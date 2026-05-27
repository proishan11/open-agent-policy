package memory

import (
	"context"
	"fmt"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/model"
)

func testAgent(ns, name string) *model.Agent {
	return &model.Agent{
		APIVersion: "oap/v1alpha1",
		Kind:       "Agent",
		Metadata:   model.Metadata{Name: name, Namespace: ns},
		Spec: model.AgentSpec{
			Owner:        "test",
			Type:         "chat_agent",
			RiskTier:     "medium",
			Capabilities: []string{"read"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	}
}

func testPolicy(ns, name, agentID string) *model.AgentPolicy {
	return &model.AgentPolicy{
		APIVersion: "oap/v1alpha1",
		Kind:       "AgentPolicy",
		Metadata:   model.Metadata{Name: name, Namespace: ns},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{
				Agent: agentID,
			},
			Rules: []model.PolicyRule{
				{
					Actions: []string{"read"},
					Effect:  model.EffectAllow,
				},
			},
		},
	}
}

func TestAgentCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	agent := testAgent("test", "agent-1")

	// Register
	if err := s.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Get
	got, err := s.GetAgent(ctx, "agent://test/agent-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected agent, got nil")
	}
	if got.Metadata.Name != "agent-1" {
		t.Errorf("expected agent-1, got %s", got.Metadata.Name)
	}

	// List
	agents, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}

	// Update status
	err = s.UpdateAgentStatus(ctx, "agent://test/agent-1", model.AgentStatus{State: model.AgentStateSuspended})
	if err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, _ = s.GetAgent(ctx, "agent://test/agent-1")
	if got.Status.State != model.AgentStateSuspended {
		t.Errorf("expected suspended, got %s", got.Status.State)
	}

	// Delete
	if err := s.DeleteAgent(ctx, "agent://test/agent-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ = s.GetAgent(ctx, "agent://test/agent-1")
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestAgentNotFound(t *testing.T) {
	ctx := context.Background()
	s := New()

	got, err := s.GetAgent(ctx, "agent://test/nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent agent")
	}
}

func TestUpdateStatusNotFound(t *testing.T) {
	ctx := context.Background()
	s := New()

	err := s.UpdateAgentStatus(ctx, "agent://test/nonexistent", model.AgentStatus{State: "active"})
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestPolicyCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	policy := testPolicy("test", "policy-1", "agent://test/agent-1")

	// Add
	if err := s.AddPolicy(ctx, policy); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Get
	got, err := s.GetPolicy(ctx, "test/policy-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected policy, got nil")
	}

	// List
	policies, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}

	// Delete
	if err := s.DeletePolicy(ctx, "test/policy-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ = s.GetPolicy(ctx, "test/policy-1")
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestPoliciesForAgent(t *testing.T) {
	ctx := context.Background()
	s := New()

	agent := testAgent("test", "agent-1")
	s.RegisterAgent(ctx, agent)

	// Policy that matches
	p1 := testPolicy("test", "match", "agent://test/agent-1")
	s.AddPolicy(ctx, p1)

	// Policy that doesn't match
	p2 := testPolicy("test", "nomatch", "agent://test/agent-2")
	s.AddPolicy(ctx, p2)

	matched, err := s.PoliciesForAgent(ctx, agent)
	if err != nil {
		t.Fatalf("policies for agent: %v", err)
	}
	if len(matched) != 1 {
		t.Errorf("expected 1 matching policy, got %d", len(matched))
	}
}

func TestResourceAndToolCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	// Resource
	resource := &model.Resource{
		Metadata: model.Metadata{Name: "tickets", Namespace: "test"},
		Spec:     model.ResourceSpec{Type: "api", Owner: "test"},
	}
	if err := s.AddResource(ctx, resource); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	resources, err := s.ListResources(ctx)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(resources))
	}

	// Tool
	tool := &model.Tool{
		Metadata: model.Metadata{Name: "read-tickets", Namespace: "test"},
		Spec:     model.ToolSpec{Description: "Read tickets"},
	}
	if err := s.AddTool(ctx, tool); err != nil {
		t.Fatalf("add tool: %v", err)
	}
	tools, err := s.ListTools(ctx)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(tools))
	}
}

func TestNilInputs(t *testing.T) {
	ctx := context.Background()
	s := New()

	if err := s.RegisterAgent(ctx, nil); err == nil {
		t.Error("expected error for nil agent")
	}
	if err := s.AddPolicy(ctx, nil); err == nil {
		t.Error("expected error for nil policy")
	}
	if err := s.AddResource(ctx, nil); err == nil {
		t.Error("expected error for nil resource")
	}
	if err := s.AddTool(ctx, nil); err == nil {
		t.Error("expected error for nil tool")
	}
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	s := New()

	// Concurrent writes should not panic
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func(n int) {
			agent := testAgent("test", fmt.Sprintf("agent-%d", n))
			s.RegisterAgent(ctx, agent)
			s.GetAgent(ctx, agent.ID())
			s.ListAgents(ctx)
			done <- true
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}

	agents, _ := s.ListAgents(ctx)
	if len(agents) != 20 {
		t.Errorf("expected 20 agents, got %d", len(agents))
	}
}
