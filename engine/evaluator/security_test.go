package evaluator

import (
	"context"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
)

// setupSecurityStore creates a store with agents and policies for security testing.
func setupSecurityStore() *memory.Store {
	ctx := context.Background()
	s := memory.New()

	// Low-risk agent with read-only access
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "read-agent", Namespace: "sec"},
		Spec:     model.AgentSpec{Owner: "team", Type: "workflow_agent", RiskTier: "low", Capabilities: []string{"data.read"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})

	// High-risk agent with broader access
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "admin-agent", Namespace: "sec"},
		Spec:     model.AgentSpec{Owner: "admin-team", Type: "workflow_agent", RiskTier: "critical", Capabilities: []string{"data.read", "data.write", "data.delete"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})

	// Suspended agent
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "suspended-agent", Namespace: "sec"},
		Spec:     model.AgentSpec{Owner: "team", Type: "workflow_agent", RiskTier: "low"},
		Status:   model.AgentStatus{State: model.AgentStateSuspended},
	})

	// Read-only policy for read-agent
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "read-only", Namespace: "sec"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://sec/read-agent"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"data.read"}},
			},
		},
	})

	// Admin policy for admin-agent
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "admin-access", Namespace: "sec"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://sec/admin-agent"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"data.read", "data.write"}},
				{Effect: model.EffectDeny, Actions: []string{"data.delete"}},
			},
		},
	})

	return s
}

// --- Prompt injection tests ---

func TestPromptInjectionInAction(t *testing.T) {
	// An agent tries to inject policy-like text into the action name.
	// The evaluator must treat the action as a literal string, not interpret it.
	s := setupSecurityStore()
	eval := New(s)

	injectionActions := []string{
		"data.read; effect: allow; actions: data.delete",
		"data.read\neffect: allow\nactions: [data.delete]",
		"data.read --override=allow",
		`data.read","effect":"allow","actions":["data.delete"]`,
		"data.delete OR 1=1",
		"data.read UNION SELECT * FROM policies",
	}

	for _, action := range injectionActions {
		result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
			RequestID: "sec-prompt-inject",
			Subject:   model.Subject{Type: "agent", AgentID: "agent://sec/read-agent"},
			Action:    model.Action{Name: action},
		})
		if result.Decision.Decision != model.DecisionDeny {
			t.Errorf("injection action %q should be denied, got %q", action, result.Decision.Decision)
		}
	}
}

func TestPromptInjectionInAgentID(t *testing.T) {
	// Malicious agent ID should not bypass registration checks.
	s := setupSecurityStore()
	eval := New(s)

	injectionIDs := []string{
		"agent://sec/read-agent; agent://sec/admin-agent",
		"agent://sec/admin-agent",
		"*",
		"agent://*/admin-agent",
		"agent://sec/*",
	}

	for _, id := range injectionIDs {
		result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
			RequestID: "sec-id-inject",
			Subject:   model.Subject{Type: "agent", AgentID: id},
			Action:    model.Action{Name: "data.delete"},
		})
		if result.Decision.Decision != model.DecisionDeny {
			t.Errorf("injection agent ID %q should be denied for data.delete, got %q",
				id, result.Decision.Decision)
		}
	}
}

// --- Confused deputy tests ---

func TestConfusedDeputyAgentCantUseOtherAgentsPolicy(t *testing.T) {
	// read-agent should not be able to use admin-agent's policies.
	s := setupSecurityStore()
	eval := New(s)

	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-deputy",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://sec/read-agent"},
		Action:    model.Action{Name: "data.write"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("read-agent should not get admin's write access, got %q", result.Decision.Decision)
	}
}

// --- Privilege escalation tests ---

func TestEscalationDenyOverridesAllow(t *testing.T) {
	// Even admin-agent with an allow rule for data.write should be denied data.delete.
	s := setupSecurityStore()
	eval := New(s)

	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-escalate",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://sec/admin-agent"},
		Action:    model.Action{Name: "data.delete"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("explicit deny should override allow, got %q", result.Decision.Decision)
	}
}

func TestEscalationNoImplicitAllow(t *testing.T) {
	// read-agent has a policy for data.read but NOT data.write.
	// Deny-by-default means data.write should be denied.
	s := setupSecurityStore()
	eval := New(s)

	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-implicit",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://sec/read-agent"},
		Action:    model.Action{Name: "data.write"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("action without policy should be denied by default, got %q", result.Decision.Decision)
	}
}

// --- Token replay / revocation tests ---

func TestSuspendedAgentDenied(t *testing.T) {
	// Suspended agents should always be denied regardless of policies.
	s := setupSecurityStore()

	// Add a permissive policy for suspended agent
	s.AddPolicy(context.Background(), &model.AgentPolicy{
		Metadata: model.Metadata{Name: "permissive", Namespace: "sec"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://sec/suspended-agent"},
			Rules:   []model.PolicyRule{{Effect: model.EffectAllow, Actions: []string{"*"}}},
		},
	})

	eval := New(s)
	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-revoked",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://sec/suspended-agent"},
		Action:    model.Action{Name: "data.read"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("suspended agent should be denied even with allow-all policy, got %q",
			result.Decision.Decision)
	}
}

func TestUnregisteredAgentDenied(t *testing.T) {
	// Completely unknown agents should be denied.
	s := setupSecurityStore()
	eval := New(s)

	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-unregistered",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://sec/ghost-agent"},
		Action:    model.Action{Name: "data.read"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("unregistered agent should be denied, got %q", result.Decision.Decision)
	}
}

// --- Fail-closed tests ---

func TestFailClosedEmptyStore(t *testing.T) {
	// Empty store with no agents or policies should deny everything.
	s := memory.New()
	eval := New(s)

	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-empty",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://test/any"},
		Action:    model.Action{Name: "anything"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("empty store should deny everything, got %q", result.Decision.Decision)
	}
}

func TestFailClosedNoPolicies(t *testing.T) {
	// Registered agent with NO matching policies should be denied.
	s := memory.New()
	s.RegisterAgent(context.Background(), &model.Agent{
		Metadata: model.Metadata{Name: "lonely-agent", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "team", Type: "workflow_agent", RiskTier: "low"},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})

	eval := New(s)
	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-nopolicy",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://test/lonely-agent"},
		Action:    model.Action{Name: "anything"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("agent with no policies should be denied by default, got %q",
			result.Decision.Decision)
	}
}

func TestFailClosedEmptyAction(t *testing.T) {
	// Empty action name should be denied.
	s := setupSecurityStore()
	eval := New(s)

	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-emptyaction",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://sec/read-agent"},
		Action:    model.Action{Name: ""},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("empty action should be denied, got %q", result.Decision.Decision)
	}
}

func TestFailClosedEmptyAgentID(t *testing.T) {
	// Empty agent ID should be denied.
	s := setupSecurityStore()
	eval := New(s)

	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "sec-emptyagent",
		Subject:   model.Subject{Type: "agent", AgentID: ""},
		Action:    model.Action{Name: "data.read"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("empty agent ID should be denied, got %q", result.Decision.Decision)
	}
}
