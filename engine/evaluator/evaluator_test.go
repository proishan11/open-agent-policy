package evaluator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
	"gopkg.in/yaml.v3"
)

// conformanceCase mirrors the YAML structure of conformance test cases.
// The "expected" block is nested: expected.decision, expected.reason_contains, etc.
type conformanceCase struct {
	Name        string                     `yaml:"name"`
	Description string                     `yaml:"description"`
	Agents      []model.Agent              `yaml:"agents"`
	Policies    []model.AgentPolicy        `yaml:"policies"`
	Request     model.AuthorizationRequest `yaml:"request"`
	Expected    expectedBlock              `yaml:"expected"`
}

type expectedBlock struct {
	Decision       string                 `yaml:"decision"`
	ReasonContains string                 `yaml:"reason_contains"`
	Constraints    map[string]interface{} `yaml:"constraints"`
	Approval       map[string]interface{} `yaml:"approval"`
}

// loadConformanceCase loads a single conformance YAML file.
func loadConformanceCase(t *testing.T, path string) conformanceCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var tc conformanceCase
	if err := yaml.Unmarshal(data, &tc); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return tc
}

// setupEvaluator creates a store, registers agents and policies from the test
// case, and returns an evaluator ready for evaluation.
func setupEvaluator(tc conformanceCase) *Evaluator {
	ctx := context.Background()
	s := memory.New()
	for i := range tc.Agents {
		agent := tc.Agents[i]
		if agent.Status.State == "" {
			agent.Status.State = model.AgentStateActive
		}
		s.RegisterAgent(ctx, &agent)
	}
	for i := range tc.Policies {
		s.AddPolicy(ctx, &tc.Policies[i])
	}
	return New(s)
}

// conformancePath returns the absolute path to the conformance cases directory.
func conformancePath(t *testing.T) string {
	t.Helper()
	// Walk up from engine/evaluator/ to repo root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(wd, "..", "..")
	casesDir := filepath.Join(root, "conformance", "cases")
	if _, err := os.Stat(casesDir); err != nil {
		t.Skipf("conformance cases directory not found at %s", casesDir)
	}
	return casesDir
}

// TestConformanceSuite runs all 10 conformance test cases against the evaluator.
func TestConformanceSuite(t *testing.T) {
	casesDir := conformancePath(t)
	entries, err := os.ReadDir(casesDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(casesDir, entry.Name())
		tc := loadConformanceCase(t, path)

		t.Run(tc.Name, func(t *testing.T) {
			eval := setupEvaluator(tc)
			result := eval.Evaluate(context.Background(), tc.Request)

			// Check decision
			if result.Decision.Decision != tc.Expected.Decision {
				t.Errorf("decision: got %q, want %q\n  trace: %+v",
					result.Decision.Decision, tc.Expected.Decision, result.Trace)
			}

			// Check reason contains expected substring
			if tc.Expected.ReasonContains != "" {
				if !containsSubstring(result.Decision.Reason, tc.Expected.ReasonContains) {
					t.Errorf("reason: got %q, want it to contain %q",
						result.Decision.Reason, tc.Expected.ReasonContains)
				}
			}

			// Check constraints if expected
			if tc.Expected.Constraints != nil {
				checkConstraints(t, result.Decision.Constraints, tc.Expected.Constraints)
			}

			// Check approval details if expected
			if tc.Expected.Approval != nil {
				checkApproval(t, result.Decision.Approval, tc.Expected.Approval)
			}
		})
	}
}

// --- Individual tests for clarity ---

func TestDenyUnregisteredAgent(t *testing.T) {
	s := memory.New()
	// No agents registered, but add a policy that would allow if agent existed
	s.AddPolicy(context.Background(), &model.AgentPolicy{
		Metadata: model.Metadata{Name: "allow-read", Namespace: "finance"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{AllAgents: true},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"erp.invoice.read"}},
			},
		},
	})

	eval := New(s)
	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "test-1",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://finance/ghost"},
		Action:    model.Action{Name: "erp.invoice.read"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision.Decision)
	}
	if !containsSubstring(result.Decision.Reason, "unregistered") {
		t.Errorf("expected reason to contain 'unregistered', got: %s", result.Decision.Reason)
	}
}

func TestDenyByDefault(t *testing.T) {
	s := memory.New()
	s.RegisterAgent(context.Background(), &model.Agent{
		Metadata: model.Metadata{Name: "data-agent", Namespace: "analytics"},
		Spec:     model.AgentSpec{Owner: "data-team", Type: "workflow_agent", RiskTier: "medium", Capabilities: []string{"db.query"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	// No policies

	eval := New(s)
	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "test-2",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://analytics/data-agent"},
		Action:    model.Action{Name: "db.query"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision.Decision)
	}
	if !containsSubstring(result.Decision.Reason, "deny by default") {
		t.Errorf("expected reason to mention deny by default, got: %s", result.Decision.Reason)
	}
}

func TestExplicitDenyOverridesAllow(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "invoice-reconciler", Namespace: "finance"},
		Spec:     model.AgentSpec{Owner: "finance-team", Type: "workflow_agent", RiskTier: "medium", Capabilities: []string{"erp.invoice.delete"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})

	// Policy that allows everything
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "allow-all", Namespace: "finance"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://finance/invoice-reconciler"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"*"}},
			},
		},
	})

	// Policy that explicitly denies delete
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "deny-delete", Namespace: "finance"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://finance/invoice-reconciler"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectDeny, Actions: []string{"erp.invoice.delete"}, Reason: "Agents may not delete invoices"},
			},
		},
	})

	eval := New(s)
	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "test-3",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://finance/invoice-reconciler"},
		Action:    model.Action{Name: "erp.invoice.delete"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision.Decision)
	}
}

func TestRevokedAgentDenied(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "old-agent", Namespace: "engineering"},
		Spec:     model.AgentSpec{Owner: "eng-team", Type: "workflow_agent", RiskTier: "low", Capabilities: []string{"read"}},
		Status:   model.AgentStatus{State: model.AgentStateRevoked},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "allow-read", Namespace: "engineering"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://engineering/old-agent"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"*"}},
			},
		},
	})

	eval := New(s)
	result := eval.Evaluate(context.Background(), model.AuthorizationRequest{
		RequestID: "test-4",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://engineering/old-agent"},
		Action:    model.Action{Name: "repo.read"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision.Decision)
	}
	if !containsSubstring(result.Decision.Reason, "revoked") {
		t.Errorf("expected reason to mention revoked, got: %s", result.Decision.Reason)
	}
}

func TestCapabilityIsUpperBound(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "reader", Namespace: "finance"},
		Spec: model.AgentSpec{
			Owner:        "finance-team",
			Type:         "workflow_agent",
			RiskTier:     "medium",
			Capabilities: []string{"erp.invoice.read"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "broad-policy", Namespace: "finance"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://finance/reader"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"erp.invoice.delete"}},
			},
		},
	})

	result := New(s).Evaluate(ctx, model.AuthorizationRequest{
		RequestID: "test-capability",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://finance/reader"},
		Action:    model.Action{Name: "erp.invoice.delete"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Fatalf("expected deny, got %s", result.Decision.Decision)
	}
	if !containsSubstring(result.Decision.Reason, "capability") {
		t.Errorf("expected capability denial, got %q", result.Decision.Reason)
	}
}

func TestUnknownConditionFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "agent", Namespace: "support"},
		Spec: model.AgentSpec{
			Owner:        "support-team",
			Type:         "chat_agent",
			RiskTier:     "medium",
			Capabilities: []string{"tickets.escalate"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "bad-condition", Namespace: "support"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://support/agent"},
			Rules: []model.PolicyRule{
				{
					Effect:     model.EffectAllow,
					Actions:    []string{"tickets.escalate"},
					Conditions: map[string]interface{}{"priorityIn": []interface{}{"P1", "P2"}},
				},
			},
		},
	})

	result := New(s).Evaluate(ctx, model.AuthorizationRequest{
		RequestID: "test-unknown-condition",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://support/agent"},
		Action:    model.Action{Name: "tickets.escalate"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Fatalf("expected deny, got %s", result.Decision.Decision)
	}
	if !containsSubstring(result.Decision.Reason, "unsupported condition") {
		t.Errorf("expected unsupported condition reason, got %q", result.Decision.Reason)
	}
}

func TestUnsupportedConstraintFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "agent", Namespace: "support"},
		Spec: model.AgentSpec{
			Owner:        "support-team",
			Type:         "chat_agent",
			RiskTier:     "medium",
			Capabilities: []string{"tickets.list"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "bad-constraint", Namespace: "support"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://support/agent"},
			Rules: []model.PolicyRule{
				{
					Effect:      model.EffectAllow,
					Actions:     []string{"tickets.list"},
					Constraints: map[string]interface{}{"max_records": 10},
				},
			},
		},
	})

	result := New(s).Evaluate(ctx, model.AuthorizationRequest{
		RequestID: "test-unsupported-constraint",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://support/agent"},
		Action:    model.Action{Name: "tickets.list"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Fatalf("expected deny, got %s", result.Decision.Decision)
	}
	if !containsSubstring(result.Decision.Reason, "unsupported constraint") {
		t.Errorf("expected unsupported constraint reason, got %q", result.Decision.Reason)
	}
}

func TestResourceSelectorMustMatch(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "agent", Namespace: "finance"},
		Spec: model.AgentSpec{
			Owner:        "finance-team",
			Type:         "workflow_agent",
			RiskTier:     "medium",
			Capabilities: []string{"erp.invoice.read"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "resource-scoped", Namespace: "finance"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://finance/agent"},
			Rules: []model.PolicyRule{
				{
					Effect:  model.EffectAllow,
					Actions: []string{"erp.invoice.read"},
					Resources: &model.PolicyResourceSelector{
						Types: []string{"erp.invoice"},
					},
				},
			},
		},
	})

	result := New(s).Evaluate(ctx, model.AuthorizationRequest{
		RequestID: "test-resource",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://finance/agent"},
		Action:    model.Action{Name: "erp.invoice.read"},
		Resource:  &model.ResourceRef{Type: "erp.payment", ID: "PAY-001"},
	})

	if result.Decision.Decision != model.DecisionDeny {
		t.Fatalf("expected deny, got %s", result.Decision.Decision)
	}
}

func TestAllowedFieldsAndExpiresInConstraints(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	s.RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "agent", Namespace: "support"},
		Spec: model.AgentSpec{
			Owner:        "support-team",
			Type:         "chat_agent",
			RiskTier:     "medium",
			Capabilities: []string{"ticket.update"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "wide", Namespace: "support"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://support/agent"},
			Rules: []model.PolicyRule{
				{
					Effect:  model.EffectAllow,
					Actions: []string{"ticket.update"},
					Constraints: map[string]interface{}{
						"allowedFields": []interface{}{"status", "priority", "assignee"},
						"expiresIn":     "15m",
					},
				},
			},
		},
	})
	s.AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "narrow", Namespace: "support"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://support/agent"},
			Rules: []model.PolicyRule{
				{
					Effect:  model.EffectAllow,
					Actions: []string{"ticket.update"},
					Constraints: map[string]interface{}{
						"allowedFields": []interface{}{"status", "assignee"},
						"expiresIn":     "5m",
					},
				},
			},
		},
	})

	result := New(s).Evaluate(ctx, model.AuthorizationRequest{
		RequestID: "test-constraints",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://support/agent"},
		Action:    model.Action{Name: "ticket.update"},
	})

	if result.Decision.Decision != model.DecisionAllowConstrained {
		t.Fatalf("expected allow_with_constraints, got %s", result.Decision.Decision)
	}
	if result.Decision.Constraints == nil || result.Decision.Constraints.AllowedFields == nil {
		t.Fatal("expected allowed_fields constraint")
	}
	if !sameStringSet(*result.Decision.Constraints.AllowedFields, []string{"status", "assignee"}) {
		t.Errorf("allowed_fields = %v, want status+assignee", *result.Decision.Constraints.AllowedFields)
	}
	if result.Decision.Constraints.ExpiresInSeconds == nil || *result.Decision.Constraints.ExpiresInSeconds != 300 {
		t.Errorf("expires_in_seconds = %v, want 300", result.Decision.Constraints.ExpiresInSeconds)
	}
}

// --- Helpers ---

func containsSubstring(s, substr string) bool {
	return len(substr) == 0 || contains(s, substr)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, expected := range want {
		found := false
		for _, actual := range got {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func checkConstraints(t *testing.T, got *model.Constraints, expected map[string]interface{}) {
	t.Helper()
	if got == nil {
		t.Error("expected constraints but got nil")
		return
	}

	if v, ok := expected["readonly"]; ok {
		if b, ok := v.(bool); ok {
			if got.ReadOnly == nil || *got.ReadOnly != b {
				t.Errorf("constraint readonly: got %v, want %v", got.ReadOnly, b)
			}
		}
	}

	if v, ok := expected["maxRecords"]; ok {
		expectedMax := toInt(v)
		if got.MaxRecords == nil || *got.MaxRecords != expectedMax {
			t.Errorf("constraint maxRecords: got %v, want %d", got.MaxRecords, expectedMax)
		}
	}

	if v, ok := expected["redact"]; ok {
		expectedRedact, _ := toStringSlice(v)
		if len(expectedRedact) > 0 {
			for _, field := range expectedRedact {
				found := false
				for _, f := range got.RedactFields {
					if f == field {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("constraint redact: missing field %q in %v", field, got.RedactFields)
				}
			}
		}
	}

	if v, ok := expected["allowedFields"]; ok {
		expectedAllowed, _ := toStringSlice(v)
		if got.AllowedFields == nil || !sameStringSet(*got.AllowedFields, expectedAllowed) {
			t.Errorf("constraint allowedFields: got %v, want %v", got.AllowedFields, expectedAllowed)
		}
	}

	if v, ok := expected["expiresInSeconds"]; ok {
		expectedExpires := toInt(v)
		if got.ExpiresInSeconds == nil || *got.ExpiresInSeconds != expectedExpires {
			t.Errorf("constraint expiresInSeconds: got %v, want %d", got.ExpiresInSeconds, expectedExpires)
		}
	}
}

func checkApproval(t *testing.T, got *model.ApprovalRef, expected map[string]interface{}) {
	t.Helper()
	if got == nil {
		t.Error("expected approval details but got nil")
		return
	}

	if v, ok := expected["approvers"]; ok {
		expectedApprovers, _ := toStringSlice(v)
		for _, approver := range expectedApprovers {
			found := false
			for _, a := range got.Approvers {
				if a == approver {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("approval approvers: missing %q in %v", approver, got.Approvers)
			}
		}
	}
}
