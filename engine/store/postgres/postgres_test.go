package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/model"
)

// getTestDSN returns the Postgres DSN for integration tests.
// Skips the test if OAP_TEST_POSTGRES is not set.
func getTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OAP_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("OAP_TEST_POSTGRES not set — skipping Postgres integration test")
	}
	return dsn
}

func TestPostgresAgentCRUD(t *testing.T) {
	dsn := getTestDSN(t)
	ctx := context.Background()

	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	agent := &model.Agent{
		APIVersion: "oap/v1alpha1",
		Kind:       "Agent",
		Metadata:   model.Metadata{Name: "pg-test-agent", Namespace: "test"},
		Spec: model.AgentSpec{
			Owner:        "test",
			Type:         "chat_agent",
			RiskTier:     "medium",
			Capabilities: []string{"read"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	}

	// Register
	if err := s.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Get
	got, err := s.GetAgent(ctx, "agent://test/pg-test-agent")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected agent")
	}
	if got.Metadata.Name != "pg-test-agent" {
		t.Errorf("expected pg-test-agent, got %s", got.Metadata.Name)
	}

	// List
	agents, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, a := range agents {
		if a.Metadata.Name == "pg-test-agent" {
			found = true
		}
	}
	if !found {
		t.Error("agent not found in list")
	}

	// Update status
	err = s.UpdateAgentStatus(ctx, "agent://test/pg-test-agent", model.AgentStatus{State: model.AgentStateSuspended})
	if err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, _ = s.GetAgent(ctx, "agent://test/pg-test-agent")
	if got.Status.State != model.AgentStateSuspended {
		t.Errorf("expected suspended, got %s", got.Status.State)
	}

	// Delete
	if err := s.DeleteAgent(ctx, "agent://test/pg-test-agent"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ = s.GetAgent(ctx, "agent://test/pg-test-agent")
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestPostgresPolicyCRUD(t *testing.T) {
	dsn := getTestDSN(t)
	ctx := context.Background()

	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	policy := &model.AgentPolicy{
		APIVersion: "oap/v1alpha1",
		Kind:       "AgentPolicy",
		Metadata:   model.Metadata{Name: "pg-test-policy", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://test/pg-test-agent"},
			Rules: []model.PolicyRule{
				{Actions: []string{"read"}, Effect: model.EffectAllow},
			},
		},
	}

	// Add
	if err := s.AddPolicy(ctx, policy); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Get
	got, err := s.GetPolicy(ctx, "test/pg-test-policy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected policy")
	}

	// PoliciesForAgent
	agent := &model.Agent{
		Metadata: model.Metadata{Name: "pg-test-agent", Namespace: "test"},
		Spec:     model.AgentSpec{Type: "chat_agent", RiskTier: "medium", Capabilities: []string{"read"}, Owner: "test"},
	}
	matched, err := s.PoliciesForAgent(ctx, agent)
	if err != nil {
		t.Fatalf("policies for agent: %v", err)
	}
	if len(matched) < 1 {
		t.Error("expected at least 1 matching policy")
	}

	// Delete
	if err := s.DeletePolicy(ctx, "test/pg-test-policy"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestPostgresSchema(t *testing.T) {
	dsn := getTestDSN(t)
	ctx := context.Background()

	// Creating the store should apply schema automatically
	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	// Verify schema version exists
	var version int
	err = s.pool.QueryRow(ctx, `SELECT version FROM oap_schema_version ORDER BY version DESC LIMIT 1`).Scan(&version)
	if err != nil {
		t.Fatalf("query schema version: %v", err)
	}
	if version < LatestSchemaVersion() {
		t.Errorf("expected schema version >= %d, got %d", LatestSchemaVersion(), version)
	}

	var name, checksum string
	err = s.pool.QueryRow(ctx, `SELECT name, checksum FROM oap_schema_version WHERE version = $1`, LatestSchemaVersion()).Scan(&name, &checksum)
	if err != nil {
		t.Fatalf("query latest migration metadata: %v", err)
	}
	if name == "" {
		t.Fatal("latest migration name is empty")
	}
	if checksum == "" {
		t.Fatal("latest migration checksum is empty")
	}

	if err := s.CheckHealth(ctx); err != nil {
		t.Fatalf("health check: %v", err)
	}
}

func TestPostgresAuditSinkQuery(t *testing.T) {
	dsn := getTestDSN(t)
	ctx := context.Background()

	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	suffix := time.Now().UnixNano()
	agentID := fmt.Sprintf("agent://test/pg-audit-%d", suffix)
	base := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	sink := NewAuditSink(s)

	events := []model.AuditEvent{
		{
			EventID:   fmt.Sprintf("evt-pg-%d-1", suffix),
			EventType: "authorization.decision",
			Timestamp: base,
			Decision:  model.DecisionAllow,
			Subject:   &model.AuditSubject{AgentID: agentID},
			Actor:     &model.AuditActor{Type: "user", ID: "alice@example.com"},
			Action:    "tickets.read",
			Resource:  &model.AuditResource{Type: "ticket", ID: "T-1"},
			RequestID: fmt.Sprintf("req-pg-%d-1", suffix),
			RunID:     fmt.Sprintf("run-pg-%d", suffix),
			Reason:    "allowed",
		},
		{
			EventID:   fmt.Sprintf("evt-pg-%d-2", suffix),
			EventType: "authorization.decision",
			Timestamp: base.Add(time.Minute),
			Decision:  model.DecisionDeny,
			Subject:   &model.AuditSubject{AgentID: agentID},
			Actor:     &model.AuditActor{Type: "user", ID: "alice@example.com"},
			Action:    "tickets.write",
			Resource:  &model.AuditResource{Type: "ticket", ID: "T-2"},
			RequestID: fmt.Sprintf("req-pg-%d-2", suffix),
			RunID:     fmt.Sprintf("run-pg-%d", suffix),
			Reason:    "denied",
		},
	}

	for _, event := range events {
		if err := sink.Write(event); err != nil {
			t.Fatalf("write audit event: %v", err)
		}
	}

	got, err := sink.Query(ctx, audit.Query{
		AgentID:      agentID,
		Decision:     model.DecisionDeny,
		ResourceType: "ticket",
		Limit:        10,
	})
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].EventID != events[1].EventID {
		t.Fatalf("got event %s, want %s", got[0].EventID, events[1].EventID)
	}
	if got[0].RequestID != events[1].RequestID {
		t.Fatalf("got request %s, want %s", got[0].RequestID, events[1].RequestID)
	}
}
