package model

import (
	"testing"
	"time"
)

func TestAgentID(t *testing.T) {
	a := &Agent{
		Metadata: Metadata{Name: "reconciler", Namespace: "finance"},
	}
	if got := a.ID(); got != "agent://finance/reconciler" {
		t.Errorf("Agent.ID() = %q, want %q", got, "agent://finance/reconciler")
	}
}

func TestAgentIsActive(t *testing.T) {
	tests := []struct {
		state string
		want  bool
	}{
		{AgentStateActive, true},
		{"", true}, // empty state defaults to active
		{AgentStateSuspended, false},
		{AgentStateRevoked, false},
	}
	for _, tt := range tests {
		a := &Agent{Status: AgentStatus{State: tt.state}}
		if got := a.IsActive(); got != tt.want {
			t.Errorf("IsActive() with state %q = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestPolicyID(t *testing.T) {
	p := &AgentPolicy{
		Metadata: Metadata{Name: "read-only", Namespace: "finance"},
	}
	if got := p.ID(); got != "finance/read-only" {
		t.Errorf("Policy.ID() = %q, want %q", got, "finance/read-only")
	}
}

func TestPolicyMatchesAgent(t *testing.T) {
	agent := &Agent{
		Metadata: Metadata{Name: "reconciler", Namespace: "finance"},
		Spec:     AgentSpec{Type: "workflow_agent"},
	}

	tests := []struct {
		name    string
		subject PolicySubject
		want    bool
	}{
		{"allAgents", PolicySubject{AllAgents: true}, true},
		{"exact agent match", PolicySubject{Agent: "agent://finance/reconciler"}, true},
		{"wrong agent", PolicySubject{Agent: "agent://finance/other"}, false},
		{"type match", PolicySubject{AgentType: "workflow_agent"}, true},
		{"wrong type", PolicySubject{AgentType: "chat_agent"}, false},
		{"namespace match", PolicySubject{AgentNamespace: "finance"}, true},
		{"wrong namespace", PolicySubject{AgentNamespace: "engineering"}, false},
		{"empty subject", PolicySubject{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &AgentPolicy{
				Spec: PolicySpec{Subject: tt.subject},
			}
			if got := p.MatchesAgent(agent); got != tt.want {
				t.Errorf("MatchesAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGrantIsExpired(t *testing.T) {
	expired := &Grant{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Status:    "active",
	}
	if !expired.IsExpired() {
		t.Error("expected expired grant to be expired")
	}

	valid := &Grant{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Status:    "active",
	}
	if valid.IsExpired() {
		t.Error("expected valid grant to not be expired")
	}
}

func TestGrantIsValid(t *testing.T) {
	active := &Grant{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Status:    "active",
	}
	if !active.IsValid() {
		t.Error("expected active non-expired grant to be valid")
	}

	revoked := &Grant{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Status:    "revoked",
	}
	if revoked.IsValid() {
		t.Error("expected revoked grant to be invalid")
	}
}
