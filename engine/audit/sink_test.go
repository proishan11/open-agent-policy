package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
)

func sampleEvent() model.AuditEvent {
	return model.AuditEvent{
		EventID:   "evt-test-1",
		EventType: "authorization.decision",
		Timestamp: time.Now().UTC(),
		Decision:  "allow",
		Subject:   &model.AuditSubject{AgentID: "agent://test/agent"},
		Action:    "test.read",
		Reason:    "allowed by policy",
	}
}

func TestMemorySink(t *testing.T) {
	sink := NewMemorySink()

	if sink.Len() != 0 {
		t.Errorf("expected 0 events, got %d", sink.Len())
	}

	if err := sink.Write(sampleEvent()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if sink.Len() != 1 {
		t.Errorf("expected 1 event, got %d", sink.Len())
	}

	if sink.Events[0].EventID != "evt-test-1" {
		t.Errorf("got event ID %q, want %q", sink.Events[0].EventID, "evt-test-1")
	}

	if err := sink.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestJSONLSink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	sink, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}

	// Write two events
	if err := sink.Write(sampleEvent()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	evt2 := sampleEvent()
	evt2.EventID = "evt-test-2"
	evt2.Decision = "deny"
	if err := sink.Write(evt2); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := splitNonEmpty(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var event1 model.AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &event1); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if event1.EventID != "evt-test-1" {
		t.Errorf("line 1 event ID = %q, want %q", event1.EventID, "evt-test-1")
	}
	if event1.Decision != "allow" {
		t.Errorf("line 1 decision = %q, want %q", event1.Decision, "allow")
	}

	var event2 model.AuditEvent
	if err := json.Unmarshal([]byte(lines[1]), &event2); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	if event2.Decision != "deny" {
		t.Errorf("line 2 decision = %q, want %q", event2.Decision, "deny")
	}
}

func TestJSONLSinkInvalidPath(t *testing.T) {
	_, err := NewJSONLSink("/nonexistent/dir/audit.jsonl")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func splitNonEmpty(s string) []string {
	var result []string
	for _, line := range splitLines(s) {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
