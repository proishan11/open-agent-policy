package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/proishan11/open-agent-policy/engine/model"
)

// Sink is the interface for audit event persistence.
// Implementations must be safe for concurrent use.
type Sink interface {
	// Write persists a single audit event.
	Write(event model.AuditEvent) error

	// Close flushes and releases any resources.
	Close() error
}

// --- JSONL Sink (file-based, one JSON line per event) ---

// JSONLSink writes audit events as newline-delimited JSON to a file.
// This is the default sink for development and local testing.
type JSONLSink struct {
	mu     sync.Mutex
	writer io.WriteCloser
	enc    *json.Encoder
}

// NewJSONLSink creates a sink that writes to the given file path.
// The file is created if it doesn't exist, and appended to if it does.
func NewJSONLSink(path string) (*JSONLSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening audit file %s: %w", path, err)
	}
	return &JSONLSink{
		writer: f,
		enc:    json.NewEncoder(f),
	}, nil
}

func (s *JSONLSink) Write(event model.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(event)
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Close()
}

// --- Stdout Sink ---

// StdoutSink writes audit events as JSON to stdout.
// Useful for containerized deployments where logs are collected from stdout.
type StdoutSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewStdoutSink creates a sink that writes to stdout.
func NewStdoutSink() *StdoutSink {
	return &StdoutSink{enc: json.NewEncoder(os.Stdout)}
}

func (s *StdoutSink) Write(event model.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(event)
}

func (s *StdoutSink) Close() error { return nil }

// --- Memory Sink (for testing) ---

// MemorySink stores audit events in memory. Used in tests.
type MemorySink struct {
	mu     sync.Mutex
	Events []model.AuditEvent
}

// NewMemorySink creates an in-memory sink.
func NewMemorySink() *MemorySink {
	return &MemorySink{}
}

func (s *MemorySink) Write(event model.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, event)
	return nil
}

func (s *MemorySink) Close() error { return nil }

// Len returns the number of events recorded.
func (s *MemorySink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Events)
}
