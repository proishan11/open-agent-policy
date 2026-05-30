package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

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

// --- Multi Sink ---

// MultiSink writes each audit event to all configured sinks.
// It is useful when deployments want durable query storage and a JSONL export.
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink creates a sink that fans out writes and close calls.
func NewMultiSink(sinks ...Sink) *MultiSink {
	filtered := make([]Sink, 0, len(sinks))
	for _, sink := range sinks {
		if sink != nil {
			filtered = append(filtered, sink)
		}
	}
	return &MultiSink{sinks: filtered}
}

func (s *MultiSink) Write(event model.AuditEvent) error {
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Write(event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *MultiSink) Close() error {
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

// Query returns in-memory audit events matching q, newest first.
func (s *MemorySink) Query(ctx context.Context, q Query) ([]model.AuditEvent, error) {
	q = q.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()

	var matched []model.AuditEvent
	for i := len(s.Events) - 1; i >= 0; i-- {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		event := s.Events[i]
		if !eventMatchesQuery(event, q) {
			continue
		}
		matched = append(matched, event)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return eventTimestamp(matched[i]).After(eventTimestamp(matched[j]))
	})

	if q.Offset >= len(matched) {
		return []model.AuditEvent{}, nil
	}
	end := q.Offset + q.Limit
	if end > len(matched) {
		end = len(matched)
	}
	return append([]model.AuditEvent(nil), matched[q.Offset:end]...), nil
}

func eventMatchesQuery(event model.AuditEvent, q Query) bool {
	if q.AgentID != "" {
		if event.Subject == nil || event.Subject.AgentID != q.AgentID {
			return false
		}
	}
	if q.ActorID != "" {
		if event.Actor == nil || event.Actor.ID != q.ActorID {
			return false
		}
	}
	if q.Action != "" && event.Action != q.Action {
		return false
	}
	if q.Decision != "" && event.Decision != q.Decision {
		return false
	}
	if q.RequestID != "" && event.RequestID != q.RequestID {
		return false
	}
	if q.RunID != "" && event.RunID != q.RunID {
		return false
	}
	if q.ResourceType != "" {
		if event.Resource == nil || event.Resource.Type != q.ResourceType {
			return false
		}
	}
	if q.ResourceID != "" {
		if event.Resource == nil || event.Resource.ID != q.ResourceID {
			return false
		}
	}
	if !q.From.IsZero() && eventTimestamp(event).Before(q.From) {
		return false
	}
	if !q.To.IsZero() && eventTimestamp(event).After(q.To) {
		return false
	}
	return true
}

func eventTimestamp(event model.AuditEvent) time.Time {
	if event.Timestamp.IsZero() {
		return time.Time{}
	}
	return event.Timestamp.UTC()
}
