package audit

import (
	"context"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
)

const (
	DefaultQueryLimit = 100
	MaxQueryLimit     = 200
)

// Query filters audit events for management/API reads.
type Query struct {
	AgentID      string
	ActorID      string
	Action       string
	Decision     string
	RequestID    string
	RunID        string
	ResourceType string
	ResourceID   string
	From         time.Time
	To           time.Time
	Limit        int
	Offset       int
}

// Normalize applies safe pagination defaults and caps.
func (q Query) Normalize() Query {
	if q.Limit <= 0 {
		q.Limit = DefaultQueryLimit
	}
	if q.Limit > MaxQueryLimit {
		q.Limit = MaxQueryLimit
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	return q
}

// Querier is implemented by audit sinks that can read back persisted events.
type Querier interface {
	Query(ctx context.Context, q Query) ([]model.AuditEvent, error)
}
