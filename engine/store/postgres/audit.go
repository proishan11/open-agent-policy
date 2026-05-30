package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/model"
)

// AuditSink persists structured audit events into the Postgres audit table and
// supports indexed query filters for the server API.
type AuditSink struct {
	store *Store
}

var _ audit.Sink = (*AuditSink)(nil)
var _ audit.Querier = (*AuditSink)(nil)

// NewAuditSink creates an audit sink backed by the given Postgres store.
func NewAuditSink(store *Store) *AuditSink {
	return &AuditSink{store: store}
}

func (s *AuditSink) Write(event model.AuditEvent) error {
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("postgres audit: marshal event: %w", err)
	}

	var agentID, actorID, resourceType, resourceID string
	if event.Subject != nil {
		agentID = event.Subject.AgentID
	}
	if event.Actor != nil {
		actorID = event.Actor.ID
	}
	if event.Resource != nil {
		resourceType = event.Resource.Type
		resourceID = event.Resource.ID
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = s.store.pool.Exec(ctx,
		`INSERT INTO oap_audit_events (
			id, agent_id, actor_id, action, decision, request_id, run_id,
			resource_type, resource_id, data, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO NOTHING`,
		event.EventID,
		agentID,
		actorID,
		event.Action,
		event.Decision,
		event.RequestID,
		event.RunID,
		resourceType,
		resourceID,
		data,
		event.Timestamp.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres audit: insert event: %w", err)
	}
	return nil
}

func (s *AuditSink) Query(ctx context.Context, query audit.Query) ([]model.AuditEvent, error) {
	query = query.Normalize()
	clauses := make([]string, 0, 10)
	args := make([]interface{}, 0, 12)

	addClause := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("%s = $%d", column, len(args)))
	}

	addClause("agent_id", query.AgentID)
	addClause("actor_id", query.ActorID)
	addClause("action", query.Action)
	addClause("decision", query.Decision)
	addClause("request_id", query.RequestID)
	addClause("run_id", query.RunID)
	addClause("resource_type", query.ResourceType)
	addClause("resource_id", query.ResourceID)

	if !query.From.IsZero() {
		args = append(args, query.From.UTC())
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !query.To.IsZero() {
		args = append(args, query.To.UTC())
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", len(args)))
	}

	sql := "SELECT data FROM oap_audit_events"
	if len(clauses) > 0 {
		sql += " WHERE " + strings.Join(clauses, " AND ")
	}

	args = append(args, query.Limit)
	limitParam := len(args)
	args = append(args, query.Offset)
	offsetParam := len(args)
	sql += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", limitParam, offsetParam)

	rows, err := s.store.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres audit: query events: %w", err)
	}
	defer rows.Close()

	events := make([]model.AuditEvent, 0, query.Limit)
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("postgres audit: scan event: %w", err)
		}
		var event model.AuditEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, fmt.Errorf("postgres audit: unmarshal event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres audit: read events: %w", err)
	}
	return events, nil
}

func (s *AuditSink) Close() error {
	return nil
}
