// Package postgres provides a PostgreSQL implementation of store.Store.
//
// This is the production storage backend. It persists agents, policies,
// resources, tools, and audit events to PostgreSQL with JSONB storage,
// connection pooling (pgxpool), and automatic schema migration.
//
// Usage:
//
//	s, err := postgres.New(ctx, "postgres://user:pass@localhost:5432/oap")
//	defer s.Close()
package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store"
)

// Store is a PostgreSQL-backed implementation of store.Store.
type Store struct {
	pool *pgxpool.Pool
}

// Verify interface compliance.
var _ store.Store = (*Store)(nil)
var _ store.HealthChecker = (*Store)(nil)

// New creates a Postgres store and runs schema migrations.
func New(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	s := &Store{pool: pool}
	if err := s.ensureSchema(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}

	return s, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// CheckHealth verifies that the Postgres connection pool can reach the database.
func (s *Store) CheckHealth(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: health check: %w", err)
	}
	return nil
}

// --- Agent operations ---

func (s *Store) GetAgent(ctx context.Context, agentID string) (*model.Agent, error) {
	var data []byte
	err := s.pool.QueryRow(ctx,
		`SELECT data FROM oap_agents WHERE id = $1`, agentID,
	).Scan(&data)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get agent: %w", err)
	}
	var agent model.Agent
	if err := json.Unmarshal(data, &agent); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal agent: %w", err)
	}
	return &agent, nil
}

func (s *Store) ListAgents(ctx context.Context) ([]*model.Agent, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM oap_agents ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agents: %w", err)
	}
	defer rows.Close()

	var agents []*model.Agent
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var agent model.Agent
		if err := json.Unmarshal(data, &agent); err != nil {
			return nil, err
		}
		agents = append(agents, &agent)
	}
	return agents, rows.Err()
}

func (s *Store) RegisterAgent(ctx context.Context, agent *model.Agent) error {
	data, err := json.Marshal(agent)
	if err != nil {
		return fmt.Errorf("postgres: marshal agent: %w", err)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oap_agents (id, namespace, name, data, state)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (id) DO UPDATE SET
		   data = EXCLUDED.data,
		   state = EXCLUDED.state,
		   version = oap_agents.version + 1,
		   updated_at = now()`,
		agent.ID(), agent.Metadata.Namespace, agent.Metadata.Name,
		data, agent.Status.State,
	)
	if err != nil {
		return fmt.Errorf("postgres: register agent: %w", err)
	}
	return nil
}

func (s *Store) UpdateAgentStatus(ctx context.Context, agentID string, status model.AgentStatus) error {
	// First get the agent, update status, then save
	agent, err := s.GetAgent(ctx, agentID)
	if err != nil {
		return err
	}
	if agent == nil {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	agent.Status = status
	data, err := json.Marshal(agent)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE oap_agents SET data = $1, state = $2, version = version + 1, updated_at = now() WHERE id = $3`,
		data, status.State, agentID,
	)
	if err != nil {
		return fmt.Errorf("postgres: update agent status: %w", err)
	}
	return nil
}

func (s *Store) DeleteAgent(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oap_agents WHERE id = $1`, agentID)
	if err != nil {
		return fmt.Errorf("postgres: delete agent: %w", err)
	}
	return nil
}

// --- Policy operations ---

func (s *Store) GetPolicy(ctx context.Context, policyID string) (*model.AgentPolicy, error) {
	var data []byte
	err := s.pool.QueryRow(ctx,
		`SELECT data FROM oap_policies WHERE id = $1`, policyID,
	).Scan(&data)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get policy: %w", err)
	}
	var policy model.AgentPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("postgres: unmarshal policy: %w", err)
	}
	return &policy, nil
}

func (s *Store) ListPolicies(ctx context.Context) ([]*model.AgentPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM oap_policies ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list policies: %w", err)
	}
	defer rows.Close()

	var policies []*model.AgentPolicy
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var policy model.AgentPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, err
		}
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

func (s *Store) PoliciesForAgent(ctx context.Context, agent *model.Agent) ([]*model.AgentPolicy, error) {
	// Fetch all policies and filter in-memory (same as memory store).
	// For large deployments, this can be optimized with JSONB queries.
	all, err := s.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	var matched []*model.AgentPolicy
	for _, p := range all {
		if p.MatchesAgent(agent) {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

func (s *Store) AddPolicy(ctx context.Context, policy *model.AgentPolicy) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("postgres: marshal policy: %w", err)
	}
	id := policy.ID()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oap_policies (id, namespace, name, data)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO UPDATE SET
		   data = EXCLUDED.data,
		   version = oap_policies.version + 1,
		   updated_at = now()`,
		id, policy.Metadata.Namespace, policy.Metadata.Name, data,
	)
	if err != nil {
		return fmt.Errorf("postgres: add policy: %w", err)
	}
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, policyID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oap_policies WHERE id = $1`, policyID)
	if err != nil {
		return fmt.Errorf("postgres: delete policy: %w", err)
	}
	return nil
}

// --- Resource operations ---

func (s *Store) ListResources(ctx context.Context) ([]*model.Resource, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM oap_resources ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list resources: %w", err)
	}
	defer rows.Close()

	var resources []*model.Resource
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var resource model.Resource
		if err := json.Unmarshal(data, &resource); err != nil {
			return nil, err
		}
		resources = append(resources, &resource)
	}
	return resources, rows.Err()
}

func (s *Store) AddResource(ctx context.Context, resource *model.Resource) error {
	data, err := json.Marshal(resource)
	if err != nil {
		return fmt.Errorf("postgres: marshal resource: %w", err)
	}
	id := resource.Metadata.Namespace + "/" + resource.Metadata.Name
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oap_resources (id, namespace, name, data)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		id, resource.Metadata.Namespace, resource.Metadata.Name, data,
	)
	if err != nil {
		return fmt.Errorf("postgres: add resource: %w", err)
	}
	return nil
}

// --- Tool operations ---

func (s *Store) ListTools(ctx context.Context) ([]*model.Tool, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM oap_tools ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tools: %w", err)
	}
	defer rows.Close()

	var tools []*model.Tool
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var tool model.Tool
		if err := json.Unmarshal(data, &tool); err != nil {
			return nil, err
		}
		tools = append(tools, &tool)
	}
	return tools, rows.Err()
}

func (s *Store) AddTool(ctx context.Context, tool *model.Tool) error {
	data, err := json.Marshal(tool)
	if err != nil {
		return fmt.Errorf("postgres: marshal tool: %w", err)
	}
	id := tool.Metadata.Namespace + "/" + tool.Metadata.Name
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oap_tools (id, namespace, name, data)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		id, tool.Metadata.Namespace, tool.Metadata.Name, data,
	)
	if err != nil {
		return fmt.Errorf("postgres: add tool: %w", err)
	}
	return nil
}
