// Package store defines the pluggable storage interface for OAP.
//
// All OAP components (evaluator, server, bundle) depend on this interface
// rather than on a concrete implementation. This allows swapping backends:
//
//   - memory.Store: In-memory (default, development, single-instance)
//   - postgres.Store: PostgreSQL (production, persistence, multi-instance)
//   - redis.CachedStore: Redis cache wrapping any other store (optional, scale)
//
// The interface is deliberately minimal — only methods the evaluator and
// server actually call are included.
package store

import (
	"context"

	"github.com/proishan11/open-agent-policy/engine/model"
)

// Store is the persistence interface for OAP agents, policies, resources, and tools.
// All methods are safe for concurrent use.
type Store interface {
	// --- Agent operations ---

	// GetAgent returns an agent by canonical ID (e.g., "agent://ns/name").
	// Returns nil, nil if not found.
	GetAgent(ctx context.Context, agentID string) (*model.Agent, error)

	// ListAgents returns all registered agents.
	ListAgents(ctx context.Context) ([]*model.Agent, error)

	// RegisterAgent creates or replaces an agent.
	RegisterAgent(ctx context.Context, agent *model.Agent) error

	// UpdateAgentStatus updates only the agent's status (e.g., suspend, revoke).
	UpdateAgentStatus(ctx context.Context, agentID string, status model.AgentStatus) error

	// DeleteAgent removes an agent.
	DeleteAgent(ctx context.Context, agentID string) error

	// --- Policy operations ---

	// GetPolicy returns a policy by its ID (namespace/name).
	// Returns nil, nil if not found.
	GetPolicy(ctx context.Context, policyID string) (*model.AgentPolicy, error)

	// ListPolicies returns all policies.
	ListPolicies(ctx context.Context) ([]*model.AgentPolicy, error)

	// PoliciesForAgent returns all policies matching the given agent.
	PoliciesForAgent(ctx context.Context, agent *model.Agent) ([]*model.AgentPolicy, error)

	// AddPolicy creates or replaces a policy.
	AddPolicy(ctx context.Context, policy *model.AgentPolicy) error

	// DeletePolicy removes a policy.
	DeletePolicy(ctx context.Context, policyID string) error

	// --- Resource operations ---

	// ListResources returns all registered resources.
	ListResources(ctx context.Context) ([]*model.Resource, error)

	// AddResource creates or replaces a resource.
	AddResource(ctx context.Context, resource *model.Resource) error

	// --- Tool operations ---

	// ListTools returns all registered tools.
	ListTools(ctx context.Context) ([]*model.Tool, error)

	// AddTool creates or replaces a tool.
	AddTool(ctx context.Context, tool *model.Tool) error
}
