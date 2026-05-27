// Package memory provides an in-memory implementation of store.Store.
//
// This is the default backend for development and single-instance deployments.
// It wraps the existing registry.Store with the new store.Store interface.
package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store"
)

// Store is an in-memory implementation of store.Store.
type Store struct {
	mu        sync.RWMutex
	agents    map[string]*model.Agent
	resources map[string]*model.Resource
	tools     map[string]*model.Tool
	policies  map[string]*model.AgentPolicy
}

// Verify interface compliance.
var _ store.Store = (*Store)(nil)

// New creates an empty in-memory store.
func New() *Store {
	return &Store{
		agents:    make(map[string]*model.Agent),
		resources: make(map[string]*model.Resource),
		tools:     make(map[string]*model.Tool),
		policies:  make(map[string]*model.AgentPolicy),
	}
}

// --- Agent operations ---

func (s *Store) GetAgent(_ context.Context, agentID string) (*model.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[agentID]
	if !ok {
		return nil, nil
	}
	return a, nil
}

func (s *Store) ListAgents(_ context.Context) ([]*model.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, a)
	}
	return result, nil
}

func (s *Store) RegisterAgent(_ context.Context, agent *model.Agent) error {
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agent.ID()] = agent
	return nil
}

func (s *Store) UpdateAgentStatus(_ context.Context, agentID string, status model.AgentStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	agent.Status = status
	return nil
}

func (s *Store) DeleteAgent(_ context.Context, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, agentID)
	return nil
}

// --- Policy operations ---

func (s *Store) GetPolicy(_ context.Context, policyID string) (*model.AgentPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (s *Store) ListPolicies(_ context.Context) ([]*model.AgentPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.AgentPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		result = append(result, p)
	}
	return result, nil
}

func (s *Store) PoliciesForAgent(_ context.Context, agent *model.Agent) ([]*model.AgentPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched []*model.AgentPolicy
	for _, p := range s.policies {
		if p.MatchesAgent(agent) {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

func (s *Store) AddPolicy(_ context.Context, policy *model.AgentPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.ID()] = policy
	return nil
}

func (s *Store) DeletePolicy(_ context.Context, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, policyID)
	return nil
}

// --- Resource operations ---

func (s *Store) ListResources(_ context.Context) ([]*model.Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.Resource, 0, len(s.resources))
	for _, r := range s.resources {
		result = append(result, r)
	}
	return result, nil
}

func (s *Store) AddResource(_ context.Context, resource *model.Resource) error {
	if resource == nil {
		return fmt.Errorf("resource is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := resource.Metadata.Namespace + "/" + resource.Metadata.Name
	s.resources[key] = resource
	return nil
}

// --- Tool operations ---

func (s *Store) ListTools(_ context.Context) ([]*model.Tool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.Tool, 0, len(s.tools))
	for _, t := range s.tools {
		result = append(result, t)
	}
	return result, nil
}

func (s *Store) AddTool(_ context.Context, tool *model.Tool) error {
	if tool == nil {
		return fmt.Errorf("tool is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tool.Metadata.Namespace + "/" + tool.Metadata.Name
	s.tools[key] = tool
	return nil
}
