package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/proishan11/open-agent-policy/engine/model"
	"gopkg.in/yaml.v3"
)

// Store is the top-level registry holding agents, resources, tools, and policies.
// It is safe for concurrent read access. Write operations (Register/Add methods)
// are protected by a mutex.
type Store struct {
	mu        sync.RWMutex
	agents    map[string]*model.Agent       // key: agent ID (agent://ns/name)
	resources map[string]*model.Resource    // key: ns/name
	tools     map[string]*model.Tool        // key: ns/name
	policies  map[string]*model.AgentPolicy // key: ns/name
}

// NewStore creates an empty registry store.
func NewStore() *Store {
	return &Store{
		agents:    make(map[string]*model.Agent),
		resources: make(map[string]*model.Resource),
		tools:     make(map[string]*model.Tool),
		policies:  make(map[string]*model.AgentPolicy),
	}
}

// --- Agent operations ---

// RegisterAgent adds or updates an agent in the registry.
// If the agent already exists, it is replaced.
func (s *Store) RegisterAgent(agent *model.Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agent.ID()] = agent
}

// GetAgent returns an agent by its canonical ID (e.g., "agent://finance/invoice-reconciler").
// Returns nil if the agent is not registered.
func (s *Store) GetAgent(agentID string) *model.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agents[agentID]
}

// ListAgents returns all registered agents.
func (s *Store) ListAgents() []*model.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, a)
	}
	return result
}

// --- Policy operations ---

// AddPolicy adds or updates a policy in the registry.
func (s *Store) AddPolicy(policy *model.AgentPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.ID()] = policy
}

// GetPolicy returns a policy by namespace/name.
func (s *Store) GetPolicy(id string) *model.AgentPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policies[id]
}

// PoliciesForAgent returns all policies whose subject selector matches the given agent.
// This is the main query used by the evaluator.
func (s *Store) PoliciesForAgent(agent *model.Agent) []*model.AgentPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched []*model.AgentPolicy
	for _, p := range s.policies {
		if p.MatchesAgent(agent) {
			matched = append(matched, p)
		}
	}
	return matched
}

// ListPolicies returns all registered policies.
func (s *Store) ListPolicies() []*model.AgentPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.AgentPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		result = append(result, p)
	}
	return result
}

// --- Resource operations ---

// AddResource adds or updates a resource in the registry.
func (s *Store) AddResource(resource *model.Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := resource.Metadata.Namespace + "/" + resource.Metadata.Name
	s.resources[key] = resource
}

// ListResources returns all registered resources.
func (s *Store) ListResources() []*model.Resource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.Resource, 0, len(s.resources))
	for _, r := range s.resources {
		result = append(result, r)
	}
	return result
}

// --- Tool operations ---

// AddTool adds or updates a tool in the registry.
func (s *Store) AddTool(tool *model.Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tool.Metadata.Namespace + "/" + tool.Metadata.Name
	s.tools[key] = tool
}

// ListTools returns all registered tools.
func (s *Store) ListTools() []*model.Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.Tool, 0, len(s.tools))
	for _, t := range s.tools {
		result = append(result, t)
	}
	return result
}

// --- File loading ---

// LoadDir loads all YAML and JSON files from a directory (recursive) into
// the registry. Each file must contain a top-level "kind" field to route it
// to the correct sub-registry. Unrecognized kinds are silently skipped.
//
// Supported kinds: Agent, Resource, Tool, AgentPolicy.
func (s *Store) LoadDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		if loadErr := s.LoadFile(path); loadErr != nil {
			return fmt.Errorf("loading %s: %w", path, loadErr)
		}
		return nil
	})
}

// LoadFile loads a single YAML or JSON file into the registry.
func (s *Store) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	// Peek at the "kind" field to determine which type to unmarshal into.
	var peek struct {
		Kind string `json:"kind" yaml:"kind"`
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &peek); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	default: // .yaml, .yml
		if err := yaml.Unmarshal(data, &peek); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	switch peek.Kind {
	case "Agent":
		var agent model.Agent
		if err := unmarshal(data, ext, &agent); err != nil {
			return err
		}
		// Set default status if not provided
		if agent.Status.State == "" {
			agent.Status.State = model.AgentStateActive
		}
		s.RegisterAgent(&agent)

	case "Resource":
		var resource model.Resource
		if err := unmarshal(data, ext, &resource); err != nil {
			return err
		}
		s.AddResource(&resource)

	case "Tool":
		var tool model.Tool
		if err := unmarshal(data, ext, &tool); err != nil {
			return err
		}
		s.AddTool(&tool)

	case "AgentPolicy":
		var policy model.AgentPolicy
		if err := unmarshal(data, ext, &policy); err != nil {
			return err
		}
		s.AddPolicy(&policy)

	default:
		// Skip files with unrecognized or empty kinds (e.g., request files, READMEs)
		return nil
	}

	return nil
}

// unmarshal deserializes data based on file extension.
func unmarshal(data []byte, ext string, v interface{}) error {
	switch ext {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		return dec.Decode(v)
	default:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		return dec.Decode(v)
	}
}
