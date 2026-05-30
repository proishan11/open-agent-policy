// Package session manages agent runtime sessions.
//
// A session is created when an agent workload proves its identity by presenting
// a runtime token (e.g., OIDC client_credentials JWT). OAP validates the token's
// issuer+subject against the agent's registered identity bindings and issues
// a short-lived session ID. Subsequent authorize calls use the session ID
// instead of re-validating the JWT on every request.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/proishan11/open-agent-policy/engine/store"
)

// AgentSession represents a validated runtime session.
type AgentSession struct {
	// SessionID is the opaque session token (prefixed "ags_").
	SessionID string `json:"session_id"`

	// AgentID is the verified canonical agent URI.
	AgentID string `json:"agent_id"`

	// Status is one of: "active", "expired", "revoked".
	Status string `json:"status"`

	// Mode is the enforcement mode: "enforce", "observe", "warn".
	Mode string `json:"mode"`

	// Instance describes the running workload that created this session.
	Instance *InstanceInfo `json:"instance,omitempty"`

	// CreatedAt is when the session was established.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the session becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// ExpiresIn is the session lifetime in seconds (for API responses).
	ExpiresIn int `json:"expires_in"`
}

// InstanceInfo describes the running agent workload.
type InstanceInfo struct {
	Environment string `json:"environment,omitempty"`
	Host        string `json:"host,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Pod         string `json:"pod,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
}

// CreateSessionRequest is the API input for session creation.
type CreateSessionRequest struct {
	AgentID            string        `json:"agent_id"`
	RuntimeToken       string        `json:"runtime_token"`
	WorkloadProofToken string        `json:"workload_proof_token,omitempty"`
	Environment        string        `json:"environment,omitempty"`
	Instance           *InstanceInfo `json:"instance,omitempty"`
	ProofContext       *ProofContext `json:"-"`
}

// ProofContext describes the HTTP request context used to validate
// request-bound workload proof tokens.
type ProofContext struct {
	Method      string
	TargetURI   string
	AccessToken string
}

// AgentRun represents one task/execution within a session.
// Each run has an actor (the user who triggered it) and a purpose.
type AgentRun struct {
	// RunID uniquely identifies this run (prefixed "run_").
	RunID string `json:"run_id"`

	// SessionID links this run to the parent session.
	SessionID string `json:"session_id"`

	// AgentID is inherited from the session.
	AgentID string `json:"agent_id"`

	// Actor is the human or service that triggered this run.
	Actor *RunActor `json:"actor,omitempty"`

	// Purpose describes what this run is for (e.g., "support_ticket_summary").
	Purpose string `json:"purpose,omitempty"`

	// Status is one of: "active", "completed", "failed".
	Status string `json:"status"`

	// CreatedAt is when the run started.
	CreatedAt time.Time `json:"created_at"`
}

// RunActor identifies the human or service on whose behalf the agent acts.
type RunActor struct {
	Type string `json:"type"` // "user", "service", "agent"
	ID   string `json:"id"`   // e.g., "user:alice@company.com"
}

// CreateRunRequest is the API input for creating a run.
type CreateRunRequest struct {
	SessionID string    `json:"session_id"`
	Actor     *RunActor `json:"actor,omitempty"`
	Purpose   string    `json:"purpose,omitempty"`
}

// Manager handles agent session and run lifecycle.
type Manager struct {
	store     store.Store
	validator *TokenValidator
	mu        sync.RWMutex
	sessions  map[string]*AgentSession
	runs      map[string]*AgentRun
	ttl       time.Duration
}

// ManagerConfig configures the session manager.
type ManagerConfig struct {
	// SessionTTL is how long sessions last. Default: 15 minutes.
	SessionTTL time.Duration
}

// NewManager creates a session manager backed by the given store.
func NewManager(s store.Store, cfg ManagerConfig) *Manager {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 15 * time.Minute
	}
	return &Manager{
		store:     s,
		validator: NewTokenValidator(),
		sessions:  make(map[string]*AgentSession),
		runs:      make(map[string]*AgentRun),
		ttl:       cfg.SessionTTL,
	}
}

// CreateSession validates a runtime token against the agent's identity bindings
// and creates a new session if verification succeeds.
//
// Flow:
//  1. Look up agent by ID → must be registered and active
//  2. Agent must have identity bindings configured
//  3. Validate the runtime JWT: signature, issuer, expiry, subject
//  4. Match token's issuer+subject against one of the agent's bindings
//     WIMSE bindings also require a request-bound Workload Proof Token.
//  5. Issue a short-lived session
func (m *Manager) CreateSession(ctx context.Context, req CreateSessionRequest) (*AgentSession, error) {
	// 1. Look up agent
	agent, err := m.store.GetAgent(ctx, req.AgentID)
	if err != nil {
		return nil, fmt.Errorf("store error: %w", err)
	}
	if agent == nil {
		return nil, fmt.Errorf("agent %q is not registered", req.AgentID)
	}
	if !agent.IsActive() {
		return nil, fmt.Errorf("agent %q is %s", req.AgentID, agent.Status.State)
	}

	// 2. Check identity bindings
	if len(agent.Spec.IdentityBindings) == 0 {
		return nil, fmt.Errorf("agent %q has no identity bindings configured", req.AgentID)
	}

	// 3+4. Validate token against bindings
	if err := m.validator.ValidateAgainstBindings(ctx, req.RuntimeToken, agent.Spec.IdentityBindings, ValidationContext{
		WorkloadProofToken: req.WorkloadProofToken,
		ProofContext:       req.ProofContext,
	}); err != nil {
		return nil, fmt.Errorf("identity verification failed: %w", err)
	}

	// 5. Create session
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	now := time.Now().UTC()
	ttlSeconds := int(m.ttl.Seconds())
	sess := &AgentSession{
		SessionID: sessionID,
		AgentID:   agent.ID(),
		Status:    "active",
		Mode:      "enforce",
		Instance:  req.Instance,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
		ExpiresIn: ttlSeconds,
	}

	m.mu.Lock()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	return sess, nil
}

// GetSession returns a valid session by ID.
// Returns an error if the session is not found, expired, or not active.
func (m *Manager) GetSession(sessionID string) (*AgentSession, error) {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}
	if sess.Status != "active" {
		return nil, fmt.Errorf("session is %s", sess.Status)
	}
	return sess, nil
}

// CreateRun creates a new run within a valid session.
func (m *Manager) CreateRun(req CreateRunRequest) (*AgentRun, error) {
	sess, err := m.GetSession(req.SessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}

	runID, err := generateID("run_")
	if err != nil {
		return nil, fmt.Errorf("generate run ID: %w", err)
	}

	run := &AgentRun{
		RunID:     runID,
		SessionID: sess.SessionID,
		AgentID:   sess.AgentID,
		Actor:     req.Actor,
		Purpose:   req.Purpose,
		Status:    "active",
		CreatedAt: time.Now().UTC(),
	}

	m.mu.Lock()
	m.runs[runID] = run
	m.mu.Unlock()

	return run, nil
}

// GetRun returns a run by ID.
func (m *Manager) GetRun(runID string) (*AgentRun, error) {
	m.mu.RLock()
	run, ok := m.runs[runID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("run not found")
	}
	return run, nil
}

// generateID creates a cryptographically random ID with the given prefix.
func generateID(prefix string) (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// generateSessionID creates a cryptographically random session token.
func generateSessionID() (string, error) {
	return generateID("ags_")
}
