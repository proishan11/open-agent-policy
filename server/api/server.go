package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/evaluator"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/registry"
)

// Server is the OAP HTTP API server. It wraps the evaluator, registry,
// and audit sink into HTTP handlers.
type Server struct {
	store     *registry.Store
	evaluator *evaluator.Evaluator
	audit     audit.Sink
	mux       *http.ServeMux
	logger    *log.Logger
}

// Config holds server configuration.
type Config struct {
	// Addr is the listen address (e.g., ":8080").
	Addr string

	// DataDir is a directory of YAML/JSON files to load on startup (agents, policies).
	DataDir string

	// AuditFile is the path for the JSONL audit log. If empty, stdout is used.
	AuditFile string

	// DevMode enables development features (relaxed validation, verbose logging).
	DevMode bool
}

// NewServer creates an OAP API server with the given config.
func NewServer(cfg Config) (*Server, error) {
	store := registry.NewStore()

	// Load initial data if a directory is provided
	if cfg.DataDir != "" {
		if err := store.LoadDir(cfg.DataDir); err != nil {
			return nil, fmt.Errorf("loading data dir %s: %w", cfg.DataDir, err)
		}
	}

	// Set up audit sink
	var auditSink audit.Sink
	if cfg.AuditFile != "" {
		sink, err := audit.NewJSONLSink(cfg.AuditFile)
		if err != nil {
			return nil, fmt.Errorf("creating audit sink: %w", err)
		}
		auditSink = sink
	} else {
		auditSink = audit.NewStdoutSink()
	}

	eval := evaluator.New(store)
	logger := log.New(log.Writer(), "[oap-server] ", log.LstdFlags)

	s := &Server{
		store:     store,
		evaluator: eval,
		audit:     auditSink,
		mux:       http.NewServeMux(),
		logger:    logger,
	}

	s.routes()
	return s, nil
}

// routes registers all HTTP handlers.
func (s *Server) routes() {
	s.mux.HandleFunc("POST /v1/authorize", s.handleAuthorize)
	s.mux.HandleFunc("POST /v1/simulate", s.handleSimulate)
	s.mux.HandleFunc("POST /v1/agents", s.handleRegisterAgent)
	s.mux.HandleFunc("GET /v1/agents", s.handleListAgents)
	s.mux.HandleFunc("POST /v1/policies", s.handleApplyPolicy)
	s.mux.HandleFunc("GET /v1/policies", s.handleListPolicies)
	s.mux.HandleFunc("GET /v1/audit", s.handleQueryAudit)
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
}

// Handler returns the HTTP handler (for use with http.Server).
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Close releases server resources (flushes audit sink, etc.).
func (s *Server) Close() error {
	return s.audit.Close()
}

// --- Handlers ---

// handleAuthorize is the core decision endpoint. It evaluates an authorization
// request and returns a structured decision.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req model.AuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}

	result := s.evaluator.Evaluate(r.Context(), req)

	// Emit audit event
	s.emitAuditEvent(req, result.Decision)

	writeJSON(w, http.StatusOK, result.Decision)
}

// handleSimulate is the dry-run endpoint. Same evaluation as authorize but
// includes the evaluation trace and does NOT emit audit events.
func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	var req model.AuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}

	result := s.evaluator.Evaluate(r.Context(), req)

	// Return decision + trace (no audit event emitted)
	resp := map[string]interface{}{
		"decision": result.Decision,
		"trace":    result.Trace,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRegisterAgent registers a new agent or updates an existing one.
func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var agent model.Agent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}

	if agent.Metadata.Name == "" || agent.Metadata.Namespace == "" {
		writeError(w, http.StatusBadRequest, "invalid_agent", "metadata.name and metadata.namespace are required")
		return
	}

	// Set defaults
	if agent.Status.State == "" {
		agent.Status.State = model.AgentStateActive
	}
	agent.Status.RegisteredAt = time.Now().UTC()

	s.store.RegisterAgent(&agent)
	s.logger.Printf("registered agent %s", agent.ID())

	writeJSON(w, http.StatusCreated, agent)
}

// handleListAgents returns all registered agents.
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents := s.store.ListAgents()
	resp := map[string]interface{}{
		"items": agents,
		"total": len(agents),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleApplyPolicy creates or updates a policy (idempotent).
func (s *Server) handleApplyPolicy(w http.ResponseWriter, r *http.Request) {
	var policy model.AgentPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}

	if policy.Metadata.Name == "" || policy.Metadata.Namespace == "" {
		writeError(w, http.StatusBadRequest, "invalid_policy", "metadata.name and metadata.namespace are required")
		return
	}

	// Check if policy already exists (for correct status code)
	existing := s.store.GetPolicy(policy.ID())
	s.store.AddPolicy(&policy)
	s.logger.Printf("applied policy %s", policy.ID())

	if existing != nil {
		writeJSON(w, http.StatusOK, policy)
	} else {
		writeJSON(w, http.StatusCreated, policy)
	}
}

// handleListPolicies returns all registered policies.
func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.store.ListPolicies()
	resp := map[string]interface{}{
		"items": policies,
		"total": len(policies),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleQueryAudit returns audit events. Currently returns a placeholder
// since audit events are written to the sink, not stored in-memory.
func (s *Server) handleQueryAudit(w http.ResponseWriter, r *http.Request) {
	// For the memory sink in tests, we could return events.
	// For file sinks, this would need a reader. Placeholder for now.
	resp := map[string]interface{}{
		"items": []interface{}{},
		"total": 0,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHealth returns server health information.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":         "healthy",
		"version":        "v1alpha1",
		"agents_count":   len(s.store.ListAgents()),
		"policies_count": len(s.store.ListPolicies()),
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- Helpers ---

// emitAuditEvent builds and writes an audit event from the request and decision.
func (s *Server) emitAuditEvent(req model.AuthorizationRequest, dec model.AuthorizationDecision) {
	event := model.AuditEvent{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		EventType: "authorization.decision",
		Timestamp: time.Now().UTC(),
		Decision:  dec.Decision,
		Subject: &model.AuditSubject{
			AgentID:    req.Subject.AgentID,
			InstanceID: req.Subject.InstanceID,
		},
		Action:    req.Action.Name,
		PolicyIDs: dec.PolicyIDs,
		RequestID: req.RequestID,
		Reason:    dec.Reason,
	}

	if req.Actor != nil {
		event.Actor = &model.AuditActor{
			Type: req.Actor.Type,
			ID:   req.Actor.ID,
		}
	}

	if req.Resource != nil {
		event.Resource = &model.AuditResource{
			Type: req.Resource.Type,
			ID:   req.Resource.ID,
		}
	}

	if req.Context != nil {
		if runID, ok := req.Context["run_id"].(string); ok {
			event.RunID = runID
		}
	}

	if err := s.audit.Write(event); err != nil {
		s.logger.Printf("ERROR: failed to write audit event: %v", err)
	}
}

// writeJSON encodes v as JSON and writes it to the response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a structured JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"code":    code,
		"message": message,
	})
}

// Store returns the underlying registry store (for CLI and testing).
func (s *Server) Store() *registry.Store {
	return s.store
}

// Evaluator returns the underlying evaluator (for CLI and testing).
func (s *Server) Evaluator() *evaluator.Evaluator {
	return s.evaluator
}

// SetAuditSink replaces the audit sink (for testing).
func (s *Server) SetAuditSink(sink audit.Sink) {
	s.audit = sink
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	httpServer := &http.Server{
		Addr:    addr,
		Handler: s.mux,
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Printf("listening on %s", addr)
	return httpServer.ListenAndServe()
}
