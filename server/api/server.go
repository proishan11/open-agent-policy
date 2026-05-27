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
	"github.com/proishan11/open-agent-policy/engine/grant"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/session"
	"github.com/proishan11/open-agent-policy/engine/store"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
)

// Server is the OAP HTTP API server. It wraps the evaluator, store,
// and audit sink into HTTP handlers.
type Server struct {
	store     store.Store
	evaluator *evaluator.Evaluator
	audit     audit.Sink
	sessions  *session.Manager
	grants    *grant.Issuer
	auth      *authMiddleware
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

	// Auth configures OIDC token validation. When IssuerURL is empty, auth is disabled.
	Auth AuthConfig

	// GrantSigningKey is the HMAC-SHA256 key for signing grant tokens.
	// When empty, a random key is generated (grants won't survive restarts).
	GrantSigningKey string
}

// NewServer creates an OAP API server with the given config.
func NewServer(cfg Config) (*Server, error) {
	s := memory.New()

	// Load initial data if a directory is provided
	if cfg.DataDir != "" {
		if err := store.LoadDir(context.Background(), s, cfg.DataDir); err != nil {
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

	eval := evaluator.New(s)
	logger := log.New(log.Writer(), "[oap-server] ", log.LstdFlags)

	// Session manager — handles runtime session creation and validation.
	sessMgr := session.NewManager(s, session.ManagerConfig{})

	// Grant issuer — signs short-lived JWTs for resource-side validation.
	grantKey := cfg.GrantSigningKey
	if grantKey == "" {
		grantKey = fmt.Sprintf("oap-dev-key-%d", time.Now().UnixNano())
	}
	grantIssuer := grant.NewIssuer(grant.IssuerConfig{
		SigningKey: grantKey,
		IssuerName: "oap-server",
		DefaultTTL: 5 * time.Minute,
	})

	auth := newAuthMiddleware(cfg.Auth, sessMgr)
	if auth.enabled() {
		logger.Printf("auth enabled: issuer=%s sessions=true", cfg.Auth.IssuerURL)
	} else {
		logger.Printf("auth disabled (no --issuer flag, no identity bindings)")
	}

	srv := &Server{
		store:     s,
		evaluator: eval,
		audit:     auditSink,
		sessions:  sessMgr,
		grants:    grantIssuer,
		auth:      auth,
		mux:       http.NewServeMux(),
		logger:    logger,
	}

	srv.routes()
	return srv, nil
}

// routes registers all HTTP handlers.
func (s *Server) routes() {
	// Runtime session — agent proves identity, gets session token
	s.mux.HandleFunc("POST /v1/runtime/session", s.handleCreateSession)

	// Runs — create a task/execution within a session
	s.mux.HandleFunc("POST /v1/runs", s.auth.wrap(s.handleCreateRun))

	// Protected endpoints — require valid session or JWT token when auth is enabled
	s.mux.HandleFunc("POST /v1/authorize", s.auth.wrap(s.handleAuthorize))
	s.mux.HandleFunc("POST /v1/agents", s.auth.wrap(s.handleRegisterAgent))

	// Grant validation — resource APIs call this to verify OAP grants
	s.mux.HandleFunc("POST /v1/grants/validate", s.handleValidateGrant)

	// Management endpoints (unprotected for now)
	s.mux.HandleFunc("POST /v1/simulate", s.handleSimulate)
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

// handleCreateSession validates a runtime token against the agent's identity
// bindings and creates a short-lived session. The returned session_id is used
// as the Bearer token for subsequent authorize calls.
//
// POST /v1/runtime/session
//
//	{
//	  "agent_id": "agent://support/ticket-assistant",
//	  "runtime_token": "<OIDC JWT from IdP>",
//	  "instance": { "environment": "production", "pod": "..." }
//	}
func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req session.CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}

	if req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "agent_id is required")
		return
	}
	if req.RuntimeToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "runtime_token is required")
		return
	}

	sess, err := s.sessions.CreateSession(r.Context(), req)
	if err != nil {
		s.logger.Printf("session creation failed for %s: %v", req.AgentID, err)
		writeError(w, http.StatusUnauthorized, "session_failed", err.Error())
		return
	}

	s.logger.Printf("session created: %s for agent %s (expires in %ds)",
		sess.SessionID, sess.AgentID, sess.ExpiresIn)

	writeJSON(w, http.StatusCreated, sess)
}

// handleCreateRun creates a new run (task/execution) within an active session.
//
// POST /v1/runs
//
//	{
//	  "session_id": "ags_...",
//	  "actor": { "type": "user", "id": "alice@company.com" },
//	  "purpose": "support_ticket_summary"
//	}
func (s *Server) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	var req session.CreateRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}

	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "session_id is required")
		return
	}

	run, err := s.sessions.CreateRun(req)
	if err != nil {
		s.logger.Printf("run creation failed: %v", err)
		writeError(w, http.StatusBadRequest, "run_failed", err.Error())
		return
	}

	s.logger.Printf("run created: %s for agent %s (session %s)",
		run.RunID, run.AgentID, run.SessionID)

	writeJSON(w, http.StatusCreated, run)
}

// handleAuthorize is the core decision endpoint. It evaluates an authorization
// request and returns a structured decision. On allow, it issues a scoped
// grant token that the agent can present to the resource API.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req model.AuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}

	// Override agent_id with cryptographically verified identity from token.
	// This prevents callers from claiming to be a different agent.
	if verifiedID, ok := VerifiedAgentID(r.Context()); ok {
		if req.Subject.AgentID != "" && req.Subject.AgentID != verifiedID {
			s.logger.Printf("WARN: agent_id mismatch: token=%s request=%s (using token)",
				verifiedID, req.Subject.AgentID)
		}
		req.Subject.AgentID = verifiedID
	}

	result := s.evaluator.Evaluate(r.Context(), req)
	dec := result.Decision

	// Issue scoped grant on allow decisions
	if dec.Decision == model.DecisionAllow || dec.Decision == model.DecisionAllowConstrained {
		var resType, resID string
		if req.Resource != nil {
			resType = req.Resource.Type
			resID = req.Resource.ID
		}
		var runID string
		if req.Context != nil {
			runID, _ = req.Context["run_id"].(string)
		}

		token, err := s.grants.IssueScoped(grant.GrantRequest{
			AgentID:      req.Subject.AgentID,
			Action:       req.Action.Name,
			ResourceType: resType,
			ResourceID:   resID,
			RunID:        runID,
			Decision:     dec,
		})
		if err != nil {
			s.logger.Printf("ERROR: grant issuance failed: %v", err)
		} else {
			dec.Grant = &model.GrantRef{
				GrantID:          dec.DecisionID,
				Token:            token,
				ExpiresInSeconds: 300, // 5 minutes
			}
		}
	}

	// Emit audit event
	s.emitAuditEvent(req, dec)

	writeJSON(w, http.StatusOK, dec)
}

// handleValidateGrant validates a grant token presented by a resource API.
// Resource APIs call this to verify the agent is authorized before
// serving the request.
//
// POST /v1/grants/validate
//
//	{ "grant_token": "<JWT>" }
func (s *Server) handleValidateGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GrantToken string `json:"grant_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	if req.GrantToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "grant_token is required")
		return
	}

	claims, err := s.grants.Verify(req.GrantToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_grant", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":         true,
		"agent_id":      claims.Subject,
		"action":        claims.Action,
		"resource_type": claims.ResourceType,
		"resource_id":   claims.ResourceID,
		"decision":      claims.Decision,
		"constraints":   claims.Constraints,
		"run_id":        claims.RunID,
		"expires_at":    claims.ExpiresAt,
	})
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

	if err := s.store.RegisterAgent(r.Context(), &agent); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	s.logger.Printf("registered agent %s", agent.ID())

	writeJSON(w, http.StatusCreated, agent)
}

// handleListAgents returns all registered agents.
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
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
	existing, _ := s.store.GetPolicy(r.Context(), policy.ID())
	if err := s.store.AddPolicy(r.Context(), &policy); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	s.logger.Printf("applied policy %s", policy.ID())

	if existing != nil {
		writeJSON(w, http.StatusOK, policy)
	} else {
		writeJSON(w, http.StatusCreated, policy)
	}
}

// handleListPolicies returns all registered policies.
func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
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
	agents, _ := s.store.ListAgents(r.Context())
	policies, _ := s.store.ListPolicies(r.Context())
	resp := map[string]interface{}{
		"status":         "healthy",
		"version":        "v1alpha1",
		"agents_count":   len(agents),
		"policies_count": len(policies),
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

// Store returns the underlying store (for CLI and testing).
func (s *Server) Store() store.Store {
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
