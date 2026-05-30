package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/evaluator"
	policybackend "github.com/proishan11/open-agent-policy/engine/evaluator/backend"
	"github.com/proishan11/open-agent-policy/engine/grant"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/session"
	"github.com/proishan11/open-agent-policy/engine/store"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
	"github.com/proishan11/open-agent-policy/engine/store/postgres"
)

// Server is the OAP HTTP API server. It wraps the evaluator, store,
// and audit sink into HTTP handlers.
type Server struct {
	store      store.Store
	evaluator  *evaluator.Evaluator
	audit      audit.Sink
	auditRead  audit.Querier
	sessions   *session.Manager
	grants     *grant.Issuer
	auth       *authMiddleware
	mux        *http.ServeMux
	logger     *log.Logger
	closeStore func()

	storeBackend     string
	policyBackend    string
	readinessTimeout time.Duration
	metrics          *serverMetrics
}

// Config holds server configuration.
type Config struct {
	// Addr is the listen address (e.g., ":8080").
	Addr string

	// DataDir is a directory of YAML/JSON files to load on startup (agents, policies).
	DataDir string

	// AuditFile is the path for the JSONL audit log. If empty, stdout is used.
	// In Postgres mode, an audit file is written in addition to durable storage.
	AuditFile string

	// Store optionally injects a storage backend. When nil, StoreBackend is used.
	Store store.Store

	// StoreBackend selects the built-in store backend: "memory" or "postgres".
	StoreBackend string

	// PostgresDSN is required when StoreBackend is "postgres".
	PostgresDSN string

	// AuditSink optionally injects an audit sink. When it implements audit.Querier,
	// GET /v1/audit will query that sink.
	AuditSink audit.Sink

	// ReadinessTimeout bounds dependency checks for /v1/ready.
	// Defaults to 2 seconds.
	ReadinessTimeout time.Duration

	// DevMode enables development features (relaxed validation, verbose logging).
	DevMode bool

	// Auth configures OIDC token validation. When IssuerURL is empty, auth is disabled.
	Auth AuthConfig

	// GrantSigningKey is the HMAC-SHA256 key for signing grant tokens.
	// When empty, a random key is generated (grants won't survive restarts).
	GrantSigningKey string

	// PolicyBackend selects the rule evaluation backend: "builtin", "opa", or "cedar".
	// Built-in is the default and has no external dependency.
	PolicyBackend string

	// OPAURL is required when PolicyBackend is "opa".
	OPAURL string

	// OPAPolicyPath is the OPA data API path to query.
	// Defaults to "v1/data/oap/authz".
	OPAPolicyPath string

	// OPATimeout bounds OPA backend calls. Defaults to the backend default.
	OPATimeout time.Duration

	// OPAFailOpen falls back to the built-in evaluator if OPA is unreachable.
	// Default behavior is fail-closed.
	OPAFailOpen bool

	// CedarURL is required when PolicyBackend is "cedar".
	CedarURL string

	// CedarPolicyStoreID optionally identifies an AWS Verified Permissions store.
	CedarPolicyStoreID string

	// CedarTimeout bounds Cedar backend calls. Defaults to the backend default.
	CedarTimeout time.Duration

	// CedarFailOpen falls back to the built-in evaluator if Cedar is unreachable.
	// Default behavior is fail-closed.
	CedarFailOpen bool
}

// NewServer creates an OAP API server with the given config.
func NewServer(cfg Config) (*Server, error) {
	logger := log.New(log.Writer(), "[oap-server] ", log.LstdFlags)
	now := time.Now().UTC()

	registry, pgStore, closeStore, storeBackend, err := newRegistryStore(cfg)
	if err != nil {
		return nil, err
	}

	// Load initial data if a directory is provided
	if cfg.DataDir != "" {
		if err := store.LoadDir(context.Background(), registry, cfg.DataDir); err != nil {
			if closeStore != nil {
				closeStore()
			}
			return nil, fmt.Errorf("loading data dir %s: %w", cfg.DataDir, err)
		}
	}

	auditSink, auditRead, err := newAuditSink(cfg, pgStore)
	if err != nil {
		if closeStore != nil {
			closeStore()
		}
		return nil, err
	}

	ruleBackend, policyBackendName, err := newPolicyBackend(cfg)
	if err != nil {
		if auditSink != nil {
			_ = auditSink.Close()
		}
		if closeStore != nil {
			closeStore()
		}
		return nil, err
	}
	eval := evaluator.New(registry, evaluator.WithBackend(ruleBackend))

	// Session manager — handles runtime session creation and validation.
	sessMgr := session.NewManager(registry, session.ManagerConfig{})

	// Grant issuer — signs short-lived JWTs for resource-side validation.
	grantKey := cfg.GrantSigningKey
	if grantKey == "" {
		grantKey = fmt.Sprintf("oap-dev-key-%d", now.UnixNano())
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
	logger.Printf("policy backend: %s", policyBackendName)

	readinessTimeout := cfg.ReadinessTimeout
	if readinessTimeout <= 0 {
		readinessTimeout = 2 * time.Second
	}

	srv := &Server{
		store:            registry,
		evaluator:        eval,
		audit:            auditSink,
		auditRead:        auditRead,
		sessions:         sessMgr,
		grants:           grantIssuer,
		auth:             auth,
		mux:              http.NewServeMux(),
		logger:           logger,
		closeStore:       closeStore,
		storeBackend:     storeBackend,
		policyBackend:    policyBackendName,
		readinessTimeout: readinessTimeout,
		metrics:          newServerMetrics(now),
	}

	srv.routes()
	return srv, nil
}

func newRegistryStore(cfg Config) (store.Store, *postgres.Store, func(), string, error) {
	if cfg.Store != nil {
		pgStore, _ := cfg.Store.(*postgres.Store)
		backend := "custom"
		if pgStore != nil {
			backend = "postgres"
		}
		return cfg.Store, pgStore, nil, backend, nil
	}

	backend := strings.ToLower(strings.TrimSpace(cfg.StoreBackend))
	if backend == "" {
		backend = "memory"
	}

	switch backend {
	case "memory":
		return memory.New(), nil, nil, "memory", nil
	case "postgres":
		if cfg.PostgresDSN == "" {
			return nil, nil, nil, "", fmt.Errorf("postgres store requires PostgresDSN")
		}
		pgStore, err := postgres.New(context.Background(), cfg.PostgresDSN)
		if err != nil {
			return nil, nil, nil, "", err
		}
		return pgStore, pgStore, pgStore.Close, "postgres", nil
	default:
		return nil, nil, nil, "", fmt.Errorf("unsupported store backend %q", cfg.StoreBackend)
	}
}

func newPolicyBackend(cfg Config) (policybackend.Backend, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.PolicyBackend))
	if backend == "" {
		backend = "builtin"
	}

	switch backend {
	case "builtin", "native":
		return nil, "builtin", nil
	case "opa":
		opaURL := strings.TrimRight(strings.TrimSpace(cfg.OPAURL), "/")
		if opaURL == "" {
			return nil, "", fmt.Errorf("opa policy backend requires OPAURL")
		}
		opaPath := strings.Trim(strings.TrimSpace(cfg.OPAPolicyPath), "/")
		return policybackend.NewOPABackend(policybackend.OPAConfig{
			URL:        opaURL,
			PolicyPath: opaPath,
			Timeout:    cfg.OPATimeout,
			FailOpen:   cfg.OPAFailOpen,
		}), "opa", nil
	case "cedar":
		cedarURL := strings.TrimSpace(cfg.CedarURL)
		if cedarURL == "" {
			return nil, "", fmt.Errorf("cedar policy backend requires CedarURL")
		}
		return policybackend.NewCedarBackend(policybackend.CedarConfig{
			URL:           cedarURL,
			PolicyStoreID: cfg.CedarPolicyStoreID,
			Timeout:       cfg.CedarTimeout,
			FailOpen:      cfg.CedarFailOpen,
		}), "cedar", nil
	default:
		return nil, "", fmt.Errorf("unsupported policy backend %q", cfg.PolicyBackend)
	}
}

func newAuditSink(cfg Config, pgStore *postgres.Store) (audit.Sink, audit.Querier, error) {
	if cfg.AuditSink != nil {
		query, _ := cfg.AuditSink.(audit.Querier)
		return cfg.AuditSink, query, nil
	}

	if pgStore != nil {
		pgAudit := postgres.NewAuditSink(pgStore)
		if cfg.AuditFile == "" {
			return pgAudit, pgAudit, nil
		}
		fileSink, err := audit.NewJSONLSink(cfg.AuditFile)
		if err != nil {
			return nil, nil, fmt.Errorf("creating audit sink: %w", err)
		}
		return audit.NewMultiSink(pgAudit, fileSink), pgAudit, nil
	}

	if cfg.AuditFile != "" {
		sink, err := audit.NewJSONLSink(cfg.AuditFile)
		if err != nil {
			return nil, nil, fmt.Errorf("creating audit sink: %w", err)
		}
		return sink, nil, nil
	}

	return audit.NewStdoutSink(), nil, nil
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
	s.mux.HandleFunc("GET /v1/ready", s.handleReady)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
}

// Handler returns the HTTP handler (for use with http.Server).
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Close releases server resources (flushes audit sink, etc.).
func (s *Server) Close() error {
	var err error
	if s.audit != nil {
		err = s.audit.Close()
	}
	if s.closeStore != nil {
		s.closeStore()
	}
	return err
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
//	  "workload_proof_token": "<optional WIMSE WPT>",
//	  "instance": { "environment": "production", "pod": "..." }
//	}
func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req session.CreateSessionRequest
	if err := decodeJSONStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	if err := applyWorkloadTokenHeaders(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
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
	req.ProofContext = &session.ProofContext{
		Method:      r.Method,
		TargetURI:   requestTargetURI(r),
		AccessToken: extractBearerToken(r),
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

func applyWorkloadTokenHeaders(r *http.Request, req *session.CreateSessionRequest) error {
	if err := applySingleTokenHeader(r, "Workload-Identity-Token", &req.RuntimeToken, "runtime_token"); err != nil {
		return err
	}
	return applySingleTokenHeader(r, "Workload-Proof-Token", &req.WorkloadProofToken, "workload_proof_token")
}

func applySingleTokenHeader(r *http.Request, headerName string, target *string, fieldName string) error {
	values := r.Header.Values(headerName)
	if len(values) == 0 {
		return nil
	}
	if len(values) != 1 {
		return fmt.Errorf("%s must appear exactly once when provided", headerName)
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return fmt.Errorf("%s must not be empty", headerName)
	}
	if *target != "" && *target != value {
		return fmt.Errorf("%s conflicts with %s", headerName, fieldName)
	}
	*target = value
	return nil
}

func requestTargetURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
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
	if err := decodeJSONStrict(r, &req); err != nil {
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
	start := time.Now()
	s.metrics.authorizeRequests.Add(1)
	var recordedDecision string
	defer func() {
		s.metrics.recordAuthorize(time.Since(start), recordedDecision)
	}()

	var req model.AuthorizationRequest
	if err := decodeJSONStrict(r, &req); err != nil {
		s.metrics.authorizeInvalid.Add(1)
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
	recordedDecision = dec.Decision

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
				ExpiresInSeconds: s.grants.EffectiveTTLSeconds(dec),
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
	if err := decodeJSONStrict(r, &req); err != nil {
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
	if err := decodeJSONStrict(r, &req); err != nil {
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
	if err := decodeJSONStrict(r, &agent); err != nil {
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
	if err := decodeJSONStrict(r, &policy); err != nil {
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

// handleQueryAudit returns audit events from a query-capable audit sink.
func (s *Server) handleQueryAudit(w http.ResponseWriter, r *http.Request) {
	s.metrics.auditQueryTotal.Add(1)

	if s.auditRead == nil {
		s.metrics.auditQueryErrors.Add(1)
		writeError(w, http.StatusNotImplemented, "audit_query_unavailable", "audit query requires a query-capable audit sink such as Postgres")
		return
	}

	query, err := auditQueryFromRequest(r.URL.Query())
	if err != nil {
		s.metrics.auditQueryErrors.Add(1)
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}

	events, err := s.auditRead.Query(r.Context(), query)
	if err != nil {
		s.metrics.auditQueryErrors.Add(1)
		writeError(w, http.StatusInternalServerError, "audit_query_failed", err.Error())
		return
	}

	query = query.Normalize()
	resp := map[string]interface{}{
		"items":  events,
		"total":  len(events),
		"limit":  query.Limit,
		"offset": query.Offset,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHealth returns server health information.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":         "healthy",
		"version":        "v1alpha1",
		"store_backend":  s.storeBackend,
		"policy_backend": s.policyBackend,
		"uptime_seconds": time.Since(s.metrics.startedAt).Seconds(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleReady verifies that dependencies needed to serve traffic are reachable.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.metrics.readinessChecks.Add(1)

	ctx, cancel := context.WithTimeout(r.Context(), s.readinessTimeout)
	defer cancel()

	components := map[string]map[string]string{}
	ready := true
	if err := s.checkStoreHealth(ctx); err != nil {
		ready = false
		components["store"] = map[string]string{
			"status":  "not_ready",
			"backend": s.storeBackend,
			"error":   err.Error(),
		}
	} else {
		components["store"] = map[string]string{
			"status":  "ready",
			"backend": s.storeBackend,
		}
	}
	components["policy_backend"] = map[string]string{
		"status":  "ready",
		"backend": s.policyBackend,
	}

	statusCode := http.StatusOK
	overall := "ready"
	if !ready {
		s.metrics.readinessFailures.Add(1)
		statusCode = http.StatusServiceUnavailable
		overall = "not_ready"
	}

	writeJSON(w, statusCode, map[string]interface{}{
		"status":         overall,
		"version":        "v1alpha1",
		"store_backend":  s.storeBackend,
		"policy_backend": s.policyBackend,
		"uptime_seconds": time.Since(s.metrics.startedAt).Seconds(),
		"components":     components,
	})
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
			Type:           req.Resource.Type,
			ID:             req.Resource.ID,
			Classification: req.Resource.Classification,
		}
	}

	if dec.Constraints != nil {
		event.Constraints = constraintsToAuditMap(dec.Constraints)
	}
	if dec.Grant != nil {
		event.GrantID = dec.Grant.GrantID
	}

	if req.Context != nil {
		if runID, ok := req.Context["run_id"].(string); ok {
			event.RunID = runID
		}
	}

	if err := s.audit.Write(event); err != nil {
		s.metrics.auditWriteErrors.Add(1)
		s.logger.Printf("ERROR: failed to write audit event: %v", err)
	}
}

func (s *Server) checkStoreHealth(ctx context.Context) error {
	if checker, ok := s.store.(store.HealthChecker); ok {
		return checker.CheckHealth(ctx)
	}
	_, err := s.store.ListAgents(ctx)
	return err
}

func auditQueryFromRequest(values url.Values) (audit.Query, error) {
	query := audit.Query{
		AgentID:      firstQueryValue(values, "agent_id", "agent"),
		ActorID:      firstQueryValue(values, "actor_id", "actor"),
		Action:       firstQueryValue(values, "action"),
		Decision:     firstQueryValue(values, "decision"),
		RequestID:    firstQueryValue(values, "request_id"),
		RunID:        firstQueryValue(values, "run_id"),
		ResourceType: firstQueryValue(values, "resource_type"),
		ResourceID:   firstQueryValue(values, "resource_id"),
	}

	var err error
	query.From, err = parseOptionalTime(firstQueryValue(values, "from", "since"), "from")
	if err != nil {
		return audit.Query{}, err
	}
	query.To, err = parseOptionalTime(firstQueryValue(values, "to", "until"), "to")
	if err != nil {
		return audit.Query{}, err
	}
	query.Limit, err = parseOptionalNonNegativeInt(values.Get("limit"), "limit")
	if err != nil {
		return audit.Query{}, err
	}
	query.Offset, err = parseOptionalNonNegativeInt(values.Get("offset"), "offset")
	if err != nil {
		return audit.Query{}, err
	}

	return query.Normalize(), nil
}

func firstQueryValue(values url.Values, names ...string) string {
	for _, name := range names {
		if value := values.Get(name); value != "" {
			return value
		}
	}
	return ""
}

func parseOptionalTime(raw, name string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be an RFC3339 timestamp", name)
	}
	return value.UTC(), nil
}

func parseOptionalNonNegativeInt(raw, name string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must be non-negative", name)
	}
	return value, nil
}

func constraintsToAuditMap(constraints *model.Constraints) map[string]interface{} {
	if constraints == nil {
		return nil
	}
	result := make(map[string]interface{})
	if constraints.MaxRecords != nil {
		result["max_records"] = *constraints.MaxRecords
	}
	if len(constraints.RedactFields) > 0 {
		result["redact_fields"] = constraints.RedactFields
	}
	if constraints.AllowedFields != nil {
		result["allowed_fields"] = *constraints.AllowedFields
	}
	if constraints.ReadOnly != nil {
		result["readonly"] = *constraints.ReadOnly
	}
	if constraints.TimeWindowSeconds != nil {
		result["time_window_seconds"] = *constraints.TimeWindowSeconds
	}
	if constraints.ExpiresInSeconds != nil {
		result["expires_in_seconds"] = *constraints.ExpiresInSeconds
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func decodeJSONStrict(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
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
	query, _ := sink.(audit.Querier)
	s.auditRead = query
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
