package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/evaluator"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/registry"
)

// Config holds gateway configuration.
type Config struct {
	// AgentID is the default agent identity for all proxied requests.
	AgentID string

	// UpstreamURL is the target API server URL.
	UpstreamURL string

	// ListenAddr is the address to listen on.
	ListenAddr string

	// ObserveMode when true logs decisions without blocking.
	ObserveMode bool

	// Routes maps HTTP method+path patterns to OAP action names.
	// Format: "GET /api/invoices" → "erp.invoice.list"
	// If a route is not mapped, the action is derived from the method and path.
	Routes map[string]string

	// Store is the registry store.
	Store *registry.Store

	// AuditSink receives audit events.
	AuditSink audit.Sink
}

// Gateway is an HTTP reverse proxy with OAP policy enforcement.
type Gateway struct {
	cfg    Config
	eval   *evaluator.Evaluator
	proxy  *httputil.ReverseProxy
	logger *log.Logger
}

// New creates a new HTTP gateway.
func New(cfg Config) (*Gateway, error) {
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", cfg.UpstreamURL, err)
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)

	g := &Gateway{
		cfg:    cfg,
		eval:   evaluator.New(cfg.Store),
		proxy:  rp,
		logger: log.New(log.Writer(), "[oap-gateway] ", log.LstdFlags),
	}

	return g, nil
}

// Handler returns the HTTP handler for the gateway.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", g.handleHealth)
	mux.HandleFunc("/", g.handleProxy)
	return mux
}

// handleProxy is the main handler. It authorizes and forwards requests.
func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	action := g.resolveAction(r.Method, r.URL.Path)

	authReq := model.AuthorizationRequest{
		RequestID: fmt.Sprintf("gw-%d", time.Now().UnixNano()),
		Subject:   model.Subject{Type: "agent", AgentID: g.cfg.AgentID},
		Action:    model.Action{Name: action},
		Resource: &model.ResourceRef{
			Type: g.resourceTypeFromPath(r.URL.Path),
			ID:   g.resourceIDFromPath(r.URL.Path),
		},
	}

	// Check for agent ID override in header
	if agentHeader := r.Header.Get("X-OAP-Agent-ID"); agentHeader != "" {
		authReq.Subject.AgentID = agentHeader
	}

	result := g.eval.Evaluate(r.Context(), authReq)

	// Emit audit event
	g.emitAuditEvent(authReq, result.Decision)

	decision := result.Decision.Decision

	if decision == model.DecisionDeny && !g.cfg.ObserveMode {
		g.logger.Printf("DENIED: %s %s → %s (%s)",
			r.Method, r.URL.Path, action, result.Decision.Reason)
		g.writeDenyResponse(w, result.Decision)
		return
	}

	if decision == model.DecisionDeny && g.cfg.ObserveMode {
		g.logger.Printf("OBSERVE (would deny): %s %s → %s (%s)",
			r.Method, r.URL.Path, action, result.Decision.Reason)
	}

	if decision == model.DecisionRequireApproval && !g.cfg.ObserveMode {
		g.logger.Printf("APPROVAL REQUIRED: %s %s → %s",
			r.Method, r.URL.Path, action)
		g.writeApprovalResponse(w, result.Decision)
		return
	}

	if result.Decision.Constraints != nil {
		g.logger.Printf("ALLOWED (constrained): %s %s → %s",
			r.Method, r.URL.Path, action)
	} else {
		g.logger.Printf("ALLOWED: %s %s → %s", r.Method, r.URL.Path, action)
	}

	// Forward to upstream
	g.proxy.ServeHTTP(w, r)
}

// resolveAction maps an HTTP request to an OAP action name.
// First checks explicit route map, then derives from method + path.
func (g *Gateway) resolveAction(method, path string) string {
	// Check explicit routes
	key := method + " " + path
	if action, ok := g.cfg.Routes[key]; ok {
		return action
	}

	// Check prefix matches
	for pattern, action := range g.cfg.Routes {
		parts := strings.SplitN(pattern, " ", 2)
		if len(parts) == 2 && parts[0] == method && strings.HasPrefix(path, parts[1]) {
			return action
		}
	}

	// Derive from method + path
	// GET /api/invoices/INV-001 → api.invoices.read
	cleanPath := strings.Trim(path, "/")
	segments := strings.Split(cleanPath, "/")
	if len(segments) > 0 {
		resource := segments[0]
		if len(segments) > 1 {
			resource = strings.Join(segments[:2], ".")
		}
		action := resource + "." + methodToVerb(method)
		return action
	}

	return method + "." + path
}

// methodToVerb maps HTTP methods to action verbs.
func methodToVerb(method string) string {
	switch strings.ToUpper(method) {
	case "GET":
		return "read"
	case "POST":
		return "create"
	case "PUT", "PATCH":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

// resourceTypeFromPath extracts a resource type from the URL path.
func (g *Gateway) resourceTypeFromPath(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) >= 2 {
		return segments[0] + "." + segments[1]
	}
	if len(segments) >= 1 {
		return segments[0]
	}
	return "unknown"
}

// resourceIDFromPath extracts a resource ID from the URL path if present.
func (g *Gateway) resourceIDFromPath(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) >= 3 {
		return segments[2]
	}
	return ""
}

// writeDenyResponse returns a structured 403 response.
func (g *Gateway) writeDenyResponse(w http.ResponseWriter, dec model.AuthorizationDecision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":      "forbidden",
		"message":    fmt.Sprintf("OAP: access denied — %s", dec.Reason),
		"policy_ids": dec.PolicyIDs,
		"decision":   dec.Decision,
	})
}

// writeApprovalResponse returns a structured 403 response for approval-required.
func (g *Gateway) writeApprovalResponse(w http.ResponseWriter, dec model.AuthorizationDecision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":    "approval_required",
		"message":  fmt.Sprintf("OAP: approval required — %s", dec.Reason),
		"approval": dec.Approval,
		"decision": dec.Decision,
	})
}

// handleHealth returns gateway health status.
func (g *Gateway) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "healthy",
		"agent_id": g.cfg.AgentID,
		"upstream": g.cfg.UpstreamURL,
		"observe":  g.cfg.ObserveMode,
		"routes":   len(g.cfg.Routes),
	})
}

// emitAuditEvent writes an audit event.
func (g *Gateway) emitAuditEvent(req model.AuthorizationRequest, dec model.AuthorizationDecision) {
	if g.cfg.AuditSink == nil {
		return
	}
	event := model.AuditEvent{
		EventID:   fmt.Sprintf("evt-gw-%d", time.Now().UnixNano()),
		EventType: "authorization.decision",
		Timestamp: time.Now().UTC(),
		Decision:  dec.Decision,
		Subject:   &model.AuditSubject{AgentID: req.Subject.AgentID},
		Action:    req.Action.Name,
		PolicyIDs: dec.PolicyIDs,
		RequestID: req.RequestID,
		Reason:    dec.Reason,
	}
	if req.Resource != nil {
		event.Resource = &model.AuditResource{
			Type: req.Resource.Type,
			ID:   req.Resource.ID,
		}
	}
	if err := g.cfg.AuditSink.Write(event); err != nil {
		g.logger.Printf("ERROR: audit write failed: %v", err)
	}
}
