package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/evaluator"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store"
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

	// Store is the policy store (for embedded evaluator mode).
	Store store.Store

	// OAPServerURL is the OAP server URL for remote auth mode.
	// When set, the gateway calls /v1/authorize on the OAP server
	// instead of using the embedded evaluator.
	OAPServerURL string

	// AuditSink receives audit events.
	AuditSink audit.Sink
}

// Gateway is an HTTP reverse proxy with OAP policy enforcement.
type Gateway struct {
	cfg    Config
	eval   *evaluator.Evaluator
	proxy  *httputil.ReverseProxy
	http   *http.Client // for OAP server calls in remote mode
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
		proxy:  rp,
		http:   &http.Client{Timeout: 5 * time.Second},
		logger: log.New(log.Writer(), "[oap-gateway] ", log.LstdFlags),
	}

	if cfg.OAPServerURL != "" {
		g.logger.Printf("remote auth mode: OAP server=%s", cfg.OAPServerURL)
	} else if cfg.Store != nil {
		g.eval = evaluator.New(cfg.Store)
		g.logger.Printf("embedded evaluator mode")
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

	agentID := g.cfg.AgentID
	if agentHeader := r.Header.Get("X-OAP-Agent-ID"); agentHeader != "" {
		agentID = agentHeader
	}

	// Extract session token from incoming request for remote mode
	bearerToken := extractBearer(r)

	authReq := model.AuthorizationRequest{
		RequestID: fmt.Sprintf("gw-%d", time.Now().UnixNano()),
		Subject:   model.Subject{Type: "agent", AgentID: agentID},
		Action:    model.Action{Name: action},
		Resource: &model.ResourceRef{
			Type: g.resourceTypeFromPath(r.URL.Path),
			ID:   g.resourceIDFromPath(r.URL.Path),
		},
	}

	var dec model.AuthorizationDecision
	if g.cfg.OAPServerURL != "" {
		dec = g.authorizeRemote(r, authReq, bearerToken)
	} else {
		result := g.eval.Evaluate(r.Context(), authReq)
		dec = result.Decision
		g.emitAuditEvent(authReq, dec)
	}

	decision := dec.Decision

	if decision == model.DecisionDeny && !g.cfg.ObserveMode {
		g.logger.Printf("DENIED: %s %s → %s (%s)",
			r.Method, r.URL.Path, action, dec.Reason)
		g.writeDenyResponse(w, dec)
		return
	}

	if decision == model.DecisionDeny && g.cfg.ObserveMode {
		g.logger.Printf("OBSERVE (would deny): %s %s → %s (%s)",
			r.Method, r.URL.Path, action, dec.Reason)
	}

	if decision == model.DecisionRequireApproval && !g.cfg.ObserveMode {
		g.logger.Printf("APPROVAL REQUIRED: %s %s → %s",
			r.Method, r.URL.Path, action)
		g.writeApprovalResponse(w, dec)
		return
	}

	if dec.Constraints != nil {
		g.logger.Printf("ALLOWED (constrained): %s %s → %s",
			r.Method, r.URL.Path, action)
	} else {
		g.logger.Printf("ALLOWED: %s %s → %s", r.Method, r.URL.Path, action)
	}

	// Inject grant token into upstream request if present
	if dec.Grant != nil && dec.Grant.Token != "" {
		r.Header.Set("X-OAP-Grant-Token", dec.Grant.Token)
	}

	// Forward to upstream
	g.proxy.ServeHTTP(w, r)
}

// authorizeRemote calls the OAP server's /v1/authorize endpoint.
func (g *Gateway) authorizeRemote(r *http.Request, authReq model.AuthorizationRequest, bearer string) model.AuthorizationDecision {
	body, _ := json.Marshal(authReq)
	httpReq, err := http.NewRequestWithContext(r.Context(), "POST",
		g.cfg.OAPServerURL+"/v1/authorize", bytes.NewReader(body))
	if err != nil {
		g.logger.Printf("ERROR: building OAP request: %v", err)
		return denyDecision("gateway error: " + err.Error())
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := g.http.Do(httpReq)
	if err != nil {
		g.logger.Printf("ERROR: OAP server unreachable: %v", err)
		return denyDecision("OAP server unreachable")
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return denyDecision("authentication failed")
	}

	var dec model.AuthorizationDecision
	if err := json.Unmarshal(respBody, &dec); err != nil {
		g.logger.Printf("ERROR: parsing OAP response: %v", err)
		return denyDecision("invalid OAP response")
	}
	return dec
}

// denyDecision creates a fail-closed deny decision.
func denyDecision(reason string) model.AuthorizationDecision {
	return model.AuthorizationDecision{
		Decision: model.DecisionDeny,
		Reason:   reason,
	}
}

// extractBearer extracts the Bearer token from the Authorization header.
func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
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
