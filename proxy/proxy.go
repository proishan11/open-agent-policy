package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/evaluator"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store"
)

// Config holds MCP proxy configuration.
type Config struct {
	// AgentID is the agent identity for all proxied tool calls.
	AgentID string

	// UpstreamURL is the upstream MCP server URL.
	UpstreamURL string

	// ListenAddr is the address to listen on (e.g., ":7777").
	ListenAddr string

	// ObserveMode when true logs decisions without blocking denied calls.
	ObserveMode bool

	// Store is the policy store (for embedded evaluator mode).
	Store store.Store

	// OAPServerURL is the OAP server URL for remote auth mode.
	// When set, the proxy calls /v1/authorize on the OAP server
	// instead of using the embedded evaluator.
	OAPServerURL string

	// AuditSink receives audit events.
	AuditSink audit.Sink
}

// MCPProxy intercepts MCP protocol requests and authorizes them.
type MCPProxy struct {
	cfg       Config
	eval      *evaluator.Evaluator
	http      *http.Client // for OAP server calls in remote mode
	logger    *log.Logger
	mu        sync.RWMutex
	toolCache map[string]MCPTool // cached upstream tools (name → tool)
}

// MCPTool represents a tool from the upstream MCP server.
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

// MCPRequest is the JSON-RPC request format for MCP.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse is the JSON-RPC response format for MCP.
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError represents a JSON-RPC error.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolCallParams holds parameters for a tools/call request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// New creates a new MCP proxy.
func New(cfg Config) *MCPProxy {
	p := &MCPProxy{
		cfg:       cfg,
		http:      &http.Client{Timeout: 5 * time.Second},
		logger:    log.New(log.Writer(), "[mcp-proxy] ", log.LstdFlags),
		toolCache: make(map[string]MCPTool),
	}
	if cfg.OAPServerURL != "" {
		p.logger.Printf("remote auth mode: OAP server=%s", cfg.OAPServerURL)
	} else if cfg.Store != nil {
		p.eval = evaluator.New(cfg.Store)
		p.logger.Printf("embedded evaluator mode")
	}
	return p
}

// Handler returns the HTTP handler for the proxy.
// MCP over HTTP uses JSON-RPC 2.0 over a single HTTP POST endpoint.
func (p *MCPProxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", p.handleMCPRequest)
	mux.HandleFunc("GET /health", p.handleHealth)
	return mux
}

// handleMCPRequest dispatches MCP JSON-RPC requests.
func (p *MCPProxy) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	var req MCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		p.writeError(w, nil, -32700, "invalid JSON")
		return
	}

	switch req.Method {
	case "tools/list":
		p.handleToolsList(w, r, &req)
	case "tools/call":
		p.handleToolsCall(w, r, &req)
	case "initialize":
		p.handleInitialize(w, r, &req)
	default:
		// Forward unknown methods to upstream as-is
		p.forwardToUpstream(w, r, &req)
	}
}

// handleInitialize responds to the MCP initialize handshake.
func (p *MCPProxy) handleInitialize(w http.ResponseWriter, _ *http.Request, req *MCPRequest) {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]interface{}{
			"name":    "oap-mcp-proxy",
			"version": "0.1.0",
		},
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
	}
	resultJSON, _ := json.Marshal(result)
	p.writeResult(w, req.ID, resultJSON)
}

// handleToolsList returns the filtered list of tools the agent is allowed to see.
func (p *MCPProxy) handleToolsList(w http.ResponseWriter, r *http.Request, req *MCPRequest) {
	// Fetch tools from upstream
	upstreamTools, err := p.fetchUpstreamTools(r.Context())
	if err != nil {
		p.logger.Printf("failed to fetch upstream tools: %v", err)
		p.writeError(w, req.ID, -32000, "upstream error: "+err.Error())
		return
	}

	// Filter tools based on policy
	var allowed []MCPTool
	for _, tool := range upstreamTools {
		result := p.eval.Evaluate(r.Context(), model.AuthorizationRequest{
			RequestID: fmt.Sprintf("list-%s-%d", tool.Name, time.Now().UnixNano()),
			Subject:   model.Subject{Type: "agent", AgentID: p.cfg.AgentID},
			Action:    model.Action{Name: tool.Name},
		})

		if result.Decision.Decision != model.DecisionDeny || p.cfg.ObserveMode {
			allowed = append(allowed, tool)
		}
	}

	result := map[string]interface{}{
		"tools": allowed,
	}
	resultJSON, _ := json.Marshal(result)
	p.writeResult(w, req.ID, resultJSON)

	p.logger.Printf("tools/list: %d/%d tools visible to %s",
		len(allowed), len(upstreamTools), p.cfg.AgentID)
}

// handleToolsCall authorizes and forwards a tool call.
func (p *MCPProxy) handleToolsCall(w http.ResponseWriter, r *http.Request, req *MCPRequest) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		p.writeError(w, req.ID, -32602, "invalid params")
		return
	}

	// Authorize
	authReq := model.AuthorizationRequest{
		RequestID: fmt.Sprintf("call-%s-%d", params.Name, time.Now().UnixNano()),
		Subject:   model.Subject{Type: "agent", AgentID: p.cfg.AgentID},
		Action:    model.Action{Name: params.Name},
		Tool:      &model.ToolRef{Name: params.Name, Protocol: "mcp"},
	}

	var dec model.AuthorizationDecision
	if p.cfg.OAPServerURL != "" {
		bearer := extractMCPBearer(r)
		dec = p.authorizeRemote(r.Context(), authReq, bearer)
	} else {
		result := p.eval.Evaluate(r.Context(), authReq)
		dec = result.Decision
		p.emitAuditEvent(authReq, dec)
	}

	decision := dec.Decision

	if decision == model.DecisionDeny && !p.cfg.ObserveMode {
		p.logger.Printf("tools/call DENIED: %s → %s (%s)",
			p.cfg.AgentID, params.Name, dec.Reason)
		p.writeError(w, req.ID, -32001,
			fmt.Sprintf("OAP: tool call denied — %s", dec.Reason))
		return
	}

	if decision == model.DecisionDeny && p.cfg.ObserveMode {
		p.logger.Printf("tools/call OBSERVE (would deny): %s → %s (%s)",
			p.cfg.AgentID, params.Name, dec.Reason)
	}

	if decision == model.DecisionRequireApproval && !p.cfg.ObserveMode {
		p.logger.Printf("tools/call APPROVAL REQUIRED: %s → %s", p.cfg.AgentID, params.Name)
		p.writeError(w, req.ID, -32002,
			fmt.Sprintf("OAP: approval required — %s", dec.Reason))
		return
	}

	// Log constraints if present
	if dec.Constraints != nil {
		p.logger.Printf("tools/call ALLOWED with constraints: %s → %s", p.cfg.AgentID, params.Name)
	} else {
		p.logger.Printf("tools/call ALLOWED: %s → %s", p.cfg.AgentID, params.Name)
	}

	// Forward to upstream
	p.forwardToUpstream(w, r, req)
}

// authorizeRemote calls the OAP server's /v1/authorize endpoint.
func (p *MCPProxy) authorizeRemote(ctx context.Context, authReq model.AuthorizationRequest, bearer string) model.AuthorizationDecision {
	body, _ := json.Marshal(authReq)
	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		p.cfg.OAPServerURL+"/v1/authorize", bytes.NewReader(body))
	if err != nil {
		p.logger.Printf("ERROR: building OAP request: %v", err)
		return mcpDenyDecision("proxy error: " + err.Error())
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := p.http.Do(httpReq)
	if err != nil {
		p.logger.Printf("ERROR: OAP server unreachable: %v", err)
		return mcpDenyDecision("OAP server unreachable")
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return mcpDenyDecision("authentication failed")
	}

	var dec model.AuthorizationDecision
	if err := json.Unmarshal(respBody, &dec); err != nil {
		p.logger.Printf("ERROR: parsing OAP response: %v", err)
		return mcpDenyDecision("invalid OAP response")
	}
	return dec
}

// mcpDenyDecision creates a fail-closed deny decision.
func mcpDenyDecision(reason string) model.AuthorizationDecision {
	return model.AuthorizationDecision{
		Decision: model.DecisionDeny,
		Reason:   reason,
	}
}

// extractMCPBearer extracts the Bearer token from the Authorization header.
func extractMCPBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// fetchUpstreamTools calls the upstream MCP server to get the tools list.
func (p *MCPProxy) fetchUpstreamTools(ctx context.Context) ([]MCPTool, error) {
	// Check cache first
	p.mu.RLock()
	if len(p.toolCache) > 0 {
		tools := make([]MCPTool, 0, len(p.toolCache))
		for _, t := range p.toolCache {
			tools = append(tools, t)
		}
		p.mu.RUnlock()
		return tools, nil
	}
	p.mu.RUnlock()

	// Call upstream
	reqBody := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}
	bodyJSON, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.cfg.UpstreamURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("calling upstream: %w", err)
	}
	defer resp.Body.Close()

	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if mcpResp.Error != nil {
		return nil, fmt.Errorf("upstream error: %s", mcpResp.Error.Message)
	}

	var result struct {
		Tools []MCPTool `json:"tools"`
	}
	if err := json.Unmarshal(mcpResp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing tools: %w", err)
	}

	// Cache
	p.mu.Lock()
	for _, t := range result.Tools {
		p.toolCache[t.Name] = t
	}
	p.mu.Unlock()

	return result.Tools, nil
}

// forwardToUpstream sends the request to the upstream MCP server and relays the response.
func (p *MCPProxy) forwardToUpstream(w http.ResponseWriter, r *http.Request, req *MCPRequest) {
	bodyJSON, _ := json.Marshal(req)

	httpReq, err := http.NewRequestWithContext(r.Context(), "POST", p.cfg.UpstreamURL,
		strings.NewReader(string(bodyJSON)))
	if err != nil {
		p.writeError(w, req.ID, -32000, "proxy error: "+err.Error())
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		p.writeError(w, req.ID, -32000, "upstream unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	var mcpResp json.RawMessage
	json.NewDecoder(resp.Body).Decode(&mcpResp)
	json.NewEncoder(w).Encode(mcpResp)
}

// handleHealth returns proxy health status.
func (p *MCPProxy) handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]interface{}{
		"status":   "healthy",
		"agent_id": p.cfg.AgentID,
		"upstream": p.cfg.UpstreamURL,
		"observe":  p.cfg.ObserveMode,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// emitAuditEvent writes an audit event for a tool call.
func (p *MCPProxy) emitAuditEvent(req model.AuthorizationRequest, dec model.AuthorizationDecision) {
	if p.cfg.AuditSink == nil {
		return
	}
	event := model.AuditEvent{
		EventID:   fmt.Sprintf("evt-mcp-%d", time.Now().UnixNano()),
		EventType: "authorization.decision",
		Timestamp: time.Now().UTC(),
		Decision:  dec.Decision,
		Subject:   &model.AuditSubject{AgentID: req.Subject.AgentID},
		Action:    req.Action.Name,
		PolicyIDs: dec.PolicyIDs,
		RequestID: req.RequestID,
		Reason:    dec.Reason,
	}
	if err := p.cfg.AuditSink.Write(event); err != nil {
		p.logger.Printf("ERROR: audit write failed: %v", err)
	}
}

// --- JSON-RPC helpers ---

func (p *MCPProxy) writeResult(w http.ResponseWriter, id interface{}, result json.RawMessage) {
	resp := MCPResponse{JSONRPC: "2.0", ID: id, Result: result}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (p *MCPProxy) writeError(w http.ResponseWriter, id interface{}, code int, message string) {
	resp := MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &MCPError{Code: code, Message: message},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors still use 200
	json.NewEncoder(w).Encode(resp)
}
