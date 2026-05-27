package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/registry"
)

// setupProxy creates a proxy with a fake upstream MCP server.
func setupProxy(t *testing.T, observe bool) (*MCPProxy, *httptest.Server, *audit.MemorySink) {
	t.Helper()

	// Fake upstream MCP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req MCPRequest
		json.NewDecoder(r.Body).Decode(&req)

		switch req.Method {
		case "tools/list":
			result := map[string]interface{}{
				"tools": []MCPTool{
					{Name: "read_ticket", Description: "Read a support ticket"},
					{Name: "delete_ticket", Description: "Delete a support ticket"},
					{Name: "send_message", Description: "Send a message"},
				},
			}
			resultJSON, _ := json.Marshal(result)
			resp := MCPResponse{JSONRPC: "2.0", ID: req.ID, Result: resultJSON}
			json.NewEncoder(w).Encode(resp)

		case "tools/call":
			result, _ := json.Marshal(map[string]string{"status": "ok"})
			resp := MCPResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
			json.NewEncoder(w).Encode(resp)

		default:
			result, _ := json.Marshal(map[string]string{"echo": req.Method})
			resp := MCPResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
			json.NewEncoder(w).Encode(resp)
		}
	}))

	store := registry.NewStore()
	store.RegisterAgent(&model.Agent{
		Metadata: model.Metadata{Name: "ticket-assistant", Namespace: "support"},
		Spec:     model.AgentSpec{Owner: "support-team", Type: "chat_agent", RiskTier: "medium", Capabilities: []string{"read_ticket", "send_message"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	store.AddPolicy(&model.AgentPolicy{
		Metadata: model.Metadata{Name: "support-policy", Namespace: "support"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://support/ticket-assistant"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"read_ticket", "send_message"}},
				{Effect: model.EffectDeny, Actions: []string{"delete_ticket"}},
			},
		},
	})

	sink := audit.NewMemorySink()
	p := New(Config{
		AgentID:     "agent://support/ticket-assistant",
		UpstreamURL: upstream.URL,
		ObserveMode: observe,
		Store:       store,
		AuditSink:   sink,
	})

	return p, upstream, sink
}

func mcpCall(t *testing.T, handler http.Handler, method string, params interface{}) MCPResponse {
	t.Helper()
	var paramsJSON json.RawMessage
	if params != nil {
		paramsJSON, _ = json.Marshal(params)
	}
	req := MCPRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: paramsJSON}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httpReq)

	var resp MCPResponse
	json.NewDecoder(w.Body).Decode(&resp)
	return resp
}

func TestInitialize(t *testing.T) {
	p, upstream, _ := setupProxy(t, false)
	defer upstream.Close()

	resp := mcpCall(t, p.Handler(), "initialize", nil)
	if resp.Error != nil {
		t.Fatalf("initialize error: %s", resp.Error.Message)
	}

	var result map[string]interface{}
	json.Unmarshal(resp.Result, &result)
	if result["protocolVersion"] == nil {
		t.Error("expected protocolVersion in initialize response")
	}
}

func TestToolsCallAllowed(t *testing.T) {
	p, upstream, sink := setupProxy(t, false)
	defer upstream.Close()

	resp := mcpCall(t, p.Handler(), "tools/call", ToolCallParams{
		Name:      "read_ticket",
		Arguments: map[string]interface{}{"ticket_id": "T-123"},
	})

	if resp.Error != nil {
		t.Fatalf("expected allow, got error: %s", resp.Error.Message)
	}

	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
}

func TestToolsCallDenied(t *testing.T) {
	p, upstream, sink := setupProxy(t, false)
	defer upstream.Close()

	resp := mcpCall(t, p.Handler(), "tools/call", ToolCallParams{
		Name: "delete_ticket",
	})

	if resp.Error == nil {
		t.Fatal("expected deny error, got success")
	}
	if resp.Error.Code != -32001 {
		t.Errorf("error code = %d, want -32001", resp.Error.Code)
	}

	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
	if sink.Events[0].Decision != model.DecisionDeny {
		t.Errorf("audit decision = %q, want deny", sink.Events[0].Decision)
	}
}

func TestToolsCallObserveMode(t *testing.T) {
	p, upstream, sink := setupProxy(t, true) // observe mode
	defer upstream.Close()

	resp := mcpCall(t, p.Handler(), "tools/call", ToolCallParams{
		Name: "delete_ticket",
	})

	// In observe mode, denied calls should still be forwarded
	if resp.Error != nil {
		t.Fatalf("observe mode should not block: %s", resp.Error.Message)
	}

	// But audit event should still show deny
	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
	if sink.Events[0].Decision != model.DecisionDeny {
		t.Errorf("audit should record deny even in observe mode, got %q", sink.Events[0].Decision)
	}
}

func TestHealth(t *testing.T) {
	p, upstream, _ := setupProxy(t, false)
	defer upstream.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health status = %d, want 200", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "healthy" {
		t.Errorf("health status = %v, want healthy", result["status"])
	}
}
