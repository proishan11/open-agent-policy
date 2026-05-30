package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/proishan11/open-agent-policy/engine/audit"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/session"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
)

type unhealthyStore struct {
	*memory.Store
}

func (s *unhealthyStore) CheckHealth(_ context.Context) error {
	return errors.New("store unavailable")
}

// setupTestServer creates a test server with a memory audit sink.
func setupTestServer(t *testing.T) (*Server, *audit.MemorySink) {
	t.Helper()
	srv, err := NewServer(Config{DevMode: true})
	if err != nil {
		t.Fatal(err)
	}
	memSink := audit.NewMemorySink()
	srv.SetAuditSink(memSink)
	return srv, memSink
}

func setupPolicyBackendTestServer(t *testing.T, cfg Config) (*Server, *audit.MemorySink) {
	t.Helper()
	if cfg.GrantSigningKey == "" {
		cfg.GrantSigningKey = "test-grant-signing-key"
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	memSink := audit.NewMemorySink()
	srv.SetAuditSink(memSink)
	return srv, memSink
}

func addPolicyBackendFixture(t *testing.T, srv *Server, action string, rules []model.PolicyRule) string {
	t.Helper()
	ctx := context.Background()
	agentID := "agent://test/backend-agent"
	if err := srv.Store().RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "backend-agent", Namespace: "test"},
		Spec: model.AgentSpec{
			Owner:        "test",
			Type:         "workflow_agent",
			RiskTier:     "medium",
			Capabilities: []string{action},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	}); err != nil {
		t.Fatalf("register backend fixture agent: %v", err)
	}
	if err := srv.Store().AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "backend-policy", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: agentID},
			Rules:   rules,
		},
	}); err != nil {
		t.Fatalf("add backend fixture policy: %v", err)
	}
	return agentID
}

func authorizeFixtureRequest(t *testing.T, srv *Server, agentID, action string) model.AuthorizationDecision {
	t.Helper()
	authReq := model.AuthorizationRequest{
		RequestID: "backend-req-1",
		Subject:   model.Subject{Type: "agent", AgentID: agentID},
		Action:    model.Action{Name: action},
		Resource:  &model.ResourceRef{Type: "ticket", ID: "T-123"},
		Context:   map[string]interface{}{"run_id": "run-backend-1"},
	}
	body, _ := json.Marshal(authReq)
	req := httptest.NewRequest("POST", "/v1/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}
	var decision model.AuthorizationDecision
	if err := json.NewDecoder(w.Body).Decode(&decision); err != nil {
		t.Fatalf("decode authorize response: %v", err)
	}
	return decision
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health: got status %d, want 200", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "healthy" {
		t.Errorf("health: got status %v, want healthy", result["status"])
	}
	if result["policy_backend"] != "builtin" {
		t.Errorf("health: got policy_backend %v, want builtin", result["policy_backend"])
	}
}

func TestReadyEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/v1/ready", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ready: got status %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode ready response: %v", err)
	}
	if result["status"] != "ready" {
		t.Errorf("ready: got status %v, want ready", result["status"])
	}
}

func TestReadyEndpointReportsStoreFailure(t *testing.T) {
	srv, err := NewServer(Config{
		DevMode: true,
		Store:   &unhealthyStore{Store: memory.New()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	req := httptest.NewRequest("GET", "/v1/ready", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready: got status %d, want 503. Body: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode ready response: %v", err)
	}
	if result["status"] != "not_ready" {
		t.Errorf("ready: got status %v, want not_ready", result["status"])
	}
}

func TestApplyWorkloadTokenHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/runtime/session?ignored=true", nil)
	req.Header.Set("Workload-Identity-Token", "wit")
	req.Header.Set("Workload-Proof-Token", "wpt")

	var sessionReq session.CreateSessionRequest
	if err := applyWorkloadTokenHeaders(req, &sessionReq); err != nil {
		t.Fatalf("applyWorkloadTokenHeaders: %v", err)
	}
	if sessionReq.RuntimeToken != "wit" {
		t.Fatalf("runtime token = %q, want wit", sessionReq.RuntimeToken)
	}
	if sessionReq.WorkloadProofToken != "wpt" {
		t.Fatalf("workload proof token = %q, want wpt", sessionReq.WorkloadProofToken)
	}
	if target := requestTargetURI(req); target != "http://example.com/v1/runtime/session" {
		t.Fatalf("target URI = %q, want http://example.com/v1/runtime/session", target)
	}
}

func TestApplyWorkloadTokenHeadersRejectsConflicts(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/runtime/session", nil)
	req.Header.Set("Workload-Identity-Token", "header-wit")
	sessionReq := session.CreateSessionRequest{RuntimeToken: "body-wit"}

	if err := applyWorkloadTokenHeaders(req, &sessionReq); err == nil {
		t.Fatal("expected conflicting WIT header and body field to fail")
	}
}

func TestApplyWorkloadTokenHeadersRejectsDuplicates(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/runtime/session", nil)
	req.Header.Add("Workload-Proof-Token", "first")
	req.Header.Add("Workload-Proof-Token", "second")

	if err := applyWorkloadTokenHeaders(req, &session.CreateSessionRequest{}); err == nil {
		t.Fatal("expected duplicate WPT headers to fail")
	}
}

func TestAuthorizeFlow(t *testing.T) {
	srv, memSink := setupTestServer(t)

	// Register an agent
	agent := model.Agent{
		APIVersion: "oap.dev/v1alpha1",
		Kind:       "Agent",
		Metadata:   model.Metadata{Name: "test-agent", Namespace: "test"},
		Spec: model.AgentSpec{
			Owner:        "test-team",
			Type:         "workflow_agent",
			RiskTier:     "low",
			Capabilities: []string{"db.read"},
		},
	}
	agentJSON, _ := json.Marshal(agent)
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(agentJSON))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register agent: got %d, want 201. Body: %s", w.Code, w.Body.String())
	}

	// Apply a policy
	policy := model.AgentPolicy{
		APIVersion: "oap.dev/v1alpha1",
		Kind:       "AgentPolicy",
		Metadata:   model.Metadata{Name: "allow-read", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://test/test-agent"},
			Rules: []model.PolicyRule{
				{Effect: model.EffectAllow, Actions: []string{"db.read"}},
			},
		},
	}
	policyJSON, _ := json.Marshal(policy)
	req = httptest.NewRequest("POST", "/v1/policies", bytes.NewReader(policyJSON))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("apply policy: got %d, want 201. Body: %s", w.Code, w.Body.String())
	}

	// Authorize — should allow
	authReq := model.AuthorizationRequest{
		RequestID: "test-req-1",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://test/test-agent"},
		Action:    model.Action{Name: "db.read"},
	}
	authJSON, _ := json.Marshal(authReq)
	req = httptest.NewRequest("POST", "/v1/authorize", bytes.NewReader(authJSON))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	var decision model.AuthorizationDecision
	json.NewDecoder(w.Body).Decode(&decision)
	if decision.Decision != model.DecisionAllow {
		t.Errorf("authorize: got %q, want %q", decision.Decision, model.DecisionAllow)
	}

	// Verify audit event was emitted
	if memSink.Len() != 1 {
		t.Errorf("audit: got %d events, want 1", memSink.Len())
	}

	// Authorize unregistered agent — should deny
	authReq.Subject.AgentID = "agent://test/ghost"
	authJSON, _ = json.Marshal(authReq)
	req = httptest.NewRequest("POST", "/v1/authorize", bytes.NewReader(authJSON))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&decision)
	if decision.Decision != model.DecisionDeny {
		t.Errorf("authorize unregistered: got %q, want deny", decision.Decision)
	}
}

func TestOPAPolicyBackendAllowWithGrantAndAudit(t *testing.T) {
	var seenOPARequest atomic.Bool
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/oap/authz" {
			http.Error(w, "unexpected OPA path", http.StatusNotFound)
			return
		}
		var payload struct {
			Input struct {
				Request model.AuthorizationRequest `json:"request"`
				Agent   *model.Agent               `json:"agent"`
			} `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid OPA request", http.StatusBadRequest)
			return
		}
		if payload.Input.Request.Action.Name != "tickets.read" {
			http.Error(w, "unexpected action", http.StatusBadRequest)
			return
		}
		if payload.Input.Agent == nil || payload.Input.Agent.ID() != "agent://test/backend-agent" {
			http.Error(w, "unexpected agent", http.StatusBadRequest)
			return
		}
		seenOPARequest.Store(true)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": map[string]interface{}{
				"decision":   model.DecisionAllowConstrained,
				"reason":     "allowed by OPA ticket policy",
				"policy_ids": []string{"opa/support-ticket-read"},
				"constraints": map[string]interface{}{
					"readonly":    true,
					"max_records": 25,
				},
			},
		})
	}))
	defer opa.Close()

	srv, memSink := setupPolicyBackendTestServer(t, Config{
		DevMode:       true,
		PolicyBackend: "opa",
		OPAURL:        opa.URL,
	})
	agentID := addPolicyBackendFixture(t, srv, "tickets.read", []model.PolicyRule{
		{Effect: model.EffectDeny, Actions: []string{"tickets.read"}, Reason: "built-in policy would deny"},
	})

	decision := authorizeFixtureRequest(t, srv, agentID, "tickets.read")
	if !seenOPARequest.Load() {
		t.Fatal("expected request to be evaluated by OPA")
	}
	if decision.Decision != model.DecisionAllowConstrained {
		t.Fatalf("decision = %q, want %q", decision.Decision, model.DecisionAllowConstrained)
	}
	if decision.Reason != "allowed by OPA ticket policy" {
		t.Fatalf("reason = %q, want OPA reason", decision.Reason)
	}
	if len(decision.PolicyIDs) != 1 || decision.PolicyIDs[0] != "opa/support-ticket-read" {
		t.Fatalf("policy_ids = %v, want OPA policy id", decision.PolicyIDs)
	}
	if decision.Constraints == nil || decision.Constraints.MaxRecords == nil || *decision.Constraints.MaxRecords != 25 {
		t.Fatalf("constraints.max_records = %#v, want 25", decision.Constraints)
	}
	if decision.Constraints.ReadOnly == nil || !*decision.Constraints.ReadOnly {
		t.Fatalf("constraints.readonly = %#v, want true", decision.Constraints)
	}
	if decision.Grant == nil || decision.Grant.Token == "" {
		t.Fatal("expected allow decision to include a grant token")
	}
	if memSink.Len() != 1 {
		t.Fatalf("audit events = %d, want 1", memSink.Len())
	}
	event := memSink.Events[0]
	if event.Decision != model.DecisionAllowConstrained {
		t.Fatalf("audit decision = %q, want %q", event.Decision, model.DecisionAllowConstrained)
	}
	if event.GrantID == "" {
		t.Fatal("expected audit event to include grant_id")
	}
	if event.Constraints["readonly"] != true || event.Constraints["max_records"] != 25 {
		t.Fatalf("audit constraints = %#v, want readonly and max_records", event.Constraints)
	}
}

func TestOPAPolicyBackendDenyDoesNotIssueGrant(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": map[string]interface{}{
				"decision":   model.DecisionDeny,
				"reason":     "denied by OPA risk rule",
				"policy_ids": []string{"opa/deny-risky-ticket-read"},
			},
		})
	}))
	defer opa.Close()

	srv, memSink := setupPolicyBackendTestServer(t, Config{
		DevMode:       true,
		PolicyBackend: "opa",
		OPAURL:        opa.URL,
	})
	agentID := addPolicyBackendFixture(t, srv, "tickets.read", []model.PolicyRule{
		{Effect: model.EffectAllow, Actions: []string{"tickets.read"}},
	})

	decision := authorizeFixtureRequest(t, srv, agentID, "tickets.read")
	if decision.Decision != model.DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision.Decision)
	}
	if decision.Grant != nil {
		t.Fatalf("deny decision got unexpected grant: %#v", decision.Grant)
	}
	if memSink.Len() != 1 {
		t.Fatalf("audit events = %d, want 1", memSink.Len())
	}
	if memSink.Events[0].GrantID != "" {
		t.Fatalf("deny audit event got unexpected grant id %q", memSink.Events[0].GrantID)
	}
}

func TestOPAPolicyBackendUnavailableFailsClosed(t *testing.T) {
	srv, _ := setupPolicyBackendTestServer(t, Config{
		DevMode:       true,
		PolicyBackend: "opa",
		OPAURL:        "http://127.0.0.1:1",
		OPATimeout:    50 * time.Millisecond,
	})
	agentID := addPolicyBackendFixture(t, srv, "tickets.read", []model.PolicyRule{
		{Effect: model.EffectAllow, Actions: []string{"tickets.read"}},
	})

	decision := authorizeFixtureRequest(t, srv, agentID, "tickets.read")
	if decision.Decision != model.DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision.Decision)
	}
	if !strings.Contains(decision.Reason, "fail-closed") {
		t.Fatalf("reason = %q, want fail-closed detail", decision.Reason)
	}
	if decision.Grant != nil {
		t.Fatalf("fail-closed deny got unexpected grant: %#v", decision.Grant)
	}
}

func TestOPAPolicyBackendFailOpenFallsBackToBuiltin(t *testing.T) {
	srv, _ := setupPolicyBackendTestServer(t, Config{
		DevMode:       true,
		PolicyBackend: "opa",
		OPAURL:        "http://127.0.0.1:1",
		OPATimeout:    50 * time.Millisecond,
		OPAFailOpen:   true,
	})
	agentID := addPolicyBackendFixture(t, srv, "tickets.read", []model.PolicyRule{
		{Effect: model.EffectAllow, Actions: []string{"tickets.read"}},
	})

	decision := authorizeFixtureRequest(t, srv, agentID, "tickets.read")
	if decision.Decision != model.DecisionAllow {
		t.Fatalf("decision = %q, want built-in allow fallback", decision.Decision)
	}
	if decision.Grant == nil || decision.Grant.Token == "" {
		t.Fatal("expected fallback allow decision to include a grant token")
	}
}

func TestCedarPolicyBackendAllowWithGrantAndAudit(t *testing.T) {
	var seenCedarRequest atomic.Bool
	cedar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Principal struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"principal"`
			Action struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"action"`
			Resource struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"resource"`
			PolicyStoreID string `json:"policyStoreId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid Cedar request", http.StatusBadRequest)
			return
		}
		if payload.Principal.ID != "agent://test/backend-agent" || payload.Action.ID != "tickets.read" {
			http.Error(w, "unexpected Cedar principal/action", http.StatusBadRequest)
			return
		}
		if payload.Resource.Type != "OAP::ticket" || payload.Resource.ID != "T-123" {
			http.Error(w, "unexpected Cedar resource", http.StatusBadRequest)
			return
		}
		if payload.PolicyStoreID != "ps-test" {
			http.Error(w, "unexpected Cedar policy store", http.StatusBadRequest)
			return
		}
		seenCedarRequest.Store(true)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"decision": "Allow",
			"diagnostics": map[string]interface{}{
				"reason": []string{"allowed by Cedar ticket policy"},
			},
			"context": map[string]interface{}{
				"constraints": map[string]interface{}{"readonly": true},
			},
		})
	}))
	defer cedar.Close()

	srv, memSink := setupPolicyBackendTestServer(t, Config{
		DevMode:            true,
		PolicyBackend:      "cedar",
		CedarURL:           cedar.URL,
		CedarPolicyStoreID: "ps-test",
	})
	agentID := addPolicyBackendFixture(t, srv, "tickets.read", []model.PolicyRule{
		{Effect: model.EffectDeny, Actions: []string{"tickets.read"}, Reason: "built-in policy would deny"},
	})

	decision := authorizeFixtureRequest(t, srv, agentID, "tickets.read")
	if !seenCedarRequest.Load() {
		t.Fatal("expected request to be evaluated by Cedar")
	}
	if decision.Decision != model.DecisionAllowConstrained {
		t.Fatalf("decision = %q, want %q", decision.Decision, model.DecisionAllowConstrained)
	}
	if decision.Reason != "allowed by Cedar ticket policy" {
		t.Fatalf("reason = %q, want Cedar reason", decision.Reason)
	}
	if decision.Grant == nil || decision.Grant.Token == "" {
		t.Fatal("expected Cedar allow decision to include a grant token")
	}
	if memSink.Len() != 1 {
		t.Fatalf("audit events = %d, want 1", memSink.Len())
	}
	if memSink.Events[0].Decision != model.DecisionAllowConstrained || memSink.Events[0].GrantID == "" {
		t.Fatalf("audit event = %#v, want constrained allow with grant", memSink.Events[0])
	}
}

func TestPolicyBackendConfigValidation(t *testing.T) {
	if _, err := NewServer(Config{DevMode: true, PolicyBackend: "opa"}); err == nil {
		t.Fatal("expected missing OPAURL to fail")
	}
	if _, err := NewServer(Config{DevMode: true, PolicyBackend: "cedar"}); err == nil {
		t.Fatal("expected missing CedarURL to fail")
	}
	if _, err := NewServer(Config{DevMode: true, PolicyBackend: "unknown"}); err == nil {
		t.Fatal("expected unsupported policy backend to fail")
	}
}

func TestAuditQueryEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)
	ctx := context.Background()

	agentID := "agent://test/audit-agent"
	if err := srv.Store().RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "audit-agent", Namespace: "test"},
		Spec: model.AgentSpec{
			Owner:        "test",
			Type:         "workflow_agent",
			RiskTier:     "low",
			Capabilities: []string{"tickets.read"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	}); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	if err := srv.Store().AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "audit-allow-read", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: agentID},
			Rules: []model.PolicyRule{
				{
					Effect:  model.EffectAllow,
					Actions: []string{"tickets.read"},
					Resources: &model.PolicyResourceSelector{
						Types: []string{"ticket"},
					},
					Constraints: map[string]interface{}{
						"maxRecords": 25,
						"readonly":   true,
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	authReq := model.AuthorizationRequest{
		RequestID: "audit-query-req-1",
		Subject:   model.Subject{Type: "agent", AgentID: agentID},
		Actor:     &model.Actor{Type: "user", ID: "alice@example.com"},
		Action:    model.Action{Name: "tickets.read"},
		Resource:  &model.ResourceRef{Type: "ticket", ID: "T-123", Classification: "confidential"},
		Context:   map[string]interface{}{"run_id": "run-audit-query-1"},
	}
	body, _ := json.Marshal(authReq)
	req := httptest.NewRequest("POST", "/v1/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	params := url.Values{}
	params.Set("agent_id", agentID)
	params.Set("decision", model.DecisionAllowConstrained)
	params.Set("resource_type", "ticket")
	params.Set("limit", "10")
	req = httptest.NewRequest("GET", "/v1/audit?"+params.Encode(), nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("audit query: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Items  []model.AuditEvent `json:"items"`
		Total  int                `json:"total"`
		Limit  int                `json:"limit"`
		Offset int                `json:"offset"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("got total=%d items=%d, want 1", resp.Total, len(resp.Items))
	}
	event := resp.Items[0]
	if event.RequestID != "audit-query-req-1" {
		t.Fatalf("got request_id %q, want audit-query-req-1", event.RequestID)
	}
	if event.Resource == nil || event.Resource.Classification != "confidential" {
		t.Fatalf("got resource %#v, want classification confidential", event.Resource)
	}
	if event.Constraints["readonly"] != true {
		t.Fatalf("got readonly constraint %v, want true", event.Constraints["readonly"])
	}
	if event.GrantID == "" {
		t.Fatal("expected audit event to include grant_id")
	}
}

func TestAuditQueryUnavailable(t *testing.T) {
	srv, err := NewServer(Config{DevMode: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	req := httptest.NewRequest("GET", "/v1/audit", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("audit query: got %d, want 501. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuditQueryRejectsBadTime(t *testing.T) {
	srv, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/audit?from=not-a-time", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("audit query bad time: got %d, want 400. Body: %s", w.Code, w.Body.String())
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)
	ctx := context.Background()

	agentID := "agent://test/metrics-agent"
	if err := srv.Store().RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "metrics-agent", Namespace: "test"},
		Spec: model.AgentSpec{
			Owner:        "test",
			Type:         "workflow_agent",
			RiskTier:     "low",
			Capabilities: []string{"metrics.read"},
		},
		Status: model.AgentStatus{State: model.AgentStateActive},
	}); err != nil {
		t.Fatalf("register agent: %v", err)
	}
	if err := srv.Store().AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "metrics-allow", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: agentID},
			Rules:   []model.PolicyRule{{Effect: model.EffectAllow, Actions: []string{"metrics.read"}}},
		},
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	authReq := model.AuthorizationRequest{
		RequestID: "metrics-req-1",
		Subject:   model.Subject{Type: "agent", AgentID: agentID},
		Action:    model.Action{Name: "metrics.read"},
	}
	body, _ := json.Marshal(authReq)
	req := httptest.NewRequest("POST", "/v1/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics: got %d, want 200", w.Code)
	}

	bodyText := w.Body.String()
	for _, want := range []string{
		"oap_authorize_requests_total 1",
		"oap_authorization_decisions_total{decision=\"allow\"} 1",
		"oap_audit_write_errors_total 0",
	} {
		if !strings.Contains(bodyText, want) {
			t.Fatalf("metrics response missing %q. Body:\n%s", want, bodyText)
		}
	}
}

func TestRegisterAgentRejectsUnknownFields(t *testing.T) {
	srv, _ := setupTestServer(t)

	body := []byte(`{
		"apiVersion": "oap.dev/v1alpha1",
		"kind": "Agent",
		"metadata": {"name": "bad-agent", "namespace": "test"},
		"spec": {
			"owner": "group:test",
			"type": "workflow_agent",
			"riskTier": "low",
			"capabilities": ["test.read"],
			"runtime": {"language": "python"}
		}
	}`)
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("register agent with unknown field: got %d, want 400. Body: %s", w.Code, w.Body.String())
	}
}

func TestSimulateEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)

	// Register agent and policy
	ctx := context.Background()
	srv.Store().RegisterAgent(ctx, &model.Agent{
		Metadata: model.Metadata{Name: "sim-agent", Namespace: "test"},
		Spec:     model.AgentSpec{Owner: "test", Type: "workflow_agent", RiskTier: "low", Capabilities: []string{"api.call"}},
		Status:   model.AgentStatus{State: model.AgentStateActive},
	})
	srv.Store().AddPolicy(ctx, &model.AgentPolicy{
		Metadata: model.Metadata{Name: "allow-api", Namespace: "test"},
		Spec: model.PolicySpec{
			Subject: model.PolicySubject{Agent: "agent://test/sim-agent"},
			Rules:   []model.PolicyRule{{Effect: model.EffectAllow, Actions: []string{"api.call"}}},
		},
	})

	authReq := model.AuthorizationRequest{
		RequestID: "sim-1",
		Subject:   model.Subject{Type: "agent", AgentID: "agent://test/sim-agent"},
		Action:    model.Action{Name: "api.call"},
	}
	body, _ := json.Marshal(authReq)
	req := httptest.NewRequest("POST", "/v1/simulate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("simulate: got %d, want 200", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)

	// Should have both decision and trace
	if result["decision"] == nil {
		t.Error("simulate: missing decision")
	}
	if result["trace"] == nil {
		t.Error("simulate: missing trace")
	}
}
