package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
)

// OPAConfig configures the OPA policy backend.
type OPAConfig struct {
	// URL is the OPA server base URL (e.g., http://localhost:8181).
	URL string

	// PolicyPath is the Rego package path to query
	// (e.g., "v1/data/oap/authz" → queries data.oap.authz).
	PolicyPath string

	// Timeout for OPA requests (default: 5s).
	Timeout time.Duration

	// FailOpen determines behavior when OPA is unreachable.
	// If false (default), fail closed → deny.
	// If true, fall back to OAP's builtin evaluator.
	FailOpen bool
}

// OPABackend delegates rule evaluation to an Open Policy Agent server.
//
// OPA receives the full OAP authorization request as input and returns
// a decision. This allows enterprises to write Rego policies that
// integrate with their existing OPA infrastructure while getting
// OAP's agent lifecycle, constraints, and audit for free.
//
// Expected Rego policy interface:
//
//	package oap.authz
//
//	default decision = "deny"
//
//	decision = "allow" {
//	    # ... your Rego rules
//	}
//
//	decision = "deny" {
//	    # ... your deny rules
//	}
//
//	reason = msg {
//	    # ... human-readable reason
//	}
//
//	constraints = obj {
//	    # ... optional constraints map
//	}
type OPABackend struct {
	cfg    OPAConfig
	client *http.Client
}

// NewOPABackend creates an OPA policy backend.
func NewOPABackend(cfg OPAConfig) *OPABackend {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.PolicyPath == "" {
		cfg.PolicyPath = "v1/data/oap/authz"
	}
	return &OPABackend{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// Name returns "opa".
func (b *OPABackend) Name() string { return "opa" }

// opaInput is the JSON structure sent to OPA.
type opaInput struct {
	Input opaInputBody `json:"input"`
}

type opaInputBody struct {
	Agent    *model.Agent                `json:"agent"`
	Request  model.AuthorizationRequest  `json:"request"`
	Policies []*model.AgentPolicy        `json:"policies"`
}

// opaResponse is the JSON structure returned by OPA.
type opaResponse struct {
	Result opaResult `json:"result"`
}

type opaResult struct {
	Decision    string                 `json:"decision"`
	Reason      string                 `json:"reason"`
	PolicyIDs   []string               `json:"policy_ids"`
	Constraints map[string]interface{} `json:"constraints"`
}

// Evaluate sends the authorization request to OPA and maps the response.
func (b *OPABackend) Evaluate(ctx context.Context, input Input) (*Result, error) {
	// Build OPA input
	opaIn := opaInput{
		Input: opaInputBody{
			Agent:    input.Agent,
			Request:  input.Request,
			Policies: input.Policies,
		},
	}

	body, err := json.Marshal(opaIn)
	if err != nil {
		return nil, fmt.Errorf("opa: marshal input: %w", err)
	}

	// POST to OPA
	url := fmt.Sprintf("%s/%s", b.cfg.URL, b.cfg.PolicyPath)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("opa: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		if b.cfg.FailOpen {
			return nil, fmt.Errorf("opa: unreachable (fail-open): %w", err)
		}
		return &Result{
			Decision: model.DecisionDeny,
			Reason:   fmt.Sprintf("opa: unreachable (fail-closed): %v", err),
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if b.cfg.FailOpen {
			return nil, fmt.Errorf("opa: HTTP %d (fail-open)", resp.StatusCode)
		}
		return &Result{
			Decision: model.DecisionDeny,
			Reason:   fmt.Sprintf("opa: HTTP %d (fail-closed)", resp.StatusCode),
		}, nil
	}

	// Parse OPA response
	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return &Result{
			Decision: model.DecisionDeny,
			Reason:   fmt.Sprintf("opa: invalid response: %v", err),
		}, nil
	}

	result := &Result{
		Decision:    opaResp.Result.Decision,
		Reason:      opaResp.Result.Reason,
		PolicyIDs:   opaResp.Result.PolicyIDs,
		Constraints: opaResp.Result.Constraints,
	}

	// Default to deny if OPA returns empty decision
	if result.Decision == "" {
		result.Decision = model.DecisionDeny
		result.Reason = "opa: no decision returned"
	}

	return result, nil
}
