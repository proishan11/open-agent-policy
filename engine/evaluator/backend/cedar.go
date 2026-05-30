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

// CedarConfig configures the Cedar policy backend.
type CedarConfig struct {
	// URL is the Cedar authorization service URL
	// (e.g., http://localhost:8180/v1/is_authorized).
	URL string

	// PolicyStoreID identifies the Cedar policy store (for AWS Verified Permissions).
	PolicyStoreID string

	// Timeout for Cedar requests (default: 5s).
	Timeout time.Duration

	// FailOpen determines behavior when Cedar is unreachable.
	FailOpen bool
}

// CedarBackend delegates rule evaluation to AWS Cedar (or a Cedar-compatible service).
//
// Cedar uses an entity-based authorization model. OAP maps its concepts to Cedar:
//
//	OAP Agent       → Cedar Principal (type: "OAP::Agent", id: agent_id)
//	OAP Action      → Cedar Action (type: "OAP::Action", id: action_name)
//	OAP Resource    → Cedar Resource (type: resource_type, id: resource_id)
//	OAP Actor       → Cedar Context.actor
//	OAP Context     → Cedar Context (additional attributes)
//
// Expected Cedar policy:
//
//	permit(
//	    principal == OAP::Agent::"agent://support/ticket-agent",
//	    action == OAP::Action::"tickets.read",
//	    resource
//	);
//
//	forbid(
//	    principal == OAP::Agent::"agent://support/ticket-agent",
//	    action == OAP::Action::"tickets.delete",
//	    resource
//	);
type CedarBackend struct {
	cfg    CedarConfig
	client *http.Client
}

// NewCedarBackend creates a Cedar policy backend.
func NewCedarBackend(cfg CedarConfig) *CedarBackend {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &CedarBackend{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// Name returns "cedar".
func (b *CedarBackend) Name() string { return "cedar" }

// FailOpen reports whether OAP should fall back to the built-in evaluator when
// Cedar returns a transport/configuration error.
func (b *CedarBackend) FailOpen() bool { return b.cfg.FailOpen }

// cedarRequest is the authorization request sent to Cedar.
type cedarRequest struct {
	Principal cedarEntityRef         `json:"principal"`
	Action    cedarEntityRef         `json:"action"`
	Resource  cedarEntityRef         `json:"resource"`
	Context   map[string]interface{} `json:"context,omitempty"`

	// AWS Verified Permissions-specific
	PolicyStoreID string `json:"policyStoreId,omitempty"`
}

// cedarEntityRef identifies a Cedar entity.
type cedarEntityRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// cedarResponse is the authorization response from Cedar.
type cedarResponse struct {
	Decision    string                 `json:"decision"` // "Allow" or "Deny"
	Diagnostics cedarDiagnostics       `json:"diagnostics,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

type cedarDiagnostics struct {
	Reason []string `json:"reason,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

// Evaluate sends the authorization request to Cedar and maps the response.
func (b *CedarBackend) Evaluate(ctx context.Context, input Input) (*Result, error) {
	// Map OAP request to Cedar entities
	resourceType := "OAP::Resource"
	resourceID := "*"
	if input.Request.Resource != nil {
		if input.Request.Resource.Type != "" {
			resourceType = "OAP::" + input.Request.Resource.Type
		}
		if input.Request.Resource.ID != "" {
			resourceID = input.Request.Resource.ID
		}
	}

	cedarCtx := make(map[string]interface{})
	if input.Request.Actor != nil {
		cedarCtx["actor"] = map[string]interface{}{
			"type": input.Request.Actor.Type,
			"id":   input.Request.Actor.ID,
		}
	}
	if input.Request.Context != nil {
		for k, v := range input.Request.Context {
			cedarCtx[k] = v
		}
	}
	// Include agent metadata in context for Cedar policy access
	if input.Agent != nil {
		cedarCtx["agent_risk_tier"] = input.Agent.Spec.RiskTier
		cedarCtx["agent_type"] = input.Agent.Spec.Type
		cedarCtx["agent_capabilities"] = input.Agent.Spec.Capabilities
	}

	cedarReq := cedarRequest{
		Principal: cedarEntityRef{Type: "OAP::Agent", ID: input.Request.Subject.AgentID},
		Action:    cedarEntityRef{Type: "OAP::Action", ID: input.Request.Action.Name},
		Resource:  cedarEntityRef{Type: resourceType, ID: resourceID},
		Context:   cedarCtx,
	}

	if b.cfg.PolicyStoreID != "" {
		cedarReq.PolicyStoreID = b.cfg.PolicyStoreID
	}

	body, err := json.Marshal(cedarReq)
	if err != nil {
		return nil, fmt.Errorf("cedar: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", b.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cedar: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		if b.cfg.FailOpen {
			return nil, fmt.Errorf("cedar: unreachable (fail-open): %w", err)
		}
		return &Result{
			Decision: model.DecisionDeny,
			Reason:   fmt.Sprintf("cedar: unreachable (fail-closed): %v", err),
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if b.cfg.FailOpen {
			return nil, fmt.Errorf("cedar: HTTP %d (fail-open)", resp.StatusCode)
		}
		return &Result{
			Decision: model.DecisionDeny,
			Reason:   fmt.Sprintf("cedar: HTTP %d (fail-closed)", resp.StatusCode),
		}, nil
	}

	var cedarResp cedarResponse
	if err := json.NewDecoder(resp.Body).Decode(&cedarResp); err != nil {
		return &Result{
			Decision: model.DecisionDeny,
			Reason:   fmt.Sprintf("cedar: invalid response: %v", err),
		}, nil
	}

	// Map Cedar decision to OAP decision
	result := &Result{}
	switch cedarResp.Decision {
	case "Allow", "allow":
		result.Decision = model.DecisionAllow
		result.Reason = "allowed by Cedar policy"
		// Check if Cedar returned constraints in context
		if constraints, ok := cedarResp.Context["constraints"].(map[string]interface{}); ok {
			result.Decision = model.DecisionAllowConstrained
			result.Constraints = constraints
			result.Reason = "allowed with constraints by Cedar policy"
		}
	case "Deny", "deny":
		result.Decision = model.DecisionDeny
		result.Reason = "denied by Cedar policy"
	default:
		result.Decision = model.DecisionDeny
		result.Reason = fmt.Sprintf("cedar: unknown decision %q", cedarResp.Decision)
	}

	if len(cedarResp.Diagnostics.Reason) > 0 {
		result.Reason = cedarResp.Diagnostics.Reason[0]
	}

	return result, nil
}
