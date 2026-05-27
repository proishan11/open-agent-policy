// Package gateway provides HTTP gateway and middleware for OAP enforcement.
//
// GrantMiddleware is a reusable HTTP middleware that validates OAP grant
// tokens presented in the X-OAP-Grant-Token header. Resource APIs embed
// this middleware to verify that an agent has been authorized by OAP
// before serving the request.
//
// Usage:
//
//	mw := gateway.NewGrantMiddleware(gateway.GrantMiddlewareConfig{
//	    OAPServerURL: "http://oap-server:8080",
//	})
//	http.Handle("/api/", mw.Wrap(myHandler))
package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GrantMiddlewareConfig configures the grant validation middleware.
type GrantMiddlewareConfig struct {
	// OAPServerURL is the OAP server to validate grants against.
	OAPServerURL string

	// HeaderName is the header containing the grant token.
	// Default: "X-OAP-Grant-Token".
	HeaderName string

	// AllowMissing when true allows requests without a grant token to pass.
	// Useful for gradual rollout. Default: false (fail-closed).
	AllowMissing bool
}

// GrantMiddleware validates OAP grant tokens on incoming requests.
type GrantMiddleware struct {
	cfg    GrantMiddlewareConfig
	client *http.Client
}

// GrantInfo contains the verified grant claims, set in request context.
type GrantInfo struct {
	AgentID      string      `json:"agent_id"`
	Action       string      `json:"action"`
	ResourceType string      `json:"resource_type"`
	ResourceID   string      `json:"resource_id"`
	Decision     string      `json:"decision"`
	Constraints  interface{} `json:"constraints,omitempty"`
	RunID        string      `json:"run_id,omitempty"`
	ExpiresAt    int64       `json:"expires_at"`
}

// NewGrantMiddleware creates a grant validation middleware.
func NewGrantMiddleware(cfg GrantMiddlewareConfig) *GrantMiddleware {
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-OAP-Grant-Token"
	}
	return &GrantMiddleware{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Wrap returns an HTTP handler that validates the grant token before
// calling the next handler. On success, grant claims are available
// via the X-OAP-Agent-ID and X-OAP-Grant-Decision response headers.
func (m *GrantMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(m.cfg.HeaderName)
		if token == "" {
			if m.cfg.AllowMissing {
				next.ServeHTTP(w, r)
				return
			}
			writeGrantError(w, http.StatusUnauthorized, "missing_grant",
				fmt.Sprintf("%s header required", m.cfg.HeaderName))
			return
		}

		info, err := m.validateGrant(r, token)
		if err != nil {
			writeGrantError(w, http.StatusForbidden, "invalid_grant", err.Error())
			return
		}

		// Set verified identity headers for the resource handler
		r.Header.Set("X-OAP-Verified-Agent-ID", info.AgentID)
		r.Header.Set("X-OAP-Verified-Action", info.Action)
		r.Header.Set("X-OAP-Verified-Decision", info.Decision)
		if info.RunID != "" {
			r.Header.Set("X-OAP-Run-ID", info.RunID)
		}

		next.ServeHTTP(w, r)
	})
}

// validateGrant calls the OAP server's /v1/grants/validate endpoint.
func (m *GrantMiddleware) validateGrant(r *http.Request, token string) (*GrantInfo, error) {
	body, _ := json.Marshal(map[string]string{"grant_token": token})
	req, err := http.NewRequestWithContext(r.Context(), "POST",
		m.cfg.OAPServerURL+"/v1/grants/validate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OAP server unreachable: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grant validation failed: %s", string(respBody))
	}

	var info GrantInfo
	if err := json.Unmarshal(respBody, &info); err != nil {
		return nil, fmt.Errorf("parsing grant response: %w", err)
	}
	return &info, nil
}

func writeGrantError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"code":    code,
		"message": message,
	})
}
