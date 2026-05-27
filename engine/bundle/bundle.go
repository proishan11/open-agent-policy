package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/registry"
)

// Bundle is a snapshot of agents and policies for distribution to embedded evaluators.
type Bundle struct {
	// Version is the bundle format version.
	Version string `json:"version"`

	// Timestamp is when the bundle was generated.
	Timestamp time.Time `json:"timestamp"`

	// ETag is a content hash for cache validation.
	ETag string `json:"etag"`

	// Agents in the bundle.
	Agents []*model.Agent `json:"agents"`

	// Policies in the bundle.
	Policies []*model.AgentPolicy `json:"policies"`
}

// Server serves policy bundles from a registry store.
type Server struct {
	store  *registry.Store
	mu     sync.RWMutex
	cached *Bundle
	logger *log.Logger
}

// NewServer creates a bundle server.
func NewServer(store *registry.Store) *Server {
	return &Server{
		store:  store,
		logger: log.New(log.Writer(), "[bundle-server] ", log.LstdFlags),
	}
}

// Handler returns an HTTP handler for the bundle endpoint.
func (s *Server) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bundle := s.Generate()

		// Check If-None-Match for caching
		if etag := r.Header.Get("If-None-Match"); etag == bundle.ETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", bundle.ETag)
		json.NewEncoder(w).Encode(bundle)
	}
}

// Generate creates a bundle from the current store state.
func (s *Server) Generate() *Bundle {
	agents := s.store.ListAgents()
	policies := s.store.ListPolicies()

	bundle := &Bundle{
		Version:   "v1",
		Timestamp: time.Now().UTC(),
		Agents:    agents,
		Policies:  policies,
	}

	// Compute ETag from content
	data, _ := json.Marshal(struct {
		A []*model.Agent       `json:"a"`
		P []*model.AgentPolicy `json:"p"`
	}{agents, policies})
	hash := sha256.Sum256(data)
	bundle.ETag = fmt.Sprintf("%x", hash[:8])

	return bundle
}

// Client polls a bundle server and updates a local store.
type Client struct {
	// ServerURL is the bundle server URL (e.g., http://oap-server:8080/v1/bundles).
	ServerURL string

	// Store is the local registry store to update.
	Store *registry.Store

	// Interval is the polling interval (default: 30 seconds).
	Interval time.Duration

	lastETag string
	logger   *log.Logger
	stopCh   chan struct{}
}

// NewClient creates a bundle sync client.
func NewClient(serverURL string, store *registry.Store, interval time.Duration) *Client {
	if interval == 0 {
		interval = 30 * time.Second
	}
	return &Client{
		ServerURL: serverURL,
		Store:     store,
		Interval:  interval,
		logger:    log.New(log.Writer(), "[bundle-client] ", log.LstdFlags),
		stopCh:    make(chan struct{}),
	}
}

// Start begins polling the bundle server in a background goroutine.
func (c *Client) Start(ctx context.Context) {
	go func() {
		// Immediate first sync
		if err := c.Sync(ctx); err != nil {
			c.logger.Printf("initial sync failed: %v", err)
		}

		ticker := time.NewTicker(c.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-ticker.C:
				if err := c.Sync(ctx); err != nil {
					c.logger.Printf("sync failed: %v", err)
				}
			}
		}
	}()
}

// Stop stops the background polling.
func (c *Client) Stop() {
	close(c.stopCh)
}

// Sync fetches the bundle and updates the local store.
func (c *Client) Sync(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.ServerURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	if c.lastETag != "" {
		req.Header.Set("If-None-Match", c.lastETag)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		c.logger.Printf("bundle unchanged (etag: %s)", c.lastETag)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var bundle Bundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return fmt.Errorf("decoding bundle: %w", err)
	}

	// Update local store
	for _, agent := range bundle.Agents {
		c.Store.RegisterAgent(agent)
	}
	for _, policy := range bundle.Policies {
		c.Store.AddPolicy(policy)
	}

	c.lastETag = bundle.ETag
	c.logger.Printf("synced bundle: %d agents, %d policies (etag: %s)",
		len(bundle.Agents), len(bundle.Policies), bundle.ETag)

	return nil
}
