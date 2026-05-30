package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/proishan11/open-agent-policy/engine/store"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
)

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	data := []byte(`apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: bad-agent
  namespace: test
spec:
  owner: group:test
  type: workflow_agent
  riskTier: low
  capabilities:
    - test.read
  runtime:
    language: python
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	err := store.LoadFile(context.Background(), memory.New(), path)
	if err == nil {
		t.Fatal("expected unknown runtime.language field to be rejected")
	}
}
