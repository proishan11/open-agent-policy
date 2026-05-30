package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/proishan11/open-agent-policy/engine/model"
	"gopkg.in/yaml.v3"
)

// LoadDir loads all YAML and JSON files from a directory (recursive) into
// the given Store. Each file must contain a top-level "kind" field to route it
// to the correct operation. Unrecognized kinds are silently skipped.
//
// Supported kinds: Agent, Resource, Tool, AgentPolicy.
func LoadDir(ctx context.Context, s Store, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		if loadErr := LoadFile(ctx, s, path); loadErr != nil {
			return fmt.Errorf("loading %s: %w", path, loadErr)
		}
		return nil
	})
}

// LoadFile loads a single YAML or JSON file into the Store.
func LoadFile(ctx context.Context, s Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	// Peek at the "kind" field to determine which type to unmarshal into.
	var peek struct {
		Kind string `json:"kind" yaml:"kind"`
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &peek); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	default: // .yaml, .yml
		if err := yaml.Unmarshal(data, &peek); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	switch peek.Kind {
	case "Agent":
		var agent model.Agent
		if err := unmarshal(data, ext, &agent); err != nil {
			return err
		}
		// Set default status if not provided
		if agent.Status.State == "" {
			agent.Status.State = model.AgentStateActive
		}
		return s.RegisterAgent(ctx, &agent)

	case "Resource":
		var resource model.Resource
		if err := unmarshal(data, ext, &resource); err != nil {
			return err
		}
		return s.AddResource(ctx, &resource)

	case "Tool":
		var tool model.Tool
		if err := unmarshal(data, ext, &tool); err != nil {
			return err
		}
		return s.AddTool(ctx, &tool)

	case "AgentPolicy":
		var policy model.AgentPolicy
		if err := unmarshal(data, ext, &policy); err != nil {
			return err
		}
		return s.AddPolicy(ctx, &policy)

	default:
		// Skip files with unrecognized or empty kinds
		return nil
	}
}

// unmarshal deserializes data based on file extension.
func unmarshal(data []byte, ext string, v interface{}) error {
	switch ext {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		return dec.Decode(v)
	default:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		return dec.Decode(v)
	}
}
