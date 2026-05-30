package commands

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

// RunAgent handles agent management commands.
// Usage: oapctl agent register -f <agent.yaml>
//        oapctl agent list [--server <url>]
func RunAgent(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: oapctl agent <register|list> [flags]")
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "register":
		return agentRegister(subArgs)
	case "list":
		return agentList(subArgs)
	default:
		return fmt.Errorf("unknown agent subcommand: %s", subCmd)
	}
}

func agentRegister(args []string) error {
	fs := flag.NewFlagSet("agent register", flag.ExitOnError)
	file := fs.String("f", "", "path to agent YAML/JSON file")
	server := fs.String("server", "http://localhost:8080", "OAP server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *file == "" {
		return fmt.Errorf("-f flag is required")
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *file, err)
	}

	// Convert YAML to JSON if needed
	jsonData, err := yamlToJSON(data)
	if err != nil {
		return fmt.Errorf("converting to JSON: %w", err)
	}

	resp, err := http.Post(*server+"/v1/agents", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("calling server: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	agentID := ""
	if meta, ok := result["metadata"].(map[string]interface{}); ok {
		ns, _ := meta["namespace"].(string)
		name, _ := meta["name"].(string)
		agentID = "agent://" + ns + "/" + name
	}

	fmt.Printf("✓ Agent registered: %s\n", agentID)
	return nil
}

func agentList(args []string) error {
	fs := flag.NewFlagSet("agent list", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "OAP server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resp, err := http.Get(*server + "/v1/agents")
	if err != nil {
		return fmt.Errorf("calling server: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	items, _ := result["items"].([]interface{})
	fmt.Printf("Registered agents (%d):\n", len(items))
	for _, item := range items {
		if agent, ok := item.(map[string]interface{}); ok {
			if meta, ok := agent["metadata"].(map[string]interface{}); ok {
				ns, _ := meta["namespace"].(string)
				name, _ := meta["name"].(string)
				fmt.Printf("  - agent://%s/%s\n", ns, name)
			}
		}
	}
	return nil
}
