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

// RunPolicy handles policy management commands.
// Usage: oapctl policy apply -f <policy.yaml>
//        oapctl policy list [--server <url>]
func RunPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: oapctl policy <apply|list> [flags]")
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "apply":
		return policyApply(subArgs)
	case "list":
		return policyList(subArgs)
	default:
		return fmt.Errorf("unknown policy subcommand: %s", subCmd)
	}
}

func policyApply(args []string) error {
	fs := flag.NewFlagSet("policy apply", flag.ExitOnError)
	file := fs.String("f", "", "path to policy YAML/JSON file")
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

	jsonData, err := yamlToJSON(data)
	if err != nil {
		return fmt.Errorf("converting to JSON: %w", err)
	}

	resp, err := http.Post(*server+"/v1/policies", "application/json", bytes.NewReader(jsonData))
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

	policyID := ""
	if meta, ok := result["metadata"].(map[string]interface{}); ok {
		ns, _ := meta["namespace"].(string)
		name, _ := meta["name"].(string)
		policyID = ns + "/" + name
	}

	action := "applied"
	if resp.StatusCode == http.StatusCreated {
		action = "created"
	}
	fmt.Printf("✓ Policy %s: %s\n", action, policyID)
	return nil
}

func policyList(args []string) error {
	fs := flag.NewFlagSet("policy list", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "OAP server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resp, err := http.Get(*server + "/v1/policies")
	if err != nil {
		return fmt.Errorf("calling server: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	items, _ := result["items"].([]interface{})
	fmt.Printf("Policies (%d):\n", len(items))
	for _, item := range items {
		if policy, ok := item.(map[string]interface{}); ok {
			if meta, ok := policy["metadata"].(map[string]interface{}); ok {
				ns, _ := meta["namespace"].(string)
				name, _ := meta["name"].(string)
				fmt.Printf("  - %s/%s\n", ns, name)
			}
		}
	}
	return nil
}
