package commands

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/proishan11/open-agent-policy/engine/evaluator"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
)

// RunSimulate runs a local simulation of an authorization decision.
// It loads agents and policies from a data directory, evaluates the request,
// and prints the decision.
//
// Usage: oapctl simulate -f <request.json> --data <dir>
func RunSimulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	file := fs.String("f", "", "path to authorization request JSON/YAML file")
	dataDir := fs.String("data", "", "directory of agent/policy files to load")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *file == "" {
		return fmt.Errorf("-f flag is required")
	}
	if *dataDir == "" {
		return fmt.Errorf("--data flag is required")
	}

	// Load data
	s := memory.New()
	if err := store.LoadDir(context.Background(), s, *dataDir); err != nil {
		return fmt.Errorf("loading data: %w", err)
	}

	// Load request
	data, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *file, err)
	}
	jsonData, err := yamlToJSON(data)
	if err != nil {
		return fmt.Errorf("converting to JSON: %w", err)
	}

	var req model.AuthorizationRequest
	if err := json.Unmarshal(jsonData, &req); err != nil {
		return fmt.Errorf("parsing request: %w", err)
	}

	// Evaluate
	eval := evaluator.New(s)
	result := eval.Evaluate(context.Background(), req)

	// Print result
	fmt.Printf("Decision: %s\n", colorDecision(result.Decision.Decision))
	fmt.Printf("Reason:   %s\n", result.Decision.Reason)
	if len(result.Decision.PolicyIDs) > 0 {
		fmt.Printf("Policies: %v\n", result.Decision.PolicyIDs)
	}
	if result.Decision.Constraints != nil {
		constraintsJSON, _ := json.MarshalIndent(result.Decision.Constraints, "          ", "  ")
		fmt.Printf("Constraints: %s\n", string(constraintsJSON))
	}
	return nil
}

// RunExplain runs a simulation with a full evaluation trace.
// Usage: oapctl explain -f <request.json> --data <dir>
func RunExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	file := fs.String("f", "", "path to authorization request JSON/YAML file")
	dataDir := fs.String("data", "", "directory of agent/policy files to load")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *file == "" {
		return fmt.Errorf("-f flag is required")
	}
	if *dataDir == "" {
		return fmt.Errorf("--data flag is required")
	}

	s := memory.New()
	if err := store.LoadDir(context.Background(), s, *dataDir); err != nil {
		return fmt.Errorf("loading data: %w", err)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *file, err)
	}
	jsonData, err := yamlToJSON(data)
	if err != nil {
		return fmt.Errorf("converting to JSON: %w", err)
	}

	var req model.AuthorizationRequest
	if err := json.Unmarshal(jsonData, &req); err != nil {
		return fmt.Errorf("parsing request: %w", err)
	}

	eval := evaluator.New(s)
	result := eval.Evaluate(context.Background(), req)

	// Print trace
	fmt.Printf("Evaluation trace for request %s:\n\n", req.RequestID)
	for i, step := range result.Trace {
		icon := "✓"
		if step.Result == "fail" {
			icon = "✗"
		} else if step.Result == "skip" {
			icon = "⊘"
		}
		policyInfo := ""
		if step.PolicyID != "" {
			policyInfo = fmt.Sprintf(" [%s]", step.PolicyID)
		}
		fmt.Printf("  %d. %s %s — %s%s\n", i+1, icon, step.Step, step.Detail, policyInfo)
	}

	fmt.Printf("\nFinal decision: %s\n", colorDecision(result.Decision.Decision))
	fmt.Printf("Reason: %s\n", result.Decision.Reason)
	return nil
}

// colorDecision returns the decision string with ANSI color codes.
func colorDecision(decision string) string {
	switch decision {
	case model.DecisionAllow, model.DecisionAllowConstrained:
		return "\033[92m" + decision + "\033[0m" // green
	case model.DecisionDeny:
		return "\033[91m" + decision + "\033[0m" // red
	case model.DecisionRequireApproval:
		return "\033[93m" + decision + "\033[0m" // yellow
	default:
		return decision
	}
}
