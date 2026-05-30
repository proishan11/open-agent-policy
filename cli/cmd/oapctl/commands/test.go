package commands

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/proishan11/open-agent-policy/engine/evaluator"
	"github.com/proishan11/open-agent-policy/engine/model"
	"github.com/proishan11/open-agent-policy/engine/store/memory"
	"gopkg.in/yaml.v3"
)

// conformanceCase is the YAML structure of a conformance test case.
type conformanceCase struct {
	Name     string                     `yaml:"name"`
	Agents   []model.Agent              `yaml:"agents"`
	Policies []model.AgentPolicy        `yaml:"policies"`
	Request  model.AuthorizationRequest `yaml:"request"`
	Expected struct {
		Decision       string                 `yaml:"decision"`
		ReasonContains string                 `yaml:"reason_contains"`
		Constraints    map[string]interface{} `yaml:"constraints"`
	} `yaml:"expected"`
}

// RunTest runs the conformance test suite.
// Usage: oapctl test --conformance [--cases <dir>]
func RunTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	conformance := fs.Bool("conformance", false, "run conformance test suite")
	casesDir := fs.String("cases", "", "path to conformance cases directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*conformance {
		return fmt.Errorf("usage: oapctl test --conformance [--cases <dir>]")
	}

	// Find conformance cases directory
	dir := *casesDir
	if dir == "" {
		// Try relative to working directory
		candidates := []string{
			"conformance/cases",
			"../conformance/cases",
			"../../conformance/cases",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				dir = c
				break
			}
		}
		if dir == "" {
			return fmt.Errorf("conformance cases directory not found; use --cases flag")
		}
	}

	return runConformanceSuite(dir)
}

// runConformanceSuite loads and evaluates all conformance test cases.
func runConformanceSuite(casesDir string) error {
	entries, err := os.ReadDir(casesDir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", casesDir, err)
	}

	// Collect YAML files and sort for deterministic order
	var files []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".yaml" {
			files = append(files, filepath.Join(casesDir, entry.Name()))
		}
	}
	sort.Strings(files)

	fmt.Printf("\n  Open Agent Policy — Conformance Tests\n")
	fmt.Printf("  ════════════════════════════════════════\n\n")

	passed := 0
	failed := 0

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("  \033[91m✗\033[0m %s: read error: %v\n", filepath.Base(path), err)
			failed++
			continue
		}

		var tc conformanceCase
		if err := yaml.Unmarshal(data, &tc); err != nil {
			fmt.Printf("  \033[91m✗\033[0m %s: parse error: %v\n", filepath.Base(path), err)
			failed++
			continue
		}

		// Set up evaluator with this case's agents and policies
		s := memory.New()
		for i := range tc.Agents {
			agent := tc.Agents[i]
			if agent.Status.State == "" {
				agent.Status.State = model.AgentStateActive
			}
			s.RegisterAgent(context.Background(), &agent)
		}
		for i := range tc.Policies {
			s.AddPolicy(context.Background(), &tc.Policies[i])
		}

		eval := evaluator.New(s)
		result := eval.Evaluate(context.Background(), tc.Request)

		// Check decision
		ok := true
		var failReasons []string

		if result.Decision.Decision != tc.Expected.Decision {
			ok = false
			failReasons = append(failReasons,
				fmt.Sprintf("decision: got %q, want %q", result.Decision.Decision, tc.Expected.Decision))
		}

		if tc.Expected.ReasonContains != "" {
			if !contains(result.Decision.Reason, tc.Expected.ReasonContains) {
				ok = false
				failReasons = append(failReasons,
					fmt.Sprintf("reason: got %q, want to contain %q", result.Decision.Reason, tc.Expected.ReasonContains))
			}
		}

		if tc.Expected.Constraints != nil {
			if err := checkConstraintsMatch(result.Decision.Constraints, tc.Expected.Constraints); err != nil {
				ok = false
				failReasons = append(failReasons, "constraints: "+err.Error())
			}
		}

		if ok {
			fmt.Printf("  \033[92m✓\033[0m %s\n", tc.Name)
			passed++
		} else {
			fmt.Printf("  \033[91m✗\033[0m %s\n", tc.Name)
			for _, r := range failReasons {
				fmt.Printf("    → %s\n", r)
			}
			failed++
		}
	}

	fmt.Printf("\n  ════════════════════════════════════════\n")
	total := passed + failed
	if failed == 0 {
		fmt.Printf("  Result: \033[92m✓ %d/%d passed\033[0m\n\n", passed, total)
	} else {
		fmt.Printf("  Result: \033[91m✗ %d/%d passed (%d failed)\033[0m\n\n", passed, total, failed)
	}

	if failed > 0 {
		return fmt.Errorf("%d conformance tests failed", failed)
	}
	return nil
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func checkConstraintsMatch(got *model.Constraints, expected map[string]interface{}) error {
	if got == nil {
		return fmt.Errorf("expected constraints but got nil")
	}

	if v, ok := expected["readonly"]; ok {
		if b, ok := v.(bool); ok {
			if got.ReadOnly == nil || *got.ReadOnly != b {
				return fmt.Errorf("readonly: got %v, want %v", got.ReadOnly, b)
			}
		}
	}

	if v, ok := expected["maxRecords"]; ok {
		expectedMax := toInt(v)
		if got.MaxRecords == nil || *got.MaxRecords != expectedMax {
			return fmt.Errorf("maxRecords: got %v, want %d", got.MaxRecords, expectedMax)
		}
	}
	return nil
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

// unused import guard — json is used for constraint checking
var _ = json.Marshal
