// oapctl is the OAP command-line tool for managing agents, policies,
// and simulating authorization decisions.
//
// Usage:
//
//	oapctl <command> [flags]
//
// Commands:
//
//	agent register -f <agent.yaml>      Register or update an agent
//	policy apply -f <policy.yaml>       Apply a policy
//	simulate -f <request.json>          Simulate an authorization decision
//	explain -f <request.json>           Explain a decision step-by-step
//	test --conformance                  Run conformance test suite
//	dev --data <dir>                    Start local dev server with data
package main

import (
	"fmt"
	"os"

	"github.com/proishan11/open-agent-policy/cli/cmd/oapctl/commands"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "dev":
		err = commands.RunDev(args)
	case "agent":
		err = commands.RunAgent(args)
	case "policy":
		err = commands.RunPolicy(args)
	case "simulate":
		err = commands.RunSimulate(args)
	case "explain":
		err = commands.RunExplain(args)
	case "test":
		err = commands.RunTest(args)
	case "version":
		fmt.Println("oapctl v0.1.0-alpha")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`oapctl — Open Agent Policy CLI

Usage:
  oapctl <command> [flags]

Commands:
  dev         Start a local dev server with data from files
  agent       Manage agents (register, list)
  policy      Manage policies (apply, list)
  simulate    Simulate an authorization decision (dry-run)
  explain     Explain a decision step-by-step
  test        Run conformance tests
  version     Print version

Use "oapctl <command> --help" for more information.`)
}
