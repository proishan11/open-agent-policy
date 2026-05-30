package commands

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/proishan11/open-agent-policy/server/api"
)

// RunDev starts a local development server pre-loaded with data files.
// Usage: oapctl dev --data <dir> [--addr :8080] [--audit-file <path>]
func RunDev(args []string) error {
	fs := flag.NewFlagSet("dev", flag.ExitOnError)
	dataDir := fs.String("data", "", "directory of YAML/JSON data files")
	addr := fs.String("addr", ":8080", "listen address")
	auditFile := fs.String("audit-file", "", "JSONL audit log path (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *dataDir == "" {
		return fmt.Errorf("--data flag is required")
	}

	cfg := api.Config{
		Addr:      *addr,
		DataDir:   *dataDir,
		AuditFile: *auditFile,
		DevMode:   true,
	}

	srv, err := api.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("starting server: %w", err)
	}
	defer srv.Close()

	s := srv.Store()
	agents, _ := s.ListAgents(context.Background())
	policies, _ := s.ListPolicies(context.Background())
	fmt.Printf("OAP Dev Server\n")
	fmt.Printf("  Addr:     %s\n", *addr)
	fmt.Printf("  Data:     %s\n", *dataDir)
	fmt.Printf("  Agents:   %d\n", len(agents))
	fmt.Printf("  Policies: %d\n", len(policies))
	fmt.Println()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("Listening on %s (press Ctrl+C to stop)\n", *addr)
	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		fmt.Fprintf(os.Stderr, "server stopped: %v\n", err)
	}
	return nil
}
