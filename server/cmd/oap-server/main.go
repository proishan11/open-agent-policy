// oap-server is the OAP control plane HTTP server.
//
// It provides the HTTP API for agent registration, policy management,
// runtime authorization, simulation, and audit queries.
//
// Usage:
//
//	oap-server [flags]
//	oap-server --addr :8080 --data ./examples/finance-invoice-agent/
//
// Flags:
//
//	--addr        Listen address (default ":8080")
//	--data        Directory of YAML/JSON files to load on startup
//	--audit-file  Path for JSONL audit log (default: stdout)
//	--dev         Enable development mode
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/proishan11/open-agent-policy/server/api"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dataDir := flag.String("data", "", "directory of YAML/JSON data files to load on startup")
	auditFile := flag.String("audit-file", "", "path for JSONL audit log (default: stdout)")
	devMode := flag.Bool("dev", false, "enable development mode")
	flag.Parse()

	cfg := api.Config{
		Addr:      *addr,
		DataDir:   *dataDir,
		AuditFile: *auditFile,
		DevMode:   *devMode,
	}

	srv, err := api.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("OAP server starting on %s (dev=%v)", *addr, *devMode)
	if *dataDir != "" {
		log.Printf("Loaded data from %s", *dataDir)
	}

	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		log.Printf("server stopped: %v", err)
	}
}
