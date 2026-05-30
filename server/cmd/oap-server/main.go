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
//	--store       Storage backend: memory or postgres
//	--postgres-dsn PostgreSQL connection string (or OAP_POSTGRES_DSN/DATABASE_URL)
//	--readiness-timeout Timeout for dependency readiness checks
//	--policy-backend Rule evaluation backend: builtin, opa, or cedar
//	--opa-url     OPA server base URL when --policy-backend=opa
//	--opa-policy-path OPA data API path (default "v1/data/oap/authz")
//	--cedar-url   Cedar-compatible authorization endpoint when --policy-backend=cedar
//	--issuer      OIDC issuer URL for agent token validation (enables auth)
//	--audience    Expected audience claim (optional)
//	--grant-key   HMAC-SHA256 key for signing grant tokens
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
	"time"

	"github.com/proishan11/open-agent-policy/server/api"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dataDir := flag.String("data", "", "directory of YAML/JSON data files to load on startup")
	auditFile := flag.String("audit-file", "", "path for JSONL audit log (default: stdout)")
	storeBackend := flag.String("store", "memory", "storage backend: memory or postgres")
	postgresDSN := flag.String("postgres-dsn", defaultPostgresDSN(), "PostgreSQL connection string (default: OAP_POSTGRES_DSN or DATABASE_URL)")
	readinessTimeout := flag.Duration("readiness-timeout", 2*time.Second, "timeout for dependency readiness checks")
	policyBackend := flag.String("policy-backend", envDefaultString("OAP_POLICY_BACKEND", "builtin"), "rule evaluation backend: builtin, opa, or cedar")
	opaURL := flag.String("opa-url", os.Getenv("OAP_OPA_URL"), "OPA server base URL when --policy-backend=opa")
	opaPolicyPath := flag.String("opa-policy-path", envDefaultString("OAP_OPA_POLICY_PATH", "v1/data/oap/authz"), "OPA data API path to query")
	opaTimeout := flag.Duration("opa-timeout", 5*time.Second, "timeout for OPA backend requests")
	opaFailOpen := flag.Bool("opa-fail-open", false, "fall back to built-in evaluator if OPA is unreachable")
	cedarURL := flag.String("cedar-url", os.Getenv("OAP_CEDAR_URL"), "Cedar-compatible authorization endpoint when --policy-backend=cedar")
	cedarPolicyStoreID := flag.String("cedar-policy-store-id", os.Getenv("OAP_CEDAR_POLICY_STORE_ID"), "Cedar/AWS Verified Permissions policy store ID")
	cedarTimeout := flag.Duration("cedar-timeout", 5*time.Second, "timeout for Cedar backend requests")
	cedarFailOpen := flag.Bool("cedar-fail-open", false, "fall back to built-in evaluator if Cedar is unreachable")
	issuer := flag.String("issuer", "", "OIDC issuer URL for agent token validation (enables auth)")
	audience := flag.String("audience", "", "expected audience claim (optional)")
	grantKey := flag.String("grant-key", "", "HMAC-SHA256 key for signing grant tokens (default: random dev key)")
	devMode := flag.Bool("dev", false, "enable development mode")
	flag.Parse()

	cfg := api.Config{
		Addr:               *addr,
		DataDir:            *dataDir,
		AuditFile:          *auditFile,
		StoreBackend:       *storeBackend,
		PostgresDSN:        *postgresDSN,
		ReadinessTimeout:   *readinessTimeout,
		DevMode:            *devMode,
		GrantSigningKey:    *grantKey,
		PolicyBackend:      *policyBackend,
		OPAURL:             *opaURL,
		OPAPolicyPath:      *opaPolicyPath,
		OPATimeout:         *opaTimeout,
		OPAFailOpen:        *opaFailOpen,
		CedarURL:           *cedarURL,
		CedarPolicyStoreID: *cedarPolicyStoreID,
		CedarTimeout:       *cedarTimeout,
		CedarFailOpen:      *cedarFailOpen,
		Auth: api.AuthConfig{
			IssuerURL: *issuer,
			Audience:  *audience,
		},
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

	log.Printf("OAP server starting on %s (dev=%v store=%s policy_backend=%s)", *addr, *devMode, *storeBackend, *policyBackend)
	if *dataDir != "" {
		log.Printf("Loaded data from %s", *dataDir)
	}
	if *storeBackend == "postgres" && *auditFile == "" {
		log.Printf("Audit events are persisted and queryable in Postgres")
	}

	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		log.Printf("server stopped: %v", err)
	}
}

func defaultPostgresDSN() string {
	if dsn := os.Getenv("OAP_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	return os.Getenv("DATABASE_URL")
}

func envDefaultString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
