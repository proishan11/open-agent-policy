# Server

The OAP HTTP server wraps the engine library into a REST API.

## Purpose

Provides the HTTP API defined in `spec/openapi/oap-server.openapi.yaml` for clients that cannot embed the evaluator. Also serves as the central control plane for agent registration, policy management, and audit.

## Architecture

```
server/
├── api/
│   ├── server.go       HTTP handlers, routing, audit event emission
│   └── server_test.go  Integration tests
└── cmd/
    └── oap-server/
        └── main.go     Binary entry point
```

The server composes three engine components:
- **Registry Store** — holds agents, resources, tools, policies in memory or Postgres
- **Evaluator** — makes authorization decisions with the built-in, OPA, or Cedar rule backend
- **Audit Sink** — writes structured events to stdout, JSONL, or Postgres

## Key Interfaces

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/authorize` | Runtime authorization (hot path) |
| POST | `/v1/simulate` | Dry-run with evaluation trace |
| POST | `/v1/agents` | Register an agent |
| GET | `/v1/agents` | List registered agents |
| POST | `/v1/policies` | Apply a policy (idempotent) |
| GET | `/v1/policies` | List policies |
| GET | `/v1/audit` | Query audit events |
| GET | `/v1/health` | Process liveness check |
| GET | `/v1/ready` | Dependency readiness check |
| GET | `/metrics` | Prometheus text metrics |

### Configuration

```
oap-server [flags]
  --addr        Listen address (default ":8080")
  --data        Directory of YAML/JSON files to load on startup
  --audit-file  Path for JSONL audit log (default: stdout)
  --store       Storage backend: memory or postgres
  --postgres-dsn PostgreSQL connection string
  --readiness-timeout Timeout for dependency readiness checks (default: 2s)
  --policy-backend Rule evaluation backend: builtin, opa, or cedar
  --opa-url     OPA server base URL
  --opa-policy-path OPA data API path (default: v1/data/oap/authz)
  --opa-timeout Timeout for OPA backend calls
  --opa-fail-open Fall back to built-in evaluator if OPA is unreachable
  --cedar-url   Cedar-compatible authorization endpoint
  --cedar-policy-store-id Cedar/AWS Verified Permissions policy store ID
  --cedar-timeout Timeout for Cedar backend calls
  --cedar-fail-open Fall back to built-in evaluator if Cedar is unreachable
  --dev         Enable development mode
```

Postgres mode makes agents, policies, resources, tools, and audit events durable:

```bash
OAP_POSTGRES_DSN='postgres://oap:oap@localhost:5432/oap?sslmode=disable' \
  oap-server --store postgres --data examples/finance-invoice-agent/
```

When `--store postgres` is used, `GET /v1/audit` queries the Postgres audit table. If `--audit-file` is also set, audit events are written to both Postgres and the JSONL file.

The Postgres store applies ordered schema migrations on startup and records
version, name, checksum, and timestamp metadata in `oap_schema_version`. A
Postgres advisory transaction lock prevents multiple server instances from
racing the migration runner.

Use `/v1/health` for liveness and `/v1/ready` for load-balancer or Kubernetes readiness. Readiness checks the configured store with a bounded timeout. `/metrics` exposes process-local Prometheus counters for authorization requests, decisions, audit query/write errors, and readiness failures.

OPA server mode delegates only rule evaluation:

```bash
oap-server \
  --data validation/policies \
  --policy-backend opa \
  --opa-url http://localhost:8181 \
  --grant-key "$OAP_GRANT_KEY"
```

Cedar server mode uses a Cedar-compatible authorization endpoint:

```bash
oap-server \
  --data validation/policies \
  --policy-backend cedar \
  --cedar-url http://localhost:8180/v1/is_authorized \
  --cedar-policy-store-id "$CEDAR_POLICY_STORE_ID" \
  --grant-key "$OAP_GRANT_KEY"
```

Both external modes fail closed by default. The fail-open flags are intended for
explicit compatibility testing, because they fall back to the built-in evaluator
when the external backend is unavailable.

## Data Flow

```
HTTP POST /v1/authorize
  │
  ├── Parse JSON body → AuthorizationRequest
  │
  ├── evaluator.Evaluate(ctx, request)
  │     ├── validate request, agent lifecycle, capabilities, policies, delegation
  │     └── evaluate rules with built-in, OPA, or Cedar backend
  │
  ├── Build AuditEvent from request + decision
  ├── auditSink.Write(event)  # stdout/JSONL/Postgres depending on config
  │
  └── Return AuthorizationDecision as JSON
```

## Testing

```bash
# Run server integration tests
go test -v ./server/api/

# Build binary
go build -o bin/oap-server ./server/cmd/oap-server/

# Run with example data
./bin/oap-server --data examples/finance-invoice-agent/ --dev
```
