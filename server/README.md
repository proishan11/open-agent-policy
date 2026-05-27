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
- **Registry Store** — holds agents, resources, tools, policies in memory
- **Evaluator** — makes authorization decisions
- **Audit Sink** — writes structured events (JSONL file or stdout)

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
| GET | `/v1/health` | Health check |

### Configuration

```
oap-server [flags]
  --addr        Listen address (default ":8080")
  --data        Directory of YAML/JSON files to load on startup
  --audit-file  Path for JSONL audit log (default: stdout)
  --dev         Enable development mode
```

## Data Flow

```
HTTP POST /v1/authorize
  │
  ├── Parse JSON body → AuthorizationRequest
  │
  ├── evaluator.Evaluate(ctx, request)
  │     └── (pure engine logic, no I/O)
  │
  ├── Build AuditEvent from request + decision
  ├── auditSink.Write(event)
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
