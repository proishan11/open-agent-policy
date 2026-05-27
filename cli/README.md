# CLI (oapctl)

`oapctl` is the OAP command-line tool for managing agents, policies, simulating decisions, and running conformance tests.

## Purpose

Provides a developer-friendly interface for interacting with OAP. Works in two modes:
- **Local mode** — loads data from files, runs the evaluator in-process (no server needed)
- **Remote mode** — talks to a running OAP server via HTTP

## Architecture

```
cli/
└── cmd/
    └── oapctl/
        ├── main.go           Entry point, command routing
        └── commands/
            ├── dev.go        Start local dev server
            ├── agent.go      Agent register/list (remote)
            ├── policy.go     Policy apply/list (remote)
            ├── simulate.go   Simulate and explain (local)
            ├── test.go       Conformance test runner (local)
            └── helpers.go    YAML/JSON conversion
```

## Commands

### `oapctl dev` — Start a local dev server

```bash
oapctl dev --data examples/finance-invoice-agent/ --addr :8080
```

Loads agents and policies from files, starts an HTTP server.

### `oapctl agent register` — Register an agent

```bash
oapctl agent register -f examples/finance-invoice-agent/oap.yaml
```

### `oapctl policy apply` — Apply a policy

```bash
oapctl policy apply -f examples/finance-invoice-agent/policies/finance-invoice-readonly.yaml
```

### `oapctl simulate` — Simulate a decision (local)

```bash
oapctl simulate -f requests/read-invoice.json --data examples/finance-invoice-agent/
# → allow_with_constraints (readonly, redact bank_account, max 25 records)
```

### `oapctl explain` — Step-by-step trace (local)

```bash
oapctl explain -f requests/read-invoice.json --data examples/finance-invoice-agent/
# → Shows each evaluation step with pass/fail/skip
```

### `oapctl test --conformance` — Run conformance tests

```bash
oapctl test --conformance
# → 10/10 passed
```

## Data Flow

```
simulate/explain (local mode):
  Load YAML/JSON files → Registry Store
  Parse request file → AuthorizationRequest
  evaluator.Evaluate(ctx, request) → Decision + Trace
  Print results to stdout

agent/policy (remote mode):
  Read YAML file → Convert to JSON
  POST to OAP server → Print result
```

## Testing

```bash
# Build CLI
go build -o bin/oapctl ./cli/cmd/oapctl/

# Run conformance suite
./bin/oapctl test --conformance
```
