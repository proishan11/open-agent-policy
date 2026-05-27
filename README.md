# Open Agent Policy (OAP)

> Zero-trust access control for AI agents.

[![CI](https://github.com/proishan11/open-agent-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/proishan11/open-agent-policy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-blue.svg)](https://conventionalcommits.org)

Open Agent Policy is an open-source, vendor-neutral framework that makes AI agents first-class security principals. It provides agent registration, policy-driven authorization, scoped grants, delegation, enforcement outside the agent, and structured audit — without changing how you build agents.

## The problem

Enterprises cannot answer basic questions about their AI agents:

- How many agents are running right now?
- Who owns each agent?
- What can each agent access?
- Can I disable a specific agent in five minutes?
- What did each agent do yesterday?

OAP exists to close that gap.

## How it works

```text
Agent registers with OAP
  → Developer attaches policies
  → Agent authenticates at runtime
  → Every tool call is authorized against policy
  → Decisions include constraints (redaction, limits, expiry)
  → Short-lived grants issued (not broad credentials)
  → Every decision is audited
  → Agents can be revoked instantly
```

## Core principles

1. **Agents must be registered** — unregistered agents are denied
2. **Deny by default** — no policy = no access
3. **Explicit deny overrides allow** — deny always wins
4. **Enforcement outside the agent** — agents don't self-enforce
5. **Audit is mandatory** — every decision is logged

## Quick start

### Prerequisites

- **Go 1.22+** — [install](https://go.dev/doc/install)
- **Python 3.11+** — [install](https://www.python.org/downloads/)
- **Make** — pre-installed on macOS/Linux

### Setup

```bash
# Clone
git clone https://github.com/proishan11/open-agent-policy.git
cd open-agent-policy

# Create venv, install Python deps + SDK in dev mode
make venv

# Activate the virtual environment
source .venv/bin/activate

# Install pre-commit hooks
make install-tools

# Build Go binaries
make build
```

### Try it out

```bash
# Run all 10 conformance tests
./bin/oapctl test --conformance

# Simulate an authorization decision
./bin/oapctl simulate \
  -f examples/finance-invoice-agent/requests/read-invoice.json \
  --data examples/finance-invoice-agent/
# → allow_with_constraints (readonly, redact bank_account, max 25 records)

# Explain the decision step-by-step
./bin/oapctl explain \
  -f examples/finance-invoice-agent/requests/delete-invoice.json \
  --data examples/finance-invoice-agent/
# → deny (Agents may not delete invoices)

# Run all tests (Go + Python + conformance)
make test
```

## Project status

OAP is in active development following a spec-driven approach.

| Milestone | Status | Description |
|---|---|---|
| 1. Spec + Conformance | ✅ Complete | JSON Schemas, OpenAPI, 10 conformance tests |
| 2. Engine + CLI | ✅ Complete | Go evaluator, oap-server, oapctl (10/10 conformance) |
| 3. Python SDK | ✅ Complete | OAPClient, @protect decorator, LangChain integration |
| 4. MCP Proxy + Gateway | ✅ Complete | MCP proxy, HTTP gateway, JWT grants, observe mode |
| 5. Production Ready | ✅ Complete | Identity verification, bundle sync, security tests, Helm chart |
| 6. Enterprise Identity & Storage | ✅ Complete | Real OIDC (Keycloak), Postgres, OPA/Cedar backends |
| Agent Identity Binding | ✅ Complete | Identity bindings, sessions, runs, scoped grants |
| Enforcement Layers | ✅ Complete | Gateway/proxy remote mode, grant middleware |
| 7. Framework Integrations | 🟡 Planned | OpenAI Agents, CrewAI, AutoGen, LlamaIndex |
| 8. Observability | 🟡 Planned | OpenTelemetry, SIEM exporters, Prometheus |

**Test coverage:** 127 Go tests · 32 Python SDK tests · 70 e2e tests = **229 total**

See [PROGRESS.md](PROGRESS.md) for detailed tracking.

## Repository structure

```text
spec/               — JSON Schemas and OpenAPI spec (the contract)
conformance/        — Conformance test cases (the specification tests)
engine/             — Go policy evaluator library
  model/            — Core domain types (Agent, Policy, Decision, Grant)
  evaluator/        — Policy decision engine (+ OPA, Cedar backends)
  store/            — Pluggable storage (memory, Postgres)
  session/          — Agent session + run management
  grant/            — Scoped JWT grant issuance + validation
  identity/         — OIDC, K8s, composite identity verifiers
  audit/            — Audit sinks (JSONL, stdout, memory)
  bundle/           — Policy bundle sync (server → embedded)
server/             — Go HTTP server (authorize, sessions, runs, grants)
cli/                — oapctl CLI (simulate, explain, test, dev)
sdk/python/         — Python SDK (OAPClient, Decision, Grant, @protect, LangChain)
gateway/            — HTTP gateway (embedded + remote mode, grant middleware)
proxy/              — MCP proxy (embedded + remote mode)
validation/         — E2e test suite (Keycloak + Postgres + 70 tests)
examples/           — Example agents, policies, and requests
docs/               — User guides, architecture docs, ADRs, flow diagrams
demos/              — Runnable demos per milestone
```

## Real-world example

The [enterprise support agent](examples/enterprise-support-agent/) demonstrates OAP protecting a realistic support ticket agent:

```bash
python examples/enterprise-support-agent/agent.py
```

| Tool | Decision | Constraints |
|---|---|---|
| `list_tickets` | ✅ Allow | max 10 records |
| `read_customer` | ✅ Allow | **Redact: SSN, credit card, bank account** |
| `update_ticket` | ✅ Allow | status/priority/assignee only |
| `escalate_ticket` | ✅ Allow | P1/P2 only |
| `send_email` (external) | ⏳ Approval | support-leads must approve |
| `delete_ticket` | 🛑 **Deny** | compliance requirement |

## Documentation

### User guides

- [Getting Started](docs/guide/getting-started.md) — setup, first agent, first policy, integration
- [Identity & Sessions](docs/guide/identity-and-sessions.md) — identity bindings, supported providers, sessions, runs, grant tokens
- [Writing Policies](docs/guide/writing-policies.md) — policy authoring, constraints, evaluation order
- [Integration Guide](docs/guide/integration.md) — SDK, gateway, proxy, grant middleware patterns

### Reference

- [Architecture](architecture.md) — system design, identity model, end-to-end flows
- [Enterprise Roadmap](ENTERPRISE_ROADMAP.md) — milestones 7-11 for full enterprise readiness
- [Development Plan](DEVELOPMENT_PLAN.md) — spec-driven approach, all milestones + gap analysis
- [Progress](PROGRESS.md) — detailed milestone tracking

### Project

- [Contributing](CONTRIBUTING.md) — how to contribute
- [Security](SECURITY.md) — vulnerability reporting
- [Changelog](CHANGELOG.md) — release history

## Architecture decisions

Recorded in [docs/adr/](docs/adr/):

- [ADR-001: Library-first evaluator](docs/adr/001-library-first-evaluator.md)
- [ADR-002: YAML rules-array policy format](docs/adr/002-yaml-policy-format.md)
- [ADR-003: Pluggable policy engine](docs/adr/003-pluggable-policy-engine.md)
- [ADR-004: Pluggable policy backend (OPA, Cedar)](docs/adr/004-pluggable-policy-backend.md)

## End-to-end flows

Mermaid sequence diagrams in [docs/flows/](docs/flows/):

- [Agent onboarding](docs/flows/agent-onboarding.md)
- [Runtime authorization](docs/flows/runtime-authorization.md)
- [Delegation](docs/flows/delegation.md)
- [Approval workflow](docs/flows/approval.md)
- [Revocation](docs/flows/revocation.md)

## Development

```bash
# First-time setup
make venv             # Create venv, install all Python deps + SDK
source .venv/bin/activate
make install-tools    # Install pre-commit hooks

# Common tasks
make build            # Build Go binaries (bin/oap-server, bin/oapctl)
make test             # Run all tests (Go + Python + conformance)
make test-go          # Run Go tests only
make test-python      # Run Python SDK tests only
make test-conformance # Validate schemas and conformance tests
make lint             # Run all linters (Go + Python + YAML + JSON + OpenAPI)
make fmt              # Format all code
make demo             # Run all demos
make clean            # Clean build artifacts
make clean-all        # Clean everything including .venv
```

## License

[MIT](LICENSE) — Copyright (c) 2026 Ishan Singh
