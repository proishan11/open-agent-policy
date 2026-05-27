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

```bash
# Install
pip install open-agent-policy   # Python SDK (coming soon)
# or
brew install oapctl             # CLI (coming soon)

# Initialize agent project
oapctl init --framework langchain

# Register agent
oapctl agent register -f oap.yaml

# Apply policy
oapctl policy apply -f policies/my-policy.yaml

# Test policy
oapctl simulate -f requests/test-request.json

# Run conformance tests
make test-conformance
```

## Project status

OAP is in active development following a spec-driven approach.

| Milestone | Status | Description |
|---|---|---|
| 1. Spec + Conformance | ✅ Complete | JSON Schemas, OpenAPI, 10 conformance tests |
| 2. Engine + CLI | 🔜 Next | Go evaluator, oap-server, oapctl |
| 3. Python SDK | Planned | @protect decorator, LangChain middleware |
| 4. MCP Proxy + Gateway | Planned | MCP proxy, HTTP gateway, JWT grants |
| 5. Production Ready | Planned | Identity verification, bundle sync, hardening |

See [PROGRESS.md](PROGRESS.md) for detailed tracking.

## Repository structure

```text
spec/               — JSON Schemas and OpenAPI spec (the contract)
conformance/        — Conformance test cases (the specification tests)
engine/             — Go policy evaluator library (coming)
server/             — Go HTTP server (coming)
cli/                — oapctl CLI (coming)
sdk/python/         — Python SDK (coming)
gateway/            — HTTP gateway (coming)
proxy/              — MCP proxy (coming)
docs/               — Architecture docs and ADRs
demos/              — Runnable demos per milestone
blog/               — Blog post drafts
```

## Key documents

- [Architecture](architecture.md) — system design, identity model, end-to-end flows
- [Development Plan](DEVELOPMENT_PLAN.md) — spec-driven approach, milestones, blog series
- [Progress](PROGRESS.md) — milestone tracking
- [Contributing](CONTRIBUTING.md) — how to contribute
- [Security](SECURITY.md) — vulnerability reporting
- [Changelog](CHANGELOG.md) — release history

## Architecture decisions

Recorded in [docs/adr/](docs/adr/):

- [ADR-001: Library-first evaluator](docs/adr/001-library-first-evaluator.md)
- [ADR-002: YAML rules-array policy format](docs/adr/002-yaml-policy-format.md)
- [ADR-003: Pluggable policy engine](docs/adr/003-pluggable-policy-engine.md)

## Development

```bash
# Setup
make install-tools    # Install pre-commit hooks, linters, formatters

# Common tasks
make lint             # Run all linters
make fmt              # Format all code
make test             # Run all tests
make test-conformance # Validate schemas and conformance tests
make demo             # Run demos
make build            # Build Go binaries
make clean            # Clean artifacts
```

## License

[MIT](LICENSE) — Copyright (c) 2026 Ishan Singh
