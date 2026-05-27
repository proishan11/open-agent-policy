# OAP Progress

**Started:** 2026-05-27  
**Approach:** Spec-driven development  
**Current milestone:** 1 — Spec + Conformance Tests

---

## Milestone 1: Spec + Conformance Tests

### Schemas
- [x] authorization-request.schema.json
- [x] authorization-decision.schema.json
- [x] agent.schema.json
- [x] resource.schema.json
- [x] tool.schema.json
- [x] policy.schema.json
- [x] audit-event.schema.json
- [x] grant.schema.json
- [x] identity-provider.schema.json
- [x] OpenAPI spec (oap-server.openapi.yaml) — 14 paths, 19 schemas, 22 operations

### Conformance Tests
- [x] 01: deny-unregistered-agent
- [x] 02: deny-by-default (no matching policy)
- [x] 03: simple-allow
- [x] 04: allow-with-constraints
- [x] 05: explicit-deny-overrides-allow
- [x] 06: require-approval
- [x] 07: actor-required-but-missing
- [x] 08: delegation-scoped
- [x] 09: constraint-merging (strictest wins)
- [x] 10: revoked-agent-denied

### Demo + Blog
- [x] Demo 01 validation script (33/33 passing)
- [ ] Blog post 01 draft: "Why AI Agents Need Zero-Trust Access Control"
- [ ] Blog post 02 draft: "Designing the OAP Spec"

### Project Infrastructure
- [x] .editorconfig (Go tabs, Python 4-space, YAML 2-space)
- [x] .gitignore (Go + Python + IDE + OAP-specific)
- [x] .pre-commit-config.yaml (conventional commits, gofmt, ruff, gitleaks, YAML/JSON checks)
- [x] .gitleaks.toml (secret scanning config)
- [x] .golangci.yml (Go linter config)
- [x] pyproject.toml (ruff, pytest, coverage config)
- [x] Makefile (lint, fmt, test, build, dev, demo, clean)
- [x] .devcontainer/devcontainer.json (Go 1.22, Python 3.13, VS Code extensions)
- [x] .goreleaser.yaml (signed releases, SBOM, multi-platform)
- [x] .github/workflows/ci.yml (lint, conformance, Go tests, Python tests, gitleaks, CodeQL)
- [x] .github/workflows/release.yml (GoReleaser, Docker, Trivy scan)
- [x] .github/dependabot.yml (Go, Python, GitHub Actions)
- [x] .github/ISSUE_TEMPLATE/ (bug report, feature request)
- [x] .github/pull_request_template.md
- [x] README.md (project overview, quick start, status, structure, dev guide)
- [x] CONTRIBUTING.md (setup, commit standards, branch strategy, PR process)
- [x] CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- [x] SECURITY.md (vulnerability reporting, response timeline, security practices)
- [x] CODEOWNERS
- [x] CHANGELOG.md
- [x] docs/adr/001-library-first-evaluator.md
- [x] docs/adr/002-yaml-policy-format.md
- [x] docs/adr/003-pluggable-policy-engine.md

---

## Milestone 2: Core Engine + CLI

### Engine Library (engine/)
- [x] engine/model/ — Core domain types (AuthorizationRequest, Decision, Agent, Policy, Resource, Tool, Grant, AuditEvent)
- [x] engine/registry/ — In-memory store with recursive file loading (Agent, Resource, Tool, AgentPolicy)
- [x] engine/evaluator/ — Policy evaluation engine (deny-overrides-allow, condition checking, constraint merging, delegation scope)
- [x] engine/audit/ — Audit sinks (JSONL, stdout, memory)
- [x] engine/evaluator: 10/10 conformance tests passing
- [x] engine/evaluator: 4 additional unit tests passing

### HTTP Server (server/)
- [x] server/api/ — HTTP handlers for authorize, simulate, agents, policies, audit, health
- [x] server/cmd/oap-server/ — Binary entry point with flags (--addr, --data, --audit-file, --dev)
- [x] server/api: 3 integration tests passing (health, authorize flow, simulate)

### CLI (cli/)
- [x] oapctl dev — Start local dev server with data from files
- [x] oapctl agent register/list — Agent management (remote mode)
- [x] oapctl policy apply/list — Policy management (remote mode)
- [x] oapctl simulate — Simulate authorization decisions (local mode)
- [x] oapctl explain — Step-by-step evaluation trace (local mode)
- [x] oapctl test --conformance — Run conformance test suite (10/10 passing)

### Examples
- [x] examples/finance-invoice-agent/oap.yaml — Agent manifest
- [x] examples/finance-invoice-agent/policies/ — Read-only policy with constraints
- [x] examples/finance-invoice-agent/requests/ — Read and delete request samples

### Documentation
- [x] engine/README.md — Purpose, architecture, key interfaces, data flow, testing
- [x] server/README.md — Purpose, endpoints, configuration, data flow, testing
- [x] cli/README.md — Purpose, commands, data flow, testing
- [x] doc.go for every package (model, registry, evaluator, audit, api)

### Demo + Blog
- [x] Demo 02 script (conformance + simulate + explain + tests)
- [ ] Blog post 03 draft: "Building the Engine"

## Milestone 3: Python SDK + LangChain

### Python SDK (sdk/python/)
- [x] Package structure with pyproject.toml (hatchling build, httpx + pyyaml deps)
- [x] OAPClient — remote mode (HTTP to oap-server) and embedded mode (oapctl subprocess)
- [x] Decision dataclass with is_allowed/is_denied/requires_approval helpers
- [x] @protect decorator — wraps tool functions with automatic authorization
- [x] Error hierarchy (OAPError, PermissionDeniedError, ApprovalRequiredError, ServerError)
- [x] Agent identity auto-discovery — configurable via constructor params

### LangChain Integration
- [x] OAPToolWrapper — wraps any LangChain BaseTool with OAP authorization
- [x] protect_tools() — one-line integration to wrap all tools in an agent
- [x] Conditional langchain-core import (optional dependency)

### Tests (32 passing)
- [x] test_client.py — Decision, client validation, remote mode via httpx mock, request body structure
- [x] test_decorators.py — allow, deny, constrained, approval, metadata, action defaults
- [x] test_langchain.py — OAPToolWrapper, protect_tools, action prefix

### Documentation
- [x] sdk/python/README.md — Purpose, architecture, key interfaces, data flow, config, testing

### Infrastructure
- [x] make venv — Python virtual environment setup
- [x] Makefile updated for venv-based Python, single Go module at root
- [x] README.md updated with setup instructions and prerequisites

### Go Test Coverage
- [x] engine/model/model_test.go — Agent, Policy, Grant tests
- [x] engine/registry/store_test.go — Store CRUD, file loading, error paths
- [x] engine/audit/sink_test.go — MemorySink, JSONLSink, invalid paths

## Milestone 4: MCP Proxy + HTTP Gateway

### MCP Proxy (proxy/)
- [x] JSON-RPC 2.0 MCP protocol handler
- [x] tools/list filtering — only shows tools the agent is allowed to use
- [x] tools/call authorization — deny returns MCP error (-32001)
- [x] Observe mode — logs decisions without blocking
- [x] Upstream tool caching
- [x] Audit event emission for every tool call
- [x] 5 integration tests (initialize, allow, deny, observe, health)

### HTTP Gateway (gateway/)
- [x] HTTP reverse proxy with policy enforcement
- [x] Route resolution — explicit routes, prefix match, or derived from method+path
- [x] Agent ID override via X-OAP-Agent-ID header
- [x] Structured 403 responses with policy IDs and reason
- [x] Observe mode — logs without blocking
- [x] Audit event emission
- [x] 6 integration tests (allow, deny, observe, health, route resolution, agent override)

### JWT Grant Issuance (engine/grant/)
- [x] HMAC-SHA256 signed JWT grants with OAP-specific claims
- [x] Claims encode: agent, action, decision, constraints, expiry
- [x] Verify with expiry and signature checks
- [x] 5 tests (issue+verify, expired, tampered, wrong key, invalid format)

### Documentation
- [x] proxy/README.md — Purpose, architecture, data flow, config
- [x] gateway/README.md — Purpose, architecture, route resolution, config
- [x] doc.go for proxy, gateway, grant packages

## Milestone 5: Production Readiness
_Not started_
