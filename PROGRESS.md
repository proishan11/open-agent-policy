# OAP Progress

**Started:** 2026-05-27  
**Approach:** Spec-driven development  
**Current milestone:** Post-M6 — Agent Identity Binding & Enforcement Layers

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
- [x] .devcontainer/devcontainer.json (Go 1.25, Python 3.13, VS Code extensions)
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
- [x] docs/adr/005-closed-policy-vocabulary.md
- [x] docs/specs/enterprise-readiness-spec.md
- [x] docs/specs/workload-identity-profile.md
- [x] docs/specs/wimse-proof-token.md

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

### Identity Verification (engine/identity/)
- [x] Verifier interface — VerifyAgent() + VerifyActor()
- [x] DevVerifier — accepts any credentials (local development)
- [x] OIDCVerifier — validates JWT issuer, audience, expiry, claim mappings
- [x] KubernetesVerifier — validates SA tokens, maps to agent://namespace/name
- [x] CompositeVerifier — tries multiple verifiers in order
- [x] 16 tests (dev, OIDC valid/wrong issuer/audience/expired, K8s valid/namespace/invalid, composite)

### Policy Bundle Sync (engine/bundle/)
- [x] Bundle format (JSON manifest with agents, policies, ETag)
- [x] BundleServer — serves bundles from registry store, supports If-None-Match
- [x] BundleClient — polls server, updates local store, ETag caching
- [x] 5 tests (generate, ETag stable/changes, HTTP handler, client sync)

### Security Abuse Tests (engine/evaluator/security_test.go)
- [x] Prompt injection in action name (6 injection vectors)
- [x] Prompt injection in agent ID (5 injection vectors)
- [x] Confused deputy — agent can't use another agent's policies
- [x] Privilege escalation — deny overrides allow, no implicit allow
- [x] Suspended agent denied even with allow-all policy
- [x] Unregistered agent denied

### Fail-Closed Behavior Tests
- [x] Empty store denies everything
- [x] Agent with no policies denied by default
- [x] Empty action name denied
- [x] Empty agent ID denied

### Deployment
- [x] Dockerfile — multi-stage build (Go builder → Alpine runtime)
- [x] docker-compose.yml — oap-server + conformance runner
- [x] Helm chart (deploy/helm/oap/) — Deployment, Service, ServiceAccount, PVC

### Documentation
- [x] doc.go for identity and bundle packages
- [x] docs/flows/agent-onboarding.md — Mermaid sequence diagram
- [x] docs/flows/runtime-authorization.md — Mermaid sequence diagram
- [x] docs/flows/delegation.md — Mermaid sequence diagram
- [x] docs/flows/approval.md — Mermaid sequence diagram
- [x] docs/flows/revocation.md — Mermaid sequence diagram

### Demos
- [x] demos/demo-03-python-sdk/demo.py — SDK demo (decisions, @protect, LangChain)
- [x] demos/demo-04-mcp-proxy/demo.sh — Proxy + gateway + JWT tests
- [x] demos/demo-05-production-setup/demo.sh — Identity, bundle, security, deploy

---

## Milestone 6: Enterprise Identity & Storage — IN PROGRESS

### Pluggable Policy Backends (OPA + Cedar)
- [x] `engine/evaluator/backend/` — Backend interface
- [x] `engine/evaluator/backend/opa.go` — OPA backend (REST, fail-closed/open)
- [x] `engine/evaluator/backend/cedar.go` — Cedar backend (entity mapping, PolicyStoreID)
- [x] 15 backend tests passing
- [x] `docs/adr/004-pluggable-policy-backend.md` — design decision

### Production OIDC Verifier
- [x] `engine/identity/oidc/verifier.go` — Real JWKS discovery + RSA/EC signature verification
- [x] `engine/identity/oidc/providers.go` — Provider helpers (Keycloak, Okta, Azure AD, Google, Cognito, Auth0, PingIdentity, OneLogin, GenericOIDC)
- [x] 21 OIDC tests (real RSA keys, fake IDP server, key rotation, alg:none rejection)
- [x] OpenID Connect discovery (`.well-known/openid-configuration`)
- [x] Clock skew tolerance, required claims, audience array support

### Store Interface + Backends
- [x] `engine/store/store.go` — Pluggable Store interface (context-aware, error-returning)
- [x] `engine/store/memory/` — In-memory implementation (8 tests)
- [x] `engine/store/postgres/` — PostgreSQL implementation (pgxpool, JSONB, auto-migration)
- [x] `engine/store/postgres/migrations.go` — Schema v1 (agents, policies, resources, tools, audit, indexes)
- [x] Postgres integration tests (skip when no DB)
- [x] Enterprise roadmap updated: Redis marked optional, storage tiers clarified

### Store Wiring
- [x] `engine/store/loader.go` — Standalone LoadDir/LoadFile for any store.Store
- [x] `engine/evaluator/evaluator.go` — Accepts store.Store interface (was *registry.Store), fail-closed on errors
- [x] `engine/bundle/bundle.go` — Server and Client use store.Store
- [x] `server/api/server.go` — Uses store.Store + memory.New() default
- [x] `proxy/proxy.go` and `gateway/gateway.go` — Config.Store is store.Store
- [x] `cli/cmd/oapctl/commands/` — All commands use memory.New() + store.LoadDir
- [x] All 15 Go test packages pass after wiring

### Validation Environment
- [x] `validation/docker-compose.yml` — Keycloak + Postgres + OAP server + e2e test runner
- [x] `validation/Dockerfile.oap-server` — Build and run OAP server with policies
- [x] `validation/Dockerfile.e2e` — Python test runner
- [x] `validation/policies/` — Agent, policy, identity provider YAML
- [x] `validation/keycloak/realm-export.json` — Realm with client credentials for support-agent
- [x] `validation/tests/conftest.py` — Keycloak token client, OAPTestClient, fixtures
- [x] 70 e2e tests passing against real Keycloak + OAP server

### Pending
- [ ] ADR: JWKS rotation and caching strategy

---

## Foundation Baseline Hardening - 2026-05-30

**Status:** validated. See `docs/guide/foundation-baseline.md`.

### Spec Contract
- [x] `policy.schema.json` closes `conditions`, `constraints`, and `obligations`
- [x] `authorization-decision.schema.json` includes `allowed_fields` and `expires_in_seconds`
- [x] `grant.schema.json` and `audit-event.schema.json` document the same constrained decision fields
- [x] OpenAPI schema matches the closed policy vocabulary
- [x] Policy manifests use camelCase keys; decision JSON uses snake_case keys

### Evaluator Semantics
- [x] Agent capabilities are enforced as an upper bound before policy authorization
- [x] Resource selectors are enforced (`types`, `classificationMax`, `environments`, `owners`)
- [x] Unsupported conditions fail closed
- [x] Unsupported constraints fail closed
- [x] Unsupported obligations fail closed
- [x] `allowedFields` merges by intersection
- [x] `expiresIn` maps to decision `expires_in_seconds`
- [x] Grant TTL honors decision `expires_in_seconds`

### Strict Input Handling
- [x] YAML/JSON file loaders reject unknown typed fields
- [x] HTTP handlers reject unknown JSON fields for request bodies
- [x] Examples and validation policies no longer use unsupported policy keys

### Validation
- [x] `go test ./...`
- [x] `python3 demos/demo-01-spec-and-conformance/validate.py` (`33/33 validations passed`)
- [x] `git diff --check`

### Durable Storage And Audit Query
- [x] Server binary storage backend selection for Postgres
- [x] Postgres-backed audit sink wired into server mode
- [x] `GET /v1/audit` queries query-capable sinks with indexed filters and pagination
- [x] JSONL audit export can run alongside Postgres audit persistence
- [x] Postgres schema is versioned through ordered migrations with advisory locking and checksums

### Operational Readiness
- [x] `/v1/health` exposes process liveness
- [x] `/v1/ready` checks store readiness with a bounded timeout
- [x] `/metrics` exposes Prometheus text counters for authorization, audit, and readiness

### Workload Identity Profile
- [x] Enterprise readiness feature tracks documented
- [x] WIMSE/SPIFFE workload identity profile specified
- [x] Agent schema supports `spec.workloadIdentity`
- [x] Agent schema supports `spec.identityBindings`
- [x] Unsupported identity binding types fail closed in the session token validator
- [x] SPIFFE JWT-SVID bindings require audience and filter bundle keys to `use: jwt-svid`
- [x] WIMSE bindings require WIT+WPT proof-of-possession, validate `cnf.jwk`, `wth`, `aud`, `exp`, `jti`, and reject process-local replay

### Still Not Enterprise-GA
- [ ] Main-path OPA/Cedar backend selection
- [ ] Audit retention, immutable export, SIEM/OTEL integration, and legal-hold workflows
- [ ] Production database HA, backup/restore, and online migration runbooks
- [ ] Shared WIMSE WPT replay cache for horizontally scaled deployments
- [ ] Production approval lifecycle
- [ ] First-class resource attribute/business conditions
- [ ] Multi-tenancy, admin RBAC, GitOps policy workflow, distributed tracing, alerts, dashboards, HA, runbooks

---

## Phase 1: Agent Identity Binding & Sessions

**Goal:** Bind verifiable runtime identities (OIDC, K8s SA, SPIFFE) to logical agents, issue session tokens.

### Identity Bindings
- [x] `engine/model/agent.go` — Added IdentityBinding struct to AgentSpec (type, issuer, subject, audience)
- [x] Supported binding types: oidc_client, kubernetes_service_account, spiffe (JWT-based), wimse (WIT+WPT)

### Session Management
- [x] `engine/session/session.go` — AgentSession model, Manager with in-memory store
- [x] CreateSession: validates runtime JWT against agent's identity bindings → ags_ session token
- [x] Cryptographically secure session ID generation (ags_ prefix, 32 random bytes, hex)
- [x] Configurable TTL (default 15 minutes)
- [x] Session lookup by token (GetSession)

### Token Validation
- [x] `engine/session/token.go` — Multi-issuer JWT verification
- [x] JWKS auto-discovery and caching via OIDC .well-known endpoints or explicit `jwksUri`
- [x] ValidateAgainstBindings: matches JWT claims (iss, sub, aud) to agent identity bindings
- [x] RS/ES/PS JWT signature verification

### Server Integration
- [x] `server/api/server.go` — POST /v1/runtime/session endpoint
- [x] `server/api/auth.go` — Auth middleware: ags_ session tokens (primary) + raw JWT (fallback)
- [x] --issuer flag for backward-compatible JWT validation
- [x] VerifiedAgentID context key — authorize handler overrides agent_id with cryptographically verified identity

### Test Coverage
- [x] Session lifecycle tests (create, verify, expire)
- [x] Identity binding validation tests (valid OIDC, wrong issuer, wrong subject)
- [x] Auth middleware tests (session token, raw JWT, missing token)

---

## Phase 2: Runs & Scoped Grants

**Goal:** Track agent execution context (runs) and issue scoped, time-bound grant tokens on allow decisions.

### Agent Runs
- [x] `engine/session/session.go` — AgentRun model (run_id, session_id, agent_id, actor, purpose, status)
- [x] CreateRun on Manager — creates run within an active session
- [x] RunActor struct (type, id) for tracking who triggered the run

### Scoped Grant Tokens
- [x] `engine/grant/jwt.go` — Enhanced Claims with resource_type, resource_id, run_id, audience
- [x] GrantRequest struct for full-context grant issuance
- [x] IssueScoped: HMAC-SHA256 signed JWT with agent_id, action, resource, decision, constraints, run_id
- [x] Default 5-minute TTL
- [x] Backward-compatible Issue() delegates to IssueScoped()

### Server Integration
- [x] `server/api/server.go` — POST /v1/runs endpoint (create run within session)
- [x] `server/api/server.go` — POST /v1/grants/validate endpoint (resource-side verification)
- [x] `server/api/server.go` — handleAuthorize issues scoped grant on allow/allow_with_constraints
- [x] `server/cmd/oap-server/main.go` — --grant-key flag for HMAC signing key

### Test Coverage
- [x] `validation/tests/e2e/test_sessions_grants.py` — 9 tests:
  - Session lifecycle (create, verify identity, token format)
  - Run creation within session
  - Grant issuance on allow decisions
  - No grant on deny decisions
  - Grant validation (valid, expired, forged rejected)

---

## Phase 3: Enforcement Layers

**Goal:** Integrate session-based auth and grant injection into gateway, proxy, and resource APIs.

### Gateway Remote Auth Mode
- [x] `gateway/gateway.go` — OAPServerURL config for remote auth mode
- [x] authorizeRemote: calls OAP server /v1/authorize with Bearer session token
- [x] Grant injection: sets X-OAP-Grant-Token header on upstream request
- [x] Fail-closed: denies on OAP server unreachable
- [x] Dual mode: embedded evaluator (sidecar) or remote OAP server (centralized)

### MCP Proxy Remote Auth Mode
- [x] `proxy/proxy.go` — OAPServerURL config for remote auth mode
- [x] authorizeRemote: calls OAP server /v1/authorize with Bearer session token
- [x] Fail-closed: denies on OAP server unreachable
- [x] Dual mode: embedded evaluator or remote OAP server

### Resource-Side Grant Middleware
- [x] `gateway/grant_middleware.go` — Reusable GrantMiddleware for resource APIs
- [x] Validates X-OAP-Grant-Token header via OAP server /v1/grants/validate
- [x] Sets verified identity headers: X-OAP-Verified-Agent-ID, X-OAP-Verified-Action, X-OAP-Verified-Decision
- [x] AllowMissing mode for gradual rollout
- [x] Fail-closed: rejects requests with missing or invalid grants

### Python SDK Session Support
- [x] `sdk/python/open_agent_policy/client.py` — Grant dataclass, Decision.grant field
- [x] OAPClient.create_session() — proves identity, auto-sets auth header
- [x] OAPClient.create_run() — creates run within session
- [x] OAPClient.validate_grant() — resource-side grant verification
- [x] session_token constructor param with auto Bearer header
- [x] Grant and Decision exported from __init__.py

### Test Coverage
- [x] `gateway/gateway_test.go` — +7 tests:
  - Remote auth allow (with grant injection verification)
  - Remote auth deny
  - OAP server down → fail-closed (403)
  - Grant middleware: valid grant, missing grant (401), allow-missing mode, invalid grant (403)
- [x] `proxy/proxy_test.go` — +3 tests:
  - Remote auth allow
  - Remote auth deny
  - OAP server down → fail-closed
- [x] All 70 e2e tests passing
- [x] All 32 Python SDK tests passing
- [x] All Go tests passing across all packages

### Deferred (noted for future implementation)
- [ ] mTLS certificate verifier (extract client cert, match CN/SAN against binding subject)
- [ ] SPIFFE X.509-SVID verifier (validate against SPIFFE trust bundle)
- [ ] Signed deployment metadata verifier (custom attestation format)
- [ ] Container image digest attestation (policy constraint, not identity)
- [ ] Refactor TokenValidator into pluggable IdentityVerifier interface
