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
_Not started_

## Milestone 3: Python SDK + LangChain
_Not started_

## Milestone 4: MCP Proxy + HTTP Gateway
_Not started_

## Milestone 5: Production Readiness
_Not started_
