# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project architecture document (`architecture.md`)
- Development plan with spec-driven approach (`DEVELOPMENT_PLAN.md`)
- JSON Schemas for all core types (v1alpha1):
  - authorization-request, authorization-decision
  - agent, resource, tool
  - policy, audit-event, grant, identity-provider
- OpenAPI spec for oap-server HTTP API (14 paths, 19 schemas, 22 operations)
- 10 conformance test cases covering all core principles
- Demo validation script (33/33 passing)
- Go policy evaluation engine (`engine/evaluator`) — deny-overrides-allow, condition
  checking, constraint merging (strictest wins), delegation scope verification
- In-memory registry store (`engine/registry`) — file-backed, recursive YAML/JSON loading
- Audit sinks (`engine/audit`) — JSONL, stdout, in-memory (for testing)
- HTTP server (`server/api`) — authorize, simulate, agent/policy CRUD, health
- CLI tool (`cli/cmd/oapctl`):
  - `oapctl dev` — start local dev server with data from files
  - `oapctl simulate` / `oapctl explain` — local policy evaluation and tracing
  - `oapctl test --conformance` — run conformance suite (10/10 passing)
  - `oapctl agent register/list` / `oapctl policy apply/list` — remote management
- Finance invoice agent example (agent manifest, policy, request samples)
- Component READMEs for engine, server, cli (per §8 documentation standards)
- doc.go for every Go package
- Python SDK (`sdk/python/open_agent_policy`):
  - `OAPClient` with remote (HTTP) and embedded (oapctl subprocess) modes
  - `@protect` decorator for automatic tool authorization
  - `OAPToolWrapper` and `protect_tools()` for LangChain integration
  - Error hierarchy (`PermissionDeniedError`, `ApprovalRequiredError`, `ServerError`)
  - 32 pytest tests passing
- Go test coverage for all engine packages (model, registry, audit)
- `make venv` for Python virtual environment setup
- Project infrastructure:
  - Pre-commit hooks (conventional commits, gofmt, ruff, gitleaks)
  - GitHub Actions CI (lint, test, security scans)
  - Makefile for common tasks
  - ADR template and initial architecture decisions
  - Open source hygiene (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, CODEOWNERS)
  - Dev container configuration
