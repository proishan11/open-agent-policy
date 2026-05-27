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
- Project infrastructure:
  - Pre-commit hooks (conventional commits, gofmt, ruff, gitleaks)
  - GitHub Actions CI (lint, test, security scans)
  - Makefile for common tasks
  - ADR template and initial architecture decisions
  - Open source hygiene (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, CODEOWNERS)
  - Dev container configuration
