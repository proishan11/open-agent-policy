# Contributing to Open Agent Policy

Thank you for your interest in contributing to OAP. This document explains how to get started.

## Development setup

```bash
# Clone the repo
git clone https://github.com/proishan11/open-agent-policy.git
cd open-agent-policy

# Install development tools
make install-tools

# Run all checks
make lint
make test
```

## Prerequisites

- **Go** 1.22+
- **Python** 3.11+
- **pre-commit** (installed via `make install-tools`)

## Commit standards

We use [Conventional Commits](https://www.conventionalcommits.org/). Every commit message must follow this format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

**Scopes:** `engine`, `server`, `cli`, `sdk-python`, `sdk-ts`, `gateway`, `proxy`, `spec`, `conformance`, `ci`, `docs`

**Examples:**

```
feat(engine): add policy evaluator with deny-by-default
fix(sdk-python): handle missing actor in authorization request
docs(spec): update authorization-request schema
test(conformance): add test for constraint merging
ci: add CodeQL security analysis
```

Pre-commit hooks enforce this format. If your commit message doesn't match, the commit will be rejected.

## Branch strategy

- `main` — stable, protected, requires CI to pass
- `milestone-N` — development branch for each milestone
- Feature branches: `feat/<short-description>`, `fix/<short-description>`

## Pull request process

1. Fork the repo and create a feature branch from the current milestone branch
2. Make your changes following the code style (enforced by pre-commit hooks)
3. Add or update tests for your changes
4. Run `make lint` and `make test` locally
5. Open a PR with a clear description of what and why
6. Wait for CI checks to pass and a maintainer review

## Code style

- **Go**: `gofmt` + `golangci-lint` (config in `.golangci.yml`)
- **Python**: `ruff` for linting and formatting (config in `pyproject.toml`)
- **YAML/JSON**: validated by pre-commit hooks
- **Markdown**: no trailing whitespace enforcement (to preserve intentional line breaks)

## Testing

- **Conformance tests** (`conformance/cases/`): YAML-based test cases that validate the spec
- **Go tests**: standard `go test` in each package
- **Python tests**: `pytest` in `sdk/python/`
- Run `make test` to execute all test suites

## Architecture Decision Records

Significant decisions are recorded in `docs/adr/`. If your change involves an architectural decision, add an ADR.

## Security

If you find a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
