.PHONY: help lint fmt test test-conformance test-python build clean dev demo install-tools pre-commit

# ── Variables ────────────────────────────────────────────────────────────
GO := go
GOFLAGS := -v
BINARY := bin/oap-server
CLI := bin/oapctl
PYTHON := python3
PIP := pip

# ── Help ─────────────────────────────────────────────────────────────────
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Setup ────────────────────────────────────────────────────────────────
install-tools: ## Install development tools
	$(PIP) install pre-commit ruff jsonschema pyyaml openapi-spec-validator pytest
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit: ## Run all pre-commit hooks
	pre-commit run --all-files

# ── Lint & Format ────────────────────────────────────────────────────────
lint: ## Run all linters
	@echo "==> Linting Go..."
	cd engine && golangci-lint run ./... || true
	cd server && golangci-lint run ./... || true
	cd cli && golangci-lint run ./... || true
	@echo "==> Linting Python..."
	ruff check sdk/python/ demos/
	@echo "==> Checking YAML..."
	$(PYTHON) -c "import yaml, sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]" conformance/cases/*.yaml
	@echo "==> Validating JSON Schemas..."
	$(PYTHON) -c "import json, sys; [json.load(open(f)) for f in sys.argv[1:]]" spec/v1alpha1/*.schema.json
	@echo "==> Validating OpenAPI..."
	$(PYTHON) -c "from openapi_spec_validator import validate; from openapi_spec_validator.readers import read_from_filename; validate(read_from_filename('spec/openapi/oap-server.openapi.yaml')[0]); print('OpenAPI valid')"

fmt: ## Format all code
	@echo "==> Formatting Go..."
	gofmt -w engine/ server/ cli/ || true
	@echo "==> Formatting Python..."
	ruff format sdk/python/ demos/

# ── Test ─────────────────────────────────────────────────────────────────
test: test-conformance test-python ## Run all tests

test-conformance: ## Validate schemas and conformance test cases
	$(PYTHON) demos/demo-01-spec-and-conformance/validate.py

test-python: ## Run Python SDK tests
	cd sdk/python && $(PYTHON) -m pytest -v || true

test-go: ## Run Go tests
	cd engine && $(GO) test $(GOFLAGS) ./... || true
	cd server && $(GO) test $(GOFLAGS) ./... || true
	cd cli && $(GO) test $(GOFLAGS) ./... || true

test-coverage-go: ## Run Go tests with coverage
	cd engine && $(GO) test -coverprofile=coverage.out ./... && $(GO) tool cover -html=coverage.out -o coverage.html || true

test-coverage-python: ## Run Python tests with coverage
	cd sdk/python && $(PYTHON) -m pytest --cov=open_agent_policy --cov-report=html || true

# ── Build ────────────────────────────────────────────────────────────────
build: ## Build Go binaries
	$(GO) build $(GOFLAGS) -o $(BINARY) ./server/cmd/oap-server/
	$(GO) build $(GOFLAGS) -o $(CLI) ./cli/cmd/oapctl/

# ── Dev ──────────────────────────────────────────────────────────────────
dev: ## Start local dev server
	$(GO) run ./server/cmd/oap-server/ --dev

# ── Demo ─────────────────────────────────────────────────────────────────
demo: demo-01 ## Run all demos

demo-01: ## Run Milestone 1 demo (spec validation)
	$(PYTHON) demos/demo-01-spec-and-conformance/validate.py

# ── Clean ────────────────────────────────────────────────────────────────
clean: ## Clean build artifacts
	rm -rf bin/ coverage.out coverage.html
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
