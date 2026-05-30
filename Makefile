.PHONY: help lint fmt test test-conformance test-python test-go build clean dev demo install-tools pre-commit venv

# ── Variables ────────────────────────────────────────────────────────────
GO := go
GOFLAGS := -v
BINARY := bin/oap-server
CLI := bin/oapctl
VENV := .venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip

# ── Help ─────────────────────────────────────────────────────────────────
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Setup ────────────────────────────────────────────────────────────────
venv: ## Create Python virtual environment
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install pre-commit ruff jsonschema pyyaml openapi-spec-validator
	$(PIP) install -e "sdk/python[dev]"
	@echo "\n✓ Virtual environment ready at $(VENV)/"
	@echo "  Activate with: source $(VENV)/bin/activate"

install-tools: venv ## Install development tools and set up pre-commit
	$(VENV)/bin/pre-commit install
	$(VENV)/bin/pre-commit install --hook-type commit-msg

pre-commit: ## Run all pre-commit hooks
	pre-commit run --all-files

# ── Lint & Format ────────────────────────────────────────────────────────
lint: ## Run all linters
	@echo "==> Linting Go..."
	golangci-lint run ./... || true
	@echo "==> Linting Python..."
	$(PYTHON) -m ruff check sdk/python/ demos/
	@echo "==> Checking YAML..."
	$(PYTHON) -c "import yaml, sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]" conformance/cases/*.yaml
	@echo "==> Validating JSON Schemas..."
	$(PYTHON) -c "import json, sys; [json.load(open(f)) for f in sys.argv[1:]]" spec/v1alpha1/*.schema.json
	@echo "==> Validating OpenAPI..."
	$(PYTHON) -c "from openapi_spec_validator import validate; from openapi_spec_validator.readers import read_from_filename; validate(read_from_filename('spec/openapi/oap-server.openapi.yaml')[0]); print('OpenAPI valid')"

fmt: ## Format all code
	@echo "==> Formatting Go..."
	gofmt -w engine/ server/ cli/
	@echo "==> Formatting Python..."
	$(PYTHON) -m ruff format sdk/python/ demos/

# ── Test ─────────────────────────────────────────────────────────────────
test: test-go test-python test-conformance ## Run all tests

test-conformance: ## Validate schemas and conformance test cases
	$(PYTHON) demos/demo-01-spec-and-conformance/validate.py

test-python: ## Run Python SDK tests
	$(PYTHON) -m pytest sdk/python/tests/ -v

test-go: ## Run Go tests
	$(GO) test $(GOFLAGS) ./...

test-coverage-go: ## Run Go tests with coverage
	$(GO) test -coverprofile=coverage.out ./... && $(GO) tool cover -html=coverage.out -o coverage.html

test-coverage-python: ## Run Python tests with coverage
	$(PYTHON) -m pytest sdk/python/tests/ --cov=open_agent_policy --cov-report=html

# ── Build ────────────────────────────────────────────────────────────────
build: ## Build Go binaries
	$(GO) build -o $(BINARY) ./server/cmd/oap-server/
	$(GO) build -o $(CLI) ./cli/cmd/oapctl/
	@echo "✓ Built $(BINARY) and $(CLI)"

# ── Dev ──────────────────────────────────────────────────────────────────
dev: ## Start local dev server
	$(GO) run ./server/cmd/oap-server/ --dev

# ── Demo ─────────────────────────────────────────────────────────────────
demo: demo-01 demo-02 ## Run all demos

demo-01: ## Run Milestone 1 demo (spec validation)
	$(PYTHON) demos/demo-01-spec-and-conformance/validate.py

demo-02: build ## Run Milestone 2 demo (engine + CLI)
	bash demos/demo-02-engine-and-cli/demo.sh

# ── Clean ────────────────────────────────────────────────────────────────
clean: ## Clean build artifacts
	rm -rf bin/ coverage.out coverage.html
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

clean-all: clean ## Clean everything including venv
	rm -rf $(VENV)
