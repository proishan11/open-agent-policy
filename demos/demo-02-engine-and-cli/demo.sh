#!/usr/bin/env bash
# Demo 02: Engine and CLI
#
# This demo shows the OAP engine and CLI in action:
# 1. Run conformance tests (10/10 should pass)
# 2. Simulate authorization decisions for the finance invoice agent
# 3. Explain a decision step-by-step
#
# Prerequisites: Go 1.22+
# Usage: bash demos/demo-02-engine-and-cli/demo.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

BOLD='\033[1m'
GREEN='\033[92m'
RESET='\033[0m'

echo -e "\n${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Demo 02: OAP Engine and CLI${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}\n"

# Step 1: Build
echo -e "${BOLD}Step 1: Building oapctl...${RESET}"
go build -o bin/oapctl ./cli/cmd/oapctl/
echo -e "${GREEN}✓${RESET} Built bin/oapctl\n"

# Step 2: Run conformance tests
echo -e "${BOLD}Step 2: Running conformance tests...${RESET}"
./bin/oapctl test --conformance
echo ""

# Step 3: Simulate read (should allow with constraints)
echo -e "${BOLD}Step 3: Simulate invoice read...${RESET}"
./bin/oapctl simulate \
  -f examples/finance-invoice-agent/requests/read-invoice.json \
  --data examples/finance-invoice-agent/
echo ""

# Step 4: Simulate delete (should deny)
echo -e "${BOLD}Step 4: Simulate invoice delete...${RESET}"
./bin/oapctl simulate \
  -f examples/finance-invoice-agent/requests/delete-invoice.json \
  --data examples/finance-invoice-agent/
echo ""

# Step 5: Explain a decision
echo -e "${BOLD}Step 5: Explain invoice read decision...${RESET}"
./bin/oapctl explain \
  -f examples/finance-invoice-agent/requests/read-invoice.json \
  --data examples/finance-invoice-agent/
echo ""

# Step 6: Run Go tests
echo -e "${BOLD}Step 6: Running Go test suite...${RESET}"
go test ./... -count=1
echo ""

echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  ${GREEN}Demo 02 complete!${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}\n"
