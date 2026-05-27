#!/usr/bin/env bash
# Demo 04: MCP Proxy + HTTP Gateway
# Runs Go tests that exercise the proxy and gateway end-to-end.
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

section() {
  echo -e "\n${BOLD}${CYAN}═══ $1 ═══${RESET}\n"
}

echo -e "${BOLD}Demo 04: MCP Proxy + HTTP Gateway${RESET}"
echo "════════════════════════════════════════"

# ── 1. Build binaries ──
section "Building binaries"
go build -o bin/oap-server ./server/cmd/oap-server/
go build -o bin/oapctl ./cli/cmd/oapctl/
echo -e "${GREEN}✓ Built bin/oap-server and bin/oapctl${RESET}"

# ── 2. MCP Proxy tests ──
section "MCP Proxy — intercepts tools/list and tools/call"
echo "Running proxy integration tests..."
go test -v ./proxy/ 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|ok |FAIL)" || true
echo ""

# ── 3. HTTP Gateway tests ──
section "HTTP Gateway — reverse proxy with policy enforcement"
echo "Running gateway integration tests..."
go test -v ./gateway/ 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|ok |FAIL)" || true
echo ""

# ── 4. JWT Grant tests ──
section "JWT Grant Issuance — signed short-lived tokens"
echo "Running grant tests..."
go test -v ./engine/grant/ 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|ok |FAIL)" || true
echo ""

# ── 5. Summary ──
section "Summary"
echo "MCP Proxy:"
echo "  • Intercepts tools/list — filters to allowed tools only"
echo "  • Intercepts tools/call — authorizes before forwarding"
echo "  • Observe mode — logs decisions without blocking"
echo "  • Audit events emitted for every tool call"
echo ""
echo "HTTP Gateway:"
echo "  • Maps HTTP method+path → OAP action"
echo "  • Returns structured 403 for denied requests"
echo "  • X-OAP-Agent-ID header for per-request agent override"
echo "  • Observe mode for safe rollout"
echo ""
echo "JWT Grants:"
echo "  • HMAC-SHA256 signed tokens with OAP claims"
echo "  • Constraints encoded in JWT for downstream enforcement"
echo "  • Expiry-based invalidation (default 15 min)"
echo ""
echo -e "${GREEN}✓ Demo 04 complete${RESET}"
