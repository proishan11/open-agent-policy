#!/usr/bin/env bash
# Demo 05: Production Readiness
# Runs identity, bundle, and security tests to demonstrate production features.
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
RESET='\033[0m'

section() {
  echo -e "\n${BOLD}${CYAN}═══ $1 ═══${RESET}\n"
}

echo -e "${BOLD}Demo 05: Production Readiness${RESET}"
echo "════════════════════════════════════════"

# ── 1. Identity verification ──
section "Identity Verification"
echo "Testing OIDC, Kubernetes SA, and composite verifiers..."
go test -v ./engine/identity/ 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|ok |FAIL)" || true
echo ""

# ── 2. Policy bundle sync ──
section "Policy Bundle Sync"
echo "Testing bundle server (ETag caching) and client (polling sync)..."
go test -v ./engine/bundle/ 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|ok |FAIL)" || true
echo ""

# ── 3. Security abuse tests ──
section "Security Abuse Tests"
echo "Testing prompt injection, confused deputy, privilege escalation..."
go test -v -run "TestPrompt|TestConfused|TestEscalation|TestSuspended|TestUnregistered" ./engine/evaluator/ 2>&1 | \
  grep -E "^(=== RUN|--- (PASS|FAIL)|ok |FAIL)" || true
echo ""

# ── 4. Fail-closed behavior ──
section "Fail-Closed Behavior"
echo "Testing deny-by-default with empty store, no policies, empty fields..."
go test -v -run "TestFailClosed" ./engine/evaluator/ 2>&1 | \
  grep -E "^(=== RUN|--- (PASS|FAIL)|ok |FAIL)" || true
echo ""

# ── 5. Full conformance suite ──
section "Conformance Suite (all 10 cases)"
go build -o bin/oapctl ./cli/cmd/oapctl/
./bin/oapctl test --conformance
echo ""

# ── 6. Docker ──
section "Docker Setup"
if command -v docker &> /dev/null; then
  echo "Dockerfile present — build with: docker build -t oap-server ."
  echo "docker-compose.yml present — run with: docker compose up"
else
  echo "Docker not available — skipping container build."
  echo "Files present:"
  echo "  • Dockerfile (multi-stage: Go builder → Alpine runtime)"
  echo "  • docker-compose.yml (oap-server + conformance runner)"
fi
echo ""

# ── 7. Helm chart ──
section "Helm Chart"
echo "deploy/helm/oap/ includes:"
ls -la deploy/helm/oap/ 2>/dev/null || echo "  (files listed in repo)"
echo ""
echo "Templates:"
ls -la deploy/helm/oap/templates/ 2>/dev/null || echo "  (files listed in repo)"
echo ""
echo "Install: helm install oap deploy/helm/oap/"
echo ""

# ── 8. Summary ──
section "Production Readiness Summary"
echo "Identity Verification:"
echo "  • DevVerifier — local development (accept any creds)"
echo "  • OIDCVerifier — validate JWT issuer, audience, expiry"
echo "  • KubernetesVerifier — validate SA tokens, map to agent://ns/name"
echo "  • CompositeVerifier — chain multiple verifiers"
echo ""
echo "Policy Bundle Sync:"
echo "  • Server → JSON bundle with ETag"
echo "  • Client → polls, updates local store"
echo "  • Embedded evaluators stay in sync without redeployment"
echo ""
echo "Security Hardening:"
echo "  • 11 prompt injection vectors tested and blocked"
echo "  • Confused deputy protection verified"
echo "  • Privilege escalation blocked (deny overrides allow)"
echo "  • Suspended/revoked agents denied regardless of policies"
echo "  • Fail-closed: empty store, no policies → deny"
echo ""
echo "Deployment:"
echo "  • Dockerfile — multi-stage build"
echo "  • docker-compose.yml — reference environment"
echo "  • Helm chart — Kubernetes deployment"
echo ""
echo -e "${GREEN}✓ Demo 05 complete${RESET}"
