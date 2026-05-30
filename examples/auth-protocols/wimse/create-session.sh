#!/usr/bin/env bash
set -euo pipefail

: "${OAP_SERVER_URL:=http://localhost:8080}"
: "${AGENT_ID:=agent://payments/payment-agent}"
: "${WIT:?set WIT to the Workload Identity Token}"
: "${WPT:?set WPT to the Workload Proof Token}"

curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
  -H "Workload-Identity-Token: $WIT" \
  -H "Workload-Proof-Token: $WPT" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"'"$AGENT_ID"'","environment":"production"}'

