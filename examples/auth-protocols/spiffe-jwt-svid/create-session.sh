#!/usr/bin/env bash
set -euo pipefail

: "${OAP_SERVER_URL:=http://localhost:8080}"
: "${AGENT_ID:=agent://support/ticket-assistant}"
: "${SPIFFE_JWT_SVID:?set SPIFFE_JWT_SVID to a JWT-SVID minted for audience oap-server}"

curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "'"$AGENT_ID"'",
    "runtime_token": "'"$SPIFFE_JWT_SVID"'",
    "environment": "production"
  }'

