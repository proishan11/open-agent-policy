#!/usr/bin/env bash
set -euo pipefail

: "${OAP_SERVER_URL:=http://localhost:8080}"
: "${AGENT_ID:=agent://support/ticket-assistant}"
: "${TOKEN_URL:?set TOKEN_URL, for example https://keycloak.company.com/realms/agents/protocol/openid-connect/token}"
: "${CLIENT_ID:=support-agent}"
: "${CLIENT_SECRET:?set CLIENT_SECRET}"
: "${AUDIENCE:=oap-server}"

token_response="$(
  curl -sS -X POST "$TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d grant_type=client_credentials \
    -d client_id="$CLIENT_ID" \
    -d client_secret="$CLIENT_SECRET" \
    -d audience="$AUDIENCE"
)"

runtime_token="$(
  printf '%s' "$token_response" | python3 -c \
    'import json, sys; print(json.load(sys.stdin)["access_token"])'
)"

session_response="$(
  curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
    -H "Content-Type: application/json" \
    -d '{
      "agent_id": "'"$AGENT_ID"'",
      "runtime_token": "'"$runtime_token"'",
      "environment": "production"
    }'
)"

session_id="$(
  printf '%s' "$session_response" | python3 -c \
    'import json, sys; print(json.load(sys.stdin)["session_id"])'
)"

curl -sS -X POST "$OAP_SERVER_URL/v1/authorize" \
  -H "Authorization: Bearer $session_id" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "example-oidc-ticket-read",
    "subject": {"type": "agent", "agent_id": "'"$AGENT_ID"'"},
    "actor": {"type": "user", "id": "alice@example.com"},
    "action": {"name": "ticket.read"},
    "resource": {"type": "support.ticket", "id": "T-100"}
  }'

