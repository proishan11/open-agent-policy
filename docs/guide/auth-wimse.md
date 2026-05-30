# WIMSE WIT And WPT

Use `wimse` when the workload identity provider issues a Workload Identity Token
that is bound to a proof-of-possession key. OAP treats WIMSE identity as a pair:

- WIT: Workload Identity Token, a JWT with `typ: wit+jwt` and `cnf.jwk`.
- WPT: Workload Proof Token, a JWT with `typ: wpt+jwt`, signed by the WIT
  confirmation key.

OAP does not treat the WIT as a bearer credential.

## Agent Binding

```yaml
apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: payment-agent
  namespace: payments
spec:
  owner: group:payments-platform
  type: autonomous_agent
  riskTier: high
  capabilities:
    - payment.read
  workloadIdentity:
    id: "wimse://company.com/service/payment-agent"
    type: wimse
    trustDomain: company.com
    attestationLevel: platform
  identityBindings:
    - type: wimse
      provider: wimse-idp
      issuer: "https://identity.company.com/workloads"
      jwksUri: "https://identity.company.com/workloads/jwks.json"
      subject: "wimse://company.com/service/payment-agent"
      audience: "oap-server"
```

## Session Request

JSON shape:

```bash
curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent://payments/payment-agent",
    "runtime_token": "'"$WIT"'",
    "workload_proof_token": "'"$WPT"'",
    "environment": "production"
  }'
```

WIMSE-native header shape:

```bash
curl -sS -X POST "$OAP_SERVER_URL/v1/runtime/session" \
  -H "Workload-Identity-Token: $WIT" \
  -H "Workload-Proof-Token: $WPT" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent://payments/payment-agent"}'
```

If a WIT or WPT is provided in both JSON and a header, the values must match.
Duplicate WIT or WPT headers are rejected.

## What OAP Checks

- WIT signature, issuer, expiry, subject, `typ`, and `cnf.jwk`.
- Binding subject equals the WIT `sub`.
- WPT is present and signed by the WIT `cnf.jwk`.
- WPT `typ`, `alg`, `aud`, `exp`, `jti`, and `wth`.
- WPT `wth` equals `base64url(sha256(ascii(WIT)))`.
- WPT `ath` matches an OAuth bearer token if one is present on the session
  request.
- WPT `jti` has not been replayed inside the WPT validity window.

## Known Limits

- WPT replay protection is process-local. Multi-instance deployments need a
  shared replay cache before this is enterprise-grade.
- WIMSE HTTP Message Signatures are not supported yet.
- `tth` and `oth` proof claims are rejected until OAP validates transaction or
  additional context tokens.

See [WIMSE Workload Proof Token](../specs/wimse-proof-token.md) for the
implementation contract.
