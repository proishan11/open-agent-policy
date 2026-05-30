# WIMSE Workload Proof Token

**Status:** draft, first implementation slice in progress  
**Date:** 2026-05-30  
**Track:** WIMSE/SPIFFE workload identity

## Goal

OAP must not treat WIMSE Workload Identity Tokens as bearer credentials. A WIMSE
runtime session requires both:

- `Workload-Identity-Token` (WIT): a JWT that identifies the workload and carries
  a `cnf.jwk` confirmation key.
- `Workload-Proof-Token` (WPT): a signed JWT proving possession of the private
  key corresponding to the WIT `cnf.jwk`.

This follows the active IETF WIMSE WPT draft shape: WITs are not bearer tokens;
the WPT binds the WIT to the request through `wth`, `aud`, `exp`, and `jti`.

## Session API Contract

Existing JSON session creation remains supported:

```json
{
  "agent_id": "agent://payments/payment-agent",
  "runtime_token": "<WIT>",
  "workload_proof_token": "<WPT>"
}
```

For WIMSE-native callers, OAP also accepts the draft header names:

```http
POST /v1/runtime/session HTTP/1.1
Workload-Identity-Token: <WIT>
Workload-Proof-Token: <WPT>
Content-Type: application/json

{"agent_id":"agent://payments/payment-agent"}
```

If a token is provided both in JSON and in a header, the values must match.
Duplicate WIT or WPT headers are rejected.

## Validation Rules

For an `identityBindings[].type: wimse` binding, OAP must:

- Verify the WIT signature against the binding issuer and JWKS trust anchor.
- Require WIT `typ` to be `wit+jwt` or `application/wit+jwt`.
- Require WIT `exp`, `iss`, `sub`, and `cnf.jwk`.
- Match the WIT `sub` to the binding `subject`.
- Require `cnf.jwk.alg` to be an asymmetric signing algorithm.
- Require a WPT.
- Require WPT `typ` to be `wpt+jwt` or `application/wpt+jwt`.
- Require the WPT JOSE `alg` to match WIT `cnf.jwk.alg`.
- Verify the WPT signature using WIT `cnf.jwk`.
- Require WPT `aud`, `exp`, `jti`, and `wth`.
- Accept WPT audience values that match the binding `audience` or the server
  derived target URI for the session request.
- Reject WPTs whose `exp` is more than five minutes in the future.
- Require WPT `wth` to equal `base64url(sha256(ascii(WIT)))`.
- If an OAuth bearer token is present on the session request, require WPT `ath`
  to equal `base64url(sha256(ascii(access_token)))`.
- Reject unsupported `tth` and `oth` claims until OAP verifies transaction or
  additional context tokens.
- Reject replayed WPT `jti` values within the WPT validity window.

## Known Limits

- Replay protection is process-local. Enterprise-GA needs a shared replay cache
  for horizontally scaled OAP servers.
- OAP validates application-level WPTs. WIMSE HTTP Message Signatures and WIC
  mTLS are separate future tracks.
- Operators should prefer explicit binding `audience` values. Server-derived
  target URI audience matching is useful for development and direct deployments,
  but production deployments behind proxies should avoid trusting external host
  headers as the sole audience control.

## References

- IETF WIMSE Workload Proof Token draft: https://ietf-wg-wimse.github.io/draft-ietf-wimse-s2s-protocol/draft-ietf-wimse-wpt.html
- IETF WIMSE Workload Credentials draft: https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds-01
