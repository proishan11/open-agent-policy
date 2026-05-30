# Workload Identity Profile

**Status:** draft, JWT binding slice in progress  
**Date:** 2026-05-30  
**Track:** WIMSE/SPIFFE workload identity

## Goal

OAP must distinguish the logical agent registration from the verifiable runtime
workload identity that proves which software is calling the PDP.

The logical agent ID remains:

```text
agent://<namespace>/<name>
```

The workload identity profile records the deployment's standards-compatible
workload identifier, preferably a SPIFFE ID or another WIMSE-compatible URI:

```text
spiffe://<trust-domain>/<path>
wimse://<trust-domain>/<path>
```

## Non-Goals

- This profile does not standardize a new identity protocol.
- This profile does not replace OIDC, SPIFFE, WIMSE, OAuth, or mTLS.
- This first slice does not implement X.509-SVID validation.

## Agent Spec Contract

Agents may declare a first-class workload identity:

```yaml
spec:
  workloadIdentity:
    id: spiffe://example.org/ns/finance/sa/invoice-reader
    type: spiffe
    trustDomain: example.org
    attestationLevel: platform
```

Fields:

| Field | Required | Meaning |
|---|---|---|
| `id` | Yes | Stable workload identifier URI. Use `spiffe://` when available. |
| `type` | No | Identifier profile: `spiffe`, `wimse`, or `custom_uri`. |
| `trustDomain` | No | Trust domain that issued or governs the workload identity. |
| `attestationLevel` | No | Assurance level: `none`, `platform`, `hardware`, or `supply_chain`. |

Identity bindings remain the runtime credential verification rules:

```yaml
spec:
  identityBindings:
    - type: spiffe
      issuer: https://spire.example.org
      jwksUri: https://spire.example.org/.well-known/jwks.json
      subject: spiffe://example.org/ns/finance/sa/invoice-reader
      audience: oap-server
```

`jwksUri` is optional for OIDC-compatible issuers with discovery metadata. It is
recommended for SPIFFE bundle endpoints and WIMSE deployments where key
distribution is configured out of band.

## Semantics

- `metadata.namespace/name` defines the OAP logical identity.
- `spec.workloadIdentity.id` defines the standards-compatible workload identity.
- `identityBindings[]` defines how presented runtime credentials prove control
  of that workload identity.
- If `workloadIdentity` is present and a binding has type `spiffe`, the binding
  subject should equal the workload identity ID.
- Authorization decisions and audit events continue to use the logical agent ID.
  Future audit hardening should include workload identity ID as an additional
  subject attribute.

## Supported Binding Types In This Slice

| Type | Credential | Validation |
|---|---|---|
| `oidc_client` | OIDC JWT | Signature, issuer, expiry, optional audience, subject/azp/client_id. |
| `kubernetes_service_account` | Kubernetes projected OIDC JWT | Same JWT path, with ServiceAccount subject. |
| `spiffe` | SPIFFE JWT-SVID | JWT validation, required audience, SPIFFE ID in `sub`, and `jwt-svid` keys from the SPIFFE bundle. |
| `wimse` | WIMSE WIT + WPT | WIT validation with workload identifier in `sub`, plus request-bound Workload Proof Token validation. |

Deferred:

- `spiffe_x509` for X.509-SVID validation.
- `mtls` for client certificate SAN/CN verification.
- WIMSE HTTP Message Signatures.
- Attestation evidence evaluation.

## Validation Requirements

- Agent schema must allow `spec.workloadIdentity`.
- Agent schema must allow `spec.identityBindings`.
- Unknown fields in both objects must be rejected.
- Unsupported binding types must fail closed.
- SPIFFE-style subjects must match the JWT `sub` claim exactly.
- SPIFFE bindings must configure an expected audience.
- SPIFFE bundle validation must only use JWKs with `use: jwt-svid`.
- WIMSE bindings must include a Workload Proof Token during runtime session creation.

## Follow-Up Work

- Add `workload_identity_id` to audit subject records.
- Add shared replay cache for horizontally scaled WIMSE WPT validation.
- Add X.509-SVID verification for mTLS deployments.
- Add attestation evidence fields and policy conditions once the evaluator can enforce them.
