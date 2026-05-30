# ADR-005: Closed policy vocabulary and fail-closed evaluation

**Status:** accepted  
**Date:** 2026-05-30  
**Deciders:** Ishan Singh  

## Context

OAP policies describe security boundaries for agents. If the evaluator silently ignores an unknown condition, constraint, obligation, or resource selector, a policy author may believe access is narrow while the implementation grants broader access.

This risk appeared in early examples that used keys such as `max_records`, `redact_fields`, `allowed_fields`, `priorityIn`, and `recipientDomain`. Some of those keys were useful ideas, but they were not part of the schema/evaluator contract. Treating them as harmless extensions would be unsafe.

## Decision

OAP v1alpha1 uses a closed policy vocabulary for the built-in evaluator:

- `conditions` has an explicit supported key set.
- `constraints` has an explicit supported key set.
- `obligations` has an explicit supported key set.
- Unsupported keys fail closed at evaluation time.
- JSON Schema and OpenAPI set `additionalProperties: false` for these policy blocks.
- File loading and HTTP request decoding reject unknown typed fields.

Policy manifests use camelCase keys such as `maxRecords`, `allowedFields`, and `expiresIn`. Authorization decisions use snake_case fields such as `max_records`, `allowed_fields`, and `expires_in_seconds`.

## Supported baseline vocabulary

Conditions:

- `actorRequired`
- `actorType`
- `actorId`
- `actorGroups`
- `environment`
- `minAuthStrength`
- `timeWindow`
- `delegationRequired`

Constraints:

- `readonly`
- `maxRecords`
- `redact`
- `timeWindowSeconds`
- `allowedFields`
- `expiresIn`

Obligations:

- `audit`
- `logFullRequest`
- `notify`

## Consequences

- Policy authors get a stronger contract: unsupported policy intent cannot be silently dropped.
- Examples must not document policy keys before they are supported by schema, tests, and evaluator code.
- Adding a new policy feature requires schema, conformance, implementation, tests, and docs.
- Some convenience/custom policy keys are rejected until OAP has first-class semantics for them.

## Alternatives Considered

1. **Allow arbitrary keys and pass them through**  
   Rejected because this makes policy author intent ambiguous and unsafe.

2. **Treat unknown keys as rule non-match**  
   Rejected because a typo in a deny rule could cause the deny to disappear.

3. **Allow custom keys only under an explicit extension namespace**  
   Deferred. This may be useful later, but extension semantics need a separate spec so enforcement points know whether a custom key is advisory or mandatory.
