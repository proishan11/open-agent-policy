# ADR-003: Pluggable policy engine with built-in default

**Status:** accepted  
**Date:** 2026-05-27  
**Deciders:** Ishan Singh  

## Context

OPA, Cedar, and OpenFGA are mature policy engines. Building a competing evaluator from scratch is risky. However, requiring enterprises to adopt OPA/Cedar as a prerequisite raises the adoption barrier.

## Decision

OAP ships with a built-in YAML policy evaluator sufficient for most use cases. The evaluator is behind a `PolicyEvaluator` interface. Enterprises already running OPA or Cedar can swap in an adapter. OAP still owns agent-native context enrichment (registry lookups, delegation verification, constraint merging, grant issuance, audit) — only the rule evaluation step is delegated.

## Consequences

- **Easier:** OAP works out of the box with no external dependencies; power users can leverage existing OPA/Cedar investments.
- **Harder:** Must maintain the built-in evaluator to a high standard; pluggable interface must be stable before v1.
