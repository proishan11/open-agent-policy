# ADR-002: YAML rules-array policy format

**Status:** accepted  
**Date:** 2026-05-27  
**Deciders:** Ishan Singh  

## Context

The PRD and post-PRD notes used multiple inconsistent policy shapes (flat effect model, rules-as-keys, rules-array). We need one canonical format before building the engine.

## Decision

Adopt a rules-array format with explicit `effect` per rule. Policy-level `subject` selector is inherited by all rules. `conditions` are boolean prerequisites; `constraints` narrow granted access. Both are distinct concepts and must not be conflated.

```yaml
spec:
  subject:
    agent: agent://namespace/name
  rules:
    - effect: allow | deny | require_approval | require_delegation
      actions: [...]
      conditions: { ... }
      constraints: { ... }
```

## Consequences

- **Easier:** Developers express allow and deny for the same agent in one file; readable in PR reviews; maps naturally to JSON Schema.
- **Harder:** Rules-array requires ordered evaluation; constraint merging across multiple matching policies adds complexity.
