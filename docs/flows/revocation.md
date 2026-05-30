# Revocation Flow

How an agent or grant is revoked, immediately cutting off access.

```mermaid
sequenceDiagram
    participant Admin
    participant Server as OAP Server
    participant Registry as Agent Registry
    participant EP1 as Enforcement Point 1
    participant EP2 as Enforcement Point 2
    participant Audit as Audit Sink

    Admin->>Server: Revoke agent (set state: revoked)
    Server->>Registry: UpdateAgent(state=revoked)
    Registry-->>Server: updated

    Server->>Audit: Emit audit event<br/>(agent.revoked)
    Server-->>Admin: ✓ Agent revoked

    Note over EP1,EP2: Next authorization request

    EP1->>EP1: Agent requests tool call
    EP1->>EP1: evaluator.Evaluate(request)
    EP1->>Registry: GetAgent(agent_id)
    Registry-->>EP1: agent (state=revoked)
    EP1-->>EP1: DENY (agent revoked)
    EP1->>Audit: Emit audit event (deny, revoked)

    Note over EP1,EP2: Embedded evaluators sync via bundles

    EP2->>Server: GET /v1/bundles (bundle sync)
    Server-->>EP2: Bundle (agent state=revoked)
    EP2->>EP2: Update local store
    EP2->>EP2: Next request → DENY
```

## Revocation Types

| Type | Scope | Effect |
|---|---|---|
| **Agent revocation** | All actions by this agent | Agent status set to `revoked`, all requests denied |
| **Agent suspension** | All actions by this agent | Agent status set to `suspended`, all requests denied (reversible) |
| **Grant revocation** | Specific grant token | Grant marked invalid, enforcement points reject the JWT |
| **Policy removal** | Actions covered by the policy | Agent loses the permissions from that policy |

## Propagation

- **Server-connected enforcement points** — immediate (next request checks live registry)
- **Embedded evaluators** — on next bundle sync (configurable interval, default 30s)
- **JWT grants** — on expiry (grants are short-lived, typically 15 min)

## Invariants

- Revoked agents are denied regardless of policies (even allow-all).
- Suspended agents are denied but can be reactivated.
- Expired grants are invalid (checked at verification time).
- Audit events are emitted for revocation actions and subsequent denials.
