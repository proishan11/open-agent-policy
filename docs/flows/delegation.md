# Delegation Flow

How a user delegates authority to an agent to act on their behalf.

```mermaid
sequenceDiagram
    participant User
    participant App as Application
    participant Agent
    participant EP as Enforcement Point
    participant Eval as Policy Evaluator

    User->>App: "Reconcile my invoices"
    App->>App: Create delegation scope<br/>(actions: [erp.invoice.read],<br/> resources: [erp.invoice],<br/> expires: 30min)

    App->>Agent: Start task with delegation context
    Agent->>EP: Tool call: erp.invoice.read

    EP->>EP: Build request with:<br/>actor: user (from OIDC token)<br/>context.delegation_scope: [erp.invoice.read]

    EP->>Eval: Evaluate(request)
    Eval->>Eval: Find matching policies
    Eval->>Eval: Check delegation scope
    
    alt Action within delegation scope
        Eval->>Eval: Evaluate normally
        Eval-->>EP: ALLOW (delegated)
    else Action outside delegation scope
        Eval-->>EP: DENY (outside delegation scope)
    end

    EP-->>Agent: Result (or denial)
    Agent-->>App: Task result
    App-->>User: "Done — 3 invoices reconciled"
```

## Key Principles

- **Delegation must be explicit** — the user defines exactly what actions and resources the agent can access on their behalf (Principle 8).
- **Scoped** — a delegation never exceeds the delegator's own permissions.
- **Time-limited** — delegations expire.
- **Agent's own policy still applies** — delegation + agent policy must both allow the action.

## Delegation Scope Enforcement

The evaluator checks delegation in two places:
1. **Condition: delegationRequired** — a policy rule can require that the action is performed under a delegation (actorRequired is a related condition).
2. **Scope check** — if `context.delegation_scope` is present, the requested action must be within that scope.
