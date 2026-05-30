# Agent Onboarding Flow

How an agent goes from unregistered to ready-to-operate.

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant CLI as oapctl
    participant Server as OAP Server
    participant Registry as Agent Registry
    participant PS as Policy Store

    Dev->>CLI: oapctl agent register -f oap.yaml
    CLI->>Server: POST /v1/agents (agent manifest)
    Server->>Registry: RegisterAgent(agent)
    Registry-->>Server: agent stored
    Server-->>CLI: 201 Created (agent_id)
    CLI-->>Dev: ✓ Registered agent://ns/name

    Dev->>CLI: oapctl policy apply -f policy.yaml
    CLI->>Server: POST /v1/policies (policy)
    Server->>PS: AddPolicy(policy)
    PS-->>Server: policy stored
    Server-->>CLI: 200 OK (policy_id)
    CLI-->>Dev: ✓ Applied ns/policy-name

    Dev->>CLI: oapctl simulate -f request.json --data ./
    CLI->>CLI: Load agents + policies from files
    CLI->>CLI: evaluator.Evaluate(request)
    CLI-->>Dev: Decision: allow_with_constraints
```

## Steps

1. **Register** — Developer creates an `oap.yaml` manifest declaring the agent's identity, owner, risk tier, and capabilities.
2. **Apply policy** — One or more policies are applied that reference the agent (by ID, type, namespace, or all-agents).
3. **Verify** — Developer simulates a request locally to confirm the agent will get the expected decision.
4. **Deploy** — Agent starts running with OAP enforcement (SDK, proxy, or gateway).

## Invariants

- Unregistered agents are always denied (Principle 1).
- An agent with no matching policies is denied by default (Principle 2).
- Registration does not grant any access — policies are required.
