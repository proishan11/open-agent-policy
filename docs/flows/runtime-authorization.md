# Runtime Authorization Flow

How every agent tool call is authorized at runtime.

```mermaid
sequenceDiagram
    participant Agent
    participant EP as Enforcement Point<br/>(SDK / Proxy / Gateway)
    participant Eval as Policy Evaluator
    participant Reg as Registry Store
    participant Audit as Audit Sink

    Agent->>EP: Tool call (e.g., read_invoice)
    EP->>EP: Build AuthorizationRequest<br/>(subject, action, resource, tool, actor, context)

    EP->>Eval: Evaluate(request)
    Eval->>Reg: GetAgent(agent_id)
    Reg-->>Eval: agent (or nil)

    alt Agent not registered
        Eval-->>EP: DENY (unregistered)
    else Agent suspended/revoked
        Eval-->>EP: DENY (inactive)
    else Agent active
        Eval->>Reg: PoliciesForAgent(agent)
        Reg-->>Eval: matching policies

        Eval->>Eval: Scan rules (deny → require_approval → allow)
        Eval->>Eval: Check conditions (actorRequired, delegation)
        Eval->>Eval: Merge constraints (strictest wins)

        alt Explicit deny matched
            Eval-->>EP: DENY (reason)
        else No allow matched
            Eval-->>EP: DENY (no matching allow rule)
        else Allow matched
            Eval-->>EP: ALLOW / ALLOW_WITH_CONSTRAINTS
        end
    end

    EP->>Audit: Write audit event

    alt Decision = allow
        EP->>Agent: Execute tool, return result
    else Decision = deny
        EP->>Agent: Return safe error message
    end
```

## Evaluation Order

1. Validate request (agent_id, action required)
2. Verify agent is registered and active
3. Find matching policies (by agent ID, type, namespace, or all-agents)
4. Scan all rules across all matching policies
5. **Deny rules first** — any match → deny (Principle 3)
6. **Require-approval rules** — any match → require_approval
7. **Allow rules** — any match → allow
8. No matching allow → deny by default (Principle 2)
9. Merge constraints from all matching allow rules (strictest wins)
10. Emit audit event (Principle 5)

## Constraint Merging

When multiple allow rules match, constraints are merged conservatively:
- **Numeric** (max_records): take the minimum
- **Boolean** (readonly): true wins over false
- **Arrays** (redact_fields): union of all values
