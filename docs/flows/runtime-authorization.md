# Runtime Authorization Flow

How every agent tool call is authorized at runtime.

## Flow 1: Embedded mode (local evaluator)

Used when the gateway, proxy, or SDK has a local policy store.

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

## Flow 2: Remote mode with sessions and grants

Used when the gateway/proxy delegates to a centralized OAP server. Includes
identity verification, session management, and grant token issuance.

```mermaid
sequenceDiagram
    participant Agent as Agent Workload
    participant IdP as Identity Provider
    participant EP as Gateway / Proxy
    participant OAP as OAP Server
    participant Resource as Upstream API

    Note over Agent,IdP: Session establishment (once per 15 min)
    Agent->>IdP: client_credentials grant
    IdP-->>Agent: JWT (signed)
    Agent->>OAP: POST /v1/runtime/session {agent_id, JWT}
    OAP->>OAP: Verify JWT against identity bindings
    OAP-->>Agent: ags_ session token

    Note over Agent,Resource: Authorized request
    Agent->>EP: HTTP request / MCP tools/call<br/>Authorization: Bearer ags_...
    EP->>OAP: POST /v1/authorize (Bearer ags_...)
    OAP->>OAP: Look up session → verified agent_id
    OAP->>OAP: Evaluate policy

    alt Allow
        OAP->>OAP: Issue grant token (HMAC-SHA256 JWT, 5min)
        OAP-->>EP: {decision: "allow", grant: {token: "eyJ..."}}
        EP->>Resource: Forward request + X-OAP-Grant-Token header
        Resource-->>EP: Response
        EP-->>Agent: Response
    else Deny
        OAP-->>EP: {decision: "deny", reason: "..."}
        EP-->>Agent: 403 / MCP error -32001
    end
```

## Flow 3: Resource-side grant validation

Resource APIs independently verify grant tokens to confirm authorization.

```mermaid
sequenceDiagram
    participant EP as Gateway / Agent
    participant Resource as Resource API<br/>(with GrantMiddleware)
    participant OAP as OAP Server

    EP->>Resource: Request + X-OAP-Grant-Token: eyJ...
    Resource->>OAP: POST /v1/grants/validate {grant_token}
    OAP->>OAP: Verify HMAC signature + expiry

    alt Valid grant
        OAP-->>Resource: {valid: true, agent_id, action, constraints}
        Resource->>Resource: Set X-OAP-Verified-Agent-ID header
        Resource->>Resource: Serve request (apply constraints)
    else Invalid / expired
        OAP-->>Resource: {valid: false, error: "..."}
        Resource-->>EP: 403 Forbidden
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
