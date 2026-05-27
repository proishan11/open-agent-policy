# Approval Flow

How high-risk actions require human approval before proceeding.

```mermaid
sequenceDiagram
    participant Agent
    participant EP as Enforcement Point
    participant Eval as Policy Evaluator
    participant Approver as Human Approver

    Agent->>EP: Tool call: erp.invoice.delete
    EP->>Eval: Evaluate(request)
    Eval->>Eval: Match rule with effect: require_approval
    Eval-->>EP: REQUIRE_APPROVAL<br/>(approvers: [group:finance-leads],<br/> reason: "Delete requires approval")

    EP-->>Agent: Approval required

    Note over Agent,Approver: Agent pauses execution

    Approver->>EP: Approve (approval_id, scope)
    
    Agent->>EP: Retry tool call with approval context
    EP->>Eval: Evaluate(request + approval)
    Eval->>Eval: Validate approval:<br/>- correct approval_id<br/>- approver authorized<br/>- within scope<br/>- not expired
    Eval-->>EP: ALLOW (approved)

    EP-->>Agent: Execute tool, return result
```

## Approval Rules

A policy rule with `effect: require_approval` triggers the approval flow:

```yaml
rules:
  - effect: require_approval
    actions:
      - erp.invoice.delete
    approval:
      approvers:
        - group:finance-leads
      maxWaitSeconds: 1800
```

## Invariants

- Approval cannot grant access that the agent's policies would deny.
- Approval is scoped — it only applies to the specific action and resource.
- Approval expires (default: 30 minutes).
- The approver must be in the configured approvers list.
- Audit events are emitted for both the approval request and the approved action.
