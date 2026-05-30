# Approval Workflows

OAP policies can return `require_approval` for risky actions. This is not an
allow decision. It is a policy result telling your application to pause the
action and route it through a human or service approval workflow.

Examples:

- send a message to an external customer channel
- issue a refund
- delete data
- change repository settings
- export more than a small number of records

## Policy Shape

```yaml
- effect: require_approval
  actions:
    - message.send
  resources:
    types:
      - slack.channel
    owners:
      - channel:external
  approval:
    approvers:
      - group:support-managers
    minApprovals: 1
    expiresIn: 30m
  reason: "External customer updates require support manager approval"
```

When a request matches this rule, OAP returns:

```json
{
  "decision": "require_approval",
  "reason": "External customer updates require support manager approval",
  "approval": {
    "approvers": ["group:support-managers"],
    "expires_in_seconds": 1800
  }
}
```

## End-to-End Flow

```text
Agent requests message.send to slack:#external-customer-updates
  -> OAP returns require_approval
Agent/app creates an approval request
Human approver approves or denies
Agent/app validates approval scope before retrying or executing
Only the originally approved agent + actor + action + resource may continue
```

OAP currently provides the policy decision and approval requirements. Your
application or approval service owns the workflow state: creating approval
requests, notifying approvers, recording decisions, and validating scope before
execution.

The local validation environment includes an approval API that demonstrates this
pattern.

## SDK Handling

Direct SDK usage:

```python
def request_external_message_approval(channel_id: str) -> dict:
    decision = client.authorize(
        action="message.send",
        resource_type="slack.channel",
        resource_id=channel_id,
        resource_owner="channel:external",
        actor_type="user",
        actor_id="alice@company.test",
    )

    if decision.requires_approval:
        approval = create_approval_request(
            agent_id="agent://support/ticket-assistant",
            actor_id="alice@company.test",
            action="message.send",
            resource_type="slack.channel",
            resource_id=channel_id,
            approvers=decision.approval["approvers"],
            reason=decision.reason,
        )
        return {"status": "pending_approval", "approval_id": approval["id"]}

    return {"status": decision.decision}
```

Decorator usage:

```python
from open_agent_policy import ApprovalRequiredError

try:
    send_external_message("slack:#external-customer-updates", text)
except ApprovalRequiredError as exc:
    approval = create_approval_request(
        approvers=exc.approvers,
        reason=str(exc),
    )
    pending_result = {"status": "pending_approval", "approval_id": approval["id"]}
```

## Scope Validation

Approval must be scoped. An approval for one resource must not unlock another
resource.

At minimum, bind approvals to:

| Field | Example |
|---|---|
| `agent_id` | `agent://support/ticket-assistant` |
| `actor_id` | `alice@company.test` |
| `action` | `message.send` |
| `resource_type` | `slack.channel` |
| `resource_id` | `slack:#external-customer-updates` |
| `expires_at` | approval expiration time |

Validation logic:

```python
def validate_approval(approval, *, agent_id, actor_id, action, resource_id):
    if approval["status"] != "approved":
        return False
    if approval["expires_at"] < now():
        return False
    if approval["agent_id"] != agent_id:
        return False
    if approval["actor_id"] != actor_id:
        return False
    if approval["action"] != action:
        return False
    if approval["resource_id"] != resource_id:
        return False
    return True
```

The validation stack tests approval replay against the wrong resource, wrong
agent, and wrong actor.

## Validation Stack Example

The local approval service exposes:

```text
POST /api/approvals
GET  /api/approvals/{approval_id}
POST /api/approvals/{approval_id}/decide
POST /api/approvals/{approval_id}/validate
```

Run the proof:

```bash
docker compose -f validation/docker-compose.yml --profile test run --rm e2e-tests
```

Relevant scenarios:

- `S007_external_message_requires_approval.yaml`
- `S008_approval_scope_mismatch_denied.yaml`
- grant replay tests in `validation/tests/security/test_grant_replay.py`

## Recommended Agent Behavior

When an action requires approval:

1. Stop before executing the tool.
2. Create an approval request with exact scope.
3. Return a pending approval result to the user or orchestration layer.
4. Resume only after approval validation passes.
5. Re-authorize or execute through a resource API that validates a scoped grant.
6. Audit both the approval decision and final action.

Do not:

- treat approval as an allow
- let the model self-approve
- reuse an approval for another resource
- skip expiration checks
- approve broad actions such as `*`

## Policy Design Tips

- Use `require_approval` for externally visible, destructive, financial, or
  high-volume actions.
- Keep the approved scope narrow.
- Prefer resource selectors over prompt text.
- Keep explicit deny rules for actions that should never happen.
- Test approval-required behavior alongside deny behavior.

Next:

- [Building Agents With OAP](building-agents-with-oap.md)
- [Protecting Resource APIs](protecting-resource-apis.md)
- [Writing Policies](writing-policies.md)
