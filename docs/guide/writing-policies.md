# Writing OAP Policies

This guide covers everything you need to know about authoring policies for Open Agent Policy — from basic allow/deny rules to advanced constraints, approval workflows, and multi-agent setups.

---

## Policy structure

Every OAP policy is a YAML document with this structure:

```yaml
apiVersion: oap/v1alpha1
kind: AgentPolicy
metadata:
  name: my-policy-name       # Unique name
  namespace: my-namespace     # Organizational scope
spec:
  subject:
    agent: "agent://namespace/agent-name"   # Which agent this applies to
  rules:
    - effect: allow|deny
      actions: [...]
      constraints: { ... }
      reason: "..."
```

### Key fields

| Field | Required | Description |
|---|---|---|
| `metadata.name` | Yes | Unique policy identifier |
| `metadata.namespace` | Yes | Scope (team, org, environment) |
| `spec.subject.agent` | Yes | Agent URI this policy applies to |
| `spec.rules` | Yes | List of allow/deny rules |

---

## Rule effects

### Allow

Permits the listed actions. Can include constraints.

```yaml
rules:
  - effect: allow
    actions:
      - ticket.read
      - ticket.list
```

### Allow with constraints

Permits the action but limits what the agent can do.

```yaml
rules:
  - effect: allow
    actions:
      - customer.read
    constraints:
      max_records: 25
      readonly: true
      redact_fields:
        - ssn
        - credit_card
        - bank_account
```

### Deny

Blocks the listed actions. **Deny always overrides allow** — this is a core OAP principle.

```yaml
rules:
  - effect: deny
    actions:
      - customer.delete
      - customer.bulk_export
    reason: "Destructive and bulk operations are prohibited"
```

### Require approval

Allows the action only after human approval.

```yaml
rules:
  - effect: require_approval
    actions:
      - email.send_external
    approval:
      approvers:
        - "group:support-leads"
      expires_in_seconds: 300
    reason: "External emails require manager approval"
```

---

## Constraint types

Constraints narrow what an agent can do within an allowed action. They are enforced by the SDK, gateway, or resource API.

| Constraint | Type | Description |
|---|---|---|
| `max_records` | Integer | Maximum number of records to return |
| `readonly` | Boolean | If true, only read operations allowed |
| `redact_fields` | String[] | Fields to redact from responses |
| `time_window_seconds` | Integer | Action only valid within this time window |
| `allowed_fields` | String[] | Only these fields can be modified (custom) |

### Custom constraints

You can add any key-value pairs to constraints. OAP passes them through to the SDK:

```yaml
constraints:
  max_records: 10
  allowed_regions: ["us-east-1", "eu-west-1"]   # custom
  require_encryption: true                        # custom
```

In your code:

```python
if decision.is_allowed:
    regions = decision.constraints.get("allowed_regions", [])
    encrypted = decision.constraints.get("require_encryption", False)
```

---

## Constraint merging

When multiple policies match the same agent and action, constraints are merged using **strictest-wins** semantics:

| Type | Merge rule | Example |
|---|---|---|
| **Integer** (max_records) | Minimum value wins | 50 + 25 → 25 |
| **Boolean** (readonly) | `true` wins over `false` | true + false → true |
| **Array** (redact_fields) | Union of all values | [ssn] + [credit_card] → [ssn, credit_card] |

---

## Agent definition

Agents must be registered before they can be authorized. An unregistered agent is always denied.

```yaml
apiVersion: oap/v1alpha1
kind: Agent
metadata:
  name: ticket-assistant
  namespace: support
spec:
  owner: "group:support-platform"     # Who owns this agent
  type: chat_agent                     # Agent type (chat, workflow, autonomous)
  riskTier: medium                     # low, medium, high, critical
  description: "Support ticket agent"

  # Actions this agent claims it can do (informational, not enforcement)
  capabilities:
    - ticket.read
    - ticket.update
    - customer.read
    - message.send

  # Identity binding for production authentication
  identityBindings:
    - type: oidc_client
      provider: keycloak
      issuer: "https://auth.company.com/realms/agents"
      subject: "ticket-assistant-client"

  runtime:
    framework: langchain
    language: python
```

### Agent states

| State | Meaning |
|---|---|
| `active` | Normal operation |
| `suspended` | Temporarily disabled (always denied even with allow policies) |
| `revoked` | Permanently disabled |

---

## Common patterns

### Read-only agent with field redaction

```yaml
rules:
  - effect: allow
    actions:
      - customer.read
      - customer.list
    constraints:
      max_records: 50
      readonly: true
      redact_fields:
        - ssn
        - credit_card
        - bank_account
        - tax_id

  - effect: deny
    actions:
      - customer.create
      - customer.update
      - customer.delete
    reason: "Agent is read-only"
```

### Tiered access by action

```yaml
rules:
  # Low-risk: allow freely
  - effect: allow
    actions:
      - ticket.read
      - ticket.list

  # Medium-risk: allow with constraints
  - effect: allow
    actions:
      - ticket.update
    constraints:
      allowed_fields:
        - status
        - priority

  # High-risk: require approval
  - effect: require_approval
    actions:
      - ticket.escalate
    approval:
      approvers: ["group:support-leads"]

  # Prohibited: always deny
  - effect: deny
    actions:
      - ticket.delete
      - ticket.bulk_export
    reason: "Destructive operations are prohibited"
```

### Lock down an agent completely

```yaml
rules:
  - effect: deny
    actions:
      - "*"
    reason: "Agent locked down pending security review"
```

> Note: OAP doesn't support wildcards natively — list all actions to deny, or simply don't add any allow rules. An agent with no matching allow rules is denied by default.

### Multiple agents sharing a policy

Use the agent URI to target specific agents:

```yaml
# Policy for all agents in the "support" namespace
spec:
  subject:
    agent: "agent://support/ticket-assistant"
```

Create separate policy files for different agents. OAP evaluates all matching policies for an agent.

---

## Evaluation order

OAP evaluates policies in this order:

1. **Agent registered?** — No → deny
2. **Agent active?** — No → deny
3. **Find matching policies** — by agent URI
4. **Scan all rules** (across all matching policies):
   - Any **deny** match → deny (overrides everything)
   - Any **require_approval** match → require_approval
   - Any **allow** match → allow (with merged constraints)
5. **No allow match** → deny by default

**Key principle: deny always wins.** If any rule in any policy denies an action, that action is denied regardless of other allow rules.

---

## File organization

Recommended directory structure:

```
policies/
├── agents.yaml              # Agent definitions
├── support-agent-policy.yaml # Per-agent policies
├── finance-agent-policy.yaml
└── global-deny-policy.yaml  # Organization-wide deny rules
```

OAP loads all `.yaml` files from the data directory recursively:

```bash
bin/oap-server --data policies/
```

---

## Testing policies

### Simulate a decision

```bash
bin/oapctl simulate \
  --data policies/ \
  --agent "agent://support/ticket-assistant" \
  --action "ticket.read"
```

### Explain a decision step-by-step

```bash
bin/oapctl explain \
  --data policies/ \
  --agent "agent://support/ticket-assistant" \
  --action "customer.delete"
```

### Run conformance tests

```bash
bin/oapctl test --conformance
```

---

## Next steps

- [Getting Started](getting-started.md) — Setup and first integration
- [Identity & Sessions](identity-and-sessions.md) — Identity bindings, supported providers, sessions, runs, grant tokens
- [Integration Guide](integration.md) — SDK, gateway, proxy, and middleware patterns
- [Runtime Authorization Flow](../flows/runtime-authorization.md) — Sequence diagram
