# Writing OAP Policies

This guide covers everything you need to know about authoring policies for Open Agent Policy — from basic allow/deny rules to advanced constraints, approval workflows, and multi-agent setups.

---

## Policy structure

Every OAP policy is a YAML document with this structure:

```yaml
apiVersion: oap.dev/v1alpha1
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
      maxRecords: 25
      readonly: true
      redact:
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
      expiresIn: 5m
    reason: "External emails require manager approval"
```

---

## Constraint types

Constraints narrow what an agent can do within an allowed action. They are enforced by the SDK, gateway, or resource API.

| Constraint | Type | Description |
|---|---|---|
| `maxRecords` | Integer | Maximum number of records to return |
| `readonly` | Boolean | If true, only read operations allowed |
| `redact` | String[] | Fields to redact from responses |
| `timeWindowSeconds` | Integer | Action only valid within this time window |
| `allowedFields` | String[] | Only these fields can be modified |
| `expiresIn` | Duration | Grant lifetime, such as `5m` or `1h` |

### Unsupported constraints

OAP rejects unknown constraint keys during evaluation. This is intentional: silently ignoring a constraint would turn a narrow allow into a broad allow.

```yaml
constraints:
  max_records: 10  # invalid policy key; use maxRecords
```

Decision JSON still uses API-style names such as `max_records`, `redact_fields`, and `allowed_fields`.

---

## Conditions

Conditions are boolean prerequisites for a rule. If a known condition is not met, the rule does not match. If a condition key is unknown or malformed, evaluation fails closed.

| Condition | Type | Description |
|---|---|---|
| `actorRequired` | Boolean | Requires an actor in the authorization request. |
| `actorType` | String | Requires actor type `user`, `service`, or `agent`. |
| `actorId` | String | Requires a specific actor ID. |
| `actorGroups` | String[] | Requires membership in at least one listed group. |
| `environment` | String | Requires `development`, `staging`, or `production`. |
| `minAuthStrength` | String | Requires `none`, `password`, `mfa`, or `phishing_resistant_mfa`. |
| `timeWindow` | Object | Requires current UTC time/day to match. |
| `delegationRequired` | Boolean | Requires verified delegation context. |

Example:

```yaml
conditions:
  actorRequired: true
  minAuthStrength: mfa
  timeWindow:
    after: "09:00"
    before: "17:00"
    daysOfWeek: ["mon", "tue", "wed", "thu", "fri"]
```

Do not use business-specific condition keys such as `priorityIn` or `recipientDomain` until they are added to the spec and evaluator.

---

## Resource selectors

Resource selectors narrow a rule to a known resource shape. If a selector is present, the authorization request must include matching resource context.

```yaml
resources:
  types:
    - support.ticket
  classificationMax: confidential
  environments:
    - production
  owners:
    - group:support-platform
```

Supported selectors:

| Selector | Description |
|---|---|
| `types` | Resource type must match one of the listed values. |
| `classificationMax` | Resource classification must not exceed the listed maximum. |
| `environments` | Resource or request context environment must match. |
| `owners` | Resource or request context owner must match. |

---

## Constraint merging

When multiple policies match the same agent and action, constraints are merged using **strictest-wins** semantics:

| Type | Merge rule | Example |
|---|---|---|
| **Integer** (maxRecords) | Minimum value wins | 50 + 25 → 25 |
| **Boolean** (readonly) | `true` wins over `false` | true + false → true |
| **Array** (redact) | Union of all values | [ssn] + [credit_card] → [ssn, credit_card] |
| **Array** (allowedFields) | Intersection wins | [status, priority] + [status] → [status] |

---

## Agent definition

Agents must be registered before they can be authorized. An unregistered agent is always denied.

```yaml
apiVersion: oap.dev/v1alpha1
kind: Agent
metadata:
  name: ticket-assistant
  namespace: support
spec:
  owner: "group:support-platform"     # Who owns this agent
  type: chat_agent                     # Agent type (chat, workflow, autonomous)
  riskTier: medium                     # low, medium, high, critical
  description: "Support ticket agent"

  # Actions this agent claims it can do. Capabilities are an upper bound
  # on what policies may authorize.
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
    - type: spiffe
      provider: spire
      issuer: "https://spire.example.org"
      jwksUri: "https://spire.example.org/.well-known/jwks.json"
      subject: "spiffe://example.org/ns/support/sa/ticket-assistant"
      audience: "oap-server"

  framework: langchain
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
      maxRecords: 50
      readonly: true
      redact:
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
      allowedFields:
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

> Note: OAP supports exact action names, `*`, and prefix wildcards such as `ticket.*`. Use broad wildcards cautiously; an agent with no matching allow rules is denied by default.

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

1. **Agent registered?** - No means deny
2. **Agent active?** - Suspended or revoked means deny
3. **Capability declared?** - Policies cannot grant actions outside agent capabilities
4. **Matching policies found?** - by agent URI, type, namespace, or all-agents
5. **Delegation scope valid?** - if delegation context is present
6. **Rule matches?** - action, resource selector, and supported conditions
7. **Policy rule valid?** - unsupported conditions, constraints, or obligations fail closed
8. **Deny rules first** - any deny match wins
9. **Require approval next** - approval beats allow
10. **Allow last** - matching allow rules merge constraints
11. **No allow match** - deny by default

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
  -f requests/ticket-read.json
```

### Explain a decision step-by-step

```bash
bin/oapctl explain \
  --data policies/ \
  -f requests/customer-delete.json
```

### Run conformance tests

```bash
bin/oapctl test --conformance
```

---

## Next steps

- [Policy Backends](policy-backends.md) — Built-in policy path plus OPA and Cedar adapter contracts
- [Getting Started](getting-started.md) — Setup and first integration
- [Identity & Sessions](identity-and-sessions.md) — Identity bindings, supported providers, sessions, runs, grant tokens
- [Integration Guide](integration.md) — SDK, gateway, proxy, and middleware patterns
- [Runtime Authorization Flow](../flows/runtime-authorization.md) — Sequence diagram
