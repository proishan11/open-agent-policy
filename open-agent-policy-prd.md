# Open Agent Policy

**Version:** v0.1 draft  
**Repo name:** `open-agent-policy`  
**Short name:** OAP  
**Tagline:** Zero-trust access control for AI agents.  
**Status:** Draft PRD / specification

---

## 1. Executive summary

Open Agent Policy is an open-source, vendor-neutral framework for defining, enforcing, and auditing authorization policies for AI agents.

The goal is to make agents first-class security principals with identity, ownership, fine-grained permissions, scoped delegation, approval gates, runtime constraints, and auditable access to tools, APIs, data, SaaS systems, infrastructure, and other agents.

Open Agent Policy should answer a simple but security-critical question:

> Can this specific agent, running in this specific context, acting for this specific user or system, perform this specific action on this specific resource, under these specific constraints, right now?

The project should bring employee-style zero-trust access control to agents: least privilege, explicit trust boundaries, runtime authorization, policy-driven decisions, strong audit trails, and fast revocation.

---

## 2. Problem statement

Enterprises already govern employees, workloads, services, and applications through identity, roles, groups, device posture, conditional access, approvals, audit logs, and revocation.

AI agents do not fit cleanly into those existing models.

An agent is not exactly a human user, not exactly a service account, and not exactly an application. It can reason, plan, call tools, chain actions, use delegated user authority, interact with external systems, and make runtime decisions.

Existing IAM systems not answer the full agent-specific question:
`
Can this specific agent, running in this specific environment, acting for this specific user or team, perform this specific action on this specific resource, for this specific purpose, under these constraints, right now?
`

These systems can authenticate users and services, but they often do not capture the full agent authorization context:


```text
agent identity
agent owner
agent runtime
agent version
acting user or service
requested action
resource classification
tool being used
purpose of access
runtime risk
approval state
delegation scope
audit obligations
```

Without a common framework, each agent application builds its own access logic. This leads to inconsistent authorization, over-broad credentials, weak auditability, unclear ownership, prompt-injection risk, and poor revocation.

Open Agent Policy exists to solve that gap.

The framework should bring zero-trust, fine-grained, policy-driven access control to AI agents in the same way enterprises restrict employees and workloads: no implicit trust, least privilege, continuous authorization, strong auditability, scoped access, and fast revocation. This aligns with the zero-trust principle that access should focus on users, assets, and resources rather than network location, and that authentication and authorization should happen before resource sessions are established

---

## 3. Product thesis

Agents should be first-class security principals.

Every agent should have:

```text
identity
owner
purpose
runtime context
capabilities
allowed actions
resource bindings
delegation context
approval requirements
audit trail
revocation path
```

Open Agent Policy should not replace enterprise IAM, OAuth, OIDC, SPIFFE, Kubernetes RBAC, cloud IAM, API gateways, policy engines, or secrets managers.

Instead, it should become the agent-aware policy and enforcement layer that integrates with those systems.

The product thesis:

> Open Agent Policy is an open-source control plane and enforcement framework for registering agents, defining agent policies, brokering least-privilege access, enforcing runtime decisions, and auditing every agent action across tools, APIs, data, SaaS systems, infrastructure, MCP servers, and other agent runtimes.

---

## 4. Goals

Open Agent Policy should provide:

1. A vendor-neutral authorization model for AI agents.
2. A consistent policy language for agent access.
3. A registry for agents, tools, and protected resources.
4. A decision API for runtime authorization.
5. Enforcement points through SDKs, gateways, proxies, and adapters.
6. Scoped, short-lived grants instead of broad standing credentials.
7. Delegation support for agents acting on behalf of users or services.
8. Approval gates for high-risk actions.
9. Structured audit logs for every decision and action.
10. Policy simulation for security review and developer testing.

It should support:
```
Human -> Agent -> Resource
Service -> Agent -> Tool -> Resource
Agent -> Agent -> Tool -> Resource
Agent -> MCP Server -> Tool -> Resource
```
The key design is a split between the policy decision point and policy enforcement point. Policy engines such as OPA already popularized the pattern of decoupling policy decision-making from enforcement, where software queries a policy engine with structured input and receives a decision. APF should adopt that pattern but make the input model agent-native.

---

## 5. Non-goals

Open Agent Policy should not become:

| Non-goal | Reason |
|---|---|
| A full IAM replacement | Enterprises already have IdPs, directories, cloud IAM, and workload identity systems. |
| A new OAuth replacement | Existing authorization and token standards should be reused. |
| A generic secrets manager | OAP may broker scoped credentials, but should not become a vault clone. |
| An LLM runtime | OAP should secure agents regardless of runtime or framework. |
| A SIEM | OAP should emit audit events, not replace downstream analytics. |
| A prompt-injection detector only | Prompt safety is one layer; OAP focuses on authorization and enforcement. |
| RBAC only | Agent authorization requires RBAC, ABAC, ReBAC, delegation, constraints, and approvals. |

---

## 6. Target users

### 6.1 Security platform teams

They need a consistent way to govern internal and third-party agents across the enterprise.

### 6.2 AI platform teams

They need reusable agent security primitives so that every agent team does not build authorization independently.

### 6.3 Application teams

They need a simple SDK or gateway to ask:

```text
Is this agent allowed to perform this action?
```

### 6.4 Governance, risk, and compliance teams

They need evidence:

```text
Which agent accessed which resource?
Who owned the agent?
Who was the agent acting for?
What policy allowed it?
Was approval required?
What constraints were applied?
What was logged?
```

### 6.5 Resource owners

They need a way to define access rules for APIs, databases, SaaS tools, queues, files, infrastructure, and business objects.

### 6.6 Agent developers

They need a clear contract for what their agents can request, what will be denied, and why.

---

## 7. Core concept

Open Agent Policy should model every protected agent action as an authorization request.

```text
subject + actor + action + resource + context -> decision + constraints + obligations
```

More explicitly:

```text
Can [agent identity]
acting as or for [human, service, team, or itself]
perform [action]
on [resource]
using [tool or channel]
for [declared purpose]
from [runtime environment]
under [current context]
with [risk, data classification, and approval state]?
```

The answer should not be limited to `allow` or `deny`.

OAP should support decisions such as:

```text
allow
deny
allow_with_constraints
require_approval
require_step_up_auth
require_delegation
require_human_review
require_redaction
require_sandbox
require_readonly_mode
```

---

## 8. Design principles

### 8.1 Agent identity is mandatory

Every protected agent must have an identity before accessing protected resources.

An anonymous agent should be denied by default.

Example:

```yaml
agent_id: agent://finance/invoice-reconciler/v1
agent_type: workflow_agent
owner: group:finance-platform
publisher: org:example
environment: production
trust_level: verified
runtime_identity: spiffe://example.org/prod/agents/invoice-reconciler
version: 1.4.2
image_digest: sha256:abc123
```

Open Agent Policy should integrate with workload identity systems rather than inventing everything from scratch. SPIFFE, for example, defines open standards for identifying software systems in heterogeneous environments, and its workload API is designed to give identity material to local workloads.

### 8.2 Deny by default

If no policy explicitly allows the action, access is denied.

### 8.3 Explicit deny overrides allow

A global deny policy must override narrower allow policies.

Example:

```text
No agent may bulk-export restricted customer data to an external destination.
```

### 8.4 Separate capability from permission

An agent may be technically capable of doing something but not authorized to do it.

```text
Capability: this agent can call jira.create_issue.
Permission: this agent may create issues only in project SECOPS when acting for approved users.
```

### 8.5 No broad standing credentials

Agents should not receive broad, long-lived API keys or service accounts.

Preferred model:

```text
Agent requests action.
OAP evaluates policy.
OAP grants short-lived scoped access.
Tool or API call is made through an enforcement point.
Audit event is written.
Credential expires.
```

### 8.6 Runtime authorization, not just registration-time authorization

Registering an agent is not enough.

Every sensitive action should be authorized at runtime based on:

```text
agent
actor
resource
action
purpose
environment
data classification
delegation
approval state
runtime posture
risk level
```

### 8.7 Prompt content is untrusted

Natural language cannot grant permissions.

The agent may claim:

```text
The user asked me to delete all records.
```

But authorization must come from identity, delegation, policy, approval, and resource metadata.

### 8.8 Delegation must be explicit and scoped

An agent acting on behalf of a user should receive limited delegated authority, not the user's full access.

Good delegation:

```text
Agent may read invoice INV-8821 for 15 minutes to reconcile a payment.
```

Bad delegation:

```text
Agent can do anything the user can do forever.
```

### 8.9 Enforcement must happen outside the agent

The agent should not be trusted to self-enforce policy.

Policy should be enforced through:

```text
SDKs
gateways
sidecars
MCP proxies
API proxies
database proxies
admission controllers
tool wrappers
resource-side checks
```

### 8.10 Auditability is mandatory

Every meaningful policy decision and protected action should be attributable, explainable, and auditable.

---

## 9. Core abstractions

### 9.1 Agent

A registered autonomous or semi-autonomous software actor.

```yaml
kind: Agent
metadata:
  name: invoice-reconciler
  namespace: finance
spec:
  owner: group:finance-platform
  description: Reconciles invoices against purchase orders
  type: workflow_agent
  lifecycle: production
  publisher: org:example
  runtime:
    workload_identity: spiffe://example.org/prod/agents/invoice-reconciler
    image_digest: sha256:abc123
    runtime: kubernetes
  capabilities:
    requested:
      - tool:erp.invoice.read
      - tool:erp.invoice.update_status
      - tool:slack.message.send
  risk:
    tier: medium
    data_access: confidential
```

### 9.2 Agent instance

A running deployment of an agent.

```yaml
agent_id: agent://finance/invoice-reconciler
instance_id: agent-instance://cluster-a/ns/finance/pod/invoice-reconciler-7d9f
runtime_identity: spiffe://example.org/prod/agents/invoice-reconciler
environment: production
started_at: "2026-05-25T08:30:00Z"
```

### 9.3 Agent run

A single task, session, or execution trace.

```yaml
run_id: run_01HZ
agent_id: agent://finance/invoice-reconciler
triggered_by: user:ishan@example.com
purpose: reconcile_invoice
started_at: "2026-05-25T08:31:00Z"
```

### 9.4 Actor

The entity on whose behalf the agent acts.

Examples:

```text
user:ishan@example.com
service:billing-api
team:finance-ops
agent:self
```

### 9.5 Resource

Anything protected by policy.

Examples:

```text
API endpoint
database table
file
ticket
cloud account
Kubernetes cluster
MCP tool
SaaS object
customer record
secret
queue
workflow
```

### 9.6 Tool

A callable capability exposed to an agent.

```yaml
kind: Tool
metadata:
  name: jira.create_issue
spec:
  provider: jira
  actions:
    - issue.create
  risk:
    level: low
  resource_types:
    - jira.project
    - jira.issue
```

### 9.7 Policy

A rule that decides whether an agent action is allowed, denied, constrained, or requires approval.

### 9.8 Grant

A temporary permission issued after successful policy evaluation.

```yaml
grant_id: grant_123
agent_id: agent://finance/invoice-reconciler
actor: user:ishan@example.com
actions:
  - erp.invoice.read
resource: erp.invoice:INV-8821
expires_at: "2026-05-25T08:46:00Z"
constraints:
  max_records: 10
  redact:
    - bank_account_number
```

### 9.9 Delegation

A scoped authorization from a user or service to an agent.

```yaml
delegation_id: del_123
delegator: user:ishan@example.com
delegate: agent://finance/invoice-reconciler
scope:
  actions:
    - erp.invoice.read
  resources:
    - erp.invoice:INV-8821
expires_at: "2026-05-25T09:00:00Z"
```

### 9.10 Approval

A human or system approval required before high-risk access.

```yaml
approval_id: appr_456
required_for:
  action: deployment.execute
  resource: prod.cluster.payments
approved_by: user:sre-lead@example.com
expires_at: "2026-05-25T10:00:00Z"
```

---

## 10. Reference architecture

```text
                    +----------------------+
                    | Existing IdP / IAM   |
                    | OIDC, SAML, LDAP     |
                    +----------+-----------+
                               |
                               v
+-------------+      +----------------------+      +----------------+
| Agent       |----->| OAP Enforcement      |----->| Tool / API /   |
| Runtime     |      | Gateway / SDK / PEP  |      | MCP Server     |
+-------------+      +----------+-----------+      +----------------+
                               |
                               v
                    +----------------------+
                    | OAP Policy Decision |
                    | Point               |
                    +----------+-----------+
                               |
        +----------------------+----------------------+
        |                      |                      |
        v                      v                      v
+---------------+      +---------------+      +----------------+
| Agent Registry|      | Policy Store  |      | Resource Catalog|
+---------------+      +---------------+      +----------------+
        |
        v
+----------------+
| Audit Log      |
+----------------+
```

### 10.1 Control plane

The control plane manages:

```text
agent registration
resource registration
tool registration
policy definitions
role bindings
delegations
approvals
grant lifecycle
audit configuration
policy simulation
```

### 10.2 Data plane

The data plane enforces:

```text
tool calls
API calls
MCP calls
database queries
file access
workflow execution
cloud actions
agent-to-agent calls
```

### 10.3 Policy Decision Point

The Policy Decision Point, or PDP, receives structured authorization input and returns a decision.

### 10.4 Policy Enforcement Point

The Policy Enforcement Point, or PEP, sits where actions happen.

Possible PEPs:

```text
language SDK
HTTP reverse proxy
Envoy external authorization adapter
MCP proxy
sidecar
Kubernetes admission controller
database proxy
CI/CD plugin
SaaS webhook gateway
resource-side middleware
```

### 10.5 Token broker

The token broker converts approved access into short-lived, scoped credentials.
MCP is especially relevant because protected MCP servers are modeled as OAuth resource servers, MCP clients act as OAuth clients, and MCP authorization relies on protected resource metadata for discovery. Open Agent Policy should not replace MCP authorization; it should add finer-grained agent policy on top of or beside it.

---

## 11. Authorization request model

Every protected action should be normalized into this shape.

```json
{
  "request_id": "req_01HZ",
  "timestamp": "2026-05-25T08:35:00Z",
  "subject": {
    "type": "agent",
    "agent_id": "agent://finance/invoice-reconciler",
    "agent_version": "1.4.2",
    "instance_id": "agent-instance://cluster-a/ns/finance/pod/x",
    "trust_level": "verified"
  },
  "actor": {
    "type": "user",
    "id": "user:ishan@example.com",
    "auth_strength": "phishing_resistant_mfa"
  },
  "action": {
    "name": "erp.invoice.read",
    "risk": "medium"
  },
  "resource": {
    "type": "erp.invoice",
    "id": "INV-8821",
    "owner": "group:finance",
    "classification": "confidential",
    "environment": "production"
  },
  "tool": {
    "name": "erp.get_invoice",
    "protocol": "mcp",
    "server": "mcp://erp.example.com"
  },
  "context": {
    "purpose": "reconcile_invoice",
    "run_id": "run_01HZ",
    "network_zone": "prod-cluster",
    "time": "2026-05-25T08:35:00Z",
    "requested_records": 1
  }
}
```

---

## 12. Authorization decision model

The PDP should return structured decisions.

```json
{
  "decision": "allow_with_constraints",
  "policy_ids": [
    "policy://finance/invoice-read",
    "policy://global/redact-payment-fields"
  ],
  "grant": {
    "expires_in_seconds": 900,
    "audience": "erp.example.com",
    "scope": [
      "erp.invoice.read"
    ]
  },
  "constraints": {
    "max_records": 5,
    "redact_fields": [
      "bank_account_number",
      "tax_identifier"
    ],
    "readonly": true,
    "log_full_request": true
  },
  "obligations": {
    "audit": true,
    "emit_event": true
  }
}
```

Supported decision values:

```text
allow
allow_with_constraints
deny
require_approval
require_step_up_auth
require_delegation
require_sandbox
```

---

## 13. Policy model

Open Agent Policy should support four policy styles.

### 13.1 Role-based access control

Useful for coarse grouping.

```yaml
role: finance-invoice-reader
permissions:
  - erp.invoice.read
  - erp.invoice.search
```

### 13.2 Attribute-based access control

Useful for contextual rules.

```yaml
condition:
  resource.classification_max: confidential
  subject.trust_level: verified
  context.environment: production
```

### 13.3 Relationship-based access control

Useful for ownership, assignment, and delegation.

```text
Agent may read a support ticket only if:
- the acting user is assigned to the ticket, or
- the acting user belongs to the owning team, or
- the resource owner delegated access to the agent.
```

### 13.4 Constraint-based policy

Useful for agent-specific access control.

```text
Agent may summarize records, but output must redact PII.
Agent may read 10 records, not export the full table.
Agent may create a ticket, not close a ticket.
Agent may propose a deployment, not execute it.
```

---

## 14. Example policies

### 14.1 Agent registration policy

```yaml
apiVersion: openagentpolicy.dev/v1alpha1
kind: AgentRegistrationPolicy
metadata:
  name: production-agents-must-have-owner
spec:
  match:
    environment: production
  require:
    owner: true
    runtime_identity: true
    image_digest: true
    risk_tier: true
    audit_enabled: true
  deny_if:
    owner: null
```

### 14.2 Read-only finance policy

```yaml
apiVersion: openagentpolicy.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: finance-invoice-readonly
spec:
  effect: allow
  subjects:
    agents:
      - agent://finance/invoice-reconciler
  actions:
    - erp.invoice.read
    - erp.invoice.search
  resources:
    types:
      - erp.invoice
    classification_max: confidential
  conditions:
    actor_required: true
    purpose_in:
      - reconcile_invoice
      - investigate_payment_status
    environment: production
  constraints:
    readonly: true
    max_records: 25
    redact_fields:
      - bank_account_number
      - tax_identifier
    expires_in: 15m
  obligations:
    audit: true
```

### 14.3 High-risk deployment policy

```yaml
apiVersion: openagentpolicy.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: production-deployments-require-approval
spec:
  effect: require_approval
  subjects:
    agent_types:
      - deployment_agent
  actions:
    - deployment.execute
  resources:
    types:
      - kubernetes.cluster
    environment: production
  conditions:
    change_ticket_required: true
    rollback_plan_required: true
  approval:
    approvers:
      - group:sre-leads
    min_approvals: 1
    expires_in: 30m
  constraints:
    max_blast_radius: single_service
  obligations:
    audit: true
```

### 14.4 Global deny policy

```yaml
apiVersion: openagentpolicy.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: deny-agent-bulk-pii-export
spec:
  effect: deny
  subjects:
    all_agents: true
  actions:
    - data.export
    - database.query
  resources:
    classification_min: restricted
  conditions:
    requested_records_greater_than: 1000
  reason: Agents may not bulk-export restricted data.
```

### 14.5 Resource policy

```yaml
apiVersion: openagentpolicy.dev/v1alpha1
kind: ResourcePolicy
metadata:
  name: customer-data-policy
spec:
  resource:
    type: customer_record
    classification: restricted
  rules:
    - effect: deny
      subjects:
        all_agents: true
      actions:
        - export
        - bulk_read
    - effect: allow
      subjects:
        agent_types:
          - support_agent
      actions:
        - read
        - summarize
      conditions:
        actor_required: true
        ticket_assigned_to_actor: true
      constraints:
        redact_fields:
          - ssn
          - payment_card
          - date_of_birth
```

---

## 15. Core workflows

### 15.1 Agent onboarding

```text
1. Developer registers an agent.
2. OAP validates required metadata.
3. Security owner reviews risk tier.
4. Runtime identity is bound.
5. Capabilities are declared.
6. Policies are attached.
7. Agent receives no broad credentials.
8. Agent can request scoped access at runtime.
```

### 15.2 Runtime authorization

```text
1. Agent wants to call a tool.
2. Tool call goes through an OAP enforcement point.
3. Enforcement point constructs an authorization request.
4. PDP evaluates policies.
5. PDP returns allow, deny, constrained allow, or approval required.
6. Enforcement point enforces the decision.
7. Token broker may issue short-lived credentials.
8. Audit event is written.
```

### 15.3 Acting on behalf of a user

```text
1. User asks an agent to perform a task.
2. Agent requests delegated access.
3. OAP checks user identity, agent identity, requested scope, resource, and purpose.
4. OAP issues scoped delegation.
5. Agent acts only within the delegated scope.
6. Delegation expires or is revoked.
```

### 15.4 Human approval

```text
1. Agent requests a high-risk action.
2. OAP returns require_approval.
3. Approval request includes action, resource, diff, risk, policy reason, and expiry.
4. Human approves or denies.
5. OAP records approval.
6. Agent retries action.
7. PDP allows action only within approval scope.
```

### 15.5 Revocation

```text
1. Security disables an agent, policy, grant, or delegation.
2. OAP propagates revocation.
3. PEPs fail closed for revoked identities.
4. Existing short-lived grants expire quickly.
5. Audit stream records revocation event.
```

---

## 16. MVP scope

### 16.1 MVP goal

Build the smallest useful open-source framework that can answer and enforce:

```text
Can this registered agent perform this action on this resource in this context?
```

### 16.2 MVP components

| Component | MVP requirement |
|---|---|
| Agent registry | Register agent identity, owner, type, runtime identity, capabilities, and risk tier. |
| Resource registry | Register resources, resource types, owners, classifications, and environments. |
| Tool registry | Register tools, actions, protocols, and risk levels. |
| Policy language | YAML/JSON policy format with allow, deny, constraints, and approval-required. |
| Decision API | `/v1/authorize` endpoint. |
| Enforcement SDK | Initial SDKs for Python and TypeScript. |
| HTTP gateway | Reverse proxy mode for APIs and tools. |
| Audit log | Append-only structured events. |
| CLI | Register agents/resources, test policies, and simulate decisions. |
| Local dev mode | File-backed config with SQLite or Postgres. |

### 16.3 MVP non-goals

Do not build in v0.1:

```text
full UI
full SIEM
full secrets vault
complex workflow approval engine
multi-cloud IAM abstraction
runtime behavior detection
prompt-injection classifier
automatic policy generation
```

---

## 17. API sketch

### 17.1 Register agent

```http
POST /v1/agents
```

```json
{
  "agent_id": "agent://finance/invoice-reconciler",
  "owner": "group:finance-platform",
  "type": "workflow_agent",
  "environment": "production",
  "runtime_identity": "spiffe://example.org/prod/agents/invoice-reconciler",
  "capabilities": [
    "erp.invoice.read",
    "erp.invoice.update_status",
    "slack.message.send"
  ],
  "risk_tier": "medium"
}
```

### 17.2 Register resource

```http
POST /v1/resources
```

```json
{
  "resource_id": "erp.invoice:*",
  "type": "erp.invoice",
  "owner": "group:finance",
  "classification": "confidential",
  "environment": "production"
}
```

### 17.3 Register tool

```http
POST /v1/tools
```

```json
{
  "tool_id": "tool://erp/get_invoice",
  "name": "erp.get_invoice",
  "protocol": "mcp",
  "actions": [
    "erp.invoice.read"
  ],
  "risk": "medium",
  "resource_types": [
    "erp.invoice"
  ]
}
```

### 17.4 Authorize action

```http
POST /v1/authorize
```

```json
{
  "subject": {
    "agent_id": "agent://finance/invoice-reconciler"
  },
  "actor": {
    "type": "user",
    "id": "user:ishan@example.com"
  },
  "action": "erp.invoice.read",
  "resource": {
    "type": "erp.invoice",
    "id": "INV-8821",
    "classification": "confidential"
  },
  "context": {
    "purpose": "reconcile_invoice",
    "run_id": "run_123"
  }
}
```

Response:

```json
{
  "decision": "allow_with_constraints",
  "policy_ids": [
    "policy://finance/invoice-readonly"
  ],
  "constraints": {
    "redact_fields": [
      "bank_account_number"
    ],
    "max_records": 5
  },
  "expires_in": 900
}
```

### 17.5 Simulate policy

```http
POST /v1/simulate
```

```json
{
  "agent_id": "agent://finance/invoice-reconciler",
  "actions": [
    "erp.invoice.read",
    "erp.invoice.delete",
    "slack.message.send"
  ],
  "resource": "erp.invoice:INV-8821"
}
```

Response:

```json
{
  "results": [
    {
      "action": "erp.invoice.read",
      "decision": "allow_with_constraints"
    },
    {
      "action": "erp.invoice.delete",
      "decision": "deny"
    },
    {
      "action": "slack.message.send",
      "decision": "require_approval"
    }
  ]
}
```

---

## 18. Audit event schema

Every decision and enforcement event should emit an audit record.

```json
{
  "event_id": "evt_01HZ",
  "event_type": "authorization.decision",
  "timestamp": "2026-05-25T08:35:00Z",
  "decision": "allow_with_constraints",
  "subject": {
    "agent_id": "agent://finance/invoice-reconciler",
    "instance_id": "agent-instance://cluster-a/ns/finance/pod/x"
  },
  "actor": {
    "type": "user",
    "id": "user:ishan@example.com"
  },
  "action": "erp.invoice.read",
  "resource": {
    "type": "erp.invoice",
    "id": "INV-8821",
    "classification": "confidential"
  },
  "policy_ids": [
    "policy://finance/invoice-readonly"
  ],
  "constraints": {
    "redact_fields": [
      "bank_account_number"
    ]
  },
  "run_id": "run_123",
  "trace_id": "trace_456"
}
```

Audit events should answer:

```text
Who acted?
Was it a human, service, or agent?
Which agent?
Which version?
Running where?
Acting for whom?
What action?
On what resource?
What policy allowed or denied it?
What constraints applied?
Was approval required?
Was approval granted?
What happened after enforcement?
```

---

## 19. Security requirements

### 19.1 Identity

OAP must support:

```text
agent identity
user identity
service identity
runtime identity
tool identity
resource identity
```

The framework should support pluggable identity providers:

```text
OIDC
OAuth
SPIFFE/SPIRE
Kubernetes service accounts
cloud workload identity
static dev identity for local testing
```

### 19.2 Credential handling

Agents must not receive broad standing credentials.

OAP should prefer:

```text
short-lived tokens
audience-bound tokens
resource-scoped tokens
delegated tokens
proof-of-possession where available
automatic expiry
revocation
```

### 19.3 Policy enforcement

PEPs must:

```text
fail closed by default
log every decision
not trust agent-supplied identity blindly
verify tokens or workload identity
enforce constraints, not just allow or deny
support local cache with short TTL
invalidate cache on revocation where possible
```

### 19.4 Prompt-injection containment

OAP should assume that:

```text
agent memory can be poisoned
retrieved content can be malicious
tool output can be malicious
user prompts can be malicious
```

Therefore:

```text
Natural language cannot modify policy.
Natural language cannot self-approve access.
Tool output cannot escalate privileges.
Retrieved documents cannot grant permissions.
Agent-generated code cannot bypass the PEP.
```

### 19.5 Runtime trust

Later versions should include runtime posture:

```text
image digest
binary signature
container identity
cluster identity
sandbox status
network zone
attestation result
dependency risk
```

---

## 20. Policy evaluation order

Recommended order:

```text
1. Validate request schema.
2. Authenticate subject identity.
3. Resolve agent registration.
4. Resolve actor identity.
5. Resolve delegation, if any.
6. Resolve resource metadata.
7. Apply global deny policies.
8. Apply resource owner policies.
9. Apply agent policies.
10. Apply role bindings.
11. Apply contextual conditions.
12. Compute constraints and obligations.
13. Return decision.
14. Emit audit event.
```

Principles:

```text
implicit deny
explicit deny wins
narrower scope wins for constraints
shortest expiry wins
highest audit requirement wins
approval requirement is sticky unless satisfied
```

---

## 21. Developer experience

### 21.1 Python example

```python
from open_agent_policy import PolicyClient

client = PolicyClient(
    agent_id="agent://finance/invoice-reconciler"
)

decision = client.authorize(
    actor="user:ishan@example.com",
    action="erp.invoice.read",
    resource={
        "type": "erp.invoice",
        "id": "INV-8821",
        "classification": "confidential",
    },
    context={
        "purpose": "reconcile_invoice",
        "run_id": "run_123",
    },
)

if decision.allowed:
    invoice = erp.get_invoice(
        "INV-8821",
        token=decision.token,
        constraints=decision.constraints,
    )
else:
    raise PermissionError(decision.reason)
```

### 21.2 Gateway mode

```text
Agent -> OAP Gateway -> API
```

The agent does not need to import the SDK.

The gateway intercepts calls, evaluates policy, injects scoped credentials, redacts responses if required, and logs the event.

### 21.3 MCP mode

```text
Agent MCP Client -> OAP MCP Proxy -> MCP Server -> Tool
```

OAP should sit between agent clients and MCP servers to enforce per-tool and per-resource policy.

---

## 22. CLI experience

Suggested binary name:

```text
oapctl
```

Example commands:

```bash
oapctl agent register -f examples/agents/invoice-reconciler.yaml
oapctl resource register -f examples/resources/invoices.yaml
oapctl policy apply -f policies/finance-invoice-readonly.yaml
oapctl authorize -f examples/requests/read-invoice.json
oapctl simulate --agent agent://finance/invoice-reconciler --resource erp.invoice:INV-8821
oapctl audit tail
```

---

## 23. Suggested repository structure

```text
open-agent-policy/
  README.md
  LICENSE
  CONTRIBUTING.md
  SECURITY.md
  CODE_OF_CONDUCT.md
  docs/
    prd.md
    concepts/
      agent-identity.md
      policy-model.md
      delegation.md
      enforcement.md
      audit.md
    spec/
      authorization-request.md
      authorization-decision.md
      policy-language.md
      audit-events.md
      agent-registry.md
      resource-registry.md
      tool-registry.md
    rfc/
      0001-agent-identity.md
      0002-policy-decision-api.md
      0003-mcp-enforcement.md
  schemas/
    agent.schema.json
    resource.schema.json
    tool.schema.json
    policy.schema.json
    authorization-request.schema.json
    authorization-decision.schema.json
    audit-event.schema.json
  oap-server/
  oap-cli/
  sdk/
    python/
    typescript/
    go/
  gateways/
    http/
    mcp/
    envoy/
  examples/
    invoice-agent/
    support-agent/
    deployment-agent/
    mcp-proxy/
  policies/
    examples/
```

---

## 24. Threat model

Open Agent Policy should explicitly defend against the following risks.

### 24.1 Over-permissioned agents

Agents should not accumulate broad roles such as:

```text
AgentAdmin
ProductionAdmin
DataLakeReadAll
CloudAccountOwner
```

### 24.2 Prompt injection

A malicious prompt, webpage, email, document, or tool response may instruct the agent to exfiltrate data or bypass policy.

OAP response:

```text
Enforce policy outside the agent.
Do not allow natural language to grant access.
Constrain or deny sensitive actions at the enforcement layer.
```

### 24.3 Confused deputy

An agent may be tricked into using its privileges for the wrong user or purpose.

OAP response:

```text
Require explicit actor, delegation, purpose, and resource match.
```

### 24.4 Credential theft

An agent runtime may leak credentials.

OAP response:

```text
Use short-lived, audience-bound, scoped credentials.
Avoid broad standing secrets.
```

### 24.5 Tool abuse

A safe-looking tool may perform dangerous downstream actions.

OAP response:

```text
Maintain a tool registry.
Map tools to actions and resource types.
Assign risk classifications.
Enforce downstream action policy.
```

### 24.6 Agent impersonation

An unregistered workload may claim to be a trusted agent.

OAP response:

```text
Verify runtime identity, signatures, workload identity, and registration binding.
```

### 24.7 Policy bypass

An agent may call a resource directly instead of through OAP.

OAP response:

```text
Use resource-side enforcement, scoped tokens, gateway mode, and network controls.
```

### 24.8 Audit gaps

An agent may perform actions that cannot be attributed.

OAP response:

```text
Emit mandatory audit events for decisions, grants, denials, approvals, and enforcement.
```

---

## 25. Success metrics

### 25.1 v0.1 metrics

```text
Time to register first agent: under 10 minutes
Time to write first policy: under 15 minutes
Every decision emits an audit event
Deny-by-default behavior works
Python SDK works
TypeScript SDK works
HTTP gateway works
Policy simulation works
```

### 25.2 Longer-term metrics

```text
Percentage of agent tool calls covered by OAP
Number of denied high-risk actions
Number of constrained actions
Number of active agents with owners
Number of orphaned agents
Mean time to revoke agent access
Policy drift detection rate
Audit completeness rate
Decision latency at p50, p95, and p99
```

---

## 26. Roadmap

### v0.1 - Local-first policy framework

```text
Agent registry
Resource registry
Tool registry
YAML policies
Authorize API
Audit log
Python SDK
TypeScript SDK
HTTP gateway
CLI simulation
```

### v0.2 - Delegation and token broker

```text
User delegation
Short-lived grants
OAuth/OIDC integration
Token exchange adapter
Scoped credential issuance
```

### v0.3 - MCP and tool governance

```text
MCP proxy
Tool registry
Per-tool policy
Per-resource policy
Tool risk classification
Tool call audit
```

### v0.4 - Enterprise controls

```text
Approval workflows
SIEM export
Policy bundles
OPA/Cedar/OpenFGA adapters
Admin UI
Multi-tenant support
```

### v0.5 - Runtime trust

```text
Workload identity
SPIFFE/SPIRE integration
Image digest verification
Runtime attestation hooks
Sandbox enforcement
```

### v1.0 - Stable spec

```text
Stable policy schema
Stable decision API
Stable audit schema
Conformance tests
Reference PEPs
Reference PDP
Security review
```

---

## 27. Initial RFCs

The first RFCs should be:

```text
RFC-0001: Agent Identity Model
RFC-0002: Authorization Request and Decision Model
RFC-0003: Policy Language
RFC-0004: Audit Event Schema
RFC-0005: Enforcement Point Contract
RFC-0006: Delegation and Grant Model
RFC-0007: MCP Enforcement Profile
```

The most important first spec is:

```text
RFC-0002: Authorization Request and Decision Model
```

Everything depends on normalizing this core question:

```text
Can this agent perform this action on this resource in this context?
```

---

## 28. Positioning

Open Agent Policy should not be positioned as only "RBAC for agents."

That is too narrow.

Recommended positioning:

> Open Agent Policy is an open-source, vendor-neutral authorization and governance framework for AI agents. It gives agents first-class identity, policy-driven least-privilege access, scoped delegation, runtime enforcement, approval gates, and auditable zero-trust controls across tools, APIs, data, SaaS systems, and infrastructure.

Short version:

> Zero-trust access control for AI agents.

---

## 29. Naming guidance

Project name:

```text
Open Agent Policy
```

Repo name:

```text
open-agent-policy
```

Short name:

```text
OAP
```

Suggested CLI:

```text
oapctl
```

Suggested server:

```text
oap-server
```

Suggested gateway:

```text
oap-gateway
```

Suggested Python package:

```text
open-agent-policy
```

Suggested Python import:

```python
import open_agent_policy
```

Suggested NPM package:

```text
@open-agent-policy/sdk
```

Suggested Go module:

```text
github.com/open-agent-policy/open-agent-policy
```

Note: avoid abbreviating Open Agent Policy as `OPA` because Open Policy Agent already commonly uses that abbreviation. Use `OAP` instead.

---

## 30. README opening draft

```markdown
# Open Agent Policy

Zero-trust access control for AI agents.

Open Agent Policy is an open-source, vendor-neutral framework for registering agents, defining authorization policies, issuing scoped grants, enforcing tool and resource access, and auditing every agent action.

It helps teams answer:

> Can this agent, acting for this user or system, perform this action on this resource, in this context, under these constraints?

Open Agent Policy is designed for agent runtimes, MCP servers, API gateways, SaaS integrations, internal tools, cloud resources, and enterprise AI platforms.
```


## Validation and Test Strategy

Open Agent Policy must be validated across three dimensions:

1. Problem validation:
   - Are agent teams over-permissioning agents today?
   - Do security teams need identity, audit, revocation, and policy for agents?
   - Do enterprises need vendor-neutral enforcement?

2. Use-case validation:
   - Support ticket agent
   - Finance invoice agent
   - Deployment agent
   - Coding/DevOps agent
   - MCP tool agent

3. Technical validation:
   - Policy conformance tests
   - Golden decision tests
   - SDK and gateway integration tests
   - Security abuse tests
   - Audit completeness tests
   - Developer-experience tests