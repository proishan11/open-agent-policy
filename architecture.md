# Open Agent Policy — Architecture

**Version:** v0.1 pre-build  
**Status:** Final architecture before implementation  
**Companion to:** open-agent-policy-prd.md, open-agent-policy-post-prd-notes.md

This document finalises the problem statement, vision, architecture, identity model, integration approach, end-to-end flows, and canonical schemas for Open Agent Policy.

---

## 1. Problem statement

Enterprises govern employees, services, and applications through identity, roles, permissions, audit, and revocation. AI agents do not fit into those existing models. An agent is not a user, not a service account, and not an application. It reasons, plans, calls tools, chains actions, uses delegated user authority, and makes runtime decisions.

Today, agents are invisible. Enterprises cannot answer:

- How many agents are running right now?
- Who owns each agent?
- What can each agent access?
- What did each agent do yesterday?
- Can I disable a specific agent in five minutes?
- Who approved this agent's level of access?

The root cause is not missing authentication. It is missing **agent-specific authorization**. No system today consistently answers:

> Can this specific agent, running in this specific environment, acting for this specific user or service, perform this specific action on this specific resource, using this specific tool, for this specific purpose, under these specific constraints, right now?

Without a common framework, each team invents its own access logic. This leads to agents running with broad service accounts, no separation between agent and user identity, no consistent policy, no audit trail, no fast revocation, and no approval gates.

Open Agent Policy exists to close that gap.

---

## 2. Vision

Open Agent Policy is an open-source, vendor-neutral framework that makes AI agents first-class security principals.

It provides:

- **Agent registration** — every agent has a known identity, owner, capabilities, and lifecycle
- **Policy-driven authorization** — every agent action is evaluated against explicit policy at runtime
- **Scoped access** — short-lived, constrained permissions instead of broad standing credentials
- **Delegation** — agents acting on behalf of users receive only the delegated authority they need
- **Enforcement outside the agent** — through gateways, proxies, SDKs, and resource-side checks
- **Audit** — structured events for every decision

### Design promise

> Add OAP without changing how you build agents.

### Security promise

> Every agent action is authorized, constrained, and auditable.

### Product question

> Can this agent, acting for this actor, perform this action on this resource, through this tool or channel, in this context?

---

## 3. Core principles

### 3.1 Agents must be registered
An unregistered agent is denied by default. Registration creates visibility, ownership, and governance.

### 3.2 Deny by default
If no policy explicitly allows the action, access is denied.

### 3.3 Explicit deny overrides allow
A deny rule always wins over an allow rule.

### 3.4 Capability is not permission
An agent may be technically capable of calling a tool but not authorized to call it in this context.

### 3.5 Runtime authorization, not just registration-time
Every sensitive action must be authorized at runtime using full context.

### 3.6 Enforcement happens outside the agent
The agent is not trusted to enforce its own policy.

### 3.7 Natural language cannot grant permissions
Prompts, retrieved documents, and tool outputs cannot modify policy or self-approve access.

### 3.8 Delegation must be explicit and scoped
Agents acting on behalf of users receive limited, time-bound authority — not full user access.

### 3.9 Audit is mandatory
Every authorization decision produces a structured, attributable audit event.

### 3.10 Adoption must be incremental
OAP must be adoptable in stages: observe → warn → enforce.

---

## 4. What OAP is and is not

**OAP is:**
- An agent registry (source of truth for which agents exist and who owns them)
- A policy engine for agent-specific authorization
- An enforcement framework (SDKs, gateways, proxies)
- An audit system (structured events for every decision)
- A credential broker (short-lived scoped grants)

**OAP is not:**
- A replacement for enterprise IdPs (Okta, Entra ID, Google stay)
- A replacement for OAuth/OIDC
- A secrets manager
- An LLM runtime or agent framework
- A SIEM
- A prompt-injection detector

---

## 5. System architecture

### 5.1 Library-first, server-optional

The policy evaluator is a library, not only a server. The same evaluation code runs:

- **Embedded** in the Python/TypeScript SDK (in-process, sub-millisecond)
- **Embedded** in the Go gateway and MCP proxy (in-process)
- **Behind the HTTP API** (remote, for clients that cannot embed)

This is critical for production. If every tool call requires a remote HTTP round-trip, agents slow down. Embedded evaluation with periodic policy bundle sync is the production model.

### 5.2 Control plane

The control plane manages registration, policy, grants, delegation, and audit.

```text
OAP Control Plane
├── Agent Registry        — source of truth for registered agents
├── Resource Registry     — resource types, owners, classifications
├── Tool Registry         — tools, actions, protocols, risk levels
├── Policy Store          — policies (file-backed, Git-synced, or DB-backed)
├── Grant Manager         — issues and tracks short-lived grants
├── Delegation Manager    — tracks actor-to-agent delegations
├── Identity Verification — verifies agent and actor credentials
├── Audit Sink            — emits structured events (pluggable: JSONL, OTLP, stdout)
├── Bundle Server         — serves policy bundles to embedded evaluators
└── HTTP API              — registration, authorization, simulation, audit queries
```

**API surface:**

| Endpoint | Purpose |
|---|---|
| POST /v1/agents | Register and manage agents |
| POST /v1/resources | Register resources |
| POST /v1/tools | Register tools |
| POST /v1/policies | Manage policies |
| POST /v1/authorize | Runtime authorization |
| POST /v1/simulate | Policy simulation (dry-run) |
| POST /v1/delegations | Manage actor-to-agent delegations |
| GET /v1/audit | Query audit events |
| GET /v1/bundles | Download policy bundles for embedded evaluators |

### 5.3 Data plane: enforcement points

Enforcement happens where agents take actions. All enforcement points share the same evaluator logic and produce the same audit events.

```text
Enforcement Points
├── Python SDK       — @protect decorator, OAPClient.authorize()
├── TypeScript SDK   — equivalent wrapper and client
├── HTTP Gateway     — reverse proxy, intercepts API calls
├── MCP Proxy        — intercepts MCP tools/list and tools/call
└── Framework MW     — LangChain middleware, CrewAI hooks, OpenAI tool wrappers
```

Every enforcement point does the same thing:

```text
1. Identify agent (from credentials or context)
2. Identify actor (from OIDC token in context)
3. Construct normalized authorization request
4. Evaluate against policy (embedded or remote)
5. Enforce decision (allow, deny, constrain)
6. Emit audit event
```

### 5.4 Deployment models

**Model 1: Local / single-process (development)**

```text
Agent process
  └── OAP SDK (embedded evaluator)
        ├── loads policies from local YAML files
        └── writes audit to local JSONL
```

No separate server. Best for development and prototyping.

**Model 2: Shared control plane (team / staging)**

```text
OAP Server (central)
  ├── registries, policy store, audit sink, bundle server

Agent A ──→ OAP SDK (embedded evaluator, syncs bundles from server)
Agent B ──→ OAP SDK (embedded evaluator, syncs bundles from server)
Agent C ──→ OAP Gateway ──→ API
```

Multiple agents, one OAP server. Evaluation is still local via synced bundles.

**Model 3: Enterprise (production)**

```text
OAP Server (HA, Postgres-backed, Git-synced policies)
  ├── OIDC verification via enterprise IdP
  ├── Agent identity via SPIFFE / k8s SA / cloud workload identity
  ├── Audit → OTLP → SIEM
  ├── Grants issued as signed JWTs
  └── Policies managed via GitOps + CI/CD

Agents authenticate via workload identity
Actors authenticated via enterprise IdP
Enforcement via gateway + credential brokering
```

All three models use the same evaluator, policy format, and schemas. Only storage and deployment differ.

### 5.5 Pluggable interfaces

These interfaces allow swapping implementations without changing the core:

```text
PolicyStore         — FileSystemPolicyStore, GitPolicyStore, PostgresPolicyStore
AuditSink           — JSONLAuditSink, OTLPAuditSink, StdoutAuditSink
RegistryStore       — FileRegistryStore, PostgresRegistryStore
IdentityVerifier    — DevVerifier, OIDCVerifier, KubernetesVerifier, SPIFFEVerifier
GrantIssuer         — JWTGrantIssuer (default), OpaqueGrantIssuer
PolicyEvaluator     — BuiltinEvaluator (default), OPAEvaluator, CedarEvaluator (future)
```

### 5.6 Policy engine architecture

OAP ships with a built-in YAML policy evaluator. This handles the standard policy format described in this document. It is sufficient for most use cases.

For enterprises that already run OPA, Cedar, or OpenFGA, OAP provides a pluggable PolicyEvaluator interface. OAP still owns the agent-native context enrichment (registry lookups, delegation verification, constraint merging, grant issuance, audit). Only the rule evaluation step is delegated.

```text
Authorization request arrives
  → OAP enriches context (registry lookups, actor verification)
  → OAP calls PolicyEvaluator.evaluate(enrichedRequest, policies)
  → Built-in evaluator (default) OR OPA/Cedar (pluggable)
  → OAP merges constraints, issues grant, emits audit
  → Decision returned
```

This means OAP does not compete with OPA. It makes OPA agent-aware.

---

## 6. Identity model

OAP manages three identity planes. It is the **authority** for agent identity. It delegates verification of actors and workloads to external systems.

### 6.1 Agent identity — OAP is the authority

Agents register with OAP. Registration creates a known, governed identity. This is the thing that does not exist today and is the core value of OAP.

**What registration captures:**

```yaml
agent_id: agent://finance/invoice-reconciler
owner: group:finance-platform
type: workflow_agent
version: 1.4.2
lifecycle: production
riskTier: medium
capabilities:
  - erp.invoice.read
  - erp.invoice.update_status
  - slack.message.send
runtimeBinding:
  kubernetes:
    namespace: finance
    serviceAccount: invoice-reconciler
```

**What registration produces:**

- Agent is known to OAP (queryable, auditable, revocable)
- Agent has an owner (accountability)
- OAP can verify the agent at runtime (via runtime binding)
- Agent is denied by default until policies are attached

**How registration happens:**

| Path | When | Example |
|---|---|---|
| CLI | Development | `oapctl agent register -f oap.yaml` |
| API | CI/CD pipeline | `POST /v1/agents` on deploy |
| GitOps | Merge to main | `oap.yaml` synced to OAP automatically |

**Agent runtime authentication:**

| Environment | Credential | Verification |
|---|---|---|
| Local dev | OAP client credentials (client_id + secret) | OAP validates directly |
| Kubernetes | ServiceAccount token | OAP calls TokenReview API, matches SA to registration |
| SPIFFE/SPIRE | SVID from Workload API | OAP validates SVID, matches SPIFFE ID to registration |
| Cloud (GCP/AWS/Azure) | Workload identity token | OAP validates with cloud provider |
| CI/CD | Short-lived OAP token | OAP validates token |

OAP does not invent a new identity protocol. It records a binding during registration and verifies that binding at runtime using the platform's native identity system.

### 6.2 Actor identity — external IdP provides, OAP verifies

When an agent acts on behalf of a user, OAP verifies the user's identity using the enterprise IdP. OAP does not manage users, passwords, or MFA.

**IdP configuration in OAP:**

```yaml
apiVersion: oap.dev/v1alpha1
kind: IdentityProvider
metadata:
  name: corporate-idp
spec:
  type: oidc
  issuer: https://company.okta.com
  jwksUri: https://company.okta.com/oauth2/v1/keys
  audience: oap-platform
  claimsMapping:
    userId: sub
    email: email
    groups: groups
```

At runtime, the agent passes the user's OIDC token. OAP validates signature, expiry, and issuer, then extracts actor identity for policy evaluation.

**Actor types:**

| Type | Example | Identification |
|---|---|---|
| Human user | user:ishan@example.com | OIDC id_token from enterprise IdP |
| Service | service:billing-job | Workload identity or OAuth client_credentials |
| Team | team:finance-ops | Mapped from user's group claims |
| Agent (self) | agent:self | Agent acts autonomously under own policy |
| Agent (upstream) | agent://support/ticket-assistant | Delegation chain verified |

### 6.3 Resource identity

Resources are registered in OAP as types with metadata. Individual instances are identified by adapters at call time.

**Resource model:**

```text
type:        dot-namespaced string (erp.invoice, support.ticket, k8s.pod)
id:          opaque string from the backend (INV-8821, TICKET-456)
attributes:  flat key-value (classification, owner, environment, region)
```

Policies match on type and attributes. Adapters populate the ID from tool arguments. Not every resource instance needs pre-registration — type registration plus inline attributes are sufficient.

### 6.4 How identities relate

```text
OAP (agent identity authority)
│
├── Agent identity verified via workload identity systems (external)
│     SPIFFE, k8s SA, cloud metadata, OAP client credentials
│
├── Actor identity verified via enterprise IdPs (external)
│     Okta, Entra ID, Google — standard OIDC
│
└── Resource metadata from OAP registry + adapter-supplied attributes

OAP owns: registration, policy, decisions, grants, audit
External systems own: user auth, workload certs, secrets
```

---

## 7. Authorization model

### 7.1 Authorization request (canonical shape)

Every protected agent action is normalized into this shape. Every enforcement point produces this same shape regardless of source framework. This is the core abstraction.

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
    "groups": ["finance-ops"],
    "auth_strength": "mfa"
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
    "protocol": "mcp"
  },
  "context": {
    "purpose": "reconcile_invoice",
    "run_id": "run_01HZ",
    "environment": "production"
  }
}
```

This request is the same whether the source is an OpenAI function tool, LangChain tool, CrewAI hook, MCP tools/call, HTTP API call, database query, or shell command. The adapter translates framework-specific context into this shape.

### 7.2 Authorization decision

```json
{
  "decision_id": "dec_01HZ",
  "decision": "allow_with_constraints",
  "policy_ids": ["policy://finance/invoice-readonly"],
  "grant": {
    "grant_id": "grant_01HZ",
    "token": "eyJ...",
    "expires_in_seconds": 900,
    "audience": "erp.example.com",
    "scope": ["erp.invoice.read"]
  },
  "constraints": {
    "max_records": 25,
    "redact_fields": ["bank_account_number", "tax_identifier"],
    "readonly": true
  },
  "obligations": {
    "audit": true,
    "log_full_request": true
  },
  "reason": "Allowed by policy finance-invoice-readonly. Constraints: readonly, redact payment fields, max 25 records. Grant expires in 15 minutes."
}
```

**Decision types:**

| Decision | Meaning |
|---|---|
| allow | Permitted, no additional constraints |
| allow_with_constraints | Permitted with constraints (redaction, limits, readonly, expiry) |
| deny | Not permitted |
| require_approval | Requires human or system approval before proceeding |
| require_delegation | Requires explicit delegation from the actor |
| require_step_up_auth | Actor must re-authenticate with stronger auth |

Every decision includes a human-readable `reason`. This is not optional.

### 7.3 Policy format (canonical)

This is the single canonical policy shape. All examples from the PRD and post-PRD notes are consolidated here.

```yaml
apiVersion: oap.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: finance-invoice-readonly
  namespace: finance
spec:
  subject:
    agent: agent://finance/invoice-reconciler

  rules:
    - effect: allow
      actions:
        - erp.invoice.read
        - erp.invoice.search
      resources:
        types:
          - erp.invoice
        classificationMax: confidential
      conditions:
        actorRequired: true
        environment: production
      constraints:
        readonly: true
        maxRecords: 25
        redact:
          - bank_account_number
          - tax_identifier
        expiresIn: 15m
      obligations:
        audit: true

    - effect: deny
      actions:
        - erp.invoice.delete
        - erp.invoice.update_payment
      reason: "Agents may not delete invoices or modify payment details."

    - effect: require_approval
      actions:
        - erp.invoice.update_status
      approval:
        approvers:
          - group:finance-leads
        minApprovals: 1
        expiresIn: 30m
```

**Schema rules:**

- `effect` is always explicit: allow, deny, require_approval, require_delegation
- `subject` at the policy level; all rules inherit it
- `conditions` are boolean prerequisites — rule does not match if they fail
- `constraints` narrow what the agent can do within the allowed action
- `reason` is human-readable — encouraged on every rule
- `obligations` are requirements that must be fulfilled (audit, logging)

**Subject matching options:**

```yaml
# Single agent
subject:
  agent: agent://finance/invoice-reconciler

# By type
subject:
  agentType: workflow_agent

# By namespace
subject:
  agentNamespace: finance

# All agents (for global policies)
subject:
  allAgents: true
```

### 7.4 Policy evaluation order

```text
1. Validate request schema
2. Verify agent identity (registered? active? credential matches binding?)
3. Verify actor identity (token valid? authenticated?)
4. Check capabilities (agent declared this action?)
5. Apply global deny policies (match → deny immediately)
6. Apply resource policies
7. Apply agent policies (match subject, evaluate rules)
8. Apply conditions
9. Merge constraints (strictest wins)
10. Determine decision
11. Issue grant if allowed
12. Emit audit event
```

**Invariants:**

```text
Unregistered agents are denied.
Revoked agents are denied.
Explicit deny always overrides allow.
No matching allow means deny (deny-by-default).
Expired grants are invalid.
Constraints cannot become weaker during evaluation.
Approval cannot authorize actions outside its scope.
Audit event is emitted for every decision.
```

---

## 8. End-to-end flows

### 8.1 Agent onboarding (one-time, before any traffic)

```text
Developer creates oap.yaml in agent repo
  │
  ▼
oapctl agent register -f oap.yaml  (or POST /v1/agents from CI/CD)
  │
  ▼
OAP validates: owner present? riskTier set? capabilities declared?
  │
  ├── If high/critical risk → flags for security review
  │
  ▼
OAP records agent in registry, binds runtime identity
  │
  ▼
Developer/security attaches policies
  oapctl policy apply -f policies/finance-invoice-readonly.yaml
  │
  ▼
Developer tests locally
  oapctl simulate -f examples/requests/read-invoice.json → allow_with_constraints
  oapctl simulate -f examples/requests/delete-invoice.json → deny
  │
  ▼
Agent deployed. Can now request runtime authorization.
```

Until policies are attached, the registered agent is denied for everything.

### 8.2 Runtime authorization (every protected tool call)

```text
Agent wants to call a tool (e.g., read invoice INV-8821)
  │
  ▼
Enforcement point intercepts
  (SDK @protect decorator, gateway, MCP proxy, or framework middleware)
  │
  ▼
Constructs normalized authorization request
  subject: agent identity (from process credentials)
  actor: user identity (from OIDC token in context)
  action: erp.invoice.read (from tool→action mapping)
  resource: erp.invoice / INV-8821 (from tool arguments)
  context: purpose, run_id, environment
  │
  ▼
Policy evaluation (embedded < 1ms, or remote < 10ms)
  verify agent → verify actor → check capabilities → evaluate rules → merge constraints
  │
  ├── deny → block tool call, return safe message to agent, emit audit event
  ├── require_approval → pause, request approval, retry when approved
  │
  ▼
allow or allow_with_constraints
  │
  ▼
Grant issued (signed JWT, scoped, time-limited)
  │
  ▼
Tool executes (with grant as credential, constraints applied)
  │
  ▼
Audit event emitted
  who (agent + actor) / what (action + resource) / decision / why (policy) / when
```

### 8.3 User-delegated action

```text
User authenticates via enterprise IdP (Okta, Entra ID)
  │
  ▼
User interacts with agent application
  Agent receives user's OIDC token
  │
  ▼
Agent needs to act on user's behalf
  │
  ▼
OAP creates scoped delegation:
  delegator: user:ishan@example.com
  delegate: agent://finance/invoice-reconciler
  scope: [erp.invoice.read] on erp.invoice:INV-8821
  expiresIn: 15m
  │
  ▼
Agent makes tool call → enforcement point includes delegation context
  │
  ▼
OAP evaluates:
  - Is the delegation valid? (not expired, not revoked)
  - Does the delegation cover this action + resource?
  - Does the user have the underlying permission?
  - Does agent policy allow this action with delegation?
  │
  ▼
Decision returned → tool executes within delegation scope
  │
  ▼
Delegation expires after 15 minutes
```

### 8.4 Approval-gated action

```text
Agent requests high-risk action (e.g., production deployment)
  │
  ▼
OAP evaluates → decision: require_approval
  │
  ▼
OAP creates approval request:
  action: deployment.execute
  resource: k8s.cluster/prod-payments
  agent: agent://deploy/deployer
  actor: user:ishan@example.com
  approvers: group:sre-leads
  expiresIn: 30m
  │
  ▼
Notification sent to approvers (webhook, Slack, email — pluggable)
  │
  ▼
Approver reviews: action, resource, agent, actor, risk, diff
  │
  ├── Denied → agent receives denial, audit event
  │
  ▼
Approved → OAP records approval with scope and expiry
  │
  ▼
Agent retries action → OAP evaluates with approval context → allow_with_constraints
  │
  ▼
Grant issued, tool executes, audit event emitted
  Approval scope: only this service, this version, this cluster, within 30 minutes
```

### 8.5 Revocation

```text
Security team runs:
  oapctl agent revoke agent://finance/invoice-reconciler --reason "incident"
  │
  ▼
OAP sets agent status to revoked
  │
  ▼
All active grants for this agent are invalidated
  │
  ▼
All enforcement points deny requests from this agent
  (embedded evaluators pick up revocation on next bundle sync)
  │
  ▼
Audit event records revocation: who revoked, why, when
  │
  ▼
Agent cannot authenticate or be authorized until re-enabled
```

---

## 9. Integration model

### 9.1 Design constraint: no new paradigm

The PRD's design promise is: **"Add OAP without changing how you build agents."**

This means:

- Developers keep their framework (LangChain, OpenAI Agents SDK, CrewAI, custom)
- Developers keep their tools and tool definitions
- Developers keep their deployment model
- OAP wraps the execution surface; it does not replace orchestration
- The integration should feel like adding middleware or a decorator, not refactoring the agent

### 9.2 Five integration modes

**Mode 1: Tool wrapper (simplest)**

```python
from oap import protect

@protect(
    action="crm.customer.read",
    resource=lambda args: {"type": "crm.customer", "id": args["customer_id"]}
)
def get_customer(customer_id: str):
    return crm.get_customer(customer_id)
```

Developer wraps individual tools. One decorator per tool. Works with any framework that exposes callable tools.

**Mode 2: Framework middleware**

```python
from oap.integrations.langchain import OAPMiddleware

agent = create_agent(
    model="...",
    tools=[read_ticket, update_ticket, send_email],
    middleware=[OAPMiddleware(agent_id="agent://support/ticket-assistant")]
)
```

Developer adds one middleware object. All tool calls are intercepted automatically. No per-tool wrapping needed. Works with frameworks that support middleware or tool-call hooks (LangChain, LangGraph).

**Mode 3: Framework hooks**

```python
from oap.integrations.crewai import install_oap

install_oap(agent_id="agent://research/market-analyst")
```

One-line installation. Uses the framework's built-in hook system (CrewAI before/after tool hooks). The hook converts framework-specific context into an OAP request.

**Mode 4: MCP proxy**

```bash
oap mcp proxy \
  --agent agent://support/ticket-assistant \
  --upstream mcp://zendesk-tools \
  --listen localhost:7777
```

Agent points to OAP proxy instead of the MCP server directly. OAP intercepts tools/list and tools/call, applies policy, and forwards allowed calls. No code changes to the agent.

**Mode 5: HTTP gateway**

```text
Agent changes API base URL:
  https://crm.internal/api  →  https://oap-gateway.internal/crm
```

OAP gateway intercepts HTTP requests, evaluates policy, injects scoped credentials, blocks denied requests, redacts responses, and audits. No SDK integration needed.

### 9.3 Enforcement tiers

Each mode provides a different level of bypass resistance. Enterprises should understand what each tier guarantees.

| Tier | Mechanism | Bypass resistance | Use case |
|---|---|---|---|
| Advisory | SDK check, agent can ignore | None — cooperative | Dev, observe mode |
| Wrapper | @protect decorator, hooks | Low — code can be changed | Low-risk tools, early adoption |
| Gateway | OAP proxy between agent and API | Medium — requires routing | Production APIs |
| Credential-gated | Agent has no direct creds; OAP mints per-grant tokens | High — can't auth without OAP | High-risk resources |
| Network-isolated | No network path except through OAP | Highest — infrastructure enforced | Regulated environments |

OAP ships Tiers 1-3 initially. Tier 4 (credential brokering via JWT grants) is designed into the architecture from day one and enabled when the grant manager is production-ready. Tier 5 is infrastructure-level and documented as a deployment guide.

### 9.4 Framework-specific integration targets

| Framework | Integration mode | Developer effort |
|---|---|---|
| OpenAI Agents SDK | Tool wrapper (`protect_tools(...)`) | Wrap tools list in one call |
| LangChain / LangGraph | Middleware (`OAPMiddleware(...)`) | Add one middleware to agent |
| CrewAI | Hook adapter (`install_oap(...)`) | One function call |
| MCP | Proxy (`oap mcp proxy`) | Change MCP server URL |
| Custom HTTP agents | Gateway | Change API base URL |
| Custom Python/TS agents | SDK (`OAPClient.authorize()`) | Add authorize call before tool |

### 9.5 Integration with existing enterprise systems

OAP integrates with, but does not replace, existing infrastructure:

| System | OAP's relationship |
|---|---|
| Enterprise IdP (Okta, Entra ID, Google) | OAP verifies actor OIDC tokens against IdP JWKS |
| Workload identity (SPIFFE, k8s SA, cloud) | OAP verifies agent runtime identity |
| Policy engines (OPA, Cedar, OpenFGA) | Pluggable backend for rule evaluation |
| Secret managers (Vault, cloud KMS) | OAP brokers scoped access; does not store secrets |
| SIEM (Splunk, Datadog, Elastic) | OAP emits structured audit events; SIEM consumes |
| CI/CD (GitHub Actions, ArgoCD) | Agent registration and policy deployment in pipelines |
| API gateways (Kong, Envoy) | OAP can run as an external authorization service |
| Service mesh (Istio, Linkerd) | OAP can integrate as an authorization extension |

---

## 10. Adoption path

### 10.1 Progressive adoption (no big bang)

OAP supports four stages. Teams move through them at their own pace.

**Stage 1: Observe**

```bash
oap run --observe
```

No blocking. OAP watches tool calls and produces an inventory: which agents exist, which tools they call, which resources they touch, potential risks.

**Stage 2: Recommend**

```bash
oap policy generate --from-traces
```

OAP generates starter policies from observed behavior. Human reviews before enabling.

**Stage 3: Warn**

OAP evaluates policies but does not block. Decisions include `would_deny`, `would_require_approval`. Teams see what would happen under enforcement.

**Stage 4: Enforce**

```bash
oap enforce agent://support/ticket-assistant
```

OAP blocks and constrains. Full enforcement.

### 10.2 Developer adoption experience (target: 15 minutes)

```bash
# 1. Install OAP
pip install open-agent-policy

# 2. Initialize in agent project
oapctl init --framework langchain

# 3. Discover tools automatically
oapctl discover

# 4. Register agent
oapctl agent register -f oap.yaml

# 5. Apply starter policy
oapctl policy apply -f policies/starter.yaml

# 6. Test
oapctl test

# 7. Run in observe mode
oap run --observe

# 8. Enforce when ready
oap enforce
```

### 10.3 Security team adoption experience

```bash
# Inventory
oapctl agents list
oapctl agents describe agent://support/ticket-assistant

# Audit
oapctl audit --agent agent://support/ticket-assistant --last 24h

# Explain a decision
oapctl explain --request req_123

# Access graph
oapctl access-graph agent://support/ticket-assistant

# Revoke
oapctl agent revoke agent://support/ticket-assistant --reason "incident"
```

---

## 11. Audit model

Every authorization decision produces a structured event:

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
  "policy_ids": ["policy://finance/invoice-readonly"],
  "constraints": {
    "redact_fields": ["bank_account_number"]
  },
  "grant_id": "grant_01HZ",
  "run_id": "run_01HZ",
  "trace_id": "trace_456",
  "reason": "Allowed by finance-invoice-readonly with redaction constraints."
}
```

Audit events answer:

- Which agent acted?
- Who was the actor?
- What action on what resource?
- What policy allowed or denied it?
- What constraints were applied?
- Was approval required and granted?
- When did it happen?

Audit sinks are pluggable: JSONL file (dev), stdout (containers), OTLP (production), webhook (custom).

---

## 12. Architectural decisions

These decisions are final for v0.

| Decision | Choice | Rationale |
|---|---|---|
| Evaluator architecture | Library-first, server wraps it | Sub-ms embedded evaluation; no remote dependency on critical path |
| Policy format | YAML, rules-array with explicit `effect` | Readable by devs and security in same PR review |
| Policy engine | Built-in YAML evaluator; pluggable interface for OPA/Cedar | Ship fast, don't compete with OPA |
| Resource model | type + opaque id + attributes bag | Avoids parsing ARNs/GCP paths; adapters populate |
| Server language | Go | Single binary, fast, fits infra ecosystem |
| SDK languages | Python first, TypeScript second | Python dominates agent frameworks today |
| Storage (v0) | File-backed YAML + SQLite for audit | Zero infrastructure for local dev |
| Storage (production) | Postgres + Git-synced policies | Standard enterprise stack |
| Grant format | Signed JWT | Verifiable by downstream services, no callback needed |
| Agent credentials (dev) | Client ID + secret from registration | Simple, works everywhere |
| Agent credentials (prod) | Workload identity binding (SPIFFE, k8s SA, cloud) | Platform-native, no shared secrets |
| Actor verification | OIDC JWT validation against IdP JWKS | Standard, no custom auth protocol |
| Fail mode | Per-policy configurable; default closed | Nuanced reliability vs. security tradeoff |
| Adoption model | Observe → warn → enforce | Reduces adoption risk |

---

## 13. Build phases

### Phase 0: Spec + schemas (week 1-2)

- JSON Schema for: authorization request, decision, agent, resource, tool, policy, audit event
- Canonical YAML policy format (locked, no ambiguity)
- 10 conformance test cases (input + policies → expected decision)
- Architecture decision records

### Phase 1: Core engine + CLI (week 2-4)

- Policy evaluator as Go library
- oap-server wrapping the library with HTTP API
- oapctl: simulate, test, explain, agent register, policy apply
- Agent registry, resource registry, tool registry (file-backed)
- Audit log (JSONL)
- All conformance tests passing
- First reference use case: finance invoice agent

### Phase 2: Python SDK + first adapter (week 4-6)

- open-agent-policy Python package
- @protect decorator
- OAPClient.authorize()
- LangChain middleware adapter
- Second reference use case: support ticket agent
- Embedded evaluation via local policy files

### Phase 3: MCP proxy + HTTP gateway (week 6-8)

- oap mcp proxy command
- oap gateway command (HTTP reverse proxy)
- JWT grant issuance from authorize API
- Observe mode for proxy and gateway
- Third reference use case: MCP tool agent

### Phase 4: Harden + production readiness (week 8-10)

- OIDC actor verification
- Kubernetes ServiceAccount agent verification
- Policy bundle sync (server → embedded evaluators)
- Security abuse tests (prompt injection, confused deputy, escalation, token replay)
- Fail-closed behavior tests
- oap dev one-command local demo
- docker compose reference environment
- Framework integration guides
- README, quickstart, architecture docs

### Post-v0 roadmap

- SPIFFE/SPIRE agent verification
- Cloud workload identity verification
- Delegation manager (full)
- Approval workflow engine
- OPA/Cedar policy backend adapters
- TypeScript SDK
- CrewAI hook adapter
- OpenAI Agents SDK adapter
- Admin UI
- GitOps policy sync
- OTLP audit export
- Multi-tenant namespace isolation
- Helm chart for Kubernetes deployment
