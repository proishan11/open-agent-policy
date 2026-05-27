# Open Agent Policy — Enterprise End-to-End Test Plan

> Every test in this plan runs against real infrastructure. No mocks.

---

## Test Infrastructure

### Required Services

| Service | Purpose | Setup |
|---|---|---|
| **OAP Server** | Policy decision point | `./bin/oap-server` with Postgres store |
| **PostgreSQL 16** | Agent/policy/audit storage | Docker or managed |
| **Redis 7** | Policy cache, rate limiting | Docker or managed |
| **Keycloak 24** | OIDC/SAML IDP (Tier 1 testing) | Docker |
| **Okta Developer** | OIDC IDP (SaaS) | Free dev tenant |
| **Azure AD / Entra ID** | OIDC IDP (SaaS) | Free Azure tenant |
| **Google Workspace** | OIDC IDP (SaaS) | Google Cloud project |
| **AWS Cognito** | OIDC IDP (cloud) | AWS account |
| **Auth0** | OIDC IDP (SaaS) | Free dev tenant |
| **OPA Server** | Policy backend testing | Docker |
| **Cedar Agent** | Policy backend testing | Docker or AWS Verified Permissions |
| **Mock APIs** | Ticketing, CRM, email | `mock_apis/server.py` on port 9100 |
| **Ollama** | Local LLM for agent testing | `ollama serve` + `llama3.2` |
| **Prometheus + Grafana** | Metrics verification | Docker |
| **Jaeger** | Trace verification | Docker |
| **Splunk HEC** | SIEM export testing | Docker (splunk/splunk) |

### docker-compose.test.yml

```yaml
# Spins up the full test infrastructure
services:
  postgres:     { image: postgres:16-alpine, ports: ["5432:5432"] }
  redis:        { image: redis:7-alpine, ports: ["6379:6379"] }
  keycloak:     { image: quay.io/keycloak/keycloak:24.0, ports: ["8180:8080"] }
  opa:          { image: openpolicyagent/opa:latest, ports: ["8181:8181"] }
  prometheus:   { image: prom/prometheus, ports: ["9090:9090"] }
  jaeger:       { image: jaegertracing/all-in-one, ports: ["16686:16686"] }
  oap-server:   { build: ., depends_on: [postgres, redis] }
  mock-apis:    { build: examples/enterprise-support-agent/mock_apis }
```

---

## TP-1: Core Engine — Policy Evaluation

### TP-1.1: Allow / Deny / Constrain / Require Approval

| # | Test | Steps | Expected |
|---|---|---|---|
| 1.1.1 | **Simple allow** | Register agent, apply policy with `effect: allow` for `tickets.read`. Send real `POST /v1/authorize` request. | `decision: allow`, audit event in Postgres |
| 1.1.2 | **Explicit deny** | Apply policy with `effect: deny` for `tickets.delete`. Agent calls `tickets.delete`. | `decision: deny`, reason contains policy text, audit logged |
| 1.1.3 | **Allow with constraints** | Policy allows `customers.read` with `redact_fields: [ssn, credit_card]`. Agent reads customer. | `decision: allow_with_constraints`, constraints in response |
| 1.1.4 | **Require approval** | Policy requires approval for `notifications.send_email` external. Agent sends external email. | `decision: require_approval`, approvers list returned |
| 1.1.5 | **Deny overrides allow** | Two policies: one allows `billing.read`, another denies `billing.*`. Agent calls `billing.read`. | `decision: deny` (deny wins) |
| 1.1.6 | **No matching policy** | Registered agent with no policies. Agent calls any action. | `decision: deny`, reason: "no matching policy" |
| 1.1.7 | **Constraint merging** | Two policies allow `tickets.read`: one with `max_records: 10`, another with `max_records: 5`. | Constraints merged: `max_records: 5` (strictest wins) |

### TP-1.2: Agent Lifecycle

| # | Test | Steps | Expected |
|---|---|---|---|
| 1.2.1 | **Unregistered agent** | Send authorize request for agent that doesn't exist. | `deny`, reason: "unregistered" |
| 1.2.2 | **Suspended agent** | Register agent, then `PATCH /v1/agents/{id}` state=suspended. Authorize. | `deny`, reason: "suspended" |
| 1.2.3 | **Revoked agent** | Register, revoke, authorize. | `deny`, reason: "revoked" |
| 1.2.4 | **Reactivate suspended** | Suspend, then set state=active. Authorize. | Previous allow policy applies again |
| 1.2.5 | **Revoke is permanent** | Revoke, then try to set state=active. | Reject or still deny (revocation is final) |

### TP-1.3: Delegation

| # | Test | Steps | Expected |
|---|---|---|---|
| 1.3.1 | **Delegated action in scope** | Policy requires delegation. Request with `delegation_scope: [tickets.read]`, action=`tickets.read`. | `allow` |
| 1.3.2 | **Delegated action out of scope** | Same policy, request with `delegation_scope: [tickets.read]`, action=`tickets.delete`. | `deny`, reason: "outside delegation scope" |
| 1.3.3 | **No delegation when required** | Policy has `delegationRequired: true`. Request has no delegation context. | `deny` |

---

## TP-2: Identity Providers — Real OIDC/SAML

### TP-2.1: Keycloak (Docker)

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.1.1 | **OIDC token validation** | Create Keycloak realm + client. Get real access token via password grant. Send to OAP with `Authorization: Bearer <token>`. | Actor identity extracted (sub, email, groups) |
| 2.1.2 | **Expired token** | Wait for token expiry (set short TTL). Send expired token. | Reject: "token expired" |
| 2.1.3 | **Wrong audience** | Get token for different client. Send to OAP configured for another audience. | Reject: "invalid audience" |
| 2.1.4 | **JWKS rotation** | Rotate signing keys in Keycloak. Issue new token with new key. | OAP auto-discovers new JWKS, validates successfully |
| 2.1.5 | **Client roles → OAP groups** | Assign client role `ticket-admin` in Keycloak. Token should map to OAP actor groups. | Actor.Groups contains "ticket-admin" |
| 2.1.6 | **Realm roles** | Assign realm role. Verify claim mapping. | Mapped to actor identity |
| 2.1.7 | **SAML assertion** | Configure SAML client in Keycloak. Get SAML response. Validate in OAP. | Actor identity extracted from SAML attributes |
| 2.1.8 | **Token revocation** | Revoke token in Keycloak (logout endpoint). Send revoked token. | Reject (if introspection enabled) or still valid until expiry |

### TP-2.2: Okta (SaaS)

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.2.1 | **OIDC validation** | Create Okta app. Get token via authorization code flow. Validate in OAP. | Actor identity extracted |
| 2.2.2 | **Custom authorization server** | Configure custom auth server in Okta. Use custom scopes + claims. | Custom claims available in OAP actor |
| 2.2.3 | **Group claims** | Add user to Okta group. Configure group claim. Verify in OAP. | Actor.Groups populated |
| 2.2.4 | **MFA context** | User authenticates with MFA. Check `auth_strength` in actor. | `auth_strength: mfa` |

### TP-2.3: Azure AD / Entra ID (SaaS)

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.3.1 | **Single-tenant validation** | Register app in Azure AD. Get v2.0 token. Validate. | Actor identity extracted |
| 2.3.2 | **Multi-tenant** | Configure OAP for multi-tenant (`issuer: https://login.microsoftonline.com/common`). Token from any tenant. | Accepted if tenant in allowlist |
| 2.3.3 | **App roles** | Assign app role in Azure. Verify role claim mapping. | Actor.Roles populated |
| 2.3.4 | **Group claims** | User in Azure AD group. `groups` claim present. | Actor.Groups populated |
| 2.3.5 | **Conditional access** | Set conditional access policy in Azure. Token includes `acrs` claim. | Auth strength reflects conditional access |

### TP-2.4: Google Workspace (SaaS)

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.4.1 | **OIDC validation** | Get Google ID token. Validate in OAP. | Actor identity extracted |
| 2.4.2 | **Hosted domain** | Configure OAP to require `hd: company.com`. Token from `company.com` user. | Accepted |
| 2.4.3 | **Wrong hosted domain** | Token from `@gmail.com` user when `hd: company.com` required. | Rejected |
| 2.4.4 | **Service account JWT** | Create GCP service account. Generate self-signed JWT. Validate. | Agent identity extracted |

### TP-2.5: AWS Cognito (Cloud)

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.5.1 | **User pool token** | Create Cognito user pool. Get token. Validate JWKS from Cognito endpoint. | Actor identity extracted |
| 2.5.2 | **Custom scopes** | Configure custom scopes in resource server. Verify scope claim. | Scopes available in OAP context |
| 2.5.3 | **Identity pool federation** | Federate Cognito user pool with identity pool. Get temporary credentials. | Agent identity mapped |

### TP-2.6: Auth0 (SaaS)

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.6.1 | **OIDC validation** | Create Auth0 app. Get token. Validate. | Actor identity extracted |
| 2.6.2 | **Custom domain** | Configure custom domain in Auth0. Token from custom issuer. | Accepted |
| 2.6.3 | **Organizations** | Create Auth0 organization. Token includes `org_id`. | Tenant/org mapped in OAP |
| 2.6.4 | **API audience** | Configure API in Auth0. Token with API audience. | Audience validated |

### TP-2.7: Kubernetes ServiceAccount

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.7.1 | **Bound SA token** | Deploy agent pod in K8s. Mount SA token. Send to OAP. | Agent identity: `agent://namespace/service-account-name` |
| 2.7.2 | **TokenReview validation** | OAP calls K8s TokenReview API. Verify real validation. | Token validated against K8s API server |
| 2.7.3 | **Wrong namespace** | Token from namespace `dev`, policy scoped to `prod`. | Deny: namespace mismatch |
| 2.7.4 | **Expired bound token** | Wait for projected volume token expiry. Send expired. | Reject |

### TP-2.8: SPIFFE / SPIRE

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.8.1 | **SVID validation** | Agent presents X.509 SVID via mTLS. OAP extracts SPIFFE ID. | Agent identity from SPIFFE URI |
| 2.8.2 | **Trust domain mismatch** | SVID from wrong trust domain. | Reject |

---

## TP-3: Storage Backends

### TP-3.1: PostgreSQL

| # | Test | Steps | Expected |
|---|---|---|---|
| 3.1.1 | **Agent CRUD** | Register agent via API. Read back. Update. Delete. | All ops succeed, data persists across OAP restart |
| 3.1.2 | **Policy CRUD** | Create/read/update/delete policy. | Persisted in Postgres |
| 3.1.3 | **Audit persistence** | Make 100 authorization requests. Query audit table. | All 100 events in Postgres with correct data |
| 3.1.4 | **Concurrent writes** | 10 goroutines register agents simultaneously. | No data corruption, all agents created |
| 3.1.5 | **Schema migration** | Start OAP with empty database. | Migrations run automatically, schema created |
| 3.1.6 | **Migration upgrade** | Run v1 schema, upgrade to v2. | Data preserved, new columns added |
| 3.1.7 | **Full-text search** | 50 policies in DB. Search by keyword. | Correct policies returned |
| 3.1.8 | **Connection pool exhaustion** | Set pool to 5 connections. Send 20 concurrent requests. | Requests queue, none fail (pool manages backpressure) |
| 3.1.9 | **Postgres down** | Stop Postgres while OAP is running. Send authorize request. | Fail-closed: deny (or use cached data) |
| 3.1.10 | **Postgres recovery** | Restart Postgres after outage. Next request. | Reconnects automatically, normal operation |

### TP-3.2: Redis Cache

| # | Test | Steps | Expected |
|---|---|---|---|
| 3.2.1 | **Cache hit** | Read agent. Read again. | Second read served from Redis (check Redis MONITOR) |
| 3.2.2 | **Cache invalidation** | Update agent via API. Read again. | Fresh data, not stale cache |
| 3.2.3 | **TTL expiry** | Read agent. Wait for TTL. Read again. | Re-fetched from Postgres after TTL |
| 3.2.4 | **Redis down** | Stop Redis. Send authorize. | Falls through to Postgres, no error to client |
| 3.2.5 | **Redis recovery** | Restart Redis. Next request. | Cache repopulated transparently |
| 3.2.6 | **Cache stampede** | Stop Redis, start Redis, 100 concurrent reads. | Only 1 Postgres query per key (singleflight) |

### TP-3.3: Git Policy Store

| # | Test | Steps | Expected |
|---|---|---|---|
| 3.3.1 | **Initial clone** | Configure Git store with policy repo URL. Start OAP. | Policies loaded from repo |
| 3.3.2 | **Webhook sync** | Push policy change to Git. Trigger webhook. | OAP picks up new policy within seconds |
| 3.3.3 | **Polling sync** | Push policy change. Wait for poll interval (30s). | Policy updated |
| 3.3.4 | **Branch environments** | `main` branch → prod, `staging` branch → staging. Switch branch config. | Correct policies for each environment |
| 3.3.5 | **Invalid policy in Git** | Push malformed YAML to repo. | OAP rejects bad policy, keeps previous valid set |
| 3.3.6 | **Git repo unavailable** | Make repo unreachable. | OAP continues with last-known policies |

---

## TP-4: Policy Backends — OPA and Cedar

### TP-4.1: OPA (Real Server)

| # | Test | Steps | Expected |
|---|---|---|---|
| 4.1.1 | **Simple Rego allow** | Deploy OPA with Rego policy that allows `tickets.read`. Configure OAP to use OPA backend. Agent calls `tickets.read`. | OPA evaluates, OAP returns allow with agent lifecycle check |
| 4.1.2 | **Rego deny** | Rego policy denies `tickets.delete`. | OAP returns deny from OPA |
| 4.1.3 | **Rego with constraints** | Rego returns `constraints: {max_records: 10}`. | OAP passes constraints through to decision |
| 4.1.4 | **OPA + OAP lifecycle** | Agent suspended in OAP. Rego would allow. | OAP denies (lifecycle overrides OPA) |
| 4.1.5 | **OPA server restart** | Restart OPA mid-request. | Fail-closed: deny, then recover on next request |
| 4.1.6 | **OPA latency** | Add 500ms delay in OPA response. | OAP decision includes OPA latency in audit event |
| 4.1.7 | **OPA fail-open** | Configure fail-open. Kill OPA. | Falls back to builtin evaluator |
| 4.1.8 | **Rego accesses agent metadata** | Rego policy checks `input.agent.spec.riskTier == "high"`. | Risk tier from OAP available in Rego input |
| 4.1.9 | **Policy bundle push** | Push new Rego bundle to OPA. | New policy takes effect on next evaluation |

### TP-4.2: Cedar (Real Server or AWS Verified Permissions)

| # | Test | Steps | Expected |
|---|---|---|---|
| 4.2.1 | **Cedar permit** | Cedar policy: `permit(principal == OAP::Agent::"agent://support/agent", action == OAP::Action::"tickets.read", resource)`. | OAP returns allow |
| 4.2.2 | **Cedar forbid** | Cedar forbid policy for `tickets.delete`. | OAP returns deny |
| 4.2.3 | **Cedar with context** | Cedar policy checks `context.agent_risk_tier == "medium"`. | OAP passes agent context, Cedar evaluates |
| 4.2.4 | **Cedar + OAP lifecycle** | Agent revoked in OAP. Cedar would permit. | OAP denies (lifecycle overrides Cedar) |
| 4.2.5 | **AWS Verified Permissions** | Configure CedarBackend with PolicyStoreID pointing to real AVP. | Decision from AWS service |
| 4.2.6 | **Cedar fail-closed** | Kill Cedar service. | Deny with reason "cedar: unreachable" |

---

## TP-5: Framework Integrations — Real Agents

### TP-5.1: LangChain / LangGraph (Real LLM)

| # | Test | Steps | Expected |
|---|---|---|---|
| 5.1.1 | **ReAct agent allow** | Run real LangChain agent with Ollama. Ask "list open tickets". | LLM calls `list_tickets`, OAP allows, tickets returned |
| 5.1.2 | **ReAct agent deny** | Ask "delete ticket TKT-1003". | LLM calls `delete_ticket`, OAP denies, agent explains to user |
| 5.1.3 | **Constraint enforcement** | Ask "look up customer CUST-501". | OAP allows with `redact_fields`, customer SSN/CC/bank redacted in response |
| 5.1.4 | **Multi-tool chain** | Ask "investigate TKT-1001 and get customer info". | LLM calls `read_ticket` then `read_customer`, both authorized separately |
| 5.1.5 | **Agent handles denial gracefully** | Ask "delete all tickets". LLM tries `delete_ticket` multiple times. | Each call denied, agent suggests alternatives |
| 5.1.6 | **LangGraph with state** | Multi-step LangGraph workflow. Each step goes through OAP. | All intermediate tool calls authorized |

### TP-5.2: OpenAI Agents SDK

| # | Test | Steps | Expected |
|---|---|---|---|
| 5.2.1 | **Function call protection** | OpenAI agent with tools wrapped by OAP. Call allowed tool. | Authorized and executed |
| 5.2.2 | **Function call denial** | Agent tries to call denied tool. | Function returns denial message, agent handles it |
| 5.2.3 | **Streaming** | Agent streams response while making tool calls. | Authorization happens before each tool call, stream not interrupted |

### TP-5.3: CrewAI

| # | Test | Steps | Expected |
|---|---|---|---|
| 5.3.1 | **Crew with OAP hooks** | Create crew with 2 agents, each with different policies. | Each agent's tool calls authorized per their own policy |
| 5.3.2 | **Cross-agent isolation** | Agent A tries to use Agent B's tools. | Denied — different agent ID, different policy |
| 5.3.3 | **Crew delegation** | CrewAI agent delegates task to another agent. | Delegation scope enforced by OAP |

### TP-5.4: AutoGen

| # | Test | Steps | Expected |
|---|---|---|---|
| 5.4.1 | **Conversation guard** | Two AutoGen agents in conversation. Function calls go through OAP. | Each function call authorized |
| 5.4.2 | **Group chat** | Multi-agent group chat. Each agent has different permissions. | Correct policy applied per agent |

### TP-5.5: MCP Proxy

| # | Test | Steps | Expected |
|---|---|---|---|
| 5.5.1 | **tools/list filtered** | MCP client connects through OAP proxy. Upstream has 10 tools. Agent policy allows 5. | `tools/list` returns only 5 tools |
| 5.5.2 | **tools/call allowed** | Call allowed tool through proxy. | Proxied to upstream, result returned |
| 5.5.3 | **tools/call denied** | Call denied tool through proxy. | JSON-RPC error, not proxied to upstream |
| 5.5.4 | **Observe mode** | Set proxy to observe mode. Call denied tool. | Allowed through but audit event has `observed: true, would_deny: true` |
| 5.5.5 | **Upstream down** | Kill upstream MCP server. Call tool. | Proxy returns error, audit event logged |

### TP-5.6: HTTP Gateway

| # | Test | Steps | Expected |
|---|---|---|---|
| 5.6.1 | **Route mapping** | Configure gateway: `GET /api/tickets → tickets.read`. Send GET request. | Authorized by OAP, proxied to upstream |
| 5.6.2 | **Denied route** | Configure deny rule for `DELETE /api/tickets/*`. Send DELETE. | 403 with OAP decision in response body |
| 5.6.3 | **Agent ID header** | Send request with `X-OAP-Agent-ID: agent://other/agent`. | Different agent's policy evaluated |
| 5.6.4 | **Observe mode** | Gateway in observe mode. Denied request. | Proxied but audit logged with `would_deny` |

---

## TP-6: Observability

### TP-6.1: OpenTelemetry

| # | Test | Steps | Expected |
|---|---|---|---|
| 6.1.1 | **Traces in Jaeger** | Make 10 authorization requests. Open Jaeger UI. | 10 traces visible with correct agent/action/decision attributes |
| 6.1.2 | **Trace propagation** | Agent SDK → OAP → upstream API. Check Jaeger. | Single trace spans all three services |
| 6.1.3 | **Metrics in Prometheus** | Make requests. Query Prometheus. | `oap_decisions_total{decision="allow"}` counter increments |
| 6.1.4 | **Latency histogram** | Make 100 requests. Check `oap_decision_duration_seconds`. | Histogram with p50/p95/p99 buckets |
| 6.1.5 | **Deny rate alert** | Make 50 deny requests rapidly. Check Prometheus alert. | Alert fires when deny rate > threshold |

### TP-6.2: Grafana Dashboard

| # | Test | Steps | Expected |
|---|---|---|---|
| 6.2.1 | **Dashboard loads** | Import OAP Grafana dashboard. | All panels render with data |
| 6.2.2 | **Per-agent breakdown** | Multiple agents making requests. Check dashboard. | Breakdown by agent ID visible |
| 6.2.3 | **Decision timeline** | Allow/deny requests over time. | Timeline shows decision distribution |

### TP-6.3: SIEM Export

| # | Test | Steps | Expected |
|---|---|---|---|
| 6.3.1 | **Splunk HEC** | Configure Splunk HEC sink. Make requests. Check Splunk. | Events searchable in Splunk with OAP fields |
| 6.3.2 | **Elastic** | Configure Elastic sink. Make requests. Check Kibana. | Events indexed and searchable |
| 6.3.3 | **CloudWatch** | Configure CloudWatch sink. Make requests. Check CloudWatch Logs. | Log group contains OAP events |

### TP-6.4: Audit Search API

| # | Test | Steps | Expected |
|---|---|---|---|
| 6.4.1 | **Search by agent** | `GET /v1/audit?agent=agent://support/agent` | Only events for that agent |
| 6.4.2 | **Search by decision** | `GET /v1/audit?decision=deny` | Only deny events |
| 6.4.3 | **Search by time range** | `GET /v1/audit?from=2026-05-27T00:00:00Z&to=2026-05-27T23:59:59Z` | Events within range |
| 6.4.4 | **Pagination** | 500 events. `GET /v1/audit?limit=50&offset=100` | Correct page |

---

## TP-7: Multi-Tenancy & RBAC

### TP-7.1: Tenant Isolation

| # | Test | Steps | Expected |
|---|---|---|---|
| 7.1.1 | **Namespace isolation** | Register agents in `finance/` and `support/` namespaces. | Each namespace sees only its own agents |
| 7.1.2 | **Cross-namespace deny** | Agent in `finance/` tries to access `support/` policy. | Denied |
| 7.1.3 | **Wildcard namespace** | Policy with `namespace: *`. | Applies to all namespaces |
| 7.1.4 | **Header-based tenancy** | Send `X-OAP-Tenant: acme-corp`. | Scoped to tenant |

### TP-7.2: RBAC for OAP Admin

| # | Test | Steps | Expected |
|---|---|---|---|
| 7.2.1 | **Admin registers agent** | Admin token → `POST /v1/agents`. | Success |
| 7.2.2 | **Non-admin blocked** | Viewer token → `POST /v1/agents`. | 403 |
| 7.2.3 | **Namespace-scoped admin** | Admin scoped to `finance/` → register agent in `support/`. | 403 |
| 7.2.4 | **Policy apply permission** | Only `policy-admin` role can `POST /v1/policies`. | Other roles denied |

### TP-7.3: Policy Management

| # | Test | Steps | Expected |
|---|---|---|---|
| 7.3.1 | **Policy versioning** | Apply policy v1, then v2. Query version history. | Both versions in history, v2 active |
| 7.3.2 | **Rollback** | Rollback to v1. Authorize. | v1 rules applied |
| 7.3.3 | **Dry-run** | Submit policy change with `?dry-run=true`. | Shows what would change, no actual change |
| 7.3.4 | **Policy diff** | `GET /v1/policies/{id}/diff?from=v1&to=v2` | Diff of rules |
| 7.3.5 | **Effective date** | Policy with `effectiveFrom: 2026-06-01`. Before that date. | Policy not active yet |
| 7.3.6 | **Rate limiting** | Agent makes 100 requests/sec. Rate limit set to 50/sec. | Requests beyond limit get `429` |

---

## TP-8: Security — Real Attack Scenarios

### TP-8.1: Token Attacks

| # | Test | Steps | Expected |
|---|---|---|---|
| 8.1.1 | **Stolen token replay** | Copy a valid JWT. Use it from a different IP/client. | Accepted (JWTs are bearer tokens) — audit shows different source |
| 8.1.2 | **Forged token** | Create JWT with wrong signing key. | Rejected: signature verification failed |
| 8.1.3 | **Algorithm confusion** | Send JWT with `alg: none`. | Rejected |
| 8.1.4 | **Token from wrong IDP** | Get token from Keycloak, send to OAP configured for Okta. | Rejected: issuer mismatch |
| 8.1.5 | **Expired token** | Send token that expired 5 minutes ago. | Rejected |
| 8.1.6 | **Future token** | Send token with `nbf` 10 minutes in the future. | Rejected (outside clock skew tolerance) |

### TP-8.2: Prompt Injection

| # | Test | Steps | Expected |
|---|---|---|---|
| 8.2.1 | **Injection in action name** | Agent sends action: `tickets.read; DROP TABLE policies`. | Denied: invalid action name |
| 8.2.2 | **Injection in agent ID** | Agent ID: `agent://../../admin/super`. | Denied: invalid agent ID format |
| 8.2.3 | **Unicode smuggling** | Action name with zero-width characters: `tickets.re​ad`. | Denied or normalized before evaluation |
| 8.2.4 | **Path traversal in resource** | Resource ID: `../../../etc/passwd`. | Does not escape resource scope |

### TP-8.3: Privilege Escalation

| # | Test | Steps | Expected |
|---|---|---|---|
| 8.3.1 | **Agent self-registration** | Agent tries `POST /v1/agents` to register itself with elevated permissions. | Requires admin credentials, not agent credentials |
| 8.3.2 | **Policy self-modification** | Agent tries `POST /v1/policies` to grant itself more access. | Requires admin credentials |
| 8.3.3 | **Namespace escape** | Agent in `support/` crafts request for `admin/` namespace. | Denied by namespace scoping |
| 8.3.4 | **Risk tier downgrade** | Agent tries to change its own risk tier from `high` to `low`. | Only admin can modify agent spec |

### TP-8.4: Confused Deputy

| # | Test | Steps | Expected |
|---|---|---|---|
| 8.4.1 | **Agent A impersonates B** | Agent A sends `agent_id: agent://ns/agent-b`. | Denied: credential doesn't match claimed agent ID |
| 8.4.2 | **Proxy spoofing** | MCP client sends fake `X-OAP-Agent-ID` header. | Only honored if proxy is in trusted sources list |
| 8.4.3 | **Actor spoofing** | Request claims `actor.id: ceo@company.com` without valid token. | Rejected: actor identity must come from verified IDP token |

### TP-8.5: Denial of Service

| # | Test | Steps | Expected |
|---|---|---|---|
| 8.5.1 | **Request flood** | 10,000 requests/sec to `/v1/authorize`. | Rate limited, system stays responsive |
| 8.5.2 | **Large policy payload** | Submit policy with 10,000 rules. | Rejected or handled without OOM |
| 8.5.3 | **Slow IDP** | IDP takes 30s to respond. | Timeout, fail-closed, request not blocked forever |
| 8.5.4 | **Connection exhaustion** | Open 1000 TCP connections without sending data. | Connections timed out, server stays healthy |

---

## TP-9: Deployment & Operations

### TP-9.1: Docker

| # | Test | Steps | Expected |
|---|---|---|---|
| 9.1.1 | **Docker build** | `docker build -t oap-server .` | Image builds under 60s, <100MB |
| 9.1.2 | **Docker compose up** | `docker compose -f docker-compose.test.yml up` | All services healthy within 60s |
| 9.1.3 | **Health check** | `GET /health` on oap-server container. | `200 OK` with component status |
| 9.1.4 | **Graceful shutdown** | `docker stop oap-server`. | In-flight requests complete, connections drain |

### TP-9.2: Kubernetes / Helm

| # | Test | Steps | Expected |
|---|---|---|---|
| 9.2.1 | **Helm install** | `helm install oap deploy/helm/oap/` in kind cluster. | Pod running, service reachable |
| 9.2.2 | **Liveness probe** | Kill OAP process in pod. | K8s restarts pod via liveness probe |
| 9.2.3 | **Readiness probe** | OAP starting up (Postgres not connected yet). | Pod not in ready state, no traffic routed |
| 9.2.4 | **Rolling update** | `helm upgrade` with new image. | Zero-downtime update |
| 9.2.5 | **HPA scaling** | Load test, HPA scales from 1 → 3 pods. | All pods serve traffic, decisions consistent |
| 9.2.6 | **PVC for audit** | Check audit PVC has data. | Audit events persisted on disk |
| 9.2.7 | **Service account** | OAP pod uses dedicated SA. | Least-privilege RBAC in K8s |

### TP-9.3: Resilience

| # | Test | Steps | Expected |
|---|---|---|---|
| 9.3.1 | **Postgres failover** | Primary Postgres dies. Standby promotes. | OAP reconnects to new primary |
| 9.3.2 | **Redis failover** | Redis sentinel failover. | OAP reconnects, cache rebuilds |
| 9.3.3 | **IDP outage** | Keycloak goes down. | Cached JWKS used for validation, new tokens can't be issued but existing ones still validate |
| 9.3.4 | **OPA outage** | OPA backend unreachable. | Fail-closed (deny) or fail-open (builtin fallback) |
| 9.3.5 | **Network partition** | OAP can't reach Postgres but can reach Redis. | Serve from cache, deny writes |
| 9.3.6 | **Full outage recovery** | Kill everything. Bring back in order: Postgres → Redis → OAP. | System recovers, all data intact |

---

## TP-10: Performance

### TP-10.1: Throughput

| # | Test | Tool | Target | Duration |
|---|---|---|---|---|
| 10.1.1 | **Authorize (builtin)** | k6 / vegeta | 10,000 decisions/sec | 5 min sustained |
| 10.1.2 | **Authorize (OPA)** | k6 / vegeta | 5,000 decisions/sec | 5 min sustained |
| 10.1.3 | **Authorize (Cedar)** | k6 / vegeta | 5,000 decisions/sec | 5 min sustained |
| 10.1.4 | **MCP proxy throughput** | k6 | 2,000 tool calls/sec | 5 min |
| 10.1.5 | **HTTP gateway throughput** | k6 | 5,000 req/sec | 5 min |

### TP-10.2: Latency

| # | Test | Target |
|---|---|---|
| 10.2.1 | **Authorize p50** | < 2ms |
| 10.2.2 | **Authorize p95** | < 10ms |
| 10.2.3 | **Authorize p99** | < 50ms |
| 10.2.4 | **Cold start (no cache)** | < 500ms for first request |
| 10.2.5 | **With OPA backend p95** | < 25ms |

### TP-10.3: Scale

| # | Test | Steps | Target |
|---|---|---|---|
| 10.3.1 | **1,000 agents** | Register 1,000 agents. Authorize random agents. | No degradation vs 10 agents |
| 10.3.2 | **10,000 policies** | Load 10,000 policies. Authorize. | p95 < 20ms |
| 10.3.3 | **1M audit events** | Write 1M events. Query recent. | Query returns in < 100ms |
| 10.3.4 | **100 concurrent agents** | 100 different agents authorize simultaneously. | No lock contention, all served |

---

## TP-11: End-to-End Scenarios

### TP-11.1: Full-Stack Support Agent

| # | Scenario | What It Tests |
|---|---|---|
| 11.1.1 | **User logs in via Keycloak → Chat UI → LangChain agent reads tickets** | OIDC → actor identity → OAP authorize → tool execution → audit |
| 11.1.2 | **Agent reads customer with SSN redaction** | Constraint enforcement end-to-end |
| 11.1.3 | **Agent escalates P1, sends internal email** | Conditional allow + notification |
| 11.1.4 | **Agent tries delete → denied → suggests archive** | Deny handling, LLM graceful degradation |
| 11.1.5 | **Admin suspends agent mid-conversation** | Real-time lifecycle enforcement |
| 11.1.6 | **Admin updates policy to add new permission, agent uses it immediately** | Live policy reload |
| 11.1.7 | **Entire flow traced in Jaeger** | E2E observability |
| 11.1.8 | **All decisions searchable in audit API** | Audit completeness |

### TP-11.2: Multi-Agent Scenario

| # | Scenario | What It Tests |
|---|---|---|
| 11.2.1 | **Support agent + billing agent on same OAP** | Tenant/namespace isolation |
| 11.2.2 | **Support agent can't access billing tools** | Cross-agent isolation |
| 11.2.3 | **Admin manages both agents from single dashboard** | Multi-agent management |
| 11.2.4 | **Billing agent suspended, support agent unaffected** | Independent lifecycle |

### TP-11.3: Observe Mode → Enforce Mode Transition

| # | Scenario | What It Tests |
|---|---|---|
| 11.3.1 | **Week 1: observe mode** | All requests pass, audit shows what would be denied |
| 11.3.2 | **Review audit logs** | Identify false positives, tune policies |
| 11.3.3 | **Week 2: enforce mode** | Denied requests actually blocked |
| 11.3.4 | **No false positives after tuning** | Policy accuracy validated by observe phase |

### TP-11.4: Disaster Recovery

| # | Scenario | What It Tests |
|---|---|---|
| 11.4.1 | **Postgres restore from backup** | All agents, policies, audit recovered |
| 11.4.2 | **OAP server replace** | New instance connects to existing Postgres, fully operational |
| 11.4.3 | **Policy rollback after bad deploy** | Revert to previous policy version, agent behavior returns to normal |
| 11.4.4 | **IDP migration (Keycloak → Okta)** | Change IDP config, existing agents continue working with new tokens |

---

## Test Execution

### Phase 1 — Core (run on every PR)
- TP-1 (engine), TP-8.1–8.3 (security basics)
- Automated, runs in CI

### Phase 2 — Integration (run weekly)
- TP-2.1 (Keycloak), TP-3.1 (Postgres), TP-3.2 (Redis), TP-4.1 (OPA)
- Docker-based, automated

### Phase 3 — SaaS IDPs (run before release)
- TP-2.2–2.6 (Okta, Azure AD, Google, Cognito, Auth0)
- Requires SaaS credentials, semi-automated

### Phase 4 — Full E2E (run before GA)
- TP-5 (all frameworks), TP-6 (observability), TP-7 (multi-tenancy), TP-9 (deployment), TP-10 (performance), TP-11 (scenarios)
- Manual + automated, full infrastructure

### Tracking

| Metric | Target |
|---|---|
| Total test cases | 170+ |
| Phase 1 automation | 100% |
| Phase 2 automation | 90% |
| Phase 3 automation | 70% |
| Phase 4 automation | 50% |
| Zero known-fail on GA | Required |
