# Open Agent Policy — Enterprise Roadmap

> From prototype to production-grade zero-trust agent policy engine.

Milestones 1–5 established the core engine, SDK, proxy, gateway, and foundational security. This roadmap transforms OAP from a well-tested prototype into an enterprise-ready platform that organizations can deploy with confidence.

---

## What's Missing for Enterprise

| Gap | Current State | Enterprise Requirement |
|---|---|---|
| **Identity** | JWT structure validation only | Real OIDC/SAML against Keycloak, Okta, Azure AD, Google |
| **Storage** | In-memory + YAML files | Postgres, Redis cache, Git-synced policy bundles |
| **Frameworks** | LangChain only | OpenAI Agents SDK, CrewAI, AutoGen, LlamaIndex, Semantic Kernel |
| **Observability** | JSONL file sink | OpenTelemetry, Datadog, Splunk, Elastic |
| **Multi-tenancy** | Single-tenant | Tenant isolation, RBAC for OAP itself |
| **HA / Scale** | Single instance | Horizontal scaling, leader election, health clustering |
| **Policy management** | File-based | GitOps sync, versioning, rollback, diff, dry-run |
| **Real-world validation** | Unit/integration tests | End-to-end with a real LangChain agent hitting real APIs |

---

## Milestone 6: Enterprise Identity & Storage

**Goal:** Replace stub verifiers with real IDP integrations and move to database-backed storage.

### 6.1 Real IDP Integrations

| Provider | Protocol | Implementation |
|---|---|---|
| **Keycloak** | OIDC | JWKS discovery, token introspection, realm mapping |
| **Okta** | OIDC | JWKS from `/.well-known/jwks.json`, org-level audience |
| **Azure AD (Entra ID)** | OIDC + SAML | Multi-tenant, v2.0 endpoints, group claims |
| **Google Workspace** | OIDC | Google-specific `hd` (hosted domain) claim |
| **Auth0** | OIDC | Custom domain support, API audience |

**Implementation deliverables:**
- `engine/identity/oidc/` — Production OIDC verifier with:
  - JWKS auto-discovery and rotation (background refresh)
  - RS256/RS384/ES256 signature verification (not just HMAC)
  - Issuer discovery via `.well-known/openid-configuration`
  - Token introspection endpoint support (opaque tokens)
  - Claim mapping configuration (per-provider)
- `engine/identity/providers/` — Provider-specific adapters:
  - `keycloak.go` — Realm-aware, client role extraction
  - `okta.go` — Org URL, custom authorization server support
  - `azuread.go` — Multi-tenant, v2.0 token format, app role claims
  - `google.go` — Hosted domain (`hd`) validation
- `engine/identity/saml/` — SAML 2.0 assertion validation (for enterprises that require it)
- Integration tests against each provider (using test containers or mock JWKS servers)

### 6.2 Database-Backed Storage

| Store | Backend | Use Case |
|---|---|---|
| **PostgresStore** | PostgreSQL | Agents, policies, audit events — primary production store |
| **RedisCache** | Redis | Hot cache for agents/policies, session data, rate limits |
| **GitPolicyStore** | Git repo | Policy-as-code, GitOps sync, PR-based policy changes |

**Implementation deliverables:**
- `engine/store/postgres/` — PostgreSQL implementation of RegistryStore:
  - Schema migrations (golang-migrate)
  - Agent CRUD with version tracking
  - Policy CRUD with effective-date support
  - Audit event table with partitioning (by date)
  - Connection pooling (pgxpool)
  - Full-text search on policies and audit events
- `engine/store/redis/` — Redis caching layer:
  - Read-through cache for agent/policy lookups
  - Cache invalidation on write
  - Configurable TTL
  - Circuit breaker for Redis failures (fall through to Postgres)
- `engine/store/git/` — Git-backed policy sync:
  - Clone/pull policy repository
  - Watch for changes (webhook or polling)
  - Branch-based policy environments (dev/staging/prod)
  - Policy diff and dry-run before apply
- Store interface abstraction so all stores are swappable

### 6.3 Deliverables

- Provider-specific OIDC configuration schemas (JSON Schema)
- Database migration files
- `docker-compose.enterprise.yml` with Postgres + Redis + Keycloak
- Integration tests for each store backend
- ADR: Why Postgres as primary store
- ADR: JWKS rotation and caching strategy

---

## Milestone 7: Framework Integrations

**Goal:** First-class support for every major agent framework.

### 7.1 Framework Matrix

| Framework | Language | Integration Type | Status |
|---|---|---|---|
| **LangChain / LangGraph** | Python | `OAPToolWrapper`, `protect_tools()` | ✅ Done |
| **OpenAI Agents SDK** | Python | Tool wrapper, function call interceptor | Planned |
| **CrewAI** | Python | Before/after tool hooks, `install_oap()` | Planned |
| **AutoGen** | Python | Function call filter, conversation guard | Planned |
| **LlamaIndex** | Python | Tool spec wrapper, query engine guard | Planned |
| **Semantic Kernel** | Python/C# | Plugin filter, function invocation filter | Planned |
| **Haystack** | Python | Pipeline component, tool node wrapper | Planned |
| **MCP** | Any | Proxy (already done) | ✅ Done |
| **OpenAI Functions** | Python/TS | Direct `OAPClient.authorize()` before function call | Planned |
| **Anthropic Tool Use** | Python/TS | Direct `OAPClient.authorize()` before tool use | Planned |

### 7.2 Implementation deliverables

- `sdk/python/open_agent_policy/integrations/openai_agents.py` — OpenAI Agents SDK wrapper
- `sdk/python/open_agent_policy/integrations/crewai.py` — CrewAI hook adapter
- `sdk/python/open_agent_policy/integrations/autogen.py` — AutoGen function filter
- `sdk/python/open_agent_policy/integrations/llamaindex.py` — LlamaIndex tool wrapper
- `sdk/python/open_agent_policy/integrations/semantic_kernel.py` — SK plugin filter
- `sdk/python/open_agent_policy/integrations/haystack.py` — Haystack pipeline guard
- Each integration gets:
  - One-line setup function
  - Automatic action name derivation from framework tool metadata
  - Constraint injection into tool arguments
  - Tests with mock clients
  - README with usage examples

### 7.3 TypeScript SDK

- `sdk/typescript/` — TypeScript/Node.js SDK mirroring Python:
  - `OAPClient` (remote mode via fetch)
  - `protectTool()` wrapper
  - Vercel AI SDK integration
  - OpenAI Node SDK integration

---

## Milestone 8: Observability & Audit

**Goal:** Enterprise-grade observability with OpenTelemetry, structured logging, and SIEM integration.

### 8.1 Implementation deliverables

- `engine/audit/otel/` — OpenTelemetry audit sink:
  - Span-per-decision with attributes (agent, action, decision, policy IDs)
  - Trace propagation from agent SDK → OAP → upstream
  - Metrics: decisions/sec, latency p50/p95/p99, deny rate, by agent
- `engine/audit/exporters/` — SIEM exporters:
  - Datadog (via OTLP or direct API)
  - Splunk HEC (HTTP Event Collector)
  - Elastic (via OTLP or Filebeat)
  - CloudWatch (AWS)
- Structured logging (slog with JSON output)
- Prometheus metrics endpoint (`/metrics`)
- Grafana dashboard template
- Audit event search API (`GET /v1/audit?agent=...&action=...&from=...&to=...`)

---

## Milestone 9: Multi-Tenancy, RBAC & Policy Management

**Goal:** Support multiple teams/orgs on a single OAP deployment with proper access control.

### 9.1 Implementation deliverables

- Tenant isolation (namespace-based, header-based)
- RBAC for OAP admin operations (who can register agents, apply policies)
- Policy versioning with effective dates
- Policy dry-run / what-if simulation
- Policy diff (before/after apply)
- Policy rollback
- GitOps workflow: PR → CI validates → merge → OAP syncs
- Rate limiting per agent / per tenant
- Quota management (max agents, max policies per namespace)

---

## Milestone 10: Real-World End-to-End Validation

**Goal:** Build a production-realistic agent and protect it with OAP, demonstrating the full stack.

### 10.1 Use Case: Enterprise Support Ticket Agent

A LangChain-based support agent that:
- Reads customer tickets from a real (simulated) ticketing API
- Looks up customer data from a CRM API
- Sends email notifications
- Escalates critical issues
- Operates under OAP policy enforcement

### 10.2 Architecture

```
User → Chat UI → LangChain Agent (with @protect)
                     │
                     ├── read_ticket (allowed, constrained: max 10 results)
                     ├── read_customer (allowed, redact: SSN, credit card)
                     ├── send_email (require_approval for external recipients)
                     ├── escalate_ticket (allowed for P1/P2 only)
                     └── delete_ticket (denied — explicit deny rule)
                     │
                     └── OAP Server (Postgres + Redis + Keycloak)
                           ├── Agent registered with risk_tier: medium
                           ├── Policy: support-agent-policy
                           ├── Actor: user authenticated via Keycloak OIDC
                           └── Audit: all decisions logged to JSONL + OTEL
```

### 10.3 Implementation deliverables

- `examples/enterprise-support-agent/`
  - `agent.py` — LangChain agent with 5 tools
  - `tools.py` — Tool implementations (ticket API, CRM, email)
  - `mock_apis/` — FastAPI mock for ticketing + CRM APIs
  - `oap.yaml` — Agent manifest
  - `policies/` — Policy files (allow, deny, constrain, require_approval)
  - `requests/` — Sample authorization requests
  - `docker-compose.yml` — Full stack (agent + OAP server + mock APIs + Keycloak)
  - `README.md` — Step-by-step walkthrough
- Demonstrates:
  - Real OIDC authentication (Keycloak)
  - Constraint enforcement (redaction, max records)
  - Approval workflow (human-in-the-loop)
  - Explicit deny (delete blocked)
  - Audit trail (every decision logged)
  - Observe mode → enforce mode transition

---

## Milestone 11: Hardening & Scale

**Goal:** Performance, resilience, and operational readiness.

### 11.1 Implementation deliverables

- Load testing (k6 or vegeta): 10k decisions/sec target
- Benchmark suite for evaluator (ns/op)
- Graceful degradation: if Postgres is down, use cached bundles
- Circuit breakers for external dependencies (IDP, Redis, upstream APIs)
- Distributed tracing end-to-end
- Security scanning (SAST, dependency audit, container scan)
- Penetration testing guide
- SOC 2 / compliance mapping document
- Operational runbook (deploy, upgrade, rollback, incident response)

---

## Priority Order

| Milestone | Priority | Rationale |
|---|---|---|
| **6: Identity + Storage** | 🔴 Critical | Can't be enterprise without real IDP and DB |
| **10: Real-World Validation** | 🔴 Critical | Proves the system works end-to-end |
| **7: Framework Integrations** | 🟡 High | Broader adoption, but LangChain covers most demos |
| **8: Observability** | 🟡 High | Enterprises need OTEL + SIEM from day one |
| **9: Multi-Tenancy** | 🟠 Medium | Required for shared deployments |
| **11: Hardening** | 🟠 Medium | Required before production GA |

**Recommended execution order:** 6 → 10 → 7 → 8 → 9 → 11

We start with Milestone 6 (real IDP + storage) and Milestone 10 (real-world agent) in parallel, since Milestone 10 validates everything Milestone 6 builds.

---

## Timeline Estimate

| Milestone | Estimated Effort |
|---|---|
| 6: Identity + Storage | 2-3 weeks |
| 10: Real-World Validation | 1-2 weeks |
| 7: Framework Integrations | 2 weeks |
| 8: Observability | 1-2 weeks |
| 9: Multi-Tenancy | 2 weeks |
| 11: Hardening | 2-3 weeks |
| **Total to enterprise GA** | **10-14 weeks** |
