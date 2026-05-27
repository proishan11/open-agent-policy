# Open Agent Policy — Spec-Driven Development Plan

This document defines the spec-driven development approach, milestone tracking, blog series outline, and demo plan for Open Agent Policy.

---

## 1. Why spec-driven development

OAP is a protocol and standard, not just a server. Multiple components must agree on the same shapes:

- Go engine evaluates policies against request schemas
- Python SDK constructs requests and interprets decisions
- TypeScript SDK does the same
- HTTP gateway intercepts requests and constructs authorization requests
- MCP proxy does the same for MCP protocol
- CLI simulates and tests against the same schemas
- Conformance tests validate any implementation against the spec

If the spec is ambiguous, every implementation interprets it differently. If the spec is locked and tested, implementations are interchangeable.

### Development flow

```text
1. Write the spec (JSON Schema, OpenAPI, YAML format spec)
2. Write conformance tests against the spec (input → expected output)
3. Build the implementation to pass conformance tests
4. Document what was built (blog post)
5. Build a runnable demo
6. Repeat for next milestone
```

### Artifacts per milestone

Every milestone produces five things:

```text
spec/          — JSON Schema or OpenAPI spec for the milestone
tests/         — Conformance tests derived from the spec
src/           — Implementation that passes the tests
docs/          — Blog post draft + updated docs
demos/         — Runnable demo showing the milestone in action
```

---

## 2. Repository structure

```text
open-agent-policy/
├── spec/
│   ├── v1alpha1/
│   │   ├── authorization-request.schema.json
│   │   ├── authorization-decision.schema.json
│   │   ├── agent.schema.json
│   │   ├── resource.schema.json
│   │   ├── tool.schema.json
│   │   ├── policy.schema.json
│   │   ├── audit-event.schema.json
│   │   ├── grant.schema.json
│   │   ├── delegation.schema.json
│   │   └── identity-provider.schema.json
│   └── openapi/
│       └── oap-server.openapi.yaml
│
├── conformance/
│   ├── README.md
│   ├── cases/
│   │   ├── 01-deny-unregistered-agent.yaml
│   │   ├── 02-deny-by-default.yaml
│   │   ├── 03-simple-allow.yaml
│   │   ├── 04-allow-with-constraints.yaml
│   │   ├── 05-explicit-deny-overrides-allow.yaml
│   │   ├── 06-require-approval.yaml
│   │   ├── 07-actor-required.yaml
│   │   ├── 08-delegation-scoped.yaml
│   │   ├── 09-constraint-merging.yaml
│   │   └── 10-revoked-agent-denied.yaml
│   └── runner/
│       └── run_conformance.go
│
├── engine/                          # Go policy evaluator library
│   ├── evaluator/
│   ├── registry/
│   ├── grant/
│   └── audit/
│
├── server/                          # Go HTTP server (wraps engine)
│   └── cmd/oap-server/
│
├── cli/                             # Go CLI
│   └── cmd/oapctl/
│
├── sdk/
│   ├── python/                      # Python SDK
│   │   └── open_agent_policy/
│   └── typescript/                  # TypeScript SDK (later)
│       └── packages/sdk/
│
├── gateway/                         # HTTP gateway
├── proxy/                           # MCP proxy
│
├── integrations/
│   ├── langchain/
│   ├── crewai/
│   └── openai-agents/
│
├── examples/
│   ├── finance-invoice-agent/       # Reference use case 1
│   ├── support-ticket-agent/        # Reference use case 2
│   └── mcp-tool-agent/             # Reference use case 3
│
├── demos/
│   ├── demo-01-spec-and-conformance/
│   ├── demo-02-engine-and-cli/
│   ├── demo-03-python-sdk/
│   ├── demo-04-mcp-proxy/
│   └── demo-05-production-setup/
│
├── blog/
│   ├── 01-why-agents-need-zero-trust.md
│   ├── 02-designing-the-spec.md
│   ├── 03-building-the-engine.md
│   ├── 04-python-sdk-and-langchain.md
│   ├── 05-mcp-proxy-and-gateway.md
│   └── 06-production-ready.md
│
├── docs/
│   ├── architecture.md              # (moved from root)
│   ├── quickstart.md
│   ├── policy-guide.md
│   └── integration-guide.md
│
├── architecture.md                  # Final architecture (current)
├── open-agent-policy-prd.md
├── open-agent-policy-post-prd-notes.md
├── DEVELOPMENT_PLAN.md              # This file
├── PROGRESS.md                      # Milestone tracking
├── LICENSE
└── README.md
```

---

## 3. Milestones

### Milestone 1: Spec + Conformance Tests

**Goal:** Lock the schemas and prove them with tests. No implementation yet — just the contract.

**Spec deliverables:**
- JSON Schema: authorization-request, authorization-decision, agent, resource, tool, policy, audit-event, grant
- OpenAPI spec for oap-server HTTP API (v1alpha1)
- Canonical YAML policy format documented with examples

**Conformance test deliverables (10 core cases):**

| # | Test case | Validates |
|---|---|---|
| 01 | Unregistered agent is denied | Principle 3.1 |
| 02 | No matching policy means deny | Principle 3.2 |
| 03 | Simple allow with matching policy | Basic allow flow |
| 04 | Allow with constraints (redaction, limits) | Constraint model |
| 05 | Explicit deny overrides allow | Principle 3.3 |
| 06 | Require approval for high-risk action | Approval flow |
| 07 | Actor required but missing | Delegation model |
| 08 | Delegation scoped correctly | Delegation bounds |
| 09 | Constraints merge (strictest wins) | Constraint merging |
| 10 | Revoked agent is denied | Revocation |

Each test case is a YAML file with:
```yaml
name: "deny-unregistered-agent"
description: "An unregistered agent must be denied"
agents: []                    # no agents registered
policies: [...]               # policies that would allow if agent existed
request: { ... }              # authorization request from unregistered agent
expected_decision: "deny"
expected_reason_contains: "unregistered"
```

**Demo:** `demo-01-spec-and-conformance/`
- A script that validates example requests/decisions against the JSON schemas
- A test runner that loads conformance cases and shows pass/fail (even before engine exists, this validates the test format)

**Blog post:** `01-why-agents-need-zero-trust.md`
- The problem statement
- Why existing IAM doesn't cover agents
- What we're building and the spec-first approach
- Link to the published schemas

---

### Milestone 2: Core Engine + CLI

**Goal:** A working policy engine that passes all 10 conformance tests, plus a CLI for simulation and testing.

**Spec consumed:**
- All JSON Schemas from Milestone 1
- Policy format spec
- Evaluation order spec

**Implementation deliverables:**
- `engine/evaluator/` — Go library: loads policies, evaluates requests, returns decisions
- `engine/registry/` — File-backed agent, resource, tool registries
- `engine/audit/` — JSONL audit sink
- `server/cmd/oap-server/` — HTTP server with POST /v1/authorize, /v1/simulate, /v1/agents
- `cli/cmd/oapctl/` — Commands: `agent register`, `policy apply`, `simulate`, `test`, `explain`

**Conformance:**
- All 10 conformance tests pass against the engine
- `oapctl test --conformance` runs the full suite

**Demo:** `demo-02-engine-and-cli/`
```bash
# Start OAP server with example data
oap dev --data examples/finance-invoice-agent/

# Register agent
oapctl agent register -f examples/finance-invoice-agent/oap.yaml

# Apply policy
oapctl policy apply -f examples/finance-invoice-agent/policies/

# Simulate decisions
oapctl simulate -f examples/finance-invoice-agent/requests/read-invoice.json
# → allow_with_constraints (readonly, redact bank_account, max 25 records)

oapctl simulate -f examples/finance-invoice-agent/requests/delete-invoice.json
# → deny (agents may not delete invoices)

# Explain a decision
oapctl explain -f examples/finance-invoice-agent/requests/read-invoice.json
# → Step-by-step evaluation trace

# Run conformance tests
oapctl test --conformance
# → 10/10 passed
```

**Blog post:** `03-building-the-engine.md`
- How we built the evaluator from the spec
- Policy evaluation order
- Conformance test results
- Demo walkthrough

---

### Milestone 3: Python SDK + LangChain Integration

**Goal:** Developers can protect agent tools with one decorator or one middleware line.

**Spec consumed:**
- Authorization request/decision schemas (SDK constructs/interprets these)
- Agent manifest format (oap.yaml)

**Implementation deliverables:**
- `sdk/python/open_agent_policy/` — Python package
  - `OAPClient` — authorize(), with embedded and remote modes
  - `@protect` decorator
  - Agent identity auto-discovery (env vars, k8s SA, SPIFFE)
- `integrations/langchain/` — OAPMiddleware for LangChain/LangGraph
- `examples/support-ticket-agent/` — Full working agent with OAP protection

**Demo:** `demo-03-python-sdk/`
```python
# A real LangChain agent with OAP protection
from langchain import create_agent
from open_agent_policy.integrations.langchain import OAPMiddleware

agent = create_agent(
    model="gpt-4",
    tools=[read_ticket, update_ticket, send_message],
    middleware=[OAPMiddleware(agent_id="agent://support/ticket-assistant")]
)

# Agent runs normally — OAP authorizes each tool call transparently
# Denied actions return safe messages
# Allowed actions include constraints (redaction, limits)
# Every decision is audited
```

Demo includes:
- Agent making tool calls (some allowed, some denied, some constrained)
- Terminal showing real-time audit log
- `oapctl audit --last 5m` showing what happened

**Blog post:** `04-python-sdk-and-langchain.md`
- Zero-code-change integration (middleware approach)
- How @protect works
- Live demo with a real agent
- Before/after comparison (unprotected vs. OAP-protected)

---

### Milestone 4: MCP Proxy + HTTP Gateway

**Goal:** Protect agents without any code changes — just change the URL.

**Spec consumed:**
- OpenAPI spec for gateway routes
- MCP protocol spec for proxy behavior

**Implementation deliverables:**
- `proxy/` — MCP proxy: intercepts tools/list and tools/call
- `gateway/` — HTTP reverse proxy with policy enforcement
- JWT grant issuance from /v1/authorize
- Observe mode for both proxy and gateway

**Demo:** `demo-04-mcp-proxy/`
```bash
# Start MCP proxy in front of an MCP server
oap mcp proxy \
  --agent agent://support/ticket-assistant \
  --upstream mcp://zendesk-tools \
  --listen localhost:7777

# Agent connects to proxy instead of MCP server directly
# Every tool call is authorized, constrained, and audited
# No code changes to the agent
```

Demo includes:
- MCP agent making tool calls through proxy
- HTTP agent going through gateway
- Side-by-side: observe mode vs. enforce mode
- Grant JWTs being issued and expiring

**Blog post:** `05-mcp-proxy-and-gateway.md`
- Protecting MCP agents without code changes
- HTTP gateway for legacy/custom agents
- Observe mode for safe rollout
- Credential brokering via JWT grants

---

### Milestone 5: Production Readiness

**Goal:** Identity verification, policy bundles, security hardening, deployment guides.

**Spec consumed:**
- Identity provider config schema
- Policy bundle format

**Implementation deliverables:**
- OIDC actor verification
- Kubernetes ServiceAccount agent verification
- Policy bundle sync (server → embedded evaluators)
- Security abuse tests (prompt injection, confused deputy, escalation, token replay)
- Fail-closed behavior tests
- `oap dev` one-command demo
- `docker compose` reference environment
- Helm chart (basic)

**Demo:** `demo-05-production-setup/`
```bash
# One-command demo with everything
docker compose up

# Includes: OAP server, example agent, MCP proxy, audit viewer
# Shows: registration, policy, tool calls, denials, audit trail
```

**Blog post:** `06-production-ready.md`
- Identity integration (OIDC + k8s SA)
- Embedded evaluation + bundle sync
- Security hardening results
- Deployment guide
- What's next (roadmap)

---

## 4. Progress tracking

Progress is tracked in `PROGRESS.md` at the repo root, updated after each milestone.

Format:

```markdown
# OAP Progress

## Milestone 1: Spec + Conformance Tests
- [x] authorization-request.schema.json
- [x] authorization-decision.schema.json
- [x] agent.schema.json
- [ ] resource.schema.json
- [ ] ...
- [ ] Conformance case 01: deny-unregistered-agent
- [ ] ...
- [ ] Blog post 01 draft
- [ ] Demo 01 working

## Milestone 2: Core Engine + CLI
- [ ] ...
```

---

## 5. Blog series outline

| # | Title | Published after | Key takeaway |
|---|---|---|---|
| 1 | **Why AI Agents Need Zero-Trust Access Control** | Milestone 1 | The problem is real. Here's the spec. |
| 2 | **Designing the OAP Spec: Schemas for Agent Authorization** | Milestone 1 | Spec-first approach. Conformance tests. Schema deep-dive. |
| 3 | **Building the OAP Policy Engine** | Milestone 2 | How the evaluator works. CLI demo. All conformance tests passing. |
| 4 | **Protecting LangChain Agents with One Line of Code** | Milestone 3 | Python SDK + middleware. Real agent demo. Before/after. |
| 5 | **MCP Proxy: Agent Authorization Without Code Changes** | Milestone 4 | Gateway and proxy. Observe mode. JWT grants. |
| 6 | **Taking OAP to Production** | Milestone 5 | Identity integration. Bundle sync. Security hardening. Deploy guide. |

Each blog post follows the same structure:
```text
1. What problem this milestone solves
2. What we built (spec + implementation)
3. How to try it (runnable demo)
4. What we learned
5. What's next
```

---

## 6. Demo strategy

Every demo must be:
- **Self-contained** — runs with one command (script or docker compose)
- **Observable** — shows decisions, denials, constraints, audit in real time
- **Reproducible** — checked into the repo, CI-tested
- **Progressive** — each demo builds on the previous one

Demo recording plan:
- Each demo gets a short (2-3 minute) terminal recording (asciinema or similar)
- Embedded in the blog post
- Linked from the README

---

## 7. Development workflow

```text
For each milestone:

1. Branch: milestone-N
2. Write/update specs in spec/
3. Write conformance tests in conformance/cases/
4. Implement to pass tests
5. Build demo in demos/demo-N/
6. Draft blog post in blog/N-title.md
7. Update PROGRESS.md
8. PR review + merge to main
9. Tag release: v0.1.0-milestone-N
10. Publish blog post
```

### Quality gates per milestone

```text
- All conformance tests pass
- All existing tests still pass (no regressions)
- Demo runs end-to-end with one command
- Blog post draft reviewed
- PROGRESS.md updated
- README updated with current capabilities
- Documentation gate passed (see §8)
```

---

## 8. Documentation standards

Every piece of code and every component must be documented well enough that a
human contributor (not just AI) can understand the flow, purpose, and design
decisions without reading the full architecture doc.

### Code-level documentation

```text
- Every Go package has a doc.go with a package-level comment explaining
  what the package does, its main types, and how it fits into the system.
- Every exported function/type has a GoDoc comment that explains:
  • What it does
  • Why it exists
  • Inputs and outputs
  • Error cases
  • Example usage (where non-obvious)
- Every Python module has a module-level docstring.
- Every public class/function has a docstring explaining purpose,
  parameters, return values, and exceptions.
- Non-obvious logic gets inline comments explaining WHY, not WHAT.
```

### Component-level documentation

Each major component gets a `README.md` in its directory:

```text
engine/README.md       — What the evaluator does, how evaluation works,
                         package structure, key interfaces, data flow
server/README.md       — Server architecture, endpoints, middleware chain,
                         how it wraps the engine library
cli/README.md          — Command structure, how commands map to server API
sdk/python/README.md   — SDK architecture, OAPClient, @protect decorator,
                         middleware integrations, embedded vs remote mode
gateway/README.md      — How the gateway intercepts requests, policy
                         enforcement, credential injection, observe mode
proxy/README.md        — MCP proxy architecture, how tools/list and
                         tools/call are intercepted
```

Each component README must include:
- **Purpose** — one paragraph on what this component does
- **Architecture** — how it works internally (with a diagram if helpful)
- **Key interfaces** — the main types/functions and what they do
- **Data flow** — how data moves through the component
- **Configuration** — how to configure the component
- **Testing** — how to run tests for this component

### Flow documentation

For each end-to-end flow, maintain a Mermaid sequence diagram in `docs/`:

```text
docs/flows/
├── agent-onboarding.md       — Registration → credential issuance
├── runtime-authorization.md  — Tool call → decision → enforcement
├── delegation.md             — User delegates to agent
├── approval.md               — Approval-gated action
└── revocation.md             — Revoke agent or grant
```

### When to document

```text
- Document BEFORE or DURING implementation, not after
- Every PR that adds a new component must include its README
- Every PR that changes a flow must update the flow diagram
- ADRs for any non-obvious design choice
```
