# Enterprise Support Agent — OAP Protected

A production-realistic support ticket agent demonstrating OAP's zero-trust access control.

## What This Demonstrates

| Tool | OAP Decision | Constraints |
|---|---|---|
| `list_tickets` | ✅ Allow | max_records: 10 |
| `read_ticket` | ✅ Allow | readonly |
| `read_customer` | ✅ Allow | **Redact: SSN, credit card, bank account** |
| `update_ticket` | ✅ Allow | allowed_fields: status, priority, assignee |
| `escalate_ticket` | ✅ Allow | P1/P2 only |
| `send_email` (internal) | ✅ Allow | — |
| `send_email` (external) | ⏳ Require Approval | support-leads must approve |
| `delete_ticket` | 🛑 **Deny** | Explicit deny — compliance requirement |
| `billing.*` | 🛑 **Deny** | No access to billing systems |

## Architecture

```
User → Agent (Python + @protect decorator)
         │
         ├── tickets.read     → OAP: allow (max 10, readonly)
         ├── customers.read   → OAP: allow (redact SSN, CC, bank)
         ├── tickets.update   → OAP: allow (status, priority, assignee only)
         ├── tickets.escalate → OAP: allow (P1/P2 conditions)
         ├── send_email       → OAP: allow (internal) / require_approval (external)
         └── tickets.delete   → OAP: DENY (explicit)
         │
         ├── OAP Server (evaluator + registry + audit)
         └── Mock APIs (ticketing + CRM + email)
```

## Real LangChain Agent (with LLM)

The **real agent** uses a LangChain ReAct agent with Ollama (local LLM). The LLM decides
which tools to call — it is NOT scripted. OAP intercepts every tool call.

```bash
# 1. Start Ollama + pull model
brew install ollama && ollama serve
ollama pull llama3.2

# 2. Start mock APIs
pip install fastapi uvicorn
uvicorn examples.enterprise-support-agent.mock_apis.server:app --port 9100

# 3. Run the real agent
python examples/enterprise-support-agent/real_agent.py
```

5 scenarios run automatically — the LLM autonomously lists tickets, investigates,
escalates, attempts deletion (blocked by policy), and updates tickets.

Override LLM: `OAP_MODEL=mistral python examples/enterprise-support-agent/real_agent.py`

## Offline Demo (No LLM Required)

```bash
python examples/enterprise-support-agent/agent.py
```

This runs with mock OAP decisions — no Ollama, no server needed.

## Key Concepts Shown

1. **@protect decorator** — Each tool function is wrapped. OAP authorizes before execution.
2. **Constraint injection** — `oap_constraints` dict is injected into tool kwargs.
3. **Field-level redaction** — Customer SSN, credit card, bank account are redacted automatically.
4. **Max records** — Ticket list is capped at 10 results.
5. **Allowed fields** — Ticket updates are restricted to status/priority/assignee.
6. **Explicit deny** — Delete is always blocked, even if the agent calls it.
7. **PermissionDeniedError** — Denied calls raise a safe error the agent can handle.

## Files

```
examples/enterprise-support-agent/
├── real_agent.py      Real LangChain ReAct agent (Ollama LLM + OAP)
├── agent.py           Offline demo (mock OAP, no LLM required)
├── tools.py           Tool implementations wrapping mock APIs
├── oap.yaml           Agent manifest
├── policies/
│   └── support-agent-policy.yaml
├── mock_apis/
│   └── server.py      FastAPI mock for ticketing, CRM, and email
└── README.md          This file
```
