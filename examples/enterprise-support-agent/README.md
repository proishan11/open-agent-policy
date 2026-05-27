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

## Quick Start (Offline — No Server Required)

```bash
# From repo root, with venv activated
python examples/enterprise-support-agent/agent.py
```

This runs the demo with mock OAP decisions, demonstrating all 7 scenarios.

## Full Stack (With OAP Server + Mock APIs)

```bash
# Terminal 1: Start mock APIs
pip install fastapi uvicorn
python -m uvicorn examples.enterprise-support-agent.mock_apis.server:app --port 9100

# Terminal 2: Build and start OAP server
make build
./bin/oap-server --data examples/enterprise-support-agent/ --dev

# Terminal 3: Run the agent
python examples/enterprise-support-agent/agent.py
```

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
├── agent.py           Main agent script (offline + live modes)
├── tools.py           Tool implementations wrapping mock APIs
├── oap.yaml           Agent manifest
├── policies/
│   └── support-agent-policy.yaml
├── mock_apis/
│   └── server.py      FastAPI mock for ticketing, CRM, and email
└── README.md          This file
```
