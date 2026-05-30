# Minimal OAP Example

This is the smallest runnable OAP example for agent builders. It has two entry
points:

- `agent.py` is a deterministic enforcement walkthrough. It does not call an LLM.
- `llm_agent.py` is an actual LLM-backed agent that asks Ollama to choose tools,
  enforces every selected tool call with OAP, then asks the LLM to produce the
  final answer from the OAP-gated tool result.
- `langchain_agent.py` is the same security flow using LangChain tools and a
  real Ollama-backed LangChain chat model.

Both demonstrate:

- agent registration
- allow-with-constraints
- scoped grant issuance
- resource API grant validation
- field redaction at the resource API
- wrong-resource grant replay rejection
- approval-required decisions
- explicit deny

The deterministic walkthrough uses only:

- `oap-server`
- the Python SDK
- Python standard library HTTP servers/clients

The LLM agent additionally uses a local Ollama model.

## Files

```text
examples/minimal-agent/
|-- agent.yaml       # registered demo agent
|-- policy.yaml      # allow, approval, and deny rules
|-- resource_api.py  # protected customer API
|-- agent.py         # deterministic OAP enforcement walkthrough
|-- llm_agent.py     # actual LLM-backed agent using Ollama
|-- langchain_agent.py # LangChain tools plus Ollama LLM calls
`-- README.md
```

## Run It

From the repository root:

```bash
make build
make venv
source .venv/bin/activate
pip install -e sdk/python
```

Terminal 1: start OAP on port 8181:

```bash
./bin/oap-server \
  --addr :8181 \
  --data examples/minimal-agent \
  --grant-key local-dev-grant-key \
  --dev
```

Terminal 2: start the protected customer API on port 9191:

```bash
OAP_SERVER_URL=http://127.0.0.1:8181 \
python3 examples/minimal-agent/resource_api.py
```

Terminal 3: run the deterministic walkthrough:

```bash
OAP_SERVER_URL=http://127.0.0.1:8181 \
RESOURCE_API_URL=http://127.0.0.1:9191 \
python3 examples/minimal-agent/agent.py
```

Expected output includes:

```text
Direct resource call without a grant is blocked
decision=allow_with_constraints
"tax_identifier": "<redacted>"
Same grant cannot be replayed against C-200
decision=require_approval
decision=deny
Demo complete
```

## Run The LLM Agent

The deterministic walkthrough proves the security flow. To run an actual AI
agent, start Ollama and use `llm_agent.py`:

```bash
ollama serve
ollama pull llama3.2
```

With OAP and the resource API still running:

```bash
OAP_SERVER_URL=http://127.0.0.1:8181 \
RESOURCE_API_URL=http://127.0.0.1:9191 \
OAP_LLM_MODEL=llama3.2 \
python3 examples/minimal-agent/llm_agent.py
```

The LLM is asked to choose tools for three tasks, and then produce the final
answer from the OAP-gated tool result:

```text
Read customer C-100 and summarize what data is visible.
Send an update to the external customer channel.
Delete customer C-100.
```

For each task, the model chooses a tool call as JSON. The script gates that tool
call through OAP, then sends the result back to the model for the final response.
Expected outcomes are the same as the deterministic demo: customer reads are
grant-protected and redacted, external messages require approval, and customer
deletion is denied.

You can also pass your own task:

```bash
python3 examples/minimal-agent/llm_agent.py "Read customer C-200"
```

## Run The LangChain Agent

Install the LangChain example dependencies:

```bash
pip install -e 'sdk/python[langchain]' langchain-ollama
```

With OAP, the resource API, and Ollama running:

```bash
OAP_SERVER_URL=http://127.0.0.1:8181 \
RESOURCE_API_URL=http://127.0.0.1:9191 \
OAP_LLM_MODEL=llama3.2 \
python3 examples/minimal-agent/langchain_agent.py
```

This version uses LangChain `@tool` functions and `ChatOllama.bind_tools`.
The model chooses a tool call, the tool asks OAP for a decision, and protected
resource reads only proceed with an OAP grant token.

Pass a custom task the same way:

```bash
python3 examples/minimal-agent/langchain_agent.py "Delete customer C-100"
```

## Check Audit Output

Every successful `/v1/authorize` evaluation emits an audit event. In the
minimal example, the dev server writes audit JSON to stdout by default. To keep
a local JSONL file:

```bash
./bin/oap-server \
  --addr :8181 \
  --data examples/minimal-agent \
  --grant-key local-dev-grant-key \
  --audit-file /tmp/oap-minimal-audit.jsonl \
  --dev
```

Then inspect the events:

```bash
tail -n 20 /tmp/oap-minimal-audit.jsonl
```

## What Happens

1. The deterministic script first calls the customer API without a grant. The API returns 401.
2. The script calls OAP `/v1/authorize` for `customer.read` on `crm.customer/C-100`.
3. OAP returns `allow_with_constraints` and a scoped grant token.
4. The agent calls the customer API with `X-OAP-Grant-Token`.
5. The customer API validates the grant with OAP and redacts sensitive fields.
6. The agent attempts to reuse the C-100 grant for C-200. The API returns 403.
7. The script or LLM agent asks to send an external message. OAP returns `require_approval`.
8. The script or LLM agent asks to delete a customer. OAP returns `deny`.

## Policy Highlights

```yaml
- effect: allow
  actions:
    - customer.read
  constraints:
    maxRecords: 1
    readonly: true
    redact:
      - tax_identifier
      - bank_account

- effect: require_approval
  actions:
    - message.send
  resources:
    types:
      - slack.channel
    owners:
      - channel:external

- effect: deny
  actions:
    - customer.delete
    - customer.bulk_export
```

## Use This As A Template

Replace:

- `agent.yaml` with your agent identity and capabilities
- `policy.yaml` with your allow, deny, approval, and constraint rules
- `resource_api.py` grant checks inside your real API middleware
- `llm_agent.py` or `langchain_agent.py` tool selection around your agent's tools

For the full guide, see [Building Agents With OAP](../../docs/guide/building-agents-with-oap.md).
