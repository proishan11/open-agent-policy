# OAP Conformance Test Suite

This directory contains the conformance test cases for Open Agent Policy. Any OAP-compliant policy evaluator must pass all tests in this suite.

## Test case format

Each YAML file in `cases/` defines:

| Field | Description |
|---|---|
| `name` | Short identifier for the test |
| `description` | What the test validates |
| `agents` | Agent registrations present in the system |
| `policies` | Policies loaded in the system |
| `delegations` | Active delegations (if applicable) |
| `request` | The authorization request to evaluate |
| `expected.decision` | The expected decision type |
| `expected.constraints` | Expected constraints (if applicable) |
| `expected.approval` | Expected approval details (if applicable) |
| `expected.reason_contains` | Substring the reason must contain |

## Core test cases

| # | Name | Validates |
|---|---|---|
| 01 | deny-unregistered-agent | Unregistered agents are always denied |
| 02 | deny-by-default | No matching policy means deny |
| 03 | simple-allow | Basic allow with matching policy |
| 04 | allow-with-constraints | Constraints are carried through |
| 05 | explicit-deny-overrides-allow | Deny always wins over allow |
| 06 | require-approval | High-risk actions can require approval |
| 07 | actor-required-but-missing | Condition evaluation (actorRequired) |
| 08 | delegation-scoped | Delegation bounds are enforced |
| 09 | constraint-merging | Strictest constraint wins |
| 10 | revoked-agent-denied | Revoked agents are always denied |

## Foundation baseline coverage

The conformance suite is the public compatibility contract. The Go unit tests add
baseline hardening coverage for evaluator behavior that is not yet represented as
portable conformance cases:

- Agent capabilities are an upper bound on policy grants.
- Resource selectors must match request resource context.
- Unsupported condition keys fail closed.
- Unsupported constraint keys fail closed.
- `allowedFields` and `expiresIn` are mapped into decision constraints.

Future policy capabilities should be promoted into this suite once their request
and expected-decision shape is stable.

## Running conformance tests

```bash
# Once the engine is built (Milestone 2):
oapctl test --conformance

# Or with the runner directly:
go run conformance/runner/main.go
```
