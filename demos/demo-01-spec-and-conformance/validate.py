#!/usr/bin/env python3
"""
OAP Milestone 1 Demo: Schema Validation

Validates example agents, policies, requests, and decisions against
the OAP JSON Schemas. This demonstrates the spec is locked and testable
before any engine code is written.

Usage:
    pip install jsonschema pyyaml
    python demos/demo-01-spec-and-conformance/validate.py
"""

import json
import sys
from pathlib import Path

try:
    import jsonschema
    import yaml
except ImportError:
    print("Install dependencies: pip install jsonschema pyyaml")
    sys.exit(1)

SPEC_DIR = Path(__file__).parent.parent.parent / "spec" / "v1alpha1"
CONFORMANCE_DIR = Path(__file__).parent.parent.parent / "conformance" / "cases"

OK = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_schema(name: str) -> dict:
    path = SPEC_DIR / f"{name}.schema.json"
    with open(path) as f:
        return json.load(f)


def validate_instance(instance: dict, schema: dict, label: str) -> bool:
    try:
        jsonschema.validate(instance=instance, schema=schema)
        print(f"  {OK} {label}")
        return True
    except jsonschema.ValidationError as e:
        print(f"  {FAIL} {label}")
        print(f"    Error: {e.message}")
        print(f"    Path: {'.'.join(str(p) for p in e.absolute_path)}")
        return False


def main():
    print(f"\n{BOLD}═══════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}  Open Agent Policy — Spec Validation (Milestone 1){RESET}")
    print(f"{BOLD}═══════════════════════════════════════════════════{RESET}\n")

    # Load schemas
    schemas = {}
    schema_names = [
        "authorization-request",
        "authorization-decision",
        "agent",
        "resource",
        "tool",
        "policy",
        "audit-event",
        "grant",
        "identity-provider",
    ]

    print(f"{BOLD}Loading schemas...{RESET}")
    for name in schema_names:
        try:
            schemas[name] = load_schema(name)
            print(f"  {OK} {name}.schema.json")
        except FileNotFoundError:
            print(f"  {FAIL} {name}.schema.json — NOT FOUND")
            return 1

    total = 0
    passed = 0

    # Validate conformance test cases
    print(f"\n{BOLD}Validating conformance test cases...{RESET}")
    case_files = sorted(CONFORMANCE_DIR.glob("*.yaml"))

    if not case_files:
        print(f"  {FAIL} No conformance test cases found")
        return 1

    for case_file in case_files:
        print(f"\n  {BOLD}Case: {case_file.name}{RESET}")
        with open(case_file) as f:
            case = yaml.safe_load(f)

        # Validate agents in the case
        for i, agent in enumerate(case.get("agents", [])):
            total += 1
            if validate_instance(agent, schemas["agent"], f"agent[{i}]"):
                passed += 1

        # Validate policies in the case
        for i, policy in enumerate(case.get("policies", [])):
            total += 1
            if validate_instance(policy, schemas["policy"], f"policy[{i}]"):
                passed += 1

        # Validate the request
        if "request" in case:
            total += 1
            if validate_instance(case["request"], schemas["authorization-request"], "request"):
                passed += 1

    # Validate a sample decision
    print(f"\n{BOLD}Validating sample decision...{RESET}")
    sample_decision = {
        "decision_id": "dec_test01",
        "request_id": "req_test01",
        "decision": "allow_with_constraints",
        "policy_ids": ["policy://finance/invoice-readonly"],
        "grant": {
            "grant_id": "grant_test01",
            "expires_in_seconds": 900,
            "scope": ["erp.invoice.read"],
            "audience": "erp.example.com"
        },
        "constraints": {
            "max_records": 25,
            "redact_fields": ["bank_account_number"],
            "readonly": True
        },
        "obligations": {
            "audit": True
        },
        "reason": "Allowed by policy finance-invoice-readonly with constraints."
    }
    total += 1
    if validate_instance(sample_decision, schemas["authorization-decision"], "sample decision"):
        passed += 1

    # Validate a sample audit event
    print(f"\n{BOLD}Validating sample audit event...{RESET}")
    sample_audit = {
        "event_id": "evt_test01",
        "event_type": "authorization.decision",
        "timestamp": "2026-05-25T08:35:00Z",
        "decision": "allow_with_constraints",
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
        "policy_ids": ["policy://finance/invoice-readonly"],
        "reason": "Allowed by finance-invoice-readonly."
    }
    total += 1
    if validate_instance(sample_audit, schemas["audit-event"], "sample audit event"):
        passed += 1

    # Validate a sample grant
    print(f"\n{BOLD}Validating sample grant...{RESET}")
    sample_grant = {
        "grant_id": "grant_test01",
        "decision_id": "dec_test01",
        "agent_id": "agent://finance/invoice-reconciler",
        "actor_id": "user:ishan@example.com",
        "scope": ["erp.invoice.read"],
        "resource": {
            "type": "erp.invoice",
            "id": "INV-8821"
        },
        "audience": "erp.example.com",
        "constraints": {
            "max_records": 25,
            "readonly": True
        },
        "issued_at": "2026-05-25T08:35:00Z",
        "expires_at": "2026-05-25T08:50:00Z",
        "status": "active"
    }
    total += 1
    if validate_instance(sample_grant, schemas["grant"], "sample grant"):
        passed += 1

    # Summary
    print(f"\n{BOLD}═══════════════════════════════════════════════════{RESET}")
    if passed == total:
        print(f"{BOLD}  Result: {OK} {passed}/{total} validations passed{RESET}")
    else:
        print(f"{BOLD}  Result: {FAIL} {passed}/{total} validations passed{RESET}")
    print(f"{BOLD}═══════════════════════════════════════════════════{RESET}\n")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
