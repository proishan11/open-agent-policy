"""Audit completeness checks for production-like authorization decisions."""

from __future__ import annotations

import time
import uuid

from conftest import OAPTestClient


AGENT_ID = "agent://support/ticket-assistant"
ACTOR_ID = "alice@company.test"


def wait_for_audit_event(oap: OAPTestClient, request_id: str) -> dict:
    """Fetch the audit event for a request ID, with a short retry window."""
    deadline = time.time() + 5
    while time.time() < deadline:
        result = oap.audit_events(request_id=request_id, limit=5)
        items = result.get("items", [])
        if items:
            assert len(items) == 1
            return items[0]
        time.sleep(0.2)
    raise AssertionError(f"no audit event found for request_id={request_id}")


class TestAuditCompleteness:
    def test_every_authorize_decision_has_queryable_audit_event(
        self,
        oap: OAPTestClient,
    ):
        """Every successful /v1/authorize decision is durably queryable."""
        run_id = f"run-audit-{uuid.uuid4()}"
        cases = [
            {
                "action": "ticket.read",
                "resource_type": "support.ticket",
                "resource_id": "T-100",
                "expected_decision": "allow_with_constraints",
            },
            {
                "action": "message.send",
                "resource_type": "slack.channel",
                "resource_id": "slack:#external-customer-updates",
                "resource_owner": "channel:external",
                "expected_decision": "require_approval",
            },
            {
                "action": "customer.bulk_export",
                "resource_type": "crm.customer",
                "resource_id": "",
                "expected_decision": "deny",
            },
        ]

        for case in cases:
            request_id = f"val-audit-{uuid.uuid4()}"
            decision = oap.authorize(
                agent_id=AGENT_ID,
                actor_id=ACTOR_ID,
                action=case["action"],
                resource_type=case["resource_type"],
                resource_id=case["resource_id"],
                resource_owner=case.get("resource_owner", ""),
                context={"run_id": run_id},
                request_id=request_id,
            )
            assert decision.status_code == 200
            assert decision.request_id == request_id
            assert decision.decision == case["expected_decision"]

            event = wait_for_audit_event(oap, request_id)
            assert event["event_type"] == "authorization.decision"
            assert event["request_id"] == request_id
            assert event["run_id"] == run_id
            assert event["action"] == case["action"]
            assert event["decision"] == case["expected_decision"]
            assert event["subject"]["agent_id"] == AGENT_ID
            assert event["actor"]["id"] == ACTOR_ID
            assert event["resource"]["type"] == case["resource_type"]
            if case["resource_id"]:
                assert event["resource"]["id"] == case["resource_id"]
            if decision.grant is not None:
                assert event["grant_id"] == decision.grant["grant_id"]
