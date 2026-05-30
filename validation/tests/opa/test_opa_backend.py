"""OPA-backed OAP validation profile.

These tests exercise the public oap-server OPA backend path with real Keycloak,
Postgres audit storage, scoped grants, and protected resource APIs.
"""

from __future__ import annotations

import os
import time
import uuid

import httpx

from conftest import (
    AGENT_CLIENT_SECRET,
    KeycloakClient,
    OAPTestClient,
    TicketAPIClient,
    CustomerAPIClient,
)


AGENT_ID = "agent://support/ticket-assistant"
ACTOR_ID = "alice@company.test"
OPA_URL = os.environ.get("OPA_URL", "http://opa:8181")
OAP_FAIL_CLOSED_SERVER_URL = os.environ.get(
    "OAP_FAIL_CLOSED_SERVER_URL",
    "http://oap-server-opa-unavailable:8080",
)


def wait_for_opa() -> None:
    deadline = time.time() + 15
    last_error = ""
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{OPA_URL}/health", timeout=2.0)
            if resp.status_code == 200:
                return
            last_error = f"HTTP {resp.status_code}: {resp.text}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise AssertionError(f"OPA did not become healthy: {last_error}")


def wait_for_audit_event(oap: OAPTestClient, request_id: str) -> dict:
    deadline = time.time() + 5
    while time.time() < deadline:
        result = oap.audit_events(request_id=request_id, limit=5)
        items = result.get("items", [])
        if items:
            assert len(items) == 1
            return items[0]
        time.sleep(0.2)
    raise AssertionError(f"no audit event found for request_id={request_id}")


def new_request_id(prefix: str) -> str:
    return f"opa-{prefix}-{uuid.uuid4()}"


class TestOPABackedServer:
    def test_health_reports_opa_backend(self, oap: OAPTestClient):
        wait_for_opa()
        health = oap.health()
        assert health["status"] == "healthy"
        assert health["policy_backend"] == "opa"
        assert health["store_backend"] == "postgres"

    def test_ticket_read_uses_opa_constraints_grant_and_audit(
        self,
        oap: OAPTestClient,
        ticket_api: TicketAPIClient,
    ):
        request_id = new_request_id("ticket-read")
        run_id = f"run-{request_id}"
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id=ACTOR_ID,
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
            context={"run_id": run_id},
            request_id=request_id,
        )

        assert result.status_code == 200
        assert result.decision == "allow_with_constraints"
        assert result.reason.startswith("OPA:")
        assert result.policy_ids == ["opa/support-ticket-read"]
        assert result.constraints == {"max_records": 25, "readonly": True}
        assert result.grant is not None

        claims = oap.validate_grant(result.grant["token"])
        assert claims["valid"] is True
        assert claims["decision"] == "allow_with_constraints"
        assert claims["constraints"]["max_records"] == 25
        assert claims["constraints"]["readonly"] is True

        ticket = ticket_api.get_ticket("T-100", result.grant["token"])
        assert ticket["id"] == "T-100"

        event = wait_for_audit_event(oap, request_id)
        assert event["decision"] == "allow_with_constraints"
        assert event["policy_ids"] == ["opa/support-ticket-read"]
        assert event["grant_id"] == result.grant["grant_id"]
        assert event["constraints"] == {"max_records": 25, "readonly": True}
        assert event["run_id"] == run_id

    def test_customer_read_uses_opa_redaction_constraints_at_resource_api(
        self,
        oap: OAPTestClient,
        customer_api: CustomerAPIClient,
    ):
        request_id = new_request_id("customer-read")
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id=ACTOR_ID,
            action="customer.read",
            resource_type="crm.customer",
            resource_id="C-100",
            request_id=request_id,
        )

        assert result.status_code == 200
        assert result.decision == "allow_with_constraints"
        assert result.policy_ids == ["opa/customer-read-redacted"]
        assert set(result.constraints["redact_fields"]) == {
            "tax_identifier",
            "billing_account",
            "bank_account",
        }
        assert result.grant is not None

        customer = customer_api.get_customer("C-100", result.grant["token"])
        assert customer["id"] == "C-100"
        assert customer["tax_identifier"] == "<redacted>"
        assert customer["billing_account"] == "<redacted>"
        assert customer["bank_account"] == "<redacted>"

        event = wait_for_audit_event(oap, request_id)
        assert event["decision"] == "allow_with_constraints"
        assert event["policy_ids"] == ["opa/customer-read-redacted"]
        assert set(event["constraints"]["redact_fields"]) == {
            "tax_identifier",
            "billing_account",
            "bank_account",
        }

    def test_opa_deny_has_no_grant_and_is_audited(self, oap: OAPTestClient):
        request_id = new_request_id("deny")
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id=ACTOR_ID,
            action="ticket.update",
            resource_type="support.ticket",
            resource_id="T-200",
            request_id=request_id,
        )

        assert result.status_code == 200
        assert result.decision == "deny"
        assert result.reason == "OPA: T-200 is locked for update in this validation profile"
        assert result.policy_ids == ["opa/ticket-update-locked-ticket"]
        assert result.grant is None

        event = wait_for_audit_event(oap, request_id)
        assert event["decision"] == "deny"
        assert event["policy_ids"] == ["opa/ticket-update-locked-ticket"]
        assert "grant_id" not in event

    def test_opa_require_approval_maps_approval_details(self, oap: OAPTestClient):
        request_id = new_request_id("approval")
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id=ACTOR_ID,
            action="message.send",
            resource_type="slack.channel",
            resource_id="slack:#external-customer-updates",
            resource_owner="channel:external",
            request_id=request_id,
        )

        assert result.status_code == 200
        assert result.decision == "require_approval"
        assert result.policy_ids == ["opa/external-message-approval"]
        assert result.grant is None
        assert result.body["approval"]["approvers"] == ["group:support-managers"]
        assert result.body["approval"]["expires_in_seconds"] == 1800

        event = wait_for_audit_event(oap, request_id)
        assert event["decision"] == "require_approval"
        assert event["policy_ids"] == ["opa/external-message-approval"]


class TestOPAUnavailableFailClosed:
    def test_unavailable_opa_backend_denies_and_audits(
        self,
        keycloak: KeycloakClient,
    ):
        token = keycloak.get_client_credentials_token(
            client_secret=AGENT_CLIENT_SECRET,
        )
        bootstrap = OAPTestClient(OAP_FAIL_CLOSED_SERVER_URL)
        session = bootstrap.create_session(
            agent_id=AGENT_ID,
            runtime_token=token.access_token,
            environment="validation",
        )
        fail_closed_oap = OAPTestClient(
            OAP_FAIL_CLOSED_SERVER_URL,
            bearer_token=session["session_id"],
        )

        health = fail_closed_oap.health()
        assert health["policy_backend"] == "opa"

        request_id = new_request_id("fail-closed")
        result = fail_closed_oap.authorize(
            agent_id=AGENT_ID,
            actor_id=ACTOR_ID,
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
            request_id=request_id,
        )

        assert result.status_code == 200
        assert result.decision == "deny"
        assert "fail-closed" in result.reason
        assert result.grant is None

        event = wait_for_audit_event(fail_closed_oap, request_id)
        assert event["decision"] == "deny"
        assert event["action"] == "ticket.read"
