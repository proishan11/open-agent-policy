"""Security tests: direct resource API bypass prevention."""

from __future__ import annotations

from conftest import CustomerAPIClient, OAPTestClient, TicketAPIClient, grant_for

TICKET_AGENT = "agent://support/ticket-assistant"


class TestDirectBypass:
    def test_ticket_api_rejects_missing_grant(self, ticket_api: TicketAPIClient):
        """Ticket API is not directly accessible without an OAP grant."""
        resp = ticket_api.get_ticket_raw("T-100")
        assert resp.status_code == 401

    def test_customer_api_rejects_missing_grant(self, customer_api: CustomerAPIClient):
        """Customer API is not directly accessible without an OAP grant."""
        resp = customer_api.get_customer_raw("C-100")
        assert resp.status_code == 401

    def test_ticket_api_accepts_scoped_grant(
        self, oap: OAPTestClient, ticket_api: TicketAPIClient
    ):
        """A valid OAP grant unlocks only the scoped ticket resource."""
        grant = grant_for(
            oap,
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        ticket = ticket_api.get_ticket("T-100", grant)
        assert ticket["id"] == "T-100"

    def test_ticket_api_rejects_wrong_resource_grant(
        self, oap: OAPTestClient, ticket_api: TicketAPIClient
    ):
        """A grant for T-100 cannot be replayed against T-200."""
        grant = grant_for(
            oap,
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        resp = ticket_api.get_ticket_raw("T-200", grant)
        assert resp.status_code == 403

    def test_customer_api_applies_redaction_constraints(
        self, oap: OAPTestClient, customer_api: CustomerAPIClient
    ):
        """Resource-side enforcement applies grant constraints, not just allow/deny."""
        grant = grant_for(
            oap,
            action="customer.read",
            resource_type="crm.customer",
            resource_id="C-100",
        )
        customer = customer_api.get_customer("C-100", grant)
        assert customer["tax_identifier"] == "<redacted>"
        assert customer["billing_account"] == "<redacted>"
        assert customer["bank_account"] == "<redacted>"

    def test_oap_rejects_unauthenticated(self, oap_unauthenticated: OAPTestClient):
        """OAP rejects requests without a valid agent token."""
        resp = oap_unauthenticated.authorize_raw(
            agent_id="agent://unknown/bypass-agent",
            actor_id="attacker@evil.com",
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        assert resp.status_code == 401

    def test_identity_spoofing_overridden_by_token(self, oap: OAPTestClient):
        """Claiming a different agent_id is overridden by the verified token.
        The support-agent token proves identity as ticket-assistant,
        so even claiming revoked-agent results in ticket-assistant evaluation."""
        result = oap.authorize(
            agent_id="agent://support/revoked-agent",
            actor_id="alice@company.test",
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        # Token overrides: evaluates as ticket-assistant, not revoked-agent
        assert result.decision in ("allow", "allow_with_constraints")
