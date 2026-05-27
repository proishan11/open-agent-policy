"""Security tests: Direct API bypass prevention.

Validates that resource APIs are accessible directly (documenting the gap)
and that OAP-governed paths enforce authorization.
"""

from __future__ import annotations

import pytest
from conftest import OAPTestClient, TicketAPIClient, CustomerAPIClient

TICKET_AGENT = "agent://support/ticket-assistant"


class TestDirectBypass:
    def test_ticket_api_direct_access_baseline(self, ticket_api: TicketAPIClient):
        """
        Baseline: ticket API is directly accessible without OAP.
        This documents the current state. After hardening (network policy
        or grant validation), this should return 401/403.
        """
        ticket = ticket_api.get_ticket("T-100")
        assert ticket["id"] == "T-100"

    def test_customer_api_direct_access_baseline(self, customer_api: CustomerAPIClient):
        """
        Baseline: customer API is directly accessible without OAP.
        Documents the gap for future hardening.
        """
        customer = customer_api.get_customer("C-100")
        assert customer["id"] == "C-100"

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
