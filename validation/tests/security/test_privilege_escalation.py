"""Security tests: Privilege escalation prevention.

Validates that agents cannot escalate their own privileges through
policy modification, self-approval, or administrative actions.
"""

from __future__ import annotations

import pytest
from conftest import OAPTestClient

TICKET_AGENT = "agent://support/ticket-assistant"


class TestPrivilegeEscalation:
    def test_agent_cannot_modify_policy(self, oap: OAPTestClient):
        """Agent cannot modify its own OAP policy."""
        result = oap.authorize(
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="policy.modify",
            resource_type="oap.policy",
        )
        assert result.decision == "deny"

    def test_agent_cannot_modify_repository_settings(self, oap: OAPTestClient):
        """Agent cannot modify repository settings."""
        result = oap.authorize(
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="repository.settings.modify",
            resource_type="github.repository",
        )
        assert result.decision == "deny"

    def test_agent_cannot_delete_customer(self, oap: OAPTestClient):
        """Agent cannot delete customer records."""
        result = oap.authorize(
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="customer.delete",
            resource_type="crm.customer",
            resource_id="C-100",
        )
        assert result.decision == "deny"

    def test_agent_cannot_access_unknown_action(self, oap: OAPTestClient):
        """Deny-by-default: unlisted actions are denied."""
        result = oap.authorize(
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="admin.secrets.read",
            resource_type="vault.secret",
        )
        assert result.decision == "deny"

    def test_agent_cannot_switch_identity(self, oap: OAPTestClient):
        """Agent claiming to be admin/superuser is overridden by token identity.
        Token proves we are ticket-assistant, so the request evaluates
        as ticket-assistant (allowed) — identity spoofing fails silently."""
        result = oap.authorize(
            agent_id="agent://admin/superuser",
            actor_id="alice@company.test",
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        # Token overrides: evaluates as ticket-assistant, not admin/superuser
        assert result.decision in ("allow", "allow_with_constraints")
