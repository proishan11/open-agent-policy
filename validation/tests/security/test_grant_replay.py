"""Security tests: Grant/approval replay prevention.

Validates that approvals are scoped and cannot be reused across
different resources, actors, agents, or after expiry.
"""

from __future__ import annotations

import pytest
from conftest import ApprovalAPIClient

TICKET_AGENT = "agent://support/ticket-assistant"
ROGUE_AGENT = "agent://unknown/rogue-agent"


@pytest.fixture
def approved_grant(approval_api: ApprovalAPIClient) -> str:
    """Create and approve a grant for alice / T-100 / ticket.read."""
    approval = approval_api.create_approval(
        agent_id=TICKET_AGENT,
        actor_id="alice@company.test",
        action="ticket.read",
        resource_type="support.ticket",
        resource_id="T-100",
    )
    approval_api.decide_approval(
        approval["id"], "charlie@company.test", "approved"
    )
    return approval["id"]


class TestGrantReplay:
    def test_valid_scope_accepted(
        self, approval_api: ApprovalAPIClient, approved_grant: str
    ):
        result = approval_api.validate_approval(
            approved_grant,
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="ticket.read",
            resource_id="T-100",
        )
        assert result["valid"] is True

    def test_wrong_resource_denied(
        self, approval_api: ApprovalAPIClient, approved_grant: str
    ):
        result = approval_api.validate_approval(
            approved_grant,
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="ticket.read",
            resource_id="T-200",
        )
        assert result["valid"] is False

    def test_wrong_agent_denied(
        self, approval_api: ApprovalAPIClient, approved_grant: str
    ):
        result = approval_api.validate_approval(
            approved_grant,
            agent_id=ROGUE_AGENT,
            actor_id="alice@company.test",
            action="ticket.read",
            resource_id="T-100",
        )
        assert result["valid"] is False

    def test_wrong_actor_denied(
        self, approval_api: ApprovalAPIClient, approved_grant: str
    ):
        result = approval_api.validate_approval(
            approved_grant,
            agent_id=TICKET_AGENT,
            actor_id="bob@company.test",
            action="ticket.read",
            resource_id="T-100",
        )
        assert result["valid"] is False

    def test_wrong_action_denied(
        self, approval_api: ApprovalAPIClient, approved_grant: str
    ):
        result = approval_api.validate_approval(
            approved_grant,
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="customer.read",
            resource_id="T-100",
        )
        assert result["valid"] is False

    def test_nonexistent_grant_denied(self, approval_api: ApprovalAPIClient):
        result = approval_api.validate_approval(
            "APR-nonexistent",
            agent_id=TICKET_AGENT,
            actor_id="alice@company.test",
            action="ticket.read",
            resource_id="T-100",
        )
        assert result["valid"] is False
