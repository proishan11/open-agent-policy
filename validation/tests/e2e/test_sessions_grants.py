"""Tests for session lifecycle, runs, and grant issuance/validation.

Validates the Phase 2 flow:
  1. Session creation (identity binding verification)
  2. Run creation within a session
  3. Grant issuance on allow decisions
  4. Grant validation by resource APIs
"""

from __future__ import annotations

import pytest

from conftest import OAPTestClient

AGENT_ID = "agent://support/ticket-assistant"


# ── Session lifecycle ─────────────────────────────────────────────────

class TestSessionLifecycle:
    def test_session_created_with_valid_binding(self, agent_session: dict):
        """Session should be created when runtime token matches identity binding."""
        assert agent_session["session_id"].startswith("ags_")
        assert agent_session["agent_id"] == AGENT_ID
        assert agent_session["status"] == "active"
        assert agent_session["expires_in"] == 900

    def test_session_token_authorizes(self, oap: OAPTestClient):
        """Session token should work for authorize calls."""
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id="alice@company.test",
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        assert result.decision in ("allow", "allow_with_constraints")


# ── Runs ──────────────────────────────────────────────────────────────

class TestRunLifecycle:
    def test_create_run(self, oap: OAPTestClient, agent_session: dict):
        """Create a run within an active session."""
        run = oap.create_run(
            session_id=agent_session["session_id"],
            actor_type="user",
            actor_id="alice@company.test",
            purpose="ticket_summary",
        )
        assert run["run_id"].startswith("run_")
        assert run["agent_id"] == AGENT_ID
        assert run["session_id"] == agent_session["session_id"]
        assert run["status"] == "active"
        assert run["actor"]["id"] == "alice@company.test"

    def test_run_with_invalid_session_rejected(self, oap: OAPTestClient):
        """Run creation should fail with an invalid session ID."""
        with pytest.raises(RuntimeError, match="Run creation failed"):
            oap.create_run(
                session_id="ags_invalid_nonexistent",
                purpose="should_fail",
            )


# ── Grant issuance ────────────────────────────────────────────────────

class TestGrantIssuance:
    def test_allow_decision_includes_grant(self, oap: OAPTestClient):
        """Allow decisions should include a signed grant token."""
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id="alice@company.test",
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        assert result.decision in ("allow", "allow_with_constraints")
        assert result.grant is not None
        assert "token" in result.grant
        assert result.grant["expires_in_seconds"] == 300

    def test_deny_decision_has_no_grant(self, oap: OAPTestClient):
        """Deny decisions should NOT include a grant."""
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id="alice@company.test",
            action="customer.bulk_export",
            resource_type="support.customer",
            resource_id="C-100",
        )
        assert result.decision == "deny"
        assert result.grant is None


# ── Grant validation ──────────────────────────────────────────────────

class TestGrantValidation:
    def test_validate_valid_grant(self, oap: OAPTestClient):
        """Resource API can validate a grant token from OAP."""
        # 1. Get a grant from an allow decision
        result = oap.authorize(
            agent_id=AGENT_ID,
            actor_id="alice@company.test",
            action="ticket.read",
            resource_type="support.ticket",
            resource_id="T-100",
        )
        assert result.grant is not None
        grant_token = result.grant["token"]

        # 2. Validate the grant
        validation = oap.validate_grant(grant_token)
        assert validation["valid"] is True
        assert validation["agent_id"] == AGENT_ID
        assert validation["action"] == "ticket.read"
        assert validation["resource_type"] == "support.ticket"
        assert validation["resource_id"] == "T-100"
        assert validation["decision"] in ("allow", "allow_with_constraints")

    def test_validate_forged_grant_rejected(self, oap: OAPTestClient):
        """Forged/tampered grant tokens should be rejected."""
        validation = oap.validate_grant("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.invalid")
        assert validation.get("valid") is not True or "code" in validation

    def test_validate_empty_grant_rejected(self, oap: OAPTestClient):
        """Empty grant token should be rejected."""
        resp = oap.client.post(
            f"{oap.base_url}/v1/grants/validate",
            json={"grant_token": ""},
        )
        assert resp.status_code == 400
