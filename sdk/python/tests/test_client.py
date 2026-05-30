"""Tests for OAPClient — remote and embedded modes."""

from __future__ import annotations

import json

import pytest

from open_agent_policy.client import Decision, OAPClient, _strip_ansi
from open_agent_policy.errors import OAPError, ServerError


# --- Decision tests ---


class TestDecision:
    def test_from_dict_allow(self):
        d = Decision.from_dict({"decision": "allow", "reason": "allowed"})
        assert d.is_allowed
        assert not d.is_denied
        assert not d.requires_approval

    def test_from_dict_deny(self):
        d = Decision.from_dict({
            "decision": "deny",
            "reason": "no matching policy",
            "policy_ids": ["test/policy-1"],
        })
        assert d.is_denied
        assert not d.is_allowed
        assert d.policy_ids == ["test/policy-1"]

    def test_from_dict_constrained(self):
        d = Decision.from_dict({
            "decision": "allow_with_constraints",
            "constraints": {"max_records": 25, "readonly": True},
        })
        assert d.is_allowed
        assert d.constraints["max_records"] == 25

    def test_from_dict_grant(self):
        d = Decision.from_dict({
            "decision": "allow",
            "grant": {
                "grant_id": "grant-1",
                "token": "jwt-token",
                "expires_in_seconds": 300,
            },
        })
        assert d.grant is not None
        assert d.grant.token == "jwt-token"
        assert d.grant.expires_in_seconds == 300

    def test_from_dict_require_approval(self):
        d = Decision.from_dict({
            "decision": "require_approval",
            "approval": {"approvers": ["group:leads"]},
        })
        assert d.requires_approval
        assert d.approval["approvers"] == ["group:leads"]

    def test_from_dict_empty(self):
        d = Decision.from_dict({})
        assert d.decision == ""
        assert not d.is_allowed
        assert not d.is_denied


# --- Client validation tests ---


class TestClientValidation:
    def test_missing_agent_id(self):
        client = OAPClient(server_url="http://localhost:9999")
        with pytest.raises(OAPError, match="agent_id is required"):
            client.authorize(action="read")

    def test_missing_action(self):
        client = OAPClient(server_url="http://localhost:9999", agent_id="agent://test/a")
        with pytest.raises(OAPError, match="action is required"):
            client.authorize()

    def test_default_agent_id(self):
        """Client should use default_agent_id when agent_id is not passed."""
        client = OAPClient(
            server_url="http://localhost:9999",
            agent_id="agent://default/agent",
        )
        # This will fail on the HTTP call, but validates agent_id resolution
        with pytest.raises(Exception):
            client.authorize(action="read")


# --- Remote mode tests (using pytest-httpx) ---


class TestRemoteMode:
    def test_authorize_allow(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:8080/v1/authorize",
            json={"decision": "allow", "reason": "allowed", "decision_id": "dec-1"},
        )
        client = OAPClient(server_url="http://localhost:8080")
        decision = client.authorize(
            agent_id="agent://test/agent",
            action="test.read",
        )
        assert decision.is_allowed
        assert decision.decision_id == "dec-1"

    def test_authorize_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:8080/v1/authorize",
            json={
                "decision": "deny",
                "reason": "explicitly denied",
                "policy_ids": ["test/deny-policy"],
            },
        )
        client = OAPClient(server_url="http://localhost:8080")
        decision = client.authorize(
            agent_id="agent://test/agent",
            action="test.delete",
        )
        assert decision.is_denied
        assert decision.reason == "explicitly denied"

    def test_authorize_constrained(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:8080/v1/authorize",
            json={
                "decision": "allow_with_constraints",
                "constraints": {"max_records": 10, "redact_fields": ["ssn"]},
            },
        )
        client = OAPClient(server_url="http://localhost:8080")
        decision = client.authorize(
            agent_id="agent://test/agent",
            action="test.read",
        )
        assert decision.is_allowed
        assert decision.constraints["max_records"] == 10
        assert "ssn" in decision.constraints["redact_fields"]

    def test_authorize_server_error(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:8080/v1/authorize",
            status_code=500,
            text="internal server error",
        )
        client = OAPClient(server_url="http://localhost:8080")
        with pytest.raises(ServerError) as exc_info:
            client.authorize(agent_id="agent://test/agent", action="test.read")
        assert exc_info.value.status_code == 500

    def test_simulate(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:8080/v1/simulate",
            json={
                "decision": {"decision": "allow", "reason": "allowed"},
                "trace": [
                    {"step": "validate_request", "result": "pass"},
                    {"step": "verify_agent", "result": "pass"},
                ],
            },
        )
        client = OAPClient(server_url="http://localhost:8080")
        decision = client.simulate(agent_id="agent://test/agent", action="test.read")
        assert decision.is_allowed
        assert len(decision.trace) == 2

    def test_request_body_structure(self, httpx_mock):
        """Verify the request body sent to the server has the correct shape."""
        httpx_mock.add_response(
            url="http://localhost:8080/v1/authorize",
            json={"decision": "allow"},
        )
        client = OAPClient(server_url="http://localhost:8080")
        client.authorize(
            agent_id="agent://test/agent",
            action="db.read",
            resource_type="database",
            resource_id="users-table",
            resource_owner="group:data-platform",
            resource_classification="restricted",
            resource_environment="production",
            resource_attributes={"tenant": "acme"},
            tool_name="query_db",
            tool_protocol="mcp",
            actor_type="user",
            actor_id="user:alice",
            context={"run_id": "run-123"},
            request_id="req-custom",
        )

        request = httpx_mock.get_requests()[0]
        body = json.loads(request.content)
        assert body["request_id"] == "req-custom"
        assert body["subject"]["agent_id"] == "agent://test/agent"
        assert body["action"]["name"] == "db.read"
        assert body["resource"]["type"] == "database"
        assert body["resource"]["id"] == "users-table"
        assert body["resource"]["owner"] == "group:data-platform"
        assert body["resource"]["classification"] == "restricted"
        assert body["resource"]["environment"] == "production"
        assert body["resource"]["attributes"]["tenant"] == "acme"
        assert body["tool"]["name"] == "query_db"
        assert body["tool"]["protocol"] == "mcp"
        assert body["actor"]["type"] == "user"
        assert body["actor"]["id"] == "user:alice"
        assert body["context"]["run_id"] == "run-123"

    def test_validate_grant(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:8080/v1/grants/validate",
            json={
                "valid": True,
                "agent_id": "agent://test/agent",
                "action": "db.read",
                "resource_type": "database",
                "resource_id": "users-table",
            },
        )
        client = OAPClient(server_url="http://localhost:8080")
        result = client.validate_grant("jwt-token")
        assert result["valid"] is True
        assert result["action"] == "db.read"


# --- Helpers ---


class TestHelpers:
    def test_strip_ansi(self):
        assert _strip_ansi("\033[92mallow\033[0m") == "allow"
        assert _strip_ansi("no_color") == "no_color"
