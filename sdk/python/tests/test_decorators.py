"""Tests for the @protect decorator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from open_agent_policy.client import Decision
from open_agent_policy.decorators import protect
from open_agent_policy.errors import ApprovalRequiredError, PermissionDeniedError


def make_mock_client(decision_data: dict) -> MagicMock:
    """Create a mock OAPClient that returns the given decision."""
    client = MagicMock()
    client.authorize.return_value = Decision.from_dict(decision_data)
    client.default_agent_id = "agent://test/mock"
    return client


class TestProtectDecorator:
    def test_allow_calls_function(self):
        client = make_mock_client({"decision": "allow"})

        @protect(client, agent_id="agent://test/agent", action="test.read")
        def read_data(item_id: str, **kwargs) -> str:
            return f"data-{item_id}"

        result = read_data("item-1")
        assert result == "data-item-1"
        client.authorize.assert_called_once()

    def test_deny_raises_permission_denied(self):
        client = make_mock_client({
            "decision": "deny",
            "reason": "not allowed",
            "policy_ids": ["test/deny"],
        })

        @protect(client, agent_id="agent://test/agent", action="test.write")
        def write_data(item_id: str) -> str:
            return "should not reach here"

        with pytest.raises(PermissionDeniedError) as exc_info:
            write_data("item-1")
        assert "not allowed" in str(exc_info.value)
        assert exc_info.value.policy_ids == ["test/deny"]

    def test_deny_return_none_mode(self):
        client = make_mock_client({"decision": "deny", "reason": "denied"})

        @protect(client, agent_id="agent://test/agent", action="test.write", on_deny="return_none")
        def write_data(item_id: str) -> str:
            return "should not reach here"

        result = write_data("item-1")
        assert result is None

    def test_constrained_injects_constraints(self):
        client = make_mock_client({
            "decision": "allow_with_constraints",
            "constraints": {"max_records": 10, "readonly": True},
        })

        @protect(client, agent_id="agent://test/agent", action="test.read")
        def read_data(item_id: str, **kwargs) -> dict:
            return {"id": item_id, "constraints": kwargs.get("oap_constraints")}

        result = read_data("item-1")
        assert result["constraints"]["max_records"] == 10
        assert result["constraints"]["readonly"] is True

    def test_require_approval_raises(self):
        client = make_mock_client({
            "decision": "require_approval",
            "reason": "needs approval",
            "approval": {"approvers": ["group:leads"], "approval_id": "apr-1"},
        })

        @protect(client, agent_id="agent://test/agent", action="test.approve")
        def approve_data(item_id: str) -> str:
            return "should not reach here"

        with pytest.raises(ApprovalRequiredError) as exc_info:
            approve_data("item-1")
        assert "group:leads" in exc_info.value.approvers

    def test_metadata_attached(self):
        client = make_mock_client({"decision": "allow"})

        @protect(client, agent_id="agent://test/agent", action="custom.action")
        def my_tool(x: str) -> str:
            return x

        assert my_tool._oap_protected is True
        assert my_tool._oap_action == "custom.action"
        assert my_tool._oap_agent_id == "agent://test/agent"

    def test_action_defaults_to_function_name(self):
        client = make_mock_client({"decision": "allow"})

        @protect(client, agent_id="agent://test/agent")
        def read_invoice(invoice_id: str, **kwargs) -> str:
            return invoice_id

        assert read_invoice._oap_action == "read_invoice"
        read_invoice("INV-1")
        call_kwargs = client.authorize.call_args
        assert call_kwargs.kwargs.get("action") or call_kwargs[1].get("action") == "read_invoice"

    def test_resource_id_from_first_arg(self):
        client = make_mock_client({"decision": "allow"})

        @protect(client, agent_id="agent://test/agent", action="test.read", resource_type="items")
        def read_item(item_id: str, **kwargs) -> str:
            return item_id

        read_item("ITEM-42")
        call_kwargs = client.authorize.call_args
        # resource_id should be "ITEM-42" (extracted from first positional arg)
        assert call_kwargs[1].get("resource_id") == "ITEM-42" or \
            call_kwargs.kwargs.get("resource_id") == "ITEM-42"
