"""Tests for LangChain integration (OAPToolWrapper, protect_tools).

These tests mock the OAPClient and use a simple fake tool instead of
requiring langchain-core as a dependency.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from open_agent_policy.client import Decision
from open_agent_policy.errors import PermissionDeniedError, ApprovalRequiredError
from open_agent_policy.integrations.langchain import OAPToolWrapper, protect_tools


class FakeTool:
    """Minimal fake tool that mimics BaseTool.invoke()."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.args_schema = None
        self._call_log: list = []

    def invoke(self, input, config=None, **kwargs):
        self._call_log.append(input)
        if isinstance(input, dict):
            return f"result for {input}"
        return f"result for {input}"


def make_mock_client(decision_data: dict) -> MagicMock:
    client = MagicMock()
    client.authorize.return_value = Decision.from_dict(decision_data)
    client.default_agent_id = "agent://test/mock"
    return client


class TestOAPToolWrapper:
    def test_allow_calls_tool(self):
        client = make_mock_client({"decision": "allow"})
        tool = FakeTool("read_ticket")
        wrapper = OAPToolWrapper(
            tool=tool,
            client=client,
            agent_id="agent://support/assistant",
            action="tickets.read",
        )

        result = wrapper.invoke("TICKET-1")
        assert "result for TICKET-1" in result
        assert len(tool._call_log) == 1
        client.authorize.assert_called_once()

    def test_deny_blocks_tool(self):
        client = make_mock_client({"decision": "deny", "reason": "denied"})
        tool = FakeTool("delete_ticket")
        wrapper = OAPToolWrapper(
            tool=tool,
            client=client,
            agent_id="agent://support/assistant",
            action="tickets.delete",
        )

        with pytest.raises(PermissionDeniedError):
            wrapper.invoke("TICKET-1")
        assert len(tool._call_log) == 0  # tool should NOT have been called

    def test_constrained_injects_into_dict_input(self):
        client = make_mock_client({
            "decision": "allow_with_constraints",
            "constraints": {"max_records": 5},
        })
        tool = FakeTool("search_tickets")
        wrapper = OAPToolWrapper(
            tool=tool,
            client=client,
            agent_id="agent://support/assistant",
            action="tickets.search",
        )

        wrapper.invoke({"query": "open bugs"})
        # Tool should have been called with constraints injected
        called_input = tool._call_log[0]
        assert called_input["oap_constraints"]["max_records"] == 5

    def test_grant_token_injects_into_dict_input(self):
        client = make_mock_client({
            "decision": "allow",
            "grant": {
                "grant_id": "grant-1",
                "token": "jwt-token",
                "expires_in_seconds": 300,
            },
        })
        tool = FakeTool("read_ticket")
        wrapper = OAPToolWrapper(
            tool=tool,
            client=client,
            agent_id="agent://support/assistant",
            action="tickets.read",
        )

        wrapper.invoke({"id": "TICKET-1"})
        called_input = tool._call_log[0]
        assert called_input["oap_grant_token"] == "jwt-token"

    def test_approval_required_raises(self):
        client = make_mock_client({
            "decision": "require_approval",
            "approval": {"approvers": ["manager"]},
        })
        tool = FakeTool("escalate_ticket")
        wrapper = OAPToolWrapper(
            tool=tool, client=client,
            agent_id="agent://support/assistant",
        )

        with pytest.raises(ApprovalRequiredError):
            wrapper.invoke("TICKET-1")
        assert len(tool._call_log) == 0

    def test_preserves_tool_metadata(self):
        client = make_mock_client({"decision": "allow"})
        tool = FakeTool("read_ticket", description="Read a support ticket")
        wrapper = OAPToolWrapper(tool=tool, client=client, agent_id="agent://test/a")

        assert wrapper.name == "read_ticket"
        assert wrapper.description == "Read a support ticket"

    def test_callable(self):
        client = make_mock_client({"decision": "allow"})
        tool = FakeTool("read_ticket")
        wrapper = OAPToolWrapper(tool=tool, client=client, agent_id="agent://test/a")

        result = wrapper("TICKET-1")
        assert "result" in result

    def test_run_method(self):
        client = make_mock_client({"decision": "allow"})
        tool = FakeTool("read_ticket")
        wrapper = OAPToolWrapper(tool=tool, client=client, agent_id="agent://test/a")

        result = wrapper.run("TICKET-1")
        assert "result" in result


class TestProtectTools:
    def test_wraps_all_tools(self):
        client = make_mock_client({"decision": "allow"})
        tools = [FakeTool("tool_a"), FakeTool("tool_b"), FakeTool("tool_c")]

        protected = protect_tools(
            tools,
            client=client,
            agent_id="agent://test/agent",
        )

        assert len(protected) == 3
        assert all(isinstance(t, OAPToolWrapper) for t in protected)

    def test_action_prefix(self):
        client = make_mock_client({"decision": "allow"})
        tools = [FakeTool("read"), FakeTool("write")]

        protected = protect_tools(
            tools,
            client=client,
            agent_id="agent://test/agent",
            action_prefix="tickets.",
        )

        assert protected[0].action == "tickets.read"
        assert protected[1].action == "tickets.write"

    def test_wrapped_tool_exports_langchain_schema(self):
        """Wrapped tools should be usable with real LangChain tool binding."""
        function_calling = pytest.importorskip("langchain_core.utils.function_calling")
        tools_module = pytest.importorskip("langchain_core.tools")

        @tools_module.tool
        def read_customer(customer_id: str) -> str:
            """Read a customer record."""
            return customer_id

        client = make_mock_client({"decision": "allow"})
        protected = OAPToolWrapper(
            tool=read_customer,
            client=client,
            agent_id="agent://test/agent",
            action="customers.read",
        )

        schema = function_calling.convert_to_openai_tool(protected)

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "read_customer"
        assert schema["function"]["parameters"]["properties"]["customer_id"]["type"] == "string"
