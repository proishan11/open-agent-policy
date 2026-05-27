"""LangChain/LangGraph integration for OAP.

OAPToolWrapper wraps any LangChain BaseTool with automatic authorization.
Every tool invocation is authorized against OAP before execution.

Usage with LangChain::

    from langchain_core.tools import tool
    from open_agent_policy import OAPClient
    from open_agent_policy.integrations.langchain import OAPToolWrapper

    client = OAPClient(server_url="http://localhost:8080")

    @tool
    def read_ticket(ticket_id: str) -> str:
        return f"Ticket {ticket_id} details..."

    # Wrap the tool with OAP authorization
    protected_read = OAPToolWrapper(
        tool=read_ticket,
        client=client,
        agent_id="agent://support/ticket-assistant",
        action="tickets.read",
    )

    # Use protected_read in your agent — it behaves like a normal tool
    # but every call is authorized first

Usage as middleware (wraps all tools in an agent)::

    from open_agent_policy.integrations.langchain import protect_tools

    tools = [read_ticket, update_ticket, send_message]
    protected_tools = protect_tools(
        tools,
        client=client,
        agent_id="agent://support/ticket-assistant",
    )
"""

from __future__ import annotations

from typing import Any

from open_agent_policy.client import OAPClient
from open_agent_policy.errors import ApprovalRequiredError, PermissionDeniedError

# Conditional import — langchain-core is an optional dependency
try:
    from langchain_core.tools import BaseTool
except ImportError:
    BaseTool = None  # type: ignore[assignment,misc]


class OAPToolWrapper:
    """Wraps a LangChain BaseTool with OAP authorization.

    Every invocation calls client.authorize() before running the tool.
    Denied calls raise PermissionDeniedError. Constrained calls inject
    constraints into the tool input.

    Args:
        tool: The LangChain tool to wrap.
        client: An OAPClient instance.
        agent_id: Agent identifier.
        action: Action name (defaults to tool.name if not provided).
        resource_type: Resource type for authorization.
    """

    def __init__(
        self,
        tool: Any,
        client: OAPClient,
        agent_id: str = "",
        action: str = "",
        resource_type: str = "",
    ) -> None:
        self.tool = tool
        self.client = client
        self.agent_id = agent_id
        self.action = action or getattr(tool, "name", "unknown")
        self.resource_type = resource_type

        # Preserve tool metadata so LangChain sees this as a valid tool
        self.name = getattr(tool, "name", "unknown")
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Authorize and invoke the wrapped tool.

        Args:
            input: Tool input (string or dict).
            config: LangChain runnable config.
            **kwargs: Additional arguments passed to the tool.

        Returns:
            Tool output if authorized.

        Raises:
            PermissionDeniedError: If the action is denied.
            ApprovalRequiredError: If approval is needed.
        """
        # Extract resource_id from input if possible
        resource_id = ""
        if isinstance(input, dict):
            resource_id = str(input.get("resource_id", input.get("id", "")))
        elif isinstance(input, str):
            resource_id = input

        decision = self.client.authorize(
            agent_id=self.agent_id,
            action=self.action,
            resource_type=self.resource_type,
            resource_id=resource_id,
            tool_name=self.name,
        )

        if decision.is_denied:
            raise PermissionDeniedError(
                message=f"Tool '{self.name}' denied: {decision.reason}",
                reason=decision.reason,
                policy_ids=decision.policy_ids,
                decision_id=decision.decision_id,
            )

        if decision.requires_approval:
            raise ApprovalRequiredError(
                message=f"Tool '{self.name}' requires approval: {decision.reason}",
                approvers=decision.approval.get("approvers", []),
            )

        # Inject constraints into tool input if present
        if decision.constraints and isinstance(input, dict):
            input["oap_constraints"] = decision.constraints

        return self.tool.invoke(input, config=config, **kwargs)

    def run(self, input: Any, **kwargs: Any) -> Any:
        """Convenience method matching BaseTool.run()."""
        return self.invoke(input, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Make wrapper callable like the original tool."""
        return self.invoke(*args, **kwargs)


def protect_tools(
    tools: list[Any],
    client: OAPClient,
    agent_id: str = "",
    action_prefix: str = "",
    resource_type: str = "",
) -> list[OAPToolWrapper]:
    """Wrap a list of LangChain tools with OAP authorization.

    This is the "one-line integration" for protecting all tools in an agent.

    Args:
        tools: List of LangChain tools.
        client: OAPClient instance.
        agent_id: Agent identifier.
        action_prefix: Prefix for action names (e.g., "tickets." → "tickets.read_ticket").
        resource_type: Default resource type for all tools.

    Returns:
        List of OAPToolWrapper instances.
    """
    wrapped = []
    for tool in tools:
        tool_name = getattr(tool, "name", str(tool))
        action = f"{action_prefix}{tool_name}" if action_prefix else tool_name
        wrapped.append(
            OAPToolWrapper(
                tool=tool,
                client=client,
                agent_id=agent_id,
                action=action,
                resource_type=resource_type,
            )
        )
    return wrapped
