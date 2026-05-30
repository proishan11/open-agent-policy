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
    from pydantic import ConfigDict
except ImportError:
    BaseTool = None  # type: ignore[assignment,misc]
    ConfigDict = None  # type: ignore[assignment,misc]


_BaseTool = BaseTool if BaseTool is not None else object


class OAPToolWrapper(_BaseTool):  # type: ignore[misc,valid-type]
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

    tool: Any
    client: Any
    agent_id: str = ""
    action: str = ""
    resource_type: str = ""
    if ConfigDict is not None:
        model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(
        self,
        tool: Any,
        client: OAPClient,
        agent_id: str = "",
        action: str = "",
        resource_type: str = "",
    ) -> None:
        tool_name = getattr(tool, "name", "unknown")
        resolved_action = action or tool_name

        if BaseTool is not None:
            super().__init__(
                name=tool_name,
                description=getattr(tool, "description", ""),
                args_schema=getattr(tool, "args_schema", None),
                tool=tool,
                client=client,
                agent_id=agent_id,
                action=resolved_action,
                resource_type=resource_type,
            )
            return

        self.tool = tool
        self.client = client
        self.agent_id = agent_id
        self.action = resolved_action
        self.resource_type = resource_type
        self.name = tool_name
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
        if BaseTool is not None:
            return super().invoke(input, config=config, **kwargs)
        return self._authorize_and_invoke(input, config=config, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """LangChain BaseTool execution hook."""
        tool_input = kwargs if kwargs else (args[0] if args else {})
        return self._authorize_and_invoke(tool_input)

    def _authorize_and_invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Authorize an input and invoke the wrapped tool."""
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

        tool_input = dict(input) if isinstance(input, dict) else input

        # Inject enforcement metadata into dict inputs so tools can call
        # resource APIs with the scoped grant and honor constraints.
        if isinstance(tool_input, dict):
            if decision.constraints:
                tool_input["oap_constraints"] = decision.constraints
            if decision.grant:
                tool_input["oap_grant_token"] = decision.grant.token
                tool_input["oap_grant"] = decision.grant

        if hasattr(self.tool, "invoke"):
            return self.tool.invoke(tool_input, config=config, **kwargs)
        if isinstance(tool_input, dict):
            return self.tool(**tool_input)
        return self.tool(tool_input)


    def run(self, input: Any, **kwargs: Any) -> Any:
        """Convenience method matching BaseTool.run()."""
        if BaseTool is not None:
            return BaseTool.run(self, input, **kwargs)
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
