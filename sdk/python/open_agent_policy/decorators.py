"""The @protect decorator for automatic tool authorization.

Wraps a tool function so that every invocation is authorized against
OAP before execution. Denied calls raise PermissionDeniedError.
Constrained calls inject an ``oap_constraints`` kwarg.
Allowed calls with scoped grants inject ``oap_grant_token`` when the wrapped
function accepts it.

Example::

    from open_agent_policy import OAPClient, protect

    client = OAPClient(server_url="http://localhost:8080")

    @protect(client, agent_id="agent://finance/reconciler", action="erp.invoice.read")
    def read_invoice(invoice_id: str, **kwargs) -> dict:
        constraints = kwargs.get("oap_constraints", {})
        grant_token = kwargs.get("oap_grant_token")
        max_records = constraints.get("max_records", 100)
        redact = constraints.get("redact_fields", [])
        # ... apply constraints to query ...
        return {"id": invoice_id}

The decorator calls ``client.authorize()`` with the configured agent_id
and action. If the decision is:

- **allow**: calls the function normally
- **allow_with_constraints**: injects ``oap_constraints`` into kwargs, then calls
- **allow/allow_with_constraints with grant**: injects ``oap_grant_token`` when accepted
- **deny**: raises PermissionDeniedError
- **require_approval**: raises ApprovalRequiredError
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from open_agent_policy.client import OAPClient
from open_agent_policy.errors import ApprovalRequiredError, PermissionDeniedError


def protect(
    client: OAPClient,
    agent_id: str = "",
    action: str = "",
    *,
    resource_type: str = "",
    tool_name: str = "",
    on_deny: str = "raise",
) -> Callable:
    """Decorator factory that wraps a tool function with OAP authorization.

    Args:
        client: An OAPClient instance.
        agent_id: Agent identifier (overrides client default).
        action: Action name. If empty, derived from function name.
        resource_type: Resource type for the authorization request.
        tool_name: Tool name for the authorization request.
        on_deny: What to do on deny — "raise" (default) or "return_none".

    Returns:
        A decorator that wraps the target function.
    """

    def decorator(func: Callable) -> Callable:
        resolved_action = action or func.__name__
        resolved_tool = tool_name or func.__name__
        signature = inspect.signature(func)
        accepts_kwargs = any(
            param.kind == inspect.Parameter.VAR_KEYWORD
            for param in signature.parameters.values()
        )

        def can_accept_kwarg(name: str) -> bool:
            return accepts_kwargs or name in signature.parameters

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract resource_id from first positional arg or kwargs if possible
            res_id = ""
            if args:
                res_id = str(args[0])
            elif "resource_id" in kwargs:
                res_id = str(kwargs["resource_id"])

            decision = client.authorize(
                agent_id=agent_id,
                action=resolved_action,
                resource_type=resource_type,
                resource_id=res_id,
                tool_name=resolved_tool,
            )

            if decision.is_denied:
                if on_deny == "return_none":
                    return None
                raise PermissionDeniedError(
                    message=f"denied: {decision.reason}",
                    reason=decision.reason,
                    policy_ids=decision.policy_ids,
                    decision_id=decision.decision_id,
                )

            if decision.requires_approval:
                raise ApprovalRequiredError(
                    message=f"approval required: {decision.reason}",
                    approvers=decision.approval.get("approvers", []),
                    approval_id=decision.approval.get("approval_id", ""),
                    expires_in_seconds=decision.approval.get("expires_in_seconds", 0),
                )

            # Inject enforcement metadata when the wrapped tool can receive it.
            if decision.constraints and can_accept_kwarg("oap_constraints"):
                kwargs["oap_constraints"] = decision.constraints
            if decision.grant:
                if can_accept_kwarg("oap_grant_token"):
                    kwargs["oap_grant_token"] = decision.grant.token
                if can_accept_kwarg("oap_grant"):
                    kwargs["oap_grant"] = decision.grant

            return func(*args, **kwargs)

        # Attach metadata for introspection
        wrapper._oap_protected = True  # type: ignore[attr-defined]
        wrapper._oap_action = resolved_action  # type: ignore[attr-defined]
        wrapper._oap_agent_id = agent_id  # type: ignore[attr-defined]

        return wrapper

    return decorator
