"""Open Agent Policy Python SDK.

Zero-trust access control for AI agents. This SDK provides:

- **OAPClient**: Authorize agent tool calls against OAP policies.
  Supports embedded mode (local evaluation via oapctl) and remote mode
  (HTTP calls to an OAP server).

- **@protect**: Decorator that wraps any tool function with automatic
  authorization. Denied calls raise PermissionDeniedError; constrained
  calls inject constraints into the tool's kwargs.

- **OAPMiddleware**: LangChain/LangGraph integration that intercepts
  tool calls and authorizes them transparently.

Quick start::

    from open_agent_policy import OAPClient, protect

    client = OAPClient(server_url="http://localhost:8080")

    @protect(client, agent_id="agent://finance/reconciler", action="erp.invoice.read")
    def read_invoice(invoice_id: str, **kwargs) -> dict:
        constraints = kwargs.get("oap_constraints", {})
        # ... respect constraints ...
        return {"id": invoice_id}
"""

from open_agent_policy.client import OAPClient, Decision, Grant
from open_agent_policy.decorators import protect
from open_agent_policy.errors import (
    OAPError,
    PermissionDeniedError,
    ApprovalRequiredError,
    ServerError,
)

__version__ = "0.1.0a1"

__all__ = [
    "OAPClient",
    "Decision",
    "Grant",
    "protect",
    "OAPError",
    "PermissionDeniedError",
    "ApprovalRequiredError",
    "ServerError",
    "__version__",
]
