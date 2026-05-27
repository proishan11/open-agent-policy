"""OAP SDK error hierarchy.

All SDK errors inherit from OAPError, making it easy to catch all
OAP-related exceptions in one handler::

    try:
        result = client.authorize(request)
    except PermissionDeniedError as e:
        log.warning("Denied: %s", e.reason)
    except ApprovalRequiredError as e:
        log.info("Needs approval from: %s", e.approvers)
    except OAPError as e:
        log.error("OAP error: %s", e)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OAPError(Exception):
    """Base exception for all OAP SDK errors."""

    message: str

    def __str__(self) -> str:
        return self.message


@dataclass
class PermissionDeniedError(OAPError):
    """Raised when an authorization request is denied.

    Attributes:
        reason: Human-readable explanation of the denial.
        policy_ids: Policies that contributed to the denial.
        decision_id: The unique decision identifier for audit correlation.
    """

    reason: str = ""
    policy_ids: list[str] = field(default_factory=list)
    decision_id: str = ""

    def __str__(self) -> str:
        return f"permission denied: {self.reason}"


@dataclass
class ApprovalRequiredError(OAPError):
    """Raised when a decision requires human approval before proceeding.

    Attributes:
        approvers: List of entities that can approve the action.
        approval_id: Identifier for tracking the approval request.
        expires_in_seconds: How long the approval window stays open.
    """

    approvers: list[str] = field(default_factory=list)
    approval_id: str = ""
    expires_in_seconds: int = 0

    def __str__(self) -> str:
        return f"approval required from: {', '.join(self.approvers)}"


@dataclass
class ServerError(OAPError):
    """Raised when the OAP server returns an unexpected error.

    Attributes:
        status_code: HTTP status code from the server.
        response_body: Raw response body for debugging.
    """

    status_code: int = 0
    response_body: str = ""

    def __str__(self) -> str:
        return f"server error ({self.status_code}): {self.message}"
