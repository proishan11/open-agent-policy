"""OAP authorization client.

OAPClient is the primary interface for authorizing agent tool calls.
It supports two modes:

- **Remote mode** (default): Sends HTTP requests to an OAP server.
  Use when you have a running ``oap-server`` instance.

- **Embedded mode**: Runs ``oapctl simulate`` locally via subprocess.
  Use for development, testing, or air-gapped environments.

Example (remote mode)::

    client = OAPClient(server_url="http://localhost:8080")
    decision = client.authorize(
        agent_id="agent://finance/reconciler",
        action="erp.invoice.read",
        resource_type="erp.invoice",
        resource_id="INV-001",
    )
    if decision.is_allowed:
        print("Go ahead!", decision.constraints)

Example (embedded mode)::

    client = OAPClient(
        mode="embedded",
        data_dir="./policies/",
    )
"""

from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from open_agent_policy.errors import (
    ApprovalRequiredError,
    OAPError,
    PermissionDeniedError,
    ServerError,
)


@dataclass
class Grant:
    """A scoped, time-bound grant token issued by OAP on allow decisions.

    Attributes:
        grant_id: Unique identifier for this grant.
        token: Signed JWT grant token to present to the resource API.
        expires_in_seconds: How long the grant is valid.
    """

    grant_id: str = ""
    token: str = ""
    expires_in_seconds: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Grant | None:
        if not data:
            return None
        return cls(
            grant_id=data.get("grant_id", ""),
            token=data.get("token", ""),
            expires_in_seconds=data.get("expires_in_seconds", 0),
        )


@dataclass
class Decision:
    """The result of an authorization evaluation.

    Attributes:
        decision: The raw decision string (allow, deny, allow_with_constraints, etc.).
        decision_id: Unique identifier for this decision.
        request_id: Correlating request identifier.
        reason: Human-readable explanation.
        policy_ids: Policies that contributed to this decision.
        constraints: Constraints applied to the allowed action (if any).
        obligations: Requirements the caller must fulfil.
        approval: Approval details if decision is require_approval.
        grant: Scoped grant token (only present on allow decisions).
        trace: Evaluation trace (only present in simulate mode).
    """

    decision: str = ""
    decision_id: str = ""
    request_id: str = ""
    reason: str = ""
    policy_ids: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)
    obligations: dict[str, Any] = field(default_factory=dict)
    approval: dict[str, Any] = field(default_factory=dict)
    grant: Grant | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        """True if the decision is allow or allow_with_constraints."""
        return self.decision in ("allow", "allow_with_constraints")

    @property
    def is_denied(self) -> bool:
        """True if the decision is deny."""
        return self.decision == "deny"

    @property
    def requires_approval(self) -> bool:
        """True if the decision requires human approval."""
        return self.decision == "require_approval"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Decision:
        """Create a Decision from a server response dict."""
        return cls(
            decision=data.get("decision", ""),
            decision_id=data.get("decision_id", ""),
            request_id=data.get("request_id", ""),
            reason=data.get("reason", ""),
            policy_ids=data.get("policy_ids") or [],
            constraints=data.get("constraints") or {},
            obligations=data.get("obligations") or {},
            approval=data.get("approval") or {},
            grant=Grant.from_dict(data.get("grant")),
            trace=data.get("trace") or [],
        )


class OAPClient:
    """Authorization client for Open Agent Policy.

    Args:
        server_url: URL of the OAP server (for remote mode).
        mode: "remote" (default) or "embedded".
        data_dir: Path to data directory (for embedded mode).
        oapctl_path: Path to oapctl binary (for embedded mode, default: "oapctl").
        timeout: HTTP timeout in seconds (default: 5).
        agent_id: Default agent ID for all requests.
        headers: Extra HTTP headers to send with every request.
    """

    def __init__(
        self,
        server_url: str = "http://localhost:8080",
        *,
        mode: str = "remote",
        data_dir: str = "",
        oapctl_path: str = "oapctl",
        timeout: float = 5.0,
        agent_id: str = "",
        headers: dict[str, str] | None = None,
        session_token: str = "",
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.mode = mode
        self.data_dir = data_dir
        self.oapctl_path = oapctl_path
        self.timeout = timeout
        self.default_agent_id = agent_id
        self.session_token = session_token
        auth_headers = dict(headers or {})
        if session_token:
            auth_headers["Authorization"] = f"Bearer {session_token}"
        self._client = httpx.Client(
            base_url=self.server_url,
            timeout=timeout,
            headers=auth_headers,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> OAPClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def authorize(
        self,
        agent_id: str = "",
        action: str = "",
        *,
        resource_type: str = "",
        resource_id: str = "",
        tool_name: str = "",
        tool_protocol: str = "",
        actor_type: str = "",
        actor_id: str = "",
        context: dict[str, Any] | None = None,
        request_id: str = "",
    ) -> Decision:
        """Authorize an agent tool call.

        This is the primary SDK method. It builds an AuthorizationRequest,
        sends it to the evaluator (remote or embedded), and returns a Decision.

        Args:
            agent_id: Agent identifier (overrides default_agent_id).
            action: Action name (e.g., "erp.invoice.read").
            resource_type: Resource type (e.g., "erp.invoice").
            resource_id: Specific resource instance.
            tool_name: Tool being used.
            tool_protocol: Tool protocol (mcp, http, function).
            actor_type: Actor type (user, service).
            actor_id: Actor identifier.
            context: Additional context (run_id, delegation_id, etc.).
            request_id: Custom request ID (auto-generated if empty).

        Returns:
            Decision with the evaluation result.

        Raises:
            PermissionDeniedError: If deny and caller should handle it.
            ApprovalRequiredError: If approval is needed.
            ServerError: If the server returns an unexpected error.
            OAPError: For other OAP-related failures.
        """
        resolved_agent_id = agent_id or self.default_agent_id
        if not resolved_agent_id:
            raise OAPError(message="agent_id is required (pass it or set default_agent_id)")
        if not action:
            raise OAPError(message="action is required")

        req_id = request_id or f"req-{uuid.uuid4().hex[:12]}"

        request_body = self._build_request(
            request_id=req_id,
            agent_id=resolved_agent_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            tool_name=tool_name,
            tool_protocol=tool_protocol,
            actor_type=actor_type,
            actor_id=actor_id,
            context=context,
        )

        if self.mode == "embedded":
            return self._authorize_embedded(request_body)
        return self._authorize_remote(request_body)

    def simulate(
        self,
        agent_id: str = "",
        action: str = "",
        **kwargs: Any,
    ) -> Decision:
        """Simulate an authorization decision (dry-run with trace).

        Same parameters as authorize(). Returns a Decision with the
        trace field populated showing each evaluation step.
        """
        resolved_agent_id = agent_id or self.default_agent_id
        req_id = kwargs.pop("request_id", f"sim-{uuid.uuid4().hex[:12]}")

        request_body = self._build_request(
            request_id=req_id,
            agent_id=resolved_agent_id,
            action=action,
            **kwargs,
        )

        if self.mode == "embedded":
            return self._simulate_embedded(request_body)
        return self._simulate_remote(request_body)

    # --- Internal: request building ---

    def _build_request(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        tool_name: str = "",
        tool_protocol: str = "",
        actor_type: str = "",
        actor_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the AuthorizationRequest payload."""
        body: dict[str, Any] = {
            "request_id": request_id,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "subject": {
                "type": "agent",
                "agent_id": agent_id,
            },
            "action": {"name": action},
        }

        if resource_type:
            body["resource"] = {"type": resource_type}
            if resource_id:
                body["resource"]["id"] = resource_id

        if tool_name:
            body["tool"] = {"name": tool_name}
            if tool_protocol:
                body["tool"]["protocol"] = tool_protocol

        if actor_type and actor_id:
            body["actor"] = {"type": actor_type, "id": actor_id}

        if context:
            body["context"] = context

        return body

    # --- Internal: remote mode ---

    def _authorize_remote(self, request_body: dict[str, Any]) -> Decision:
        """Send authorization request to the OAP server."""
        resp = self._client.post("/v1/authorize", json=request_body)
        if resp.status_code != 200:
            raise ServerError(
                message="authorize request failed",
                status_code=resp.status_code,
                response_body=resp.text,
            )
        return Decision.from_dict(resp.json())

    def _simulate_remote(self, request_body: dict[str, Any]) -> Decision:
        """Send simulation request to the OAP server."""
        resp = self._client.post("/v1/simulate", json=request_body)
        if resp.status_code != 200:
            raise ServerError(
                message="simulate request failed",
                status_code=resp.status_code,
                response_body=resp.text,
            )
        data = resp.json()
        decision = Decision.from_dict(data.get("decision", {}))
        decision.trace = data.get("trace", [])
        return decision

    # --- Internal: embedded mode ---

    def _authorize_embedded(self, request_body: dict[str, Any]) -> Decision:
        """Run oapctl simulate locally and parse the JSON output."""
        return self._run_oapctl(request_body)

    def _simulate_embedded(self, request_body: dict[str, Any]) -> Decision:
        """Run oapctl simulate locally (same as authorize in embedded mode)."""
        return self._run_oapctl(request_body)

    def _run_oapctl(self, request_body: dict[str, Any]) -> Decision:
        """Execute oapctl as a subprocess for embedded evaluation.

        Writes the request to a temp file, runs ``oapctl simulate``,
        and parses stdout as a Decision.
        """
        import tempfile

        if not self.data_dir:
            raise OAPError(message="data_dir is required for embedded mode")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(request_body, f)
            tmp_path = f.name

        try:
            result = subprocess.run(  # noqa: S603
                [self.oapctl_path, "simulate", "-f", tmp_path, "--data", self.data_dir],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            raise OAPError(
                message=f"oapctl not found at '{self.oapctl_path}'. "
                "Install it or set oapctl_path."
            ) from None
        except subprocess.TimeoutExpired:
            raise OAPError(message="oapctl timed out") from None

        if result.returncode != 0:
            raise OAPError(message=f"oapctl failed: {result.stderr.strip()}")

        # Parse the text output from oapctl simulate
        # Format: "Decision: <decision>\nReason: <reason>\n..."
        return self._parse_oapctl_output(result.stdout)

    def _parse_oapctl_output(self, output: str) -> Decision:
        """Parse oapctl simulate text output into a Decision."""
        decision = Decision()
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("Decision:"):
                # Strip ANSI color codes
                raw = line.split(":", 1)[1].strip()
                decision.decision = _strip_ansi(raw)
            elif line.startswith("Reason:"):
                decision.reason = line.split(":", 1)[1].strip()
            elif line.startswith("Policies:"):
                raw = line.split(":", 1)[1].strip().strip("[]")
                decision.policy_ids = [p.strip() for p in raw.split() if p.strip()]
        return decision


    # --- Session & run management ---

    def create_session(
        self,
        agent_id: str = "",
        runtime_token: str = "",
        environment: str = "",
    ) -> dict[str, Any]:
        """Create a runtime session by proving agent identity.

        Args:
            agent_id: Agent identifier.
            runtime_token: OIDC/JWT token from the identity provider.
            environment: Deployment environment name.

        Returns:
            Session dict with session_id, agent_id, status, expires_in.
        """
        body: dict[str, Any] = {
            "agent_id": agent_id or self.default_agent_id,
            "runtime_token": runtime_token,
        }
        if environment:
            body["environment"] = environment

        resp = self._client.post("/v1/runtime/session", json=body)
        if resp.status_code != 201:
            raise ServerError(
                message="session creation failed",
                status_code=resp.status_code,
                response_body=resp.text,
            )
        data = resp.json()

        # Auto-set session token for subsequent calls
        self.session_token = data["session_id"]
        self._client.headers["Authorization"] = f"Bearer {self.session_token}"

        return data

    def create_run(
        self,
        session_id: str = "",
        actor_type: str = "",
        actor_id: str = "",
        purpose: str = "",
    ) -> dict[str, Any]:
        """Create a run (task/execution) within an active session.

        Args:
            session_id: Session ID (defaults to current session).
            actor_type: Type of actor (user, service).
            actor_id: Actor identifier.
            purpose: Description of the run's purpose.

        Returns:
            Run dict with run_id, session_id, agent_id, status.
        """
        body: dict[str, Any] = {
            "session_id": session_id or self.session_token,
        }
        if actor_type or actor_id:
            body["actor"] = {"type": actor_type, "id": actor_id}
        if purpose:
            body["purpose"] = purpose

        resp = self._client.post("/v1/runs", json=body)
        if resp.status_code != 201:
            raise ServerError(
                message="run creation failed",
                status_code=resp.status_code,
                response_body=resp.text,
            )
        return resp.json()

    def validate_grant(self, grant_token: str) -> dict[str, Any]:
        """Validate a grant token (resource-side verification).

        Args:
            grant_token: The signed JWT grant token to validate.

        Returns:
            Dict with valid, agent_id, action, resource_type, etc.
        """
        resp = self._client.post(
            "/v1/grants/validate",
            json={"grant_token": grant_token},
        )
        return resp.json()


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from a string."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)
