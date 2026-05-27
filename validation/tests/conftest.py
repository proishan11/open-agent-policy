"""Shared fixtures for the OAP production-like validation test suite.

Provides real Keycloak tokens, real API clients, and real OAP server access.
No mocks.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

import httpx
import pytest


# ── Environment ───────────────────────────────────────────────────────

OAP_SERVER_URL = os.environ.get("OAP_SERVER_URL", "http://localhost:8080")
TICKET_API_URL = os.environ.get("TICKET_API_URL", "http://localhost:9100")
CUSTOMER_API_URL = os.environ.get("CUSTOMER_API_URL", "http://localhost:9101")
APPROVAL_API_URL = os.environ.get("APPROVAL_API_URL", "http://localhost:9102")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8443")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "oap-validation")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "validation-tests")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "validation-tests-secret")
AGENT_CLIENT_ID = os.environ.get("AGENT_CLIENT_ID", "support-agent")
AGENT_CLIENT_SECRET = os.environ.get("AGENT_CLIENT_SECRET", "support-agent-secret")


# ── Data classes ──────────────────────────────────────────────────────

@dataclass
class TokenResponse:
    access_token: str
    expires_in: int
    token_type: str
    scope: Optional[str] = None


@dataclass
class AuthorizationResult:
    status_code: int
    body: dict
    decision: str
    reason: str
    policy_ids: list
    constraints: Optional[dict] = None
    grant: Optional[dict] = None


# ── Keycloak helper ───────────────────────────────────────────────────

class KeycloakClient:
    """Real Keycloak token client — no mocks."""

    def __init__(self, base_url: str, realm: str):
        self.token_url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
        self.client = httpx.Client(timeout=30.0)

    def get_user_token(
        self, username: str, password: str,
        client_id: str = KEYCLOAK_CLIENT_ID,
        client_secret: str = KEYCLOAK_CLIENT_SECRET,
    ) -> TokenResponse:
        """Get a real IdP-issued token via resource owner password grant."""
        resp = self.client.post(self.token_url, data={
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": username,
            "password": password,
            "scope": "openid",
        })
        if resp.status_code != 200:
            raise RuntimeError(
                f"Keycloak auth failed for {username}: {resp.status_code} {resp.text}"
            )
        data = resp.json()
        return TokenResponse(
            access_token=data["access_token"],
            expires_in=data.get("expires_in", 300),
            token_type=data.get("token_type", "Bearer"),
            scope=data.get("scope"),
        )

    def get_client_credentials_token(
        self,
        client_id: str = AGENT_CLIENT_ID,
        client_secret: str = AGENT_CLIENT_SECRET,
    ) -> TokenResponse:
        """Get a real client_credentials token for agent identity."""
        resp = self.client.post(self.token_url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        })
        if resp.status_code != 200:
            raise RuntimeError(
                f"Keycloak client_credentials failed: {resp.status_code} {resp.text}"
            )
        data = resp.json()
        return TokenResponse(
            access_token=data["access_token"],
            expires_in=data.get("expires_in", 300),
            token_type=data.get("token_type", "Bearer"),
        )


# ── OAP client ────────────────────────────────────────────────────────

class OAPTestClient:
    """Real OAP server client — no mocks."""

    def __init__(self, base_url: str, bearer_token: str = ""):
        self.base_url = base_url
        self.bearer_token = bearer_token
        self.client = httpx.Client(timeout=30.0)

    def _auth_headers(self, token_override: str = "") -> dict:
        """Build Authorization header from agent token."""
        token = token_override or self.bearer_token
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def authorize(
        self, agent_id: str, actor_id: str, action: str,
        resource_type: str = "", resource_id: str = "",
        context: Optional[dict] = None,
        bearer_token: str = "",
    ) -> AuthorizationResult:
        """Send real authorization request to OAP server with agent token."""
        req_body = {
            "request_id": f"val-{int(time.time() * 1000)}",
            "subject": {
                "type": "agent",
                "agent_id": agent_id,
            },
            "action": {"name": action},
            "resource": {
                "type": resource_type,
                "id": resource_id,
            },
            "context": context or {},
        }
        if actor_id:
            req_body["subject"]["actor"] = actor_id

        resp = self.client.post(
            f"{self.base_url}/v1/authorize",
            json=req_body,
            headers=self._auth_headers(bearer_token),
        )
        body = resp.json()
        return AuthorizationResult(
            status_code=resp.status_code,
            body=body,
            decision=body.get("decision", ""),
            reason=body.get("reason", ""),
            policy_ids=body.get("policy_ids", []),
            constraints=body.get("constraints"),
            grant=body.get("grant"),
        )

    def authorize_raw(
        self, agent_id: str, actor_id: str, action: str,
        resource_type: str = "", resource_id: str = "",
        context: Optional[dict] = None,
        bearer_token: str = "",
    ) -> httpx.Response:
        """Send authorize request and return raw HTTP response (for 401 tests)."""
        req_body = {
            "request_id": f"val-{int(time.time() * 1000)}",
            "subject": {
                "type": "agent",
                "agent_id": agent_id,
            },
            "action": {"name": action},
            "resource": {"type": resource_type, "id": resource_id},
            "context": context or {},
        }
        if actor_id:
            req_body["subject"]["actor"] = actor_id
        return self.client.post(
            f"{self.base_url}/v1/authorize",
            json=req_body,
            headers=self._auth_headers(bearer_token),
        )

    def create_run(
        self, session_id: str, actor_type: str = "",
        actor_id: str = "", purpose: str = "",
    ) -> dict:
        """POST /v1/runs — start a new task/execution within a session."""
        body: dict = {"session_id": session_id}
        if actor_type or actor_id:
            body["actor"] = {"type": actor_type, "id": actor_id}
        if purpose:
            body["purpose"] = purpose
        resp = self.client.post(
            f"{self.base_url}/v1/runs",
            json=body,
            headers=self._auth_headers(),
        )
        if resp.status_code != 201:
            raise RuntimeError(
                f"Run creation failed: {resp.status_code} {resp.text}"
            )
        return resp.json()

    def validate_grant(self, grant_token: str) -> dict:
        """POST /v1/grants/validate — verify a grant token."""
        resp = self.client.post(
            f"{self.base_url}/v1/grants/validate",
            json={"grant_token": grant_token},
        )
        return resp.json()

    def create_session(
        self, agent_id: str, runtime_token: str,
        environment: str = "", instance: Optional[dict] = None,
    ) -> dict:
        """POST /v1/runtime/session — prove identity, get session token."""
        body: dict = {
            "agent_id": agent_id,
            "runtime_token": runtime_token,
        }
        if environment:
            body["environment"] = environment
        if instance:
            body["instance"] = instance
        resp = self.client.post(
            f"{self.base_url}/v1/runtime/session",
            json=body,
        )
        if resp.status_code != 201:
            raise RuntimeError(
                f"Session creation failed: {resp.status_code} {resp.text}"
            )
        return resp.json()

    def health(self) -> dict:
        resp = self.client.get(f"{self.base_url}/v1/health")
        return resp.json()


# ── Resource API clients ──────────────────────────────────────────────

class TicketAPIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.Client(timeout=15.0)

    def get_ticket(self, ticket_id: str) -> dict:
        resp = self.client.get(f"{self.base_url}/api/tickets/{ticket_id}")
        resp.raise_for_status()
        return resp.json()

    def list_tickets(self, **params) -> dict:
        resp = self.client.get(f"{self.base_url}/api/tickets", params=params)
        resp.raise_for_status()
        return resp.json()


class CustomerAPIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.Client(timeout=15.0)

    def get_customer(self, customer_id: str) -> dict:
        resp = self.client.get(f"{self.base_url}/api/customers/{customer_id}")
        resp.raise_for_status()
        return resp.json()


class ApprovalAPIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.Client(timeout=15.0)

    def create_approval(self, **kwargs) -> dict:
        resp = self.client.post(f"{self.base_url}/api/approvals", json=kwargs)
        resp.raise_for_status()
        return resp.json()

    def get_approval(self, approval_id: str) -> dict:
        resp = self.client.get(f"{self.base_url}/api/approvals/{approval_id}")
        resp.raise_for_status()
        return resp.json()

    def decide_approval(self, approval_id: str, approver_id: str, decision: str) -> dict:
        resp = self.client.post(
            f"{self.base_url}/api/approvals/{approval_id}/decide",
            json={"approver_id": approver_id, "decision": decision},
        )
        resp.raise_for_status()
        return resp.json()

    def validate_approval(self, approval_id: str, **kwargs) -> dict:
        resp = self.client.post(
            f"{self.base_url}/api/approvals/{approval_id}/validate",
            params=kwargs,
        )
        resp.raise_for_status()
        return resp.json()


# ── Pytest fixtures ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def keycloak() -> KeycloakClient:
    return KeycloakClient(KEYCLOAK_URL, KEYCLOAK_REALM)


@pytest.fixture(scope="session")
def agent_session(keycloak: KeycloakClient) -> dict:
    """Create a runtime session: get IdP token, prove identity to OAP, get session_id."""
    # 1. Get client_credentials JWT from Keycloak
    token_resp = keycloak.get_client_credentials_token()

    # 2. Create runtime session — OAP validates token against identity bindings
    tmp_client = OAPTestClient(OAP_SERVER_URL)
    session_data = tmp_client.create_session(
        agent_id="agent://support/ticket-assistant",
        runtime_token=token_resp.access_token,
        environment="validation",
    )
    return session_data


@pytest.fixture(scope="session")
def oap(agent_session: dict) -> OAPTestClient:
    """OAP client authenticated with a runtime session token."""
    client = OAPTestClient(OAP_SERVER_URL, bearer_token=agent_session["session_id"])
    health = client.health()
    assert health.get("status") == "ok" or "status" in health
    return client


@pytest.fixture(scope="session")
def oap_unauthenticated() -> OAPTestClient:
    """OAP client with NO token — for testing 401 rejection."""
    return OAPTestClient(OAP_SERVER_URL)


@pytest.fixture(scope="session")
def ticket_api() -> TicketAPIClient:
    return TicketAPIClient(TICKET_API_URL)


@pytest.fixture(scope="session")
def customer_api() -> CustomerAPIClient:
    return CustomerAPIClient(CUSTOMER_API_URL)


@pytest.fixture(scope="session")
def approval_api() -> ApprovalAPIClient:
    return ApprovalAPIClient(APPROVAL_API_URL)


@pytest.fixture(scope="session")
def alice_token(keycloak: KeycloakClient) -> str:
    """Real Keycloak-issued token for alice@company.test."""
    return keycloak.get_user_token("alice@company.test", "alice123").access_token


@pytest.fixture(scope="session")
def bob_token(keycloak: KeycloakClient) -> str:
    """Real Keycloak-issued token for bob@company.test."""
    return keycloak.get_user_token("bob@company.test", "bob123").access_token


@pytest.fixture(scope="session")
def charlie_token(keycloak: KeycloakClient) -> str:
    """Real Keycloak-issued token for charlie@company.test."""
    return keycloak.get_user_token("charlie@company.test", "charlie123").access_token


@pytest.fixture(scope="session")
def dana_token(keycloak: KeycloakClient) -> str:
    """Real Keycloak-issued token for dana@company.test."""
    return keycloak.get_user_token("dana@company.test", "dana123").access_token


@pytest.fixture(scope="session")
def agent_token(keycloak: KeycloakClient) -> str:
    """Real client_credentials JWT from Keycloak for the support agent."""
    return keycloak.get_client_credentials_token().access_token


@pytest.fixture(scope="session")
def agent_session_id(agent_session: dict) -> str:
    """Just the session_id string for tests that need it directly."""
    return agent_session["session_id"]
