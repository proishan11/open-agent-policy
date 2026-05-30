#!/usr/bin/env python3
"""Create an OAP session from a projected Kubernetes ServiceAccount token."""

from __future__ import annotations

import os
from pathlib import Path

from open_agent_policy import OAPClient


AGENT_ID = os.environ.get("OAP_AGENT_ID", "agent://support/ticket-assistant")
OAP_SERVER_URL = os.environ.get("OAP_SERVER_URL", "https://oap.company.com")
TOKEN_FILE = os.environ.get("OAP_TOKEN_FILE", "/var/run/secrets/oap/token")


def main() -> None:
    runtime_token = Path(TOKEN_FILE).read_text(encoding="utf-8").strip()

    client = OAPClient(server_url=OAP_SERVER_URL, agent_id=AGENT_ID)
    session = client.create_session(
        runtime_token=runtime_token,
        environment="production",
    )
    print(f"created session {session['session_id']} for {session['agent_id']}")

    decision = client.authorize(
        action="ticket.read",
        resource_type="support.ticket",
        resource_id="T-100",
        actor_type="user",
        actor_id="alice@example.com",
    )
    print(decision.decision)


if __name__ == "__main__":
    main()

