#!/usr/bin/env python3
"""Minimal protected resource API for the OAP demo.

This is intentionally dependency-light. It uses Python's standard library and
calls OAP /v1/grants/validate before serving customer data.
"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


HOST = os.environ.get("RESOURCE_API_HOST", "127.0.0.1")
PORT = int(os.environ.get("RESOURCE_API_PORT", "9191"))
OAP_SERVER_URL = os.environ.get("OAP_SERVER_URL", "http://127.0.0.1:8181").rstrip("/")

CUSTOMERS = {
    "C-100": {
        "id": "C-100",
        "name": "Ada Lovelace",
        "company": "Analytical Engines LLC",
        "email": "ada@example.com",
        "region": "US",
        "tax_identifier": "US-TAX-1234",
        "bank_account": "US00-DEMO-0001",
    },
    "C-200": {
        "id": "C-200",
        "name": "Grace Hopper",
        "company": "Compiler Labs",
        "email": "grace@example.com",
        "region": "EU",
        "tax_identifier": "EU-TAX-5678",
        "bank_account": "EU00-DEMO-0002",
    },
}


def json_response(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
    data = json.dumps(body, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def validate_grant(grant_token: str) -> tuple[int, dict[str, Any]]:
    payload = json.dumps({"grant_token": grant_token}).encode("utf-8")
    req = Request(
        f"{OAP_SERVER_URL}/v1/grants/validate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except json.JSONDecodeError:
            body = {"error": exc.reason}
        return exc.code, body
    except URLError as exc:
        return HTTPStatus.BAD_GATEWAY, {"error": f"OAP unavailable: {exc.reason}"}


def require_oap_grant(
    handler: BaseHTTPRequestHandler,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
) -> dict[str, Any] | None:
    grant_token = handler.headers.get("X-OAP-Grant-Token", "")
    if not grant_token:
        json_response(
            handler,
            HTTPStatus.UNAUTHORIZED,
            {"error": "X-OAP-Grant-Token is required"},
        )
        return None

    status, grant = validate_grant(grant_token)
    if status != HTTPStatus.OK or grant.get("valid") is not True:
        json_response(handler, HTTPStatus.FORBIDDEN, {"error": "invalid OAP grant"})
        return None
    if grant.get("decision") not in ("allow", "allow_with_constraints"):
        json_response(
            handler,
            HTTPStatus.FORBIDDEN,
            {"error": "grant decision does not allow access"},
        )
        return None
    if grant.get("action") != action:
        json_response(handler, HTTPStatus.FORBIDDEN, {"error": "grant action mismatch"})
        return None
    if grant.get("resource_type") != resource_type:
        json_response(handler, HTTPStatus.FORBIDDEN, {"error": "grant resource type mismatch"})
        return None
    if (grant.get("resource_id") or "") != resource_id:
        json_response(handler, HTTPStatus.FORBIDDEN, {"error": "grant resource id mismatch"})
        return None
    return grant


def redact_record(grant: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(record)
    for field in (grant.get("constraints") or {}).get("redact_fields") or []:
        if field in redacted:
            redacted[field] = "<redacted>"
    return redacted


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            json_response(
                self,
                HTTPStatus.OK,
                {"status": "healthy", "customers": len(CUSTOMERS)},
            )
            return

        prefix = "/customers/"
        if parsed.path.startswith(prefix):
            customer_id = parsed.path[len(prefix):]
            customer = CUSTOMERS.get(customer_id)
            if customer is None:
                json_response(
                    self,
                    HTTPStatus.NOT_FOUND,
                    {"error": f"customer {customer_id} not found"},
                )
                return

            grant = require_oap_grant(
                self,
                action="customer.read",
                resource_type="crm.customer",
                resource_id=customer_id,
            )
            if grant is None:
                return
            json_response(self, HTTPStatus.OK, redact_record(grant, customer))
            return

        json_response(self, HTTPStatus.NOT_FOUND, {"error": "not found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"minimal resource API listening on http://{HOST}:{PORT}")
    print(f"validating grants with {OAP_SERVER_URL}")
    server.serve_forever()


if __name__ == "__main__":
    main()
