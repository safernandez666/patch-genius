"""Unit tests for the Wazuh manager API client."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx
import pytest

from app.wazuh.manager import WazuhManagerClient, WazuhManagerError

TOKEN_PAYLOAD = {"data": {"token": "jwt-token"}}


def _client(handler) -> WazuhManagerClient:
    """A client whose transport is a canned handler instead of the network."""
    client = WazuhManagerClient("https://wazuh.test:55000", "wui", "pw")
    transport = httpx.MockTransport(handler)
    client._client = lambda: httpx.AsyncClient(  # type: ignore[method-assign]
        base_url="https://wazuh.test:55000", transport=transport
    )
    return client


def test_list_agents_drops_the_manager_and_flattens_os():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json=TOKEN_PAYLOAD)
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {"id": "000", "name": "manager", "status": "active", "os": {}},
                        {
                            "id": "003",
                            "name": "WIN-DC01",
                            "status": "active",
                            "version": "Wazuh v4.14.0",
                            "lastKeepAlive": "2026-08-23T10:00:00Z",
                            "os": {"name": "Microsoft Windows Server 2022", "platform": "windows"},
                        },
                    ]
                }
            },
        )

    agents = asyncio.run(_client(handler).list_agents())
    assert [a["id"] for a in agents] == ["003"]
    assert agents[0]["os"] == "Microsoft Windows Server 2022"
    assert agents[0]["platform"] == "windows"


def test_restart_agents_sends_the_list_and_reports_failures():
    seen: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json=TOKEN_PAYLOAD)
        seen["method"] = request.method
        seen["agents_list"] = request.url.params.get("agents_list")
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": ["003"],
                    "failed_items": [
                        {"error": {"message": "Agent is not active"}, "id": ["007"]},
                    ],
                },
                "message": "Restart command sent to some agents",
            },
        )

    result = asyncio.run(_client(handler).restart_agents(["003", "007"]))
    assert seen == {
        "method": "PUT",
        "agents_list": "003,007",
        "auth": "Bearer jwt-token",
    }
    assert result["restarted"] == ["003"]
    assert result["failed"] == [{"id": "007", "error": "Agent is not active"}]


def test_restart_refuses_the_manager_agent():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never called
        raise AssertionError("no request should be made")

    with pytest.raises(WazuhManagerError):
        asyncio.run(_client(handler).restart_agents(["000"]))


def test_bad_credentials_surface_as_a_manager_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Unauthorized"})

    with pytest.raises(WazuhManagerError, match="credentials"):
        asyncio.run(_client(handler).list_agents())


def test_ping_reports_version_and_agent_count():
    calls: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json=TOKEN_PAYLOAD)
        if request.url.path == "/":
            return httpx.Response(200, json={"data": {"api_version": "4.14.0", "hostname": "wz"}})
        return httpx.Response(200, json={"data": {"total_affected_items": 12}})

    info = asyncio.run(_client(handler).ping())
    assert info == {"api_version": "4.14.0", "hostname": "wz", "agents": 12}
    assert calls == ["/security/user/authenticate", "/", "/agents"]
