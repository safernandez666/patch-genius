"""Unit tests for public enrichment feeds."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from app.feeds import fetch_epss, fetch_kev


class MockResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> Any:
        return self._payload


class MockAsyncClient:
    """Stand-in for httpx.AsyncClient that returns canned responses."""

    def __init__(self, responses: Optional[List[MockResponse]] = None) -> None:
        self._responses = responses or []
        self._index = 0

    async def __aenter__(self) -> "MockAsyncClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    async def get(self, url: str, *args: Any, **kwargs: Any) -> MockResponse:
        resp = self._responses[self._index]
        self._index += 1
        return resp


class MockStore:
    def __init__(self) -> None:
        self._cache: Optional[Dict[str, Dict[str, Any]]] = None

    async def load_kev_cache(self, ttl_hours: int = 6) -> Optional[Dict[str, Dict[str, Any]]]:
        return self._cache

    async def save_kev_cache(self, catalog: Dict[str, Dict[str, Any]]) -> None:
        self._cache = catalog


def _run(coro):
    return asyncio.run(coro)


def test_fetch_epss_maps_scores():
    payload = {
        "data": [
            {"cve": "CVE-2024-0001", "epss": 0.123},
            {"cve": "CVE-2024-0002", "epss": "0.456"},
        ]
    }

    original = __import__("app.feeds", fromlist=["httpx"]).httpx.AsyncClient
    __import__("app.feeds", fromlist=["httpx"]).httpx.AsyncClient = lambda **_: MockAsyncClient(
        [MockResponse(payload)]
    )
    try:
        result = _run(fetch_epss(["CVE-2024-0001", "CVE-2024-0002"]))
    finally:
        __import__("app.feeds", fromlist=["httpx"]).httpx.AsyncClient = original

    assert result == {"CVE-2024-0001": 0.123, "CVE-2024-0002": 0.456}


def test_fetch_kev_uses_cache_when_fresh():
    store = MockStore()
    store._cache = {"CVE-2024-1000": {"ransomware": True}}

    result = _run(fetch_kev(store, ttl_hours=6))

    assert result == {"CVE-2024-1000": {"ransomware": True}}


def test_fetch_kev_downloads_and_caches():
    store = MockStore()
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1000",
                "dueDate": "2024-06-01",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply updates",
                "vulnerabilityName": "Test vuln",
            }
        ]
    }

    original = __import__("app.feeds", fromlist=["httpx"]).httpx.AsyncClient
    __import__("app.feeds", fromlist=["httpx"]).httpx.AsyncClient = lambda **_: MockAsyncClient(
        [MockResponse(payload)]
    )
    try:
        result = _run(fetch_kev(store, ttl_hours=6))
    finally:
        __import__("app.feeds", fromlist=["httpx"]).httpx.AsyncClient = original

    assert "CVE-2024-1000" in result
    assert result["CVE-2024-1000"]["ransomware"] is True
    assert store._cache == result
