"""Client for the Wazuh Manager API (port 55000) — agent list and agent restart.

The indexer client next to this one only reads the vulnerability state index.
Wazuh 4.8+ exposes no "run a vulnerability scan now" endpoint: detection is
event-driven, and the manager re-evaluates a host only when syscollector reports
a new inventory for it. The one lever the API does expose is restarting the
agent, which makes it run syscollector on start (`scan_on_start`, on by default)
and therefore push a fresh package list the manager scores against the CTI feed.

So "force a rescan" is, concretely: restart the agent, wait for the inventory to
land in the index, and re-ingest. The wait is why the rescan route in main.py
schedules the ingest instead of running it inline.

This is the only place in the codebase that writes to Wazuh. Restarting an agent
is disruptive enough that the caller must always name the agents explicitly, and
agent `000` — the manager itself — is refused here as well as in the route.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx
import structlog

from app.wazuh.indexer import transport_reason

logger = structlog.get_logger(__name__)

# Agent 000 is the manager. Restarting it restarts the whole server, which is
# never what "rescan this Windows box" means.
MANAGER_AGENT_ID = "000"

# Fields asked of GET /agents. Explicit so a mapping change surfaces as a missing
# key here rather than as a silently empty column in the rescan dialog.
AGENT_FIELDS = "id,name,status,version,lastKeepAlive,os.name,os.platform,os.version"


class WazuhManagerError(RuntimeError):
    """Raised when the manager API is unreachable or rejects the request."""


class WazuhManagerClient:
    """Minimal async client — authenticate, list agents, restart agents.

    `verify_tls` defaults to False for the same reason as the indexer client:
    Wazuh ships self-signed certificates.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 20.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._auth = (username, password)
        self._verify = verify_tls
        self._timeout = timeout

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            verify=self._verify,
            timeout=self._timeout,
        )

    async def _token(self, client: httpx.AsyncClient) -> str:
        """Exchange the credentials for a JWT.

        The token lives ~15 minutes, far longer than any single call here, so it
        is fetched per client session rather than cached across requests.
        """
        try:
            resp = await client.get("/security/user/authenticate", auth=self._auth)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise WazuhManagerError(
                    f"manager API rejected the credentials ({exc.response.status_code})"
                ) from exc
            raise WazuhManagerError(
                f"manager API returned {exc.response.status_code}: {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise WazuhManagerError(
                f"cannot reach the manager API: {transport_reason(exc)}"
            ) from exc
        token = (resp.json().get("data") or {}).get("token")
        if not token:
            raise WazuhManagerError("manager API did not return a token")
        return str(token)

    @staticmethod
    async def _request(
        client: httpx.AsyncClient,
        method: str,
        path: str,
        token: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            resp = await client.request(
                method, path, params=params, headers={"Authorization": f"Bearer {token}"}
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise WazuhManagerError(
                f"{method} {path} failed ({exc.response.status_code}): {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise WazuhManagerError(f"{method} {path} failed: {transport_reason(exc)}") from exc
        return resp.json()

    async def ping(self) -> Dict[str, Any]:
        """API version plus agent count — used by the Integrations tab."""
        async with self._client() as client:
            token = await self._token(client)
            info = await self._request(client, "GET", "/", token)
            agents = await self._request(
                client, "GET", "/agents", token, params={"limit": 1, "select": "id"}
            )
        data = info.get("data") or {}
        return {
            "api_version": data.get("api_version", ""),
            "hostname": data.get("hostname", ""),
            "agents": (agents.get("data") or {}).get("total_affected_items", 0),
        }

    async def list_agents(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Every enrolled agent except the manager itself, sorted by name."""
        async with self._client() as client:
            token = await self._token(client)
            payload = await self._request(
                client,
                "GET",
                "/agents",
                token,
                params={"limit": limit, "select": AGENT_FIELDS, "sort": "+name"},
            )
        items = (payload.get("data") or {}).get("affected_items") or []
        out: List[Dict[str, Any]] = []
        for item in items:
            agent_id = str(item.get("id") or "")
            if not agent_id or agent_id == MANAGER_AGENT_ID:
                continue
            os_info = item.get("os") or {}
            out.append(
                {
                    "id": agent_id,
                    "name": item.get("name") or agent_id,
                    "status": item.get("status") or "unknown",
                    "version": item.get("version") or "",
                    "os": os_info.get("name") or os_info.get("platform") or "",
                    "platform": os_info.get("platform") or "",
                    "last_keep_alive": item.get("lastKeepAlive") or "",
                }
            )
        return out

    async def restart_agents(self, agent_ids: List[str]) -> Dict[str, Any]:
        """Restart the named agents so they re-run syscollector on start.

        Returns which ids the manager accepted and which it refused, with the
        reason — a disconnected agent fails here, and the operator needs to see
        that rather than wait for an ingest that will not change anything.
        """
        ids = [str(a).strip() for a in agent_ids if str(a).strip()]
        ids = [a for a in ids if a != MANAGER_AGENT_ID]
        if not ids:
            raise WazuhManagerError("no agent to restart")

        async with self._client() as client:
            token = await self._token(client)
            payload = await self._request(
                client,
                "PUT",
                "/agents/restart",
                token,
                params={"agents_list": ",".join(ids)},
            )
        data = payload.get("data") or {}
        failed = []
        for item in data.get("failed_items") or []:
            error = item.get("error") or {}
            for bad in item.get("id") or []:
                failed.append(
                    {
                        "id": str(bad),
                        "error": error.get("message") or error.get("remediation") or "failed",
                    }
                )
        restarted = [str(a) for a in data.get("affected_items") or []]
        logger.info("wazuh_agents_restarted", restarted=len(restarted), failed=len(failed))
        return {"restarted": restarted, "failed": failed, "message": payload.get("message", "")}
