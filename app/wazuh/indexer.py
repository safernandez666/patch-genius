"""Read-only client for the Wazuh Indexer (OpenSearch) vulnerability state index.

Wazuh 4.8 moved vulnerability data out of the manager API and into the indexer;
`GET /vulnerability/{agent_id}` on port 55000 is gone (verified 404 on 4.14.6).
The only supported source is the `wazuh-states-vulnerabilities-*` index.

The index holds *currently active* vulnerabilities only: a row disappears once the
package is patched. There is no status field, so "resolved" is derived by diffing
successive pulls (see app/ingest.py), not read from here.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)

INDEX_PATTERN = "wazuh-states-vulnerabilities-*"

# Fields pulled per hit. Kept explicit so an index-mapping change surfaces as a
# missing key here rather than as silently absent data on the dashboard.
SOURCE_FIELDS = [
    "agent.id",
    "agent.name",
    "host.os.name",
    "host.os.platform",
    "host.os.version",
    "package.name",
    "package.version",
    "package.type",
    "package.architecture",
    "vulnerability.id",
    "vulnerability.severity",
    "vulnerability.score.base",
    "vulnerability.score.version",
    "vulnerability.description",
    "vulnerability.published_at",
    "vulnerability.detected_at",
    "vulnerability.reference",
    "vulnerability.category",
    "vulnerability.under_evaluation",
]


class WazuhIndexerError(RuntimeError):
    """Raised when the indexer is unreachable or rejects the request."""


def transport_reason(exc: Exception) -> str:
    """Readable cause for a transport error.

    httpx timeouts stringify to the empty string, which reached the operator as
    "search failed: " — a message that says nothing. Fall back to the exception
    class, which at least distinguishes a timeout from a refused connection.
    """
    return str(exc) or type(exc).__name__


class WazuhIndexerClient:
    """Minimal async client — search and count over the vulnerability index.

    `verify_tls` defaults to False because Wazuh ships self-signed certificates
    and the node cert's CN rarely matches the address operators connect to.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 30.0,
        index_pattern: str = INDEX_PATTERN,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.index_pattern = index_pattern
        self._auth = (username, password)
        self._verify = verify_tls
        self._timeout = timeout

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            auth=self._auth,
            verify=self._verify,
            timeout=self._timeout,
        )

    async def ping(self) -> Dict[str, Any]:
        """Cluster health plus vulnerability doc count — used by the config tab."""
        async with self._client() as client:
            try:
                health = await client.get("/_cluster/health")
                health.raise_for_status()
                count = await client.get(f"/{self.index_pattern}/_count")
                count.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise WazuhIndexerError(
                    f"indexer returned {exc.response.status_code}: {exc.response.text[:200]}"
                ) from exc
            except httpx.HTTPError as exc:
                raise WazuhIndexerError(f"cannot reach indexer: {transport_reason(exc)}") from exc
        h = health.json()
        return {
            "cluster_name": h.get("cluster_name", ""),
            "status": h.get("status", ""),
            "nodes": h.get("number_of_nodes", 0),
            "vulnerability_docs": count.json().get("count", 0),
        }

    async def iter_vulnerabilities(
        self, page_size: int = 1000, agent_ids: Optional[List[str]] = None
    ) -> AsyncIterator[Dict[str, Any]]:
        """Yield every active vulnerability record.

        Paginated with a point-in-time plus `search_after`, not from/size: the
        default `max_result_window` is 10k and a real fleet blows past it.

        The PIT matters for correctness, not just depth. The scanner deletes rows
        from this index the moment a package is patched, and `refresh_interval` is
        2s — without a frozen view, concurrent deletes shift the result set under
        the cursor and records get skipped or repeated mid-pull. Since the ingest
        diffs one pull against the previous one to derive "resolved", a skipped
        record would be misreported as patched.
        """
        query: Dict[str, Any] = {"match_all": {}}
        if agent_ids:
            query = {"terms": {"agent.id": agent_ids}}

        async with self._client() as client:
            pit_id = await self._open_pit(client)
            body: Dict[str, Any] = {
                "size": page_size,
                "query": query,
                "_source": SOURCE_FIELDS,
                # _doc is the cheapest total order. Note this is OpenSearch, not
                # Elasticsearch: _shard_doc does not exist here and a PIT search
                # sorting on it fails with "No mapping found for [_shard_doc]".
                "sort": [{"_doc": "asc"}],
            }
            if pit_id:
                body["pit"] = {"id": pit_id, "keep_alive": "5m"}
            path = "/_search" if pit_id else f"/{self.index_pattern}/_search"

            total = 0
            try:
                search_after: Optional[List[Any]] = None
                while True:
                    if search_after is not None:
                        body["search_after"] = search_after
                    try:
                        resp = await client.post(path, json=body)
                        resp.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        raise WazuhIndexerError(
                            f"search failed ({exc.response.status_code}): {exc.response.text[:200]}"
                        ) from exc
                    except httpx.HTTPError as exc:
                        raise WazuhIndexerError(f"search failed: {transport_reason(exc)}") from exc

                    payload = resp.json()
                    # A PIT search returns a refreshed id that must be carried forward.
                    if pit_id and payload.get("pit_id"):
                        pit_id = payload["pit_id"]
                        body["pit"]["id"] = pit_id

                    hits = payload.get("hits", {}).get("hits", [])
                    if not hits:
                        break
                    for hit in hits:
                        yield hit.get("_source", {})
                    total += len(hits)
                    if len(hits) < page_size:
                        break
                    search_after = hits[-1].get("sort")
                    if not search_after:
                        break
            finally:
                if pit_id:
                    await self._close_pit(client, pit_id)
            logger.info("wazuh_indexer_pull_done", docs=total, pit=bool(pit_id))

    async def _open_pit(self, client: httpx.AsyncClient) -> Optional[str]:
        """Open a point-in-time, or return None if the cluster will not grant one."""
        try:
            resp = await client.post(
                f"/{self.index_pattern}/_search/point_in_time", params={"keep_alive": "5m"}
            )
            resp.raise_for_status()
            return resp.json().get("pit_id")
        except httpx.HTTPError as exc:
            # Older or restricted clusters may refuse PIT; an unfrozen _doc-sorted
            # scan is less consistent but better than failing the whole ingest.
            logger.warning("wazuh_indexer_pit_unavailable", error=str(exc))
            return None

    async def _close_pit(self, client: httpx.AsyncClient, pit_id: str) -> None:
        try:
            await client.request("DELETE", "/_search/point_in_time", json={"pit_id": pit_id})
        except httpx.HTTPError as exc:
            # The keep_alive expires on its own; a leaked PIT is not worth failing on.
            logger.warning("wazuh_indexer_pit_close_failed", error=str(exc))
