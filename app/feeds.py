"""Public enrichment feeds: EPSS (FIRST.org) and the CISA KEV catalog.

Both are queried by CVE identifier only. No hostname, package, IP or any other
detail about the monitored infrastructure is sent, so these are safe to enable on
a deployment watching private infrastructure. On an air-gapped host they can be
turned off in the Configuration tab and scoring degrades to CVSS-only.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

import httpx
import structlog

logger = structlog.get_logger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# FIRST.org accepts a comma-separated cve list; keep batches well under the URL
# length limit and under the documented 100-item envelope.
EPSS_BATCH = 100


async def fetch_epss(cves: Iterable[str], timeout: float = 30.0) -> Dict[str, float]:
    """Map CVE -> EPSS probability. Missing entries simply do not appear."""
    unique: List[str] = sorted({c for c in cves if c})
    scores: Dict[str, float] = {}
    if not unique:
        return scores

    async with httpx.AsyncClient(timeout=timeout) as client:
        for start in range(0, len(unique), EPSS_BATCH):
            batch = unique[start : start + EPSS_BATCH]
            try:
                resp = await client.get(EPSS_URL, params={"cve": ",".join(batch)})
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                # Enrichment is best-effort: a feed outage must not fail the ingest.
                logger.warning("epss_batch_failed", error=str(exc), size=len(batch))
                continue
            for item in resp.json().get("data", []):
                cve = item.get("cve")
                try:
                    if cve:
                        scores[cve] = float(item["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
    logger.info("epss_fetched", requested=len(unique), resolved=len(scores))
    return scores


async def fetch_kev(timeout: float = 60.0) -> Dict[str, Dict[str, Any]]:
    """Map CVE -> KEV entry for every actively-exploited CVE CISA tracks."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            payload = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("kev_fetch_failed", error=str(exc))
        return {}

    catalog: Dict[str, Dict[str, Any]] = {}
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cveID")
        if not cve:
            continue
        catalog[cve] = {
            "vencimiento": item.get("dueDate", ""),
            "ransomware": str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "accion": item.get("requiredAction", ""),
            "nombre": item.get("vulnerabilityName", ""),
        }
    logger.info("kev_fetched", entries=len(catalog))
    return catalog
