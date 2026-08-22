"""Pull vulnerability state from Wazuh and refresh the dashboard's cache.

Wazuh's index holds only *currently active* vulnerabilities and has no status
field: a record is deleted the moment the package is patched or a Windows KB that
fixes it is installed. Everything the dashboard shows about history — first seen,
aging, patch SLA, resolved-in-the-last-7-days — therefore has to be derived here,
by diffing each pull against the state we recorded last time.

For the same reason the ingest keeps its own first-seen date. Wazuh's
`vulnerability.detected_at` is rewritten whenever it re-indexes a record, so an
SLA clock based on it silently restarts and never breaches.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import structlog

from app.feeds import fetch_epss, fetch_kev
from app.scoring import priority_score
from app.wazuh.indexer import WazuhIndexerClient
from app.wazuh.mapper import aggregate_by_cve

logger = structlog.get_logger(__name__)

# Per-(CVE, agent) lifecycle. The fleet-wide vuln_cve_state table cannot express
# "patched on DC01, still open on pve01", which is the normal case once more than
# one host is monitored.
AGENT_STATE_SQL = """
CREATE TABLE IF NOT EXISTS vuln_cve_agent_state (
    cve TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    agent_name TEXT NOT NULL DEFAULT '',
    plataforma TEXT NOT NULL DEFAULT '',
    first_seen DATE NOT NULL,
    last_seen DATE NOT NULL,
    status TEXT NOT NULL,
    resolved_at DATE,
    PRIMARY KEY (cve, agent_id)
);
CREATE INDEX IF NOT EXISTS vuln_cve_agent_state_cve_idx ON vuln_cve_agent_state (cve);
"""

# Existing installs key assignments by CVE alone. Widen to (cve, agent_id) and
# keep old rows as fleet-wide assignments under the empty agent id.
ASSIGNMENT_MIGRATION_SQL = """
ALTER TABLE vuln_assignments ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT '';
"""


async def migrate_assignments(pool: asyncpg.Pool) -> None:
    """Widen vuln_assignments to (cve, agent_id) without losing existing rows."""
    await pool.execute(AGENT_STATE_SQL)
    await pool.execute(ASSIGNMENT_MIGRATION_SQL)
    pk = await pool.fetchval(
        """
        SELECT constraint_name FROM information_schema.table_constraints
        WHERE table_name = 'vuln_assignments' AND constraint_type = 'PRIMARY KEY'
        """
    )
    # Only rebuild the key when it is still the single-column original.
    cols = await pool.fetch(
        """
        SELECT column_name FROM information_schema.key_column_usage
        WHERE constraint_name = $1 AND table_name = 'vuln_assignments'
        """,
        pk,
    )
    if pk and len(cols) == 1:
        await pool.execute(f'ALTER TABLE vuln_assignments DROP CONSTRAINT "{pk}"')
        await pool.execute("ALTER TABLE vuln_assignments ADD PRIMARY KEY (cve, agent_id)")
        logger.info("vuln_assignments_key_widened")


def _entry_priority(row: Dict[str, Any], settings: Any) -> Optional[float]:
    return priority_score(
        row.get("cvss"),
        row.get("epss"),
        bool(row.get("kev")),
        settings.vuln_cvss_weight,
        settings.vuln_epss_weight,
        settings.vuln_kev_weight,
    )


async def _sync_agent_lifecycle(
    pool: asyncpg.Pool, seen: List[Tuple[str, str, str, str]], today: date
) -> Dict[str, int]:
    """Record which (CVE, agent) pairs are currently open and close the rest."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "CREATE TEMP TABLE seen_pairs (cve TEXT, agent_id TEXT, agent_name TEXT,"
                " plataforma TEXT) ON COMMIT DROP"
            )
            await conn.copy_records_to_table("seen_pairs", records=seen)
            # Present now: new on first sight, reopened if we had closed it.
            await conn.execute(
                """
                INSERT INTO vuln_cve_agent_state
                    (cve, agent_id, agent_name, plataforma, first_seen, last_seen, status)
                SELECT cve, agent_id, agent_name, plataforma, $1, $1, 'open' FROM seen_pairs
                ON CONFLICT (cve, agent_id) DO UPDATE SET
                    last_seen = $1,
                    agent_name = EXCLUDED.agent_name,
                    plataforma = EXCLUDED.plataforma,
                    status = CASE WHEN vuln_cve_agent_state.status = 'resolved'
                                  THEN 'reopened' ELSE vuln_cve_agent_state.status END,
                    resolved_at = NULL
                """,
                today,
            )
            # Absent now but open before: Wazuh deleted the record, so it is patched.
            resolved = await conn.fetchval(
                """
                WITH closed AS (
                    UPDATE vuln_cve_agent_state s SET status = 'resolved', resolved_at = $1
                    WHERE s.status <> 'resolved' AND NOT EXISTS (
                        SELECT 1 FROM seen_pairs p
                        WHERE p.cve = s.cve AND p.agent_id = s.agent_id
                    )
                    RETURNING 1
                ) SELECT COUNT(*) FROM closed
                """,
                today,
            )
            opened = await conn.fetchval(
                "SELECT COUNT(*) FROM vuln_cve_agent_state WHERE first_seen = $1", today
            )
    return {"resueltos": int(resolved or 0), "nuevos": int(opened or 0)}


async def run_ingest(pool: asyncpg.Pool, config: Dict[str, Any], settings: Any) -> Dict[str, Any]:
    """Pull from Wazuh, enrich, score and persist. Returns a run summary."""
    if not config.get("indexer_url"):
        raise ValueError("no indexer URL configured")

    client = WazuhIndexerClient(
        base_url=config["indexer_url"],
        username=config["indexer_user"],
        password=config["indexer_password"],
        verify_tls=bool(config.get("verify_tls")),
    )

    docs = [doc async for doc in client.iter_vulnerabilities()]
    if not docs:
        logger.warning("ingest_no_documents")

    rows = aggregate_by_cve(docs)
    cves = [r["cve"] for r in rows]

    epss = await fetch_epss(cves) if config.get("enrich_epss") else {}
    kev = await fetch_kev() if config.get("enrich_kev") else {}

    rows = aggregate_by_cve(docs, epss_by_cve=epss, kev_by_cve=kev)
    for row in rows:
        row["priority_score"] = _entry_priority(row, settings)

    today = date.today()
    pairs = [
        (r["cve"], a["agent_id"], a["agente"], a["plataforma"])
        for r in rows
        for a in r["detalle_agentes"]
    ]
    lifecycle = await _sync_agent_lifecycle(pool, pairs, today)

    # first_seen per CVE is the earliest across agents, so aging reflects how long
    # the fleet has carried it rather than when the newest host picked it up.
    first_seen = {
        r["cve"]: r["first_seen"]
        for r in await pool.fetch(
            "SELECT cve, MIN(first_seen) AS first_seen FROM vuln_cve_agent_state"
            " WHERE status <> 'resolved' GROUP BY cve"
        )
    }
    for row in rows:
        fs = first_seen.get(row["cve"])
        row["first_seen"] = fs.isoformat() if fs else today.isoformat()

    summary = _build_summary(rows, today)
    await _save(pool, rows, summary, today)

    result = {
        "cves": len(rows),
        "documentos": len(docs),
        "epss_resueltos": len(epss),
        "kev_coincidencias": sum(1 for r in rows if r["kev"]),
        **lifecycle,
        "actualizado": summary["actualizado"],
    }
    logger.info("ingest_done", **result)
    return result


_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Untriaged": 0}


def _top_paquetes(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rank what is vulnerable, keeping OS findings distinct from packages.

    A Windows OS entry aggregates every CVE of that build — thousands on a stock
    server — so mixed into one ranking it buries every real package. `tipo` lets
    the UI split them into separate charts.
    """
    agg: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        is_os = "os_update" in row["tipos"]
        for pkg in row["paquetes"]:
            entry = agg.setdefault(
                pkg,
                {"cves": set(), "severidad_max": "Untriaged",
                 "tipo": "os" if is_os else "paquete"},
            )
            entry["cves"].add(row["cve"])
            if _SEV_RANK.get(row["severidad"], 0) > _SEV_RANK.get(entry["severidad_max"], 0):
                entry["severidad_max"] = row["severidad"]
    top = [
        {"paquete": k, "cves": len(v["cves"]), "severidad_max": v["severidad_max"],
         "tipo": v["tipo"]}
        for k, v in agg.items()
    ]
    top.sort(key=lambda r: (-r["cves"], -_SEV_RANK.get(r["severidad_max"], 0)))
    return top


def _build_summary(rows: List[Dict[str, Any]], today: date) -> Dict[str, Any]:
    por_sev: Dict[str, int] = {}
    por_agente: Dict[str, Dict[str, int]] = {}
    for row in rows:
        sev = row["severidad"]
        por_sev[sev] = por_sev.get(sev, 0) + 1
        for agent in row["detalle_agentes"]:
            bucket = por_agente.setdefault(
                agent["agente"],
                {"critical": 0, "high": 0, "medium": 0, "low": 0, "untriaged": 0, "total": 0},
            )
            key = sev.lower()
            if key in bucket:
                bucket[key] += 1
            bucket["total"] += 1
    top = _top_paquetes(rows)
    return {
        "actualizado": f"{today.isoformat()}T00:00:00+00:00",
        "cves": rows,
        "total": sum(r["instalaciones"] for r in rows),
        "cves_unicos": len(rows),
        "criticas_altas": sum(1 for r in rows if r["severidad"] in ("Critical", "High")),
        "por_severidad": [{"severidad": k, "n": v} for k, v in sorted(por_sev.items())],
        "servidores": [{"agente": k, **v} for k, v in sorted(por_agente.items())],
        "top_paquetes": top,
        "paquetes_unicos": len(top),
        "plataformas": sorted({p for r in rows for p in r["plataformas"]}),
        "sin_datos": not rows,
    }


async def _save(
    pool: asyncpg.Pool, rows: List[Dict[str, Any]], summary: Dict[str, Any], today: date
) -> None:
    import json

    await pool.execute(
        """
        INSERT INTO vuln_state_cache (id, updated_at, state) VALUES (1, NOW(), $1)
        ON CONFLICT (id) DO UPDATE SET updated_at = NOW(), state = EXCLUDED.state
        """,
        json.dumps(summary),
    )
    await pool.execute(
        """
        INSERT INTO vuln_snapshots (fecha, total, criticas_altas, cves_unicos,
                                    por_severidad, por_servidor)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (fecha) DO UPDATE SET
            total = EXCLUDED.total, criticas_altas = EXCLUDED.criticas_altas,
            cves_unicos = EXCLUDED.cves_unicos, por_severidad = EXCLUDED.por_severidad,
            por_servidor = EXCLUDED.por_servidor
        """,
        today,
        summary["total"],
        summary["criticas_altas"],
        summary["cves_unicos"],
        json.dumps({s["severidad"]: s["n"] for s in summary["por_severidad"]}),
        json.dumps({s["agente"]: s for s in summary["servidores"]}),
    )
