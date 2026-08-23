"""Persistencia del seguimiento de vulnerabilidades (Postgres).

Tablas principales, creadas con ``CREATE TABLE IF NOT EXISTS`` al conectar:

* ``vuln_cve_agent_state`` — ciclo de vida por (CVE, agente).
* ``vuln_snapshots`` — un snapshot por día con los totales; da la serie
  temporal para los gráficos de evolución.
* ``vuln_assignments`` — owner + estado de remediación por CVE, cargado a
  mano desde la pantalla.
* ``vuln_state_cache`` — fila única con el último estado "enriquecido"
  (CVSS/EPSS/KEV/priority_score). La pantalla lee de acá siempre.
* ``vuln_priority_brief`` — fila única con un párrafo de "qué priorizar".
* ``vuln_kev_cache`` — cache local del catálogo CISA KEV.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import structlog

logger = structlog.get_logger(__name__)

ASSIGNMENT_STATUSES = ("pendiente", "en_curso", "parcial", "resuelto", "aceptado_riesgo")

_WS_RE = re.compile(r"\s+")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


TABLES_SQL = """
CREATE TABLE IF NOT EXISTS vuln_snapshots (
    fecha DATE PRIMARY KEY,
    total INTEGER NOT NULL,
    criticas_altas INTEGER NOT NULL,
    cves_unicos INTEGER NOT NULL,
    por_severidad JSONB NOT NULL DEFAULT '{}',
    por_servidor JSONB NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS vuln_assignments (
    cve TEXT PRIMARY KEY,
    owner TEXT NOT NULL DEFAULT '',
    owner_email TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pendiente',
    due_date DATE,
    notes TEXT NOT NULL DEFAULT '',
    updated_by TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS vuln_state_cache (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    state JSONB NOT NULL,
    CHECK (id = 1)
);
CREATE TABLE IF NOT EXISTS vuln_priority_brief (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    brief TEXT NOT NULL,
    cve_refs JSONB NOT NULL DEFAULT '[]',
    CHECK (id = 1)
);
CREATE TABLE IF NOT EXISTS vuln_kev_cache (
    cve TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    fetched_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
"""


class VulnStore:
    """Acceso a las tablas de seguimiento de vulnerabilidades."""

    def __init__(self, dsn: str, pool: Optional[asyncpg.Pool] = None) -> None:
        self.dsn = dsn
        self._pool = pool
        self._owns_pool = pool is None

    async def connect(self) -> None:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=5)
        try:
            await self._pool.execute(TABLES_SQL)
        except Exception as exc:  # noqa: BLE001
            logger.warning("vuln_tables_init_failed", error=str(exc))

    async def close(self) -> None:
        if self._pool and self._owns_pool:
            await self._pool.close()
            self._pool = None

    # ------------------------------------------------------------------
    # Métricas de patching
    # ------------------------------------------------------------------
    async def patching_metrics(
        self, today: Optional[date] = None, sla_days: int = 15
    ) -> Dict[str, Any]:
        """Aging, SLA de críticas y altas/bajas de los últimos 7 días.

        Se calcula sobre ``vuln_cve_agent_state`` — el par (CVE, agente). Un
        CVE resuelto en un servidor y abierto en otro cuenta como lo que es:
        uno de cada.
        """
        if self._pool is None:
            return {}
        today = today or date.today()
        week_ago = today - timedelta(days=7)
        sla_cutoff = today - timedelta(days=sla_days)

        row = await self._pool.fetchrow(
            """
            SELECT
              COUNT(*) FILTER (WHERE first_seen >= $1 AND status <> 'resolved') AS nuevas_7d,
              COUNT(*) FILTER (WHERE resolved_at >= $1) AS resueltas_7d,
              COUNT(*) FILTER (WHERE reopened_at >= $1 AND status <> 'resolved') AS reabiertas_7d,
              COUNT(*) FILTER (WHERE status <> 'resolved') AS activas,
              COUNT(*) FILTER (
                  WHERE status <> 'resolved' AND severidad = 'Critical' AND first_seen <= $2
              ) AS criticas_vencen_sla,
              COUNT(*) FILTER (
                  WHERE status <> 'resolved' AND severidad = 'Critical'
              ) AS criticas_activas,
              COALESCE(AVG($3::date - first_seen)
                       FILTER (WHERE status <> 'resolved'), 0) AS aging_promedio_dias,
              COUNT(*) FILTER (
                  WHERE status = 'resolved' AND severidad = 'Critical'
              ) AS criticas_resueltas,
              COUNT(*) FILTER (
                  WHERE status = 'resolved' AND severidad = 'Critical'
                        AND resolved_at - first_seen <= $4
              ) AS criticas_resueltas_en_sla
            FROM vuln_cve_agent_state
            """,
            week_ago,
            sla_cutoff,
            today,
            sla_days,
        )
        out = dict(row) if row else {}
        out["aging_promedio_dias"] = round(float(out.get("aging_promedio_dias") or 0), 1)
        resueltas = out.get("criticas_resueltas") or 0
        out["sla_criticas_pct"] = (
            round(100.0 * (out.get("criticas_resueltas_en_sla") or 0) / resueltas, 1)
            if resueltas
            else None
        )
        out["sla_dias"] = sla_days
        return out

    # ------------------------------------------------------------------
    # Ciclo de vida por CVE (para la tabla de la pantalla)
    # ------------------------------------------------------------------
    async def lifecycle_map(self) -> Dict[str, Dict[str, Any]]:
        """``{cve: {first_seen, status, ...}}`` para anotar la lista viva.

        La fuente de verdad es ``vuln_cve_agent_state``: un CVE está resuelto
        solo cuando todos los agentes lo están.
        """
        if self._pool is None:
            return {}
        rows = await self._pool.fetch(
            """
            SELECT
                cve,
                MIN(first_seen) AS first_seen,
                MAX(last_seen) AS last_seen,
                CASE WHEN COUNT(*) FILTER (WHERE status <> 'resolved') = 0
                     THEN 'resolved' ELSE 'open' END AS status,
                MAX(resolved_at) AS resolved_at
            FROM vuln_cve_agent_state
            GROUP BY cve
            """
        )
        return {r["cve"]: dict(r) for r in rows}

    # ------------------------------------------------------------------
    # Cache del estado vivo
    # ------------------------------------------------------------------

    async def load_state_cache(self) -> Optional[Dict[str, Any]]:
        """``{updated_at, state}`` o ``None`` si todavía no se sembró nada."""
        if self._pool is None:
            return None
        row = await self._pool.fetchrow(
            "SELECT updated_at, state FROM vuln_state_cache WHERE id = 1"
        )
        if not row:
            return None
        state = row["state"]
        if isinstance(state, str):
            state = json.loads(state)
        return {"updated_at": row["updated_at"].isoformat(), "state": state}

    # ------------------------------------------------------------------
    # Brief de priorización (queda vacío en esta demo salvo carga manual)
    # ------------------------------------------------------------------
    async def save_priority_brief(self, brief: str, meta: Dict[str, Any]) -> None:
        """Guarda el resumen generado. Fila unica: solo interesa el ultimo."""
        if self._pool is None:
            raise RuntimeError("VulnStore not connected")
        await self._pool.execute(
            """
            INSERT INTO vuln_priority_brief (id, updated_at, brief, cve_refs)
            VALUES (1, NOW(), $1, $2)
            ON CONFLICT (id) DO UPDATE SET
                updated_at = NOW(), brief = EXCLUDED.brief, cve_refs = EXCLUDED.cve_refs
            """,
            brief,
            json.dumps(meta),
        )

    async def load_priority_brief(self) -> Optional[Dict[str, Any]]:
        if self._pool is None:
            return None
        row = await self._pool.fetchrow(
            "SELECT updated_at, brief, cve_refs FROM vuln_priority_brief WHERE id = 1"
        )
        if not row:
            return None
        cve_refs = row["cve_refs"]
        if isinstance(cve_refs, str):
            cve_refs = json.loads(cve_refs)
        return {
            "updated_at": row["updated_at"].isoformat(),
            "brief": row["brief"],
            "cve_refs": cve_refs,
        }

    # ------------------------------------------------------------------
    # KEV cache
    # ------------------------------------------------------------------
    async def load_kev_cache(self, ttl_hours: int = 6) -> Optional[Dict[str, Dict[str, Any]]]:
        """Return cached KEV catalog if it is still fresh."""
        if self._pool is None:
            return None
        since = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
        rows = await self._pool.fetch(
            "SELECT cve, data FROM vuln_kev_cache WHERE fetched_at >= $1", since
        )
        if not rows:
            return None
        return {r["cve"]: dict(r["data"]) for r in rows}

    async def save_kev_cache(self, catalog: Dict[str, Dict[str, Any]]) -> None:
        """Replace the cached KEV catalog with a fresh download."""
        if self._pool is None:
            return
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("TRUNCATE vuln_kev_cache")
                for cve, data in catalog.items():
                    await conn.execute(
                        "INSERT INTO vuln_kev_cache (cve, data, fetched_at) VALUES ($1, $2, NOW())",
                        cve,
                        json.dumps(data),
                    )

    # ------------------------------------------------------------------
    # Snapshots (serie temporal)
    # ------------------------------------------------------------------
    async def history(self, days: int = 90) -> List[Dict[str, Any]]:
        if self._pool is None:
            return []
        rows = await self._pool.fetch(
            """SELECT fecha, total, criticas_altas, cves_unicos, por_severidad, por_servidor
               FROM vuln_snapshots
               WHERE fecha >= $1
               ORDER BY fecha""",
            date.today() - timedelta(days=days),
        )
        out = []
        for r in rows:
            d = dict(r)
            d["fecha"] = d["fecha"].isoformat()
            for k in ("por_severidad", "por_servidor"):
                if isinstance(d[k], str):
                    try:
                        d[k] = json.loads(d[k])
                    except (ValueError, TypeError):
                        d[k] = {}
            out.append(d)
        return out

    # ------------------------------------------------------------------
    # Assignments (owner + seguimiento)
    # ------------------------------------------------------------------
    async def assignments(self) -> Dict[str, Dict[str, Any]]:
        """Todos los assignments indexados por CVE."""
        if self._pool is None:
            return {}
        rows = await self._pool.fetch(
            "SELECT cve, owner, owner_email, status, due_date, notes, updated_by, updated_at "
            "FROM vuln_assignments"
        )
        out = {}
        for r in rows:
            d = dict(r)
            if d.get("due_date"):
                d["due_date"] = d["due_date"].isoformat()
            if d.get("updated_at"):
                d["updated_at"] = d["updated_at"].isoformat()
            out[d["cve"]] = d
        return out

    async def owners(self) -> List[str]:
        """Owners ya usados (para el datalist de la pantalla)."""
        if self._pool is None:
            return []
        rows = await self._pool.fetch(
            "SELECT DISTINCT owner FROM vuln_assignments WHERE owner <> '' ORDER BY owner"
        )
        return [r["owner"] for r in rows]

    async def _canonical_owner(self, owner: str) -> str:
        """Normaliza espacios y converge a la grafía ya usada en la base."""
        normalized = _WS_RE.sub(" ", owner.strip())
        if not normalized or self._pool is None:
            return normalized
        row = await self._pool.fetchrow(
            "SELECT owner FROM vuln_assignments WHERE lower(owner) = lower($1) LIMIT 1",
            normalized,
        )
        return row["owner"] if row else normalized

    async def upsert_assignment(
        self,
        cve: str,
        owner: str,
        status: str,
        due_date: Optional[str],
        notes: str,
        updated_by: str,
        owner_email: str = "",
    ) -> Dict[str, Any]:
        """Crea/actualiza el seguimiento de un CVE."""
        if self._pool is None:
            raise RuntimeError("VulnStore not connected")
        if status not in ASSIGNMENT_STATUSES:
            raise ValueError(
                f"status inválido: {status!r} (válidos: {', '.join(ASSIGNMENT_STATUSES)})"
            )
        owner_email = owner_email.strip()
        if owner_email and not _EMAIL_RE.match(owner_email):
            raise ValueError(f"correo inválido: {owner_email!r}")
        owner = await self._canonical_owner(owner)
        due = date.fromisoformat(due_date) if due_date else None

        await self._pool.execute(
            """INSERT INTO vuln_assignments
                   (cve, owner, owner_email, status, due_date, notes, updated_by, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
               ON CONFLICT (cve) DO UPDATE SET
                   owner = EXCLUDED.owner,
                   owner_email = EXCLUDED.owner_email,
                   status = EXCLUDED.status,
                   due_date = EXCLUDED.due_date,
                   notes = EXCLUDED.notes,
                   updated_by = EXCLUDED.updated_by,
                   updated_at = NOW()""",
            cve,
            owner,
            owner_email,
            status,
            due,
            notes,
            updated_by,
        )
        logger.info("vuln_assignment_updated", cve=cve, owner=owner, status=status, by=updated_by)
        return {
            "cve": cve,
            "owner": owner,
            "owner_email": owner_email,
            "status": status,
            "due_date": due_date,
            "notes": notes,
        }

    async def delete_assignment(self, cve: str, deleted_by: str) -> bool:
        """Borra el seguimiento de un CVE. True si existía."""
        if self._pool is None:
            return False
        result = await self._pool.execute("DELETE FROM vuln_assignments WHERE cve = $1", cve)
        deleted = result.endswith("1")
        if deleted:
            logger.info("vuln_assignment_deleted", cve=cve, by=deleted_by)
        return deleted
