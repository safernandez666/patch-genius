"""Vulnerability & Patch Tracking — demo pública.

Extraído de un panel SOC productivo: acá se sacó todo lo que no hace falta
para un demo público y anónimo sobre datos sintéticos — autenticación,
auditoría, Wazuh en vivo, EPSS/KEV en vivo, correo. Las 6 rutas de lectura y
seguimiento son las mismas que en el sistema original.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import date
from typing import Any, Dict, List, Optional

import asyncpg
import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.auth import SESSION_COOKIE, AuthManager
from app.config_store import ConfigError, ConfigStore
from app.ingest import migrate_assignments, purge_demo_data, run_ingest
from app.scoring import SEV_RANK, sev_rank
from app.settings import settings
from app.vuln_store import ASSIGNMENT_STATUSES, VulnStore
from app.wazuh.indexer import WazuhIndexerClient, WazuhIndexerError
from seed.generate_seed import seed_if_empty

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = await asyncpg.create_pool(settings.postgres_dsn, min_size=1, max_size=5)
    store = VulnStore(settings.postgres_dsn, pool=pool)
    await store.connect()
    await migrate_assignments(pool)

    config_store = ConfigStore(pool, settings.app_secret_key)
    await config_store.init()
    auth = AuthManager(pool, settings.app_secret_key)
    await auth.init(settings.admin_user, settings.admin_password)

    app.state.pg_pool = pool
    app.state.store = store
    app.state.config_store = config_store
    app.state.auth = auth

    cfg = await config_store.load()
    if cfg["data_source"] == "demo":
        # Only seed synthetic data while the deployment has no real source; a
        # Wazuh-backed install must never have demo CVEs mixed into its inventory.
        if await seed_if_empty(store):
            logger.info("vuln_demo_seeded")
    app.state.refresh_task = asyncio.create_task(_refresh_loop(app))

    yield
    app.state.refresh_task.cancel()
    await pool.close()


async def _refresh_loop(app: FastAPI) -> None:
    """Periodically re-ingest from Wazuh while the data source is not the demo."""
    while True:
        try:
            cfg = await app.state.config_store.load()
            if cfg["data_source"] == "wazuh" and cfg["indexer_url"]:
                await run_ingest(app.state.pg_pool, cfg, settings)
            await asyncio.sleep(max(5, int(cfg["refresh_minutes"])) * 60)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            # A failed refresh must not kill the loop — the dashboard keeps
            # serving the last good cache until the next attempt succeeds.
            logger.error("refresh_loop_failed", error=str(exc))
            await asyncio.sleep(300)


app = FastAPI(title="Vulnerability & Patch Tracking", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    # A deployment reading a real Wazuh must name its origin; the wildcard stays
    # only for the synthetic demo, where there is nothing to protect.
    allow_origins=settings.cors_origin_list or ["*"],
    allow_credentials=bool(settings.cors_origin_list),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")


def _store(request: Request) -> VulnStore:
    return request.app.state.store


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/version")
async def version():
    return {"version": "public-demo"}


@app.get("/")
async def index(request: Request):
    if await _auth_required(request) and not await current_user(request):
        return RedirectResponse("/login", status_code=302)
    return FileResponse("static/index.html")


# ---------------------------------------------------------------------------
# Authentication. Enabled automatically whenever the data source is real Wazuh:
# the dashboard then lists unpatched CVEs of live hosts, and the Configuration
# tab holds Wazuh credentials. The synthetic demo stays open.
# ---------------------------------------------------------------------------
async def _auth_required(request: Request) -> bool:
    cfg = await request.app.state.config_store.load_public()
    return cfg["data_source"] != "demo"


async def current_user(request: Request) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    data = request.app.state.auth.read_session(token)
    return data.get("u") if data else None


async def require_user(request: Request) -> str:
    """Reject anonymous callers once the deployment is backed by real data."""
    user = await current_user(request)
    if user:
        return user
    if not await _auth_required(request):
        return "visitante-demo"
    raise HTTPException(status_code=401, detail="authentication required")


async def require_admin(request: Request) -> str:
    """Guard the Configuration tab. Never open, even in demo mode: it stores
    the Wazuh password and can switch the whole deployment onto live data."""
    user = await current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


@app.get("/login")
async def login_page():
    return FileResponse("static/login.html")


@app.post("/api/login")
async def api_login(request: Request, response: Response):
    body = await request.json()
    user = await request.app.state.auth.authenticate(
        str(body.get("username", "")), str(body.get("password", ""))
    )
    if not user:
        # Same message for unknown user and wrong password.
        raise HTTPException(status_code=401, detail="credenciales invalidas")
    token = request.app.state.auth.issue_session(user)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=8 * 60 * 60,
    )
    return {"ok": True, "user": user}


@app.post("/api/logout")
async def api_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/session")
async def api_session(request: Request):
    return {
        "user": await current_user(request),
        "auth_required": await _auth_required(request),
    }


# ---------------------------------------------------------------------------
# Configuration tab — Wazuh onboarding.
# ---------------------------------------------------------------------------
@app.get("/config")
async def config_page():
    return FileResponse("static/config.html")


@app.get("/api/config")
async def api_config_get(request: Request, user: str = Depends(require_admin)):
    return await request.app.state.config_store.load_public()


@app.put("/api/config")
async def api_config_put(request: Request, user: str = Depends(require_admin)):
    body = await request.json()
    previous = await request.app.state.config_store.load_public()
    try:
        saved = await request.app.state.config_store.save(body, updated_by=user)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Leaving demo mode: clear the synthetic seed so it cannot be mistaken for,
    # or mixed into, the real inventory.
    if previous["data_source"] == "demo" and saved["data_source"] == "wazuh":
        purged = await purge_demo_data(request.app.state.pg_pool)
        saved["demo_purgado"] = purged
    return saved


@app.post("/api/config/test")
async def api_config_test(request: Request, user: str = Depends(require_admin)):
    """Probe the Wazuh indexer with the submitted settings without saving them."""
    body = await request.json()
    stored = await request.app.state.config_store.load()
    password = body.get("indexer_password") or stored["indexer_password"]
    url = (body.get("indexer_url") or stored["indexer_url"] or "").strip().rstrip("/")
    if not url:
        raise HTTPException(status_code=400, detail="falta la URL del indexer")
    client = WazuhIndexerClient(
        base_url=url,
        username=body.get("indexer_user") or stored["indexer_user"],
        password=password,
        verify_tls=bool(body.get("verify_tls", stored["verify_tls"])),
        timeout=15.0,
    )
    try:
        return {"ok": True, **await client.ping()}
    except WazuhIndexerError as exc:
        return {"ok": False, "error": str(exc)}


@app.post("/api/ingest")
async def api_ingest(request: Request, user: str = Depends(require_admin)):
    """Run an ingest now, instead of waiting for the refresh interval."""
    cfg = await request.app.state.config_store.load()
    if cfg["data_source"] != "wazuh":
        raise HTTPException(status_code=400, detail="el origen de datos no es wazuh")
    try:
        return await run_ingest(request.app.state.pg_pool, cfg, settings)
    except (WazuhIndexerError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Helpers compartidos por /summary y /cves — así los KPIs y la tabla nunca se
# desincronizan (mismo patrón que el sistema del que se extrajo esta pantalla).
# ---------------------------------------------------------------------------
async def _load_state(store: VulnStore) -> tuple[dict, Optional[str]]:
    cached = await store.load_state_cache()
    if cached is None:
        return {
            "sin_datos": True,
            "total": 0,
            "por_severidad": [],
            "criticas_altas": 0,
            "cves_unicos": 0,
            "paquetes_unicos": 0,
            "servidores": [],
            "cves": [],
            "top_paquetes": [],
        }, None
    return cached["state"], cached["updated_at"]


def _vuln_rows(state: dict, lifecycle: dict, assigns: dict) -> List[dict]:
    today = date.today()
    rows = []
    for c in state.get("cves", []):
        life = lifecycle.get(c["cve"]) or {}
        # A Wazuh ingest computes first_seen per (CVE, agent) and stores it on the
        # cached row; vuln_cve_state only ever holds the synthetic demo lifecycle.
        # Prefer the ingested value so aging and the patch SLA work on real data.
        first_seen = c.get("first_seen") or life.get("first_seen")
        if isinstance(first_seen, str) and first_seen:
            try:
                first_seen = date.fromisoformat(first_seen)
            except ValueError:
                first_seen = None
        asg = assigns.get(c["cve"]) or {}
        kev_info = c.get("kev_info") or {}
        rows.append(
            {
                "cve": c["cve"],
                "severidad": c["severidad"],
                "cvss": c.get("cvss"),
                "descripcion": c.get("descripcion", ""),
                "referencia": c.get("referencia", ""),
                "publicado": c.get("publicado", ""),
                "paquetes": c.get("paquetes", []),
                "agentes": c.get("agentes", []),
                "instalaciones": c.get("instalaciones", 0),
                "epss": c.get("epss"),
                "kev": c.get("kev", False),
                "kev_vencimiento": kev_info.get("vencimiento", ""),
                "kev_ransomware": kev_info.get("ransomware", False),
                "priority_score": c.get("priority_score"),
                "first_seen": first_seen.isoformat() if first_seen else "",
                "dias_detectado": (today - first_seen).days if first_seen else None,
                "owner": asg.get("owner", ""),
                "owner_email": asg.get("owner_email", ""),
                "estado": asg.get("status", ""),
                "due_date": asg.get("due_date", ""),
                "notes": asg.get("notes", ""),
            }
        )
    return rows


def _servidores_from_rows(rows: List[dict], only_agent: str) -> List[dict]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for r in rows:
        sev_key = (r["severidad"] or "").lower()
        if sev_key in counts:
            counts[sev_key] += 1
        counts["total"] += 1
    return [{"agente": only_agent, **counts}]


def _servidores_leaderboard_from_rows(rows: List[dict]) -> List[dict]:
    agg: Dict[str, Dict[str, int]] = {}
    for r in rows:
        sev_key = (r["severidad"] or "").lower()
        for agente in r["agentes"]:
            e = agg.setdefault(
                agente, {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
            )
            if sev_key in e:
                e[sev_key] += 1
            e["total"] += 1
    servidores = [{"agente": a, **c} for a, c in agg.items()]
    servidores.sort(key=lambda r: (-r["critical"], -r["high"], -r["total"]))
    return servidores


def _top_paquetes_from_rows(rows: List[dict]) -> List[dict]:
    agg: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        for p in r["paquetes"]:
            e = agg.setdefault(p, {"cves": set(), "severidad_max": ""})
            e["cves"].add(r["cve"])
            if sev_rank(r["severidad"] or "") > sev_rank(e["severidad_max"]):
                e["severidad_max"] = r["severidad"] or ""
    top = [
        {"paquete": p, "cves": len(e["cves"]), "severidad_max": e["severidad_max"]}
        for p, e in agg.items()
    ]
    top.sort(key=lambda r: (-r["cves"], -sev_rank(r["severidad_max"])))
    return top


def _apply_vuln_filters(
    rows: List[dict],
    severity: Optional[str] = None,
    kev: Optional[int] = None,
    owner: Optional[str] = None,
    status: Optional[str] = None,
    agent: Optional[str] = None,
    q: Optional[str] = None,
    ransomware: Optional[int] = None,
) -> List[dict]:
    if severity:
        sev = severity.lower()
        rows = [r for r in rows if (r["severidad"] or "").lower() == sev]
    if kev:
        rows = [r for r in rows if r["kev"]]
    if ransomware:
        rows = [r for r in rows if r["kev_ransomware"]]
    if owner:
        rows = [r for r in rows if r["owner"] == owner]
    if status:
        rows = [r for r in rows if r["estado"] == status]
    if agent:
        rows = [r for r in rows if agent in r["agentes"]]
    if q:
        needle = q.lower()
        rows = [
            r
            for r in rows
            if needle in r["cve"].lower()
            or needle in r["descripcion"].lower()
            or any(needle in p.lower() for p in r["paquetes"])
        ]
    return rows


@app.get("/vulnerabilities/summary")
async def vuln_summary(
    request: Request,
    user: str = Depends(require_user),
    severity: Optional[str] = None,
    kev: Optional[int] = None,
    owner: Optional[str] = None,
    status: Optional[str] = None,
    agent: Optional[str] = None,
    q: Optional[str] = None,
    ransomware: Optional[int] = None,
):
    store = _store(request)
    state, updated_at = await _load_state(store)
    lifecycle = await store.lifecycle_map()
    assigns = await store.assignments()
    patching = await store.patching_metrics(sla_days=settings.vuln_sla_critical_days)
    owners = await store.owners()

    rows = _apply_vuln_filters(
        _vuln_rows(state, lifecycle, assigns),
        severity=severity,
        kev=kev,
        owner=owner,
        status=status,
        agent=agent,
        q=q,
        ransomware=ransomware,
    )

    por_sev_counts: Dict[str, int] = {}
    for r in rows:
        sev = r["severidad"] or ""
        por_sev_counts[sev] = por_sev_counts.get(sev, 0) + 1
    por_sev = sorted(
        ({"severidad": s, "n": n} for s, n in por_sev_counts.items()),
        key=lambda r: -sev_rank(r["severidad"]),
    )
    criticas_altas = sum(n for s, n in por_sev_counts.items() if sev_rank(s) >= SEV_RANK["high"])

    any_filter = bool(severity or kev or ransomware or owner or status or agent or q)
    if agent:
        servidores = _servidores_from_rows(rows, agent)
    elif any_filter:
        servidores = _servidores_leaderboard_from_rows(rows)
    else:
        servidores = state.get("servidores", [])
    top_paquetes = _top_paquetes_from_rows(rows) if any_filter else state.get("top_paquetes", [])

    epss_hi = settings.vuln_epss_high_threshold
    prio_crit = settings.vuln_priority_critical_threshold
    return {
        "sin_datos": state.get("sin_datos", False),
        "actualizado": updated_at,
        "total": len(rows),
        "criticas_altas": criticas_altas,
        "cves_unicos": len(rows),
        "paquetes_unicos": state.get("paquetes_unicos", 0),
        "por_severidad": por_sev,
        "servidores": servidores,
        "servidores_count": len({a for r in rows for a in r["agentes"]}),
        "top_paquetes": top_paquetes,
        "kev_count": sum(1 for r in rows if r["kev"]),
        "ransomware_count": sum(1 for r in rows if r["kev_ransomware"]),
        "epss_alto_count": sum(
            1 for r in rows if r.get("epss") is not None and r["epss"] >= epss_hi
        ),
        "prioridad_critica_count": sum(
            1 for r in rows if (r.get("priority_score") or 0) >= prio_crit
        ),
        "patching": patching,
        "owners": owners,
        "umbrales": {
            "epss_alto": epss_hi,
            "prioridad_critica": prio_crit,
            "sla_criticas_dias": settings.vuln_sla_critical_days,
        },
    }


@app.get("/vulnerabilities/cves")
async def vuln_cves(
    request: Request,
    user: str = Depends(require_user),
    severity: Optional[str] = None,
    kev: Optional[int] = None,
    owner: Optional[str] = None,
    status: Optional[str] = None,
    agent: Optional[str] = None,
    q: Optional[str] = None,
    ransomware: Optional[int] = None,
):
    store = _store(request)
    state, _ = await _load_state(store)
    lifecycle = await store.lifecycle_map()
    assigns = await store.assignments()

    rows = _apply_vuln_filters(
        _vuln_rows(state, lifecycle, assigns),
        severity=severity,
        kev=kev,
        owner=owner,
        status=status,
        agent=agent,
        q=q,
        ransomware=ransomware,
    )
    return {"cves": rows, "total": len(rows)}


@app.get("/vulnerabilities/history")
async def vuln_history(request: Request, days: int = 90, user: str = Depends(require_user)):
    days = max(7, min(int(days), 365))
    return {"snapshots": await _store(request).history(days)}


@app.get("/vulnerabilities/priority-brief")
async def vuln_priority_brief(request: Request, user: str = Depends(require_user)):
    cached = await _store(request).load_priority_brief()
    if cached is None:
        return {"brief": None, "cve_refs": [], "updated_at": None}
    return cached


@app.post("/vulnerabilities/assignments")
async def vuln_assign(request: Request, user: str = Depends(require_user)):
    """Crea/actualiza el seguimiento (owner, estado, fecha objetivo) de un CVE."""
    body = await request.json()
    cve = (body.get("cve") or "").strip().upper()
    if not cve:
        raise HTTPException(status_code=400, detail="Falta el campo: cve")
    store = _store(request)
    try:
        saved = await store.upsert_assignment(
            cve=cve,
            owner=(body.get("owner") or "").strip(),
            owner_email=(body.get("owner_email") or "").strip(),
            status=(body.get("status") or "pendiente").strip(),
            due_date=(body.get("due_date") or "").strip() or None,
            notes=(body.get("notes") or "").strip(),
            updated_by=user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "assignment": saved, "valid_statuses": list(ASSIGNMENT_STATUSES)}


@app.delete("/vulnerabilities/assignments/{cve}")
async def vuln_unassign(cve: str, request: Request, user: str = Depends(require_user)):
    """Borra el seguimiento de un CVE."""
    deleted = await _store(request).delete_assignment(cve.strip().upper(), deleted_by=user)
    if not deleted:
        raise HTTPException(status_code=404, detail="Ese CVE no tiene seguimiento cargado")
    return {"status": "deleted", "cve": cve.strip().upper()}
