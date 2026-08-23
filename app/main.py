"""Vulnerability & Patch Tracking.

Reads vulnerability state from a Wazuh deployment the operator configures on
first run, scores it with CVSS + EPSS + CISA KEV, and tracks patching per CVE
and per agent. Every route requires a login: the screen lists unpatched CVEs of
live hosts and the configuration holds Wazuh credentials.
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

from app.ai import AIError, build_snapshot, generate_brief
from app.auth import SESSION_COOKIE, AuthError, AuthManager
from app.config_store import ConfigError, ConfigStore
from app.ingest import migrate_assignments, run_ingest
from app.notify import NotifyError, jira_ping, post_webhook, send_email
from app.scoring import SEV_RANK, sev_rank
from app.settings import settings
from app.vuln_store import ASSIGNMENT_STATUSES, VulnStore
from app.wazuh.indexer import WazuhIndexerClient, WazuhIndexerError

logger = structlog.get_logger(__name__)

# Tope de filas por pagina. Existe para que un `limit` disparatado no vuelva a
# serializar el parque entero, que es justamente lo que el paginado evita.
MAX_PAGE_SIZE = 500


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

    app.state.refresh_task = asyncio.create_task(_refresh_loop(app))

    yield
    app.state.refresh_task.cancel()
    await pool.close()


async def _brief_if_stale(app: FastAPI) -> None:
    """Regenera el resumen una vez por dia.

    Diario y no por ingesta: son tokens cada vez, y el panorama de un parque no
    cambia lo suficiente en una hora como para justificar reescribirlo.
    """
    try:
        cfg = await app.state.config_store.load_integration("ai")
        if not cfg["enabled"]:
            return
        current = await app.state.store.load_priority_brief()
        if current:
            updated = current["updated_at"][:10]
            if updated == date.today().isoformat():
                return
        await _make_brief(app)
    except AIError as exc:
        # Que falle el resumen no puede tumbar el refresco de los datos.
        logger.warning("brief_skipped", error=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.error("brief_failed", error=str(exc))


async def _refresh_loop(app: FastAPI) -> None:
    """Periodically re-ingest from Wazuh once a connection is configured."""
    while True:
        try:
            cfg = await app.state.config_store.load()
            if cfg["indexer_url"]:
                await run_ingest(app.state.pg_pool, cfg, settings)
                await _brief_if_stale(app)
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
    # This serves a live vulnerability inventory, so a deployment should name its
    # origin. The wildcard remains the fallback for a single-host install where
    # the API is only ever called from the page it serves.
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
    return {"version": "1.0"}


@app.get("/")
async def index(request: Request):
    if not await current_user(request):
        if not await request.app.state.auth.has_users():
            return RedirectResponse("/signup", status_code=302)
        return RedirectResponse("/login", status_code=302)
    return FileResponse("static/index.html")


# ---------------------------------------------------------------------------
# Authentication. Always required: the dashboard lists unpatched CVEs of live
# hosts and the Configuration tab holds Wazuh credentials.
# ---------------------------------------------------------------------------
async def current_user(request: Request) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    data = request.app.state.auth.read_session(token)
    return data.get("u") if data else None


async def require_user(request: Request) -> str:
    """Reject anonymous callers. There is no unauthenticated view."""
    user = await current_user(request)
    if user:
        return user
    raise HTTPException(status_code=401, detail="authentication required")


async def require_admin(request: Request) -> str:
    """Guard the Configuration tab, which stores the Wazuh password."""
    user = await current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    if not await request.app.state.auth.is_admin(user):
        raise HTTPException(status_code=403, detail="admin role required")
    return user


@app.get("/login")
async def login_page(request: Request):
    # Nothing to sign in to yet: send the first operator to set up their account.
    if not await request.app.state.auth.has_users():
        return RedirectResponse("/signup", status_code=302)
    return FileResponse("static/login.html")


@app.get("/signup")
async def signup_page(request: Request):
    """First-run setup. Closes itself once an account exists."""
    if await request.app.state.auth.has_users():
        return RedirectResponse("/login", status_code=302)
    return FileResponse("static/signup.html")


@app.get("/api/lang")
async def api_lang(request: Request):
    """Idioma de la interfaz. Sin autenticacion: las pantallas de login y de
    setup tambien se traducen, y el idioma no es informacion sensible."""
    cfg = await request.app.state.config_store.load_public()
    return {"lang": cfg.get("lang", "en")}


@app.get("/api/setup-state")
async def api_setup_state(request: Request):
    """Whether the deployment still needs its first account."""
    return {"needs_setup": not await request.app.state.auth.has_users()}


@app.get("/auth/me")
async def auth_me(request: Request):
    """Return the current session's user and role for the UI sidebar."""
    user = await current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    info = await request.app.state.auth.get_user(user)
    if info is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return {"user": {"username": info["username"], "role": info["role"], "name": info["username"]}}


@app.post("/api/signup")
async def api_signup(request: Request, response: Response):
    body = await request.json()
    try:
        await request.app.state.auth.create_first_user(
            str(body.get("username", "")), str(body.get("password", ""))
        )
    except AuthError as exc:
        # "an account already exists" is a 409, not a validation error: the page
        # was open when someone else finished the setup.
        code = 409 if "already exists" in str(exc) else 400
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    token = request.app.state.auth.issue_session(str(body.get("username", "")).strip())
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=8 * 60 * 60,
    )
    return {"ok": True}


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
    return {
        "ok": True,
        "user": user,
        "role": (await request.app.state.auth.get_user(user) or {}).get("role", "admin"),
    }


@app.post("/api/logout")
async def api_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/session")
async def api_session(request: Request):
    return {"user": await current_user(request)}


# ---------------------------------------------------------------------------
# Configuration tab — Wazuh onboarding.
# ---------------------------------------------------------------------------
@app.get("/ayuda")
async def help_page():
    return FileResponse("static/ayuda.html")


@app.get("/config")
async def config_page():
    return FileResponse("static/config.html")


@app.get("/api/config")
async def api_config_get(request: Request, user: str = Depends(require_admin)):
    return await request.app.state.config_store.load_public()


@app.put("/api/config")
async def api_config_put(request: Request, user: str = Depends(require_admin)):
    body = await request.json()
    try:
        return await request.app.state.config_store.save(body, updated_by=user)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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


@app.get("/brief")
async def brief_page():
    return FileResponse("static/brief.html")


@app.get("/integraciones")
async def integrations_page():
    return FileResponse("static/integraciones.html")


@app.get("/api/integrations")
async def api_integrations(request: Request, user: str = Depends(require_admin)):
    return {"integrations": await request.app.state.config_store.load_integrations_public()}


@app.put("/api/integrations/{name}")
async def api_integration_save(name: str, request: Request, user: str = Depends(require_admin)):
    body = await request.json()
    try:
        return await request.app.state.config_store.save_integration(
            name,
            enabled=bool(body.get("enabled")),
            settings=body.get("settings") or {},
            secret=body.get("secret"),
            updated_by=user,
        )
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/integrations/{name}/test")
async def api_integration_test(name: str, request: Request, user: str = Depends(require_admin)):
    """Ejercitar la integracion de verdad: mandar el correo, tocar Jira, publicar
    en el canal. Un 'guardado' que nunca se probo no dice nada."""
    body = await request.json()
    store = request.app.state.config_store
    try:
        cfg = await store.load_integration(name)
    except ConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # Permitir probar lo que hay en pantalla sin haberlo guardado todavia.
    if body.get("settings"):
        cfg["settings"] = {**cfg["settings"], **body["settings"]}
    if body.get("secret"):
        cfg["secret"] = body["secret"]
    if name == "ai":
        # _make_brief relee de la base, asi que para probar sin guardar hay que
        # dejarle ver lo que el usuario acaba de escribir.
        cfg["enabled"] = True

    try:
        if name == "ai":
            # Probar de verdad es generar el resumen: una comprobacion de
            # credenciales no dice si el modelo entiende el snapshot.
            result = await _make_brief(request.app, cfg)
            return {
                "ok": True,
                "detail": f"resumen generado con {result['model']}",
                "preview": result["text"][:280],
            }
        if name == "smtp":
            to = (body.get("to") or cfg["settings"].get("from_addr") or "").strip()
            if not to:
                raise NotifyError("indica una direccion de destino para la prueba")
            await asyncio.to_thread(
                send_email,
                cfg,
                to,
                "Patch Genius — prueba de configuracion",
                "Si estas leyendo esto, el SMTP de Patch Genius quedo bien configurado.",
            )
            return {"ok": True, "detail": f"correo enviado a {to}"}
        if name == "jira":
            return {"ok": True, **await jira_ping(cfg)}
        if name in ("slack", "teams"):
            await post_webhook(cfg, "Patch Genius: prueba de configuracion.", name)
            return {"ok": True, "detail": "mensaje publicado"}
    except (NotifyError, AIError) as exc:
        return {"ok": False, "error": str(exc)}
    raise HTTPException(status_code=404, detail=f"unknown integration: {name}")


async def _make_brief(app: FastAPI, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Construye el snapshot y pide el resumen. Lanza AIError si algo falla.

    `cfg` permite probar lo que el usuario tiene en pantalla sin haberlo guardado.
    """
    if cfg is None:
        cfg = await app.state.config_store.load_integration("ai")
    if not cfg["enabled"]:
        raise AIError("la integracion de IA esta desactivada")
    store = app.state.store
    state, _ = await _load_state(store)
    lifecycle = await store.lifecycle_map()
    assigns = await store.assignments()
    rows = _sort_by_priority(_vuln_rows(state, lifecycle, assigns))
    metrics = await store.patching_metrics(sla_days=settings.vuln_sla_critical_days)
    app_cfg = await app.state.config_store.load_public()
    snapshot = build_snapshot(state, rows, metrics or {})
    result = await generate_brief(cfg, snapshot, language=app_cfg.get("lang", "en"))
    await store.save_priority_brief(
        result["text"],
        {
            "provider": result["provider"],
            "model": result["model"],
            "input_tokens": result.get("input_tokens"),
            "output_tokens": result.get("output_tokens"),
            "cves": [r["cve"] for r in rows[:25]],
        },
    )
    logger.info("brief_generated", provider=result["provider"], model=result["model"])
    return result


@app.post("/api/brief")
async def api_brief(request: Request, user: str = Depends(require_user)):
    """Genera el resumen ahora. El boton del panel llega por aca."""
    try:
        result = await _make_brief(request.app)
    except AIError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"ok": True, "provider": result["provider"], "model": result["model"]}


@app.post("/api/password")
async def api_password(request: Request, user: str = Depends(require_admin)):
    """Change the signed-in account's password.

    Whoever deploys this sets a bootstrap password in the environment; this is
    how they replace it without touching .env or the database by hand.
    """
    body = await request.json()
    current = str(body.get("current_password", ""))
    new_password = str(body.get("new_password", ""))
    if not await request.app.state.auth.authenticate(user, current):
        raise HTTPException(status_code=401, detail="la contraseña actual no es correcta")
    try:
        await request.app.state.auth.set_password(user, new_password)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True}


@app.post("/api/ingest")
async def api_ingest(request: Request, user: str = Depends(require_admin)):
    """Run an ingest now, instead of waiting for the refresh interval."""
    cfg = await request.app.state.config_store.load()
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
        # cached row. Prefer it so aging and the patch SLA measure how long the
        # fleet has actually carried the CVE.
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
                "plataformas": c.get("plataformas", []),
                "tipos": c.get("tipos", []),
                "detalle_agentes": c.get("detalle_agentes", []),
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


def _sort_by_priority(rows: List[dict]) -> List[dict]:
    """Highest priority first — the whole point of the screen.

    priority_score already folds in CVSS, EPSS and the KEV bonus, so it leads.
    A row with no score at all sinks to the bottom instead of tying with a
    genuine zero. Ties break by KEV, then severity, then age, then CVE id, so
    the order stays stable between reloads rather than shuffling under whoever
    is reading it.
    """
    return sorted(
        rows,
        key=lambda r: (
            1 if r.get("priority_score") is None else 0,
            -(r.get("priority_score") or 0.0),
            0 if r.get("kev") else 1,
            -sev_rank(r.get("severidad") or ""),
            -(r.get("dias_detectado") or 0),
            r.get("cve", ""),
        ),
    )


def _apply_vuln_filters(
    rows: List[dict],
    severity: Optional[str] = None,
    plataforma: Optional[str] = None,
    kev: Optional[int] = None,
    owner: Optional[str] = None,
    status: Optional[str] = None,
    agent: Optional[str] = None,
    q: Optional[str] = None,
    ransomware: Optional[int] = None,
    tipo: Optional[str] = None,
    score_min: Optional[float] = None,
    sla: Optional[str] = None,
) -> List[dict]:
    if severity:
        sev = severity.lower()
        rows = [r for r in rows if (r["severidad"] or "").lower() == sev]
    if plataforma:
        plat = plataforma.lower()
        rows = [r for r in rows if plat in [p.lower() for p in r.get("plataformas", [])]]
    if tipo:
        rows = [r for r in rows if tipo in r.get("tipos", [])]
    if score_min is not None:
        rows = [r for r in rows if (r.get("priority_score") or 0) >= score_min]
    if sla == "vencidos":
        # Only criticals carry a patching SLA, so "breached" means a critical that
        # has been open longer than the configured window.
        rows = [
            r
            for r in rows
            if r["severidad"] == "Critical"
            and (r.get("dias_detectado") or 0) > settings.vuln_sla_critical_days
        ]
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
    plataforma: Optional[str] = None,
    tipo: Optional[str] = None,
    score_min: Optional[float] = None,
    sla: Optional[str] = None,
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
        plataforma=plataforma,
        tipo=tipo,
        score_min=score_min,
        sla=sla,
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
        "plataformas": state.get("plataformas", []),
        "por_plataforma": state.get("por_plataforma", []),
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
    plataforma: Optional[str] = None,
    tipo: Optional[str] = None,
    score_min: Optional[float] = None,
    sla: Optional[str] = None,
    kev: Optional[int] = None,
    owner: Optional[str] = None,
    status: Optional[str] = None,
    agent: Optional[str] = None,
    q: Optional[str] = None,
    ransomware: Optional[int] = None,
    limit: int = 10,
    offset: int = 0,
):
    store = _store(request)
    state, _ = await _load_state(store)
    lifecycle = await store.lifecycle_map()
    assigns = await store.assignments()

    rows = _apply_vuln_filters(
        _vuln_rows(state, lifecycle, assigns),
        severity=severity,
        plataforma=plataforma,
        tipo=tipo,
        score_min=score_min,
        sla=sla,
        kev=kev,
        owner=owner,
        status=status,
        agent=agent,
        q=q,
        ransomware=ransomware,
    )
    # Paginado en el servidor: cada fila trae el detalle por agente y por paquete,
    # asi que devolver el parque entero para pintar una pagina eran megabytes por
    # cada cambio de filtro.
    limit = max(1, min(int(limit), MAX_PAGE_SIZE))
    offset = max(0, int(offset))
    ordered = _sort_by_priority(rows)
    return {
        "cves": ordered[offset : offset + limit],
        "total": len(ordered),
        "limit": limit,
        "offset": offset,
    }


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
