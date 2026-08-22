"""Genera el estado sintético de vulnerabilidades para la demo pública.

No hay Wazuh ni EPSS/KEV en vivo acá: se arma directamente el shape
"enriquecido" que la pantalla espera (el mismo que en el sistema real
produce fetch + enrich), con un puñado de CVEs reales y de alto perfil
(información pública de la industria, no de ningún cliente) mezclados con
CVEs sintéticos para dar volumen.

Uso:
    python -m seed.generate_seed          # sembrar (no hace nada si ya hay datos)
    python -m seed.generate_seed --reset --yes   # vaciar y volver a sembrar
"""
from __future__ import annotations

import argparse
import asyncio
import random
from datetime import date, timedelta
from typing import Any, Dict, List

from app.scoring import SEV_RANK, priority_score
from app.settings import settings
from app.vuln_store import VulnStore

SEED = 20260822

SERVERS = [
    "web-01", "web-02", "app-01", "app-02", "db-01", "db-02",
    "cache-01", "lb-01", "mail-01", "vpn-01",
]

PACKAGES = [
    ("openssl", "3.0.2"), ("openssh-server", "8.9p1"), ("libxml2", "2.9.13"),
    ("curl", "7.81.0"), ("nginx", "1.22.0"), ("apache2", "2.4.52"),
    ("python3.10", "3.10.6"), ("glibc", "2.35"), ("systemd", "249.11"),
    ("docker-ce", "24.0.5"), ("postgresql-15", "15.3"), ("samba", "4.15.13"),
    ("bind9", "9.18.1"), ("vim", "8.2.3995"), ("busybox", "1.35.0"),
]

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_WEIGHTS = [0.08, 0.22, 0.42, 0.28]

# CVEs reales y públicos de alto perfil — se usan solo para que la alerta de
# CISA KEV/ransomware se vea creíble. Información pública de la industria.
KNOWN_KEV: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2021-44228", "paquete": "log4j", "cvss": 10.0, "epss": 0.97,
        "descripcion": "Apache Log4j2 JNDI — Log4Shell: ejecución remota de código vía lookups JNDI no controlados.",
        "vencimiento": "2022-01-04", "ransomware": True,
    },
    {
        "cve": "CVE-2021-34527", "paquete": "print-spooler", "cvss": 8.8, "epss": 0.94,
        "descripcion": "Windows Print Spooler — PrintNightmare: ejecución remota de código con privilegios de sistema.",
        "vencimiento": "2021-07-20", "ransomware": True,
    },
    {
        "cve": "CVE-2023-4966", "paquete": "netscaler", "cvss": 9.4, "epss": 0.93,
        "descripcion": "Citrix NetScaler ADC/Gateway — Citrix Bleed: divulgación de sesiones vía desbordamiento de buffer.",
        "vencimiento": "2023-11-08", "ransomware": True,
    },
    {
        "cve": "CVE-2020-1472", "paquete": "samba", "cvss": 10.0, "epss": 0.92,
        "descripcion": "Netlogon — Zerologon: elevación de privilegios hasta controlador de dominio.",
        "vencimiento": "2020-09-11", "ransomware": False,
    },
]

WEIGHTS = dict(cvss_weight=5.0, epss_weight=30.0, kev_weight=20.0)


def _rng() -> random.Random:
    return random.Random(SEED)


def _fake_cve_id(rng: random.Random, used: set) -> str:
    while True:
        cve = f"CVE-{rng.randint(2022, 2026)}-{rng.randint(1000, 49999)}"
        if cve not in used:
            used.add(cve)
            return cve


def build_state(n_random_cves: int = 60) -> Dict[str, Any]:
    rng = _rng()
    used: set = set()
    cves: List[Dict[str, Any]] = []

    for k in KNOWN_KEV:
        agentes = rng.sample(SERVERS, k=rng.randint(2, 5))
        used.add(k["cve"])
        cves.append({
            "cve": k["cve"], "severidad": "Critical", "cvss": k["cvss"],
            "descripcion": k["descripcion"],
            "referencia": f"https://nvd.nist.gov/vuln/detail/{k['cve']}",
            "publicado": k["vencimiento"], "paquetes": [k["paquete"]],
            "agentes": agentes, "instalaciones": len(agentes),
            "epss": k["epss"], "epss_percentile": 0.99, "kev": True,
            "kev_info": {"vencimiento": k["vencimiento"], "ransomware": k["ransomware"]},
        })

    for _ in range(n_random_cves):
        sev = rng.choices(SEVERITIES, weights=SEV_WEIGHTS)[0]
        cvss = {
            "Critical": rng.uniform(9.0, 10.0), "High": rng.uniform(7.0, 8.9),
            "Medium": rng.uniform(4.0, 6.9), "Low": rng.uniform(0.1, 3.9),
        }[sev]
        pkg, _ver = rng.choice(PACKAGES)
        epss = round(rng.betavariate(2, 8), 3) if sev in ("Critical", "High") else round(rng.betavariate(1, 20), 3)
        agentes = rng.sample(SERVERS, k=rng.randint(1, 4))
        published = date(2024, 1, 1) + timedelta(days=rng.randint(0, 900))
        cves.append({
            "cve": _fake_cve_id(rng, used), "severidad": sev, "cvss": round(cvss, 1),
            "descripcion": (
                f"Vulnerabilidad sintética en {pkg} generada para esta demo — "
                "no corresponde a un CVE real."
            ),
            "referencia": "", "publicado": published.isoformat(),
            "paquetes": [pkg], "agentes": agentes, "instalaciones": len(agentes),
            "epss": epss, "epss_percentile": round(epss, 2), "kev": False, "kev_info": None,
        })

    for c in cves:
        c["priority_score"] = priority_score(c["cvss"], c["epss"], c["kev"], **WEIGHTS)
    cves.sort(key=lambda c: (-c["priority_score"], -SEV_RANK.get(c["severidad"].lower(), 0)))

    por_sev_counts: Dict[str, int] = {}
    for c in cves:
        por_sev_counts[c["severidad"]] = por_sev_counts.get(c["severidad"], 0) + 1
    por_severidad = sorted(
        ({"severidad": s, "n": n} for s, n in por_sev_counts.items()),
        key=lambda r: -SEV_RANK.get(r["severidad"].lower(), 0),
    )

    servidores = []
    for srv in SERVERS:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for c in cves:
            if srv in c["agentes"]:
                counts[c["severidad"].lower()] += 1
                counts["total"] += 1
        servidores.append({"agente": srv, **counts})
    servidores.sort(key=lambda s: (-s["critical"], -s["high"], -s["total"]))

    pkg_agg: Dict[str, Dict[str, Any]] = {}
    version_by_pkg = dict(PACKAGES)
    for c in cves:
        for p in c["paquetes"]:
            e = pkg_agg.setdefault(p, {"cves": 0, "severidad_max": "", "instalaciones": 0})
            e["cves"] += 1
            e["instalaciones"] += c["instalaciones"]
            if SEV_RANK.get(c["severidad"].lower(), 0) > SEV_RANK.get(e["severidad_max"].lower(), 0):
                e["severidad_max"] = c["severidad"]
    top_paquetes = sorted(
        [{"paquete": p, "version": version_by_pkg.get(p, ""), **v} for p, v in pkg_agg.items()],
        key=lambda p: (-p["cves"], -SEV_RANK.get(p["severidad_max"].lower(), 0)),
    )

    criticas_altas = sum(1 for c in cves if c["severidad"] in ("Critical", "High"))
    return {
        "sin_datos": False,
        "total": len(cves),
        "por_severidad": por_severidad,
        "criticas_altas": criticas_altas,
        "cves_unicos": len(cves),
        "paquetes_unicos": len(pkg_agg),
        "servidores": servidores,
        "cves": cves,
        "top_paquetes": top_paquetes,
    }


def build_snapshots(state: Dict[str, Any], days: int = 90) -> List[Dict[str, Any]]:
    """Random-walk hasta llegar al estado actual — para que Evolución no sea una línea plana."""
    rng = _rng()
    today = date.today()
    total, ca, cves_u = state["total"], state["criticas_altas"], state["cves_unicos"]
    t = max(10, total - rng.randint(10, 30))
    c = max(5, ca - rng.randint(3, 10))
    u = max(10, cves_u - rng.randint(10, 30))
    por_sev = {s["severidad"]: s["n"] for s in state["por_severidad"]}
    por_srv = {s["agente"]: {"total": s["total"], "crit_alta": s["critical"] + s["high"]} for s in state["servidores"]}

    out = []
    for i in range(days, -1, -1):
        fecha = today - timedelta(days=i)
        t = max(5, t + rng.randint(-3, 4))
        c = max(0, min(t, c + rng.randint(-2, 3)))
        u = max(5, u + rng.randint(-3, 4))
        out.append({
            "fecha": fecha.isoformat(), "total": t, "criticas_altas": c, "cves_unicos": u,
            "por_severidad": por_sev, "por_servidor": por_srv,
        })
    out[-1].update(total=total, criticas_altas=ca, cves_unicos=cves_u)
    return out


SAMPLE_ASSIGNMENTS = [
    {
        "cve": "CVE-2021-44228", "owner": "Equipo Infraestructura", "status": "en_curso",
        "due_date": lambda: (date.today() + timedelta(days=3)).isoformat(),
        "notes": "Actualizando log4j en los servidores afectados — ventana de mantenimiento programada.",
    },
    {
        "cve": "CVE-2020-1472", "owner": "Equipo Identidad", "status": "pendiente",
        "due_date": lambda: (date.today() - timedelta(days=2)).isoformat(),
        "notes": "Pendiente de coordinar con el equipo de dominio.",
    },
]


async def seed_if_empty(store: VulnStore) -> bool:
    """Siembra la base con datos sintéticos si todavía no corrió el seed."""
    if await store.load_state_cache() is not None:
        return False
    await _seed(store)
    return True


async def _seed(store: VulnStore) -> None:
    rng = _rng()
    state = build_state()
    await store.save_state_cache(state)

    today = date.today()
    for c in state["cves"]:
        status = "new" if rng.random() < 0.1 else "ongoing"
        first_seen = today - timedelta(days=rng.randint(1, 60))
        await store.seed_cve_state(c["cve"], first_seen, status, c["severidad"], c["cvss"])

    await store.import_snapshots(build_snapshots(state))

    for a in SAMPLE_ASSIGNMENTS:
        await store.upsert_assignment(
            cve=a["cve"], owner=a["owner"], status=a["status"],
            due_date=a["due_date"](), notes=a["notes"], updated_by="seed",
        )


async def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="vaciar las tablas antes de sembrar")
    parser.add_argument("--yes", action="store_true", help="confirmar el --reset (destructivo)")
    args = parser.parse_args()

    store = VulnStore(settings.postgres_dsn)
    await store.connect()
    try:
        if args.reset:
            if not args.yes:
                raise SystemExit("--reset requiere --yes (borra todo lo cargado en la demo)")
            await store.truncate_all()
            print("Tablas vaciadas.")
        await _seed(store)
        print("Seed completado.")
    finally:
        await store.close()


if __name__ == "__main__":
    asyncio.run(_main())
