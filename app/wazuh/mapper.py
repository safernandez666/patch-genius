"""Turn raw Wazuh Indexer records into the CVE-centric shape the dashboard reads.

The dashboard's state cache is aggregated *per CVE*, with `paquetes` and `agentes`
as lists — one row per CVE, not per (agent, package). These functions are pure so
they can be tested against captured fixtures without a live Wazuh.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

# Wazuh emits "-" (not null) for vulnerabilities NVD has not scored yet. Roughly 12%
# of records on a typical fleet. They are kept as a distinct bucket rather than
# dropped or silently folded into Low.
UNTRIAGED = "Untriaged"

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, UNTRIAGED: 0}

# `vulnerability.category` distinguishes an OS-level finding from a package one.
CATEGORY_OS = "OS"


def normalize_severity(raw: Optional[str]) -> str:
    """Map a Wazuh severity onto the dashboard's buckets."""
    if not raw or raw == "-":
        return UNTRIAGED
    sev = raw.strip().capitalize()
    return sev if sev in SEVERITY_ORDER else UNTRIAGED


def normalize_score(raw: Any) -> Optional[float]:
    """CVSS base score, or None when Wazuh has no real score for the record."""
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    # An unscored record carries 0.0 alongside severity "-"; treat it as absent so
    # priority_score degrades instead of ranking it as a genuine zero.
    return score if score > 0 else None


def package_label(doc: Dict[str, Any]) -> str:
    """Human label for what is actually vulnerable.

    For OS-category findings Wazuh puts the entire OS string *including the build
    number* in `package.name` — e.g. "Microsoft Windows Server 2022 Standard
    Evaluation 10.0.20348.587". Feeding that to the "top packages" chart gives one
    enormous bucket per patch level, so OS findings use the stable OS name instead
    and carry the build in `package.version`.
    """
    vuln = doc.get("vulnerability") or {}
    pkg = doc.get("package") or {}
    if vuln.get("category") == CATEGORY_OS:
        os_name = ((doc.get("host") or {}).get("os") or {}).get("name")
        if os_name:
            return os_name
    return pkg.get("name") or "(unknown)"


def remediation_kind(doc: Dict[str, Any]) -> str:
    """How this finding gets fixed — drives what the UI tells the operator.

    Windows OS findings are closed by a cumulative update / KB, not by bumping a
    package, so they are tracked separately from application and distro packages.
    """
    vuln = doc.get("vulnerability") or {}
    pkg_type = (doc.get("package") or {}).get("type") or ""
    if vuln.get("category") == CATEGORY_OS:
        return "os_update"
    if pkg_type in ("deb", "rpm", "apk", "pacman"):
        return "distro_package"
    return "application"


def aggregate_by_cve(
    docs: Iterable[Dict[str, Any]],
    epss_by_cve: Optional[Dict[str, float]] = None,
    kev_by_cve: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Collapse per-(agent, package) records into one entry per CVE."""
    epss_by_cve = epss_by_cve or {}
    kev_by_cve = kev_by_cve or {}
    acc: Dict[str, Dict[str, Any]] = {}

    for doc in docs:
        vuln = doc.get("vulnerability") or {}
        cve = vuln.get("id")
        if not cve:
            continue

        pkg = doc.get("package") or {}
        agent = doc.get("agent") or {}
        host_os = (doc.get("host") or {}).get("os") or {}
        sev = normalize_severity(vuln.get("severity"))
        score = normalize_score((vuln.get("score") or {}).get("base"))

        entry = acc.get(cve)
        if entry is None:
            entry = acc[cve] = {
                "cve": cve,
                "severidad": sev,
                "cvss": score,
                "descripcion": vuln.get("description") or "",
                "referencia": vuln.get("reference") or "",
                "publicado": vuln.get("published_at") or "",
                "_paquetes": {},
                "_agentes": {},
                "_plataformas": set(),
                "_tipos": set(),
                "instalaciones": 0,
            }

        # Highest severity and score win — one agent may be further behind than another.
        if SEVERITY_ORDER[sev] > SEVERITY_ORDER[entry["severidad"]]:
            entry["severidad"] = sev
        if score is not None and (entry["cvss"] is None or score > entry["cvss"]):
            entry["cvss"] = score
        if not entry["descripcion"] and vuln.get("description"):
            entry["descripcion"] = vuln["description"]

        label = package_label(doc)
        entry["_paquetes"].setdefault(
            label, {"paquete": label, "versiones": set(), "agentes": set()}
        )
        if pkg.get("version"):
            entry["_paquetes"][label]["versiones"].add(pkg["version"])

        agent_name = agent.get("name") or agent.get("id") or "(unknown)"
        entry["_paquetes"][label]["agentes"].add(agent_name)
        entry["_agentes"].setdefault(
            agent_name,
            {
                "agente": agent_name,
                "agent_id": agent.get("id") or "",
                "plataforma": host_os.get("platform") or "",
                "so": host_os.get("name") or "",
                "paquetes": set(),
            },
        )
        entry["_agentes"][agent_name]["paquetes"].add(label)
        if host_os.get("platform"):
            entry["_plataformas"].add(host_os["platform"])
        entry["_tipos"].add(remediation_kind(doc))
        entry["instalaciones"] += 1

    rows: List[Dict[str, Any]] = []
    for cve, entry in acc.items():
        kev_info = kev_by_cve.get(cve)
        rows.append(
            {
                "cve": cve,
                "severidad": entry["severidad"],
                "cvss": entry["cvss"],
                "descripcion": entry["descripcion"],
                "referencia": entry["referencia"],
                "publicado": entry["publicado"],
                "paquetes": sorted(entry["_paquetes"]),
                "agentes": sorted(entry["_agentes"]),
                "instalaciones": entry["instalaciones"],
                "plataformas": sorted(entry["_plataformas"]),
                "tipos": sorted(entry["_tipos"]),
                "detalle_paquetes": [
                    {
                        "paquete": p["paquete"],
                        "versiones": sorted(p["versiones"]),
                        "agentes": sorted(p["agentes"]),
                    }
                    for p in sorted(entry["_paquetes"].values(), key=lambda x: x["paquete"])
                ],
                "detalle_agentes": [
                    {
                        "agente": a["agente"],
                        "agent_id": a["agent_id"],
                        "plataforma": a["plataforma"],
                        "so": a["so"],
                        "paquetes": sorted(a["paquetes"]),
                    }
                    for a in sorted(entry["_agentes"].values(), key=lambda x: x["agente"])
                ],
                "epss": epss_by_cve.get(cve),
                "kev": kev_info is not None,
                "kev_info": kev_info or {},
            }
        )
    return rows
