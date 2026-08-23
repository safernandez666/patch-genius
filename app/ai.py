"""AI-generated prioritisation brief.

The dashboard ranks CVEs; this turns that ranking into a paragraph an analyst can
act on — what to patch first this week, and why.

Three providers are supported because the choice is not only about quality. A
brief is built from the fleet's real state, including hostnames, so sending it to
a hosted model means that inventory leaves the network. Anyone who cannot accept
that runs a local model instead and nothing leaves. The feature is disabled by
default and the UI states plainly what is sent.
"""

from __future__ import annotations

from typing import Any, Dict, List

import httpx
import structlog

logger = structlog.get_logger(__name__)

PROVIDERS = ("anthropic", "openai", "local")

# Defaults per provider. All three are overridable from the Integrations page,
# because model names move faster than releases of this app.
DEFAULT_MODELS = {
    "anthropic": "claude-opus-5",
    "openai": "gpt-4o",
    "local": "llama3.1",
}

TIMEOUT = 120.0

SYSTEM_PROMPT = """You are a senior vulnerability analyst writing the weekly patching
brief for a SOC team.

You are given the current state of a fleet monitored by Wazuh, already scored: CISA KEV
membership (confirmed exploitation in the wild), EPSS (probability of exploitation within
30 days), CVSS, and a combined priority score.

Write a brief that a team can act on Monday morning. Cover, in this order:

1. The headline — what deserves attention first, and why. Anything in KEV outranks a high
   CVSS with no evidence of exploitation.
2. Concrete next actions, naming the affected hosts and packages.
3. Anything that looks like drift or a process problem: criticals past their SLA, CVEs
   reopening after being resolved, a host falling behind the rest.

Rules:
- Be specific. Name CVEs, hosts and packages. Never pad with generalities about the
  importance of patching.
- Operating-system findings close with a cumulative update or KB, not a package upgrade.
  Group them rather than listing each CVE.
- Untriaged CVEs have no NVD score yet. Treat them as unknown, not as low severity.
- If the data does not support a claim, do not make it. Say what is missing instead.
- No preamble, no closing pleasantries. Plain prose with short paragraphs, at most
  400 words. Write in {language}."""


class AIError(RuntimeError):
    """Raised when the model is unreachable, misconfigured, or refuses."""


def build_snapshot(
    state: Dict[str, Any],
    rows: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    include_hostnames: bool = True,
) -> str:
    """Render the fleet state as the prompt's factual input.

    Only the top of the ranking is included. Two thousand rows would cost more,
    read no better, and the tail is precisely what the score already decided is
    not urgent.
    """
    lines: List[str] = []
    total = state.get("cves_unicos", 0)
    hosts = len(state.get("servidores", []))
    lines.append(f"Fleet: {total} unique CVEs across {hosts} hosts.")

    sev = ", ".join(f"{s['severidad']}: {s['n']}" for s in state.get("por_severidad", []))
    if sev:
        lines.append(f"By severity — {sev}.")

    plat = ", ".join(
        f"{p['plataforma']}: {p['total']} ({p.get('critical', 0)} critical,"
        f" {p.get('high', 0)} high)"
        for p in state.get("por_plataforma", [])
    )
    if plat:
        lines.append(f"By platform — {plat}.")

    if metrics:
        lines.append(
            "Patching — criticals past SLA: {sla}; new in 7 days: {new}; resolved: {res}; "
            "reopened: {reo}; average age of active findings: {age} days.".format(
                sla=metrics.get("criticas_vencen_sla", 0),
                new=metrics.get("nuevas_7d", 0),
                res=metrics.get("resueltas_7d", 0),
                reo=metrics.get("reabiertas_7d", 0),
                age=metrics.get("aging_promedio_dias", 0),
            )
        )

    kev = [r for r in rows if r.get("kev")]
    ransom = [r for r in kev if r.get("kev_ransomware")]
    lines.append(
        f"\nIn CISA KEV: {len(kev)}, of which {len(ransom)} have a known ransomware campaign."
    )

    lines.append("\nTop findings by priority score:")
    for r in rows[:25]:
        flags = []
        if r.get("kev"):
            flags.append("KEV")
        if r.get("kev_ransomware"):
            flags.append("ransomware")
        if "os_update" in (r.get("tipos") or []):
            flags.append("OS-level")
        epss = r.get("epss")
        hosts = r.get("agentes") or []
        if include_hostnames:
            host_txt = ", ".join(hosts[:6]) or "n/a"
        else:
            host_txt = f"{len(hosts)} host(s)" if hosts else "n/a"
        lines.append(
            "- {cve} score={score} severity={sev} cvss={cvss} epss={epss}{flags}"
            " | packages: {pkgs} | hosts: {hosts} | open {days}d".format(
                cve=r.get("cve", "?"),
                score=r.get("priority_score"),
                sev=r.get("severidad"),
                cvss=r.get("cvss"),
                epss=f"{epss:.3f}" if isinstance(epss, (int, float)) else "n/a",
                flags=" [" + ", ".join(flags) + "]" if flags else "",
                pkgs=", ".join((r.get("paquetes") or [])[:3]) or "n/a",
                hosts=host_txt,
                days=r.get("dias_detectado") if r.get("dias_detectado") is not None else "?",
            )
        )
    return "\n".join(lines)


async def generate_brief(
    cfg: Dict[str, Any], snapshot: str, language: str = "es"
) -> Dict[str, Any]:
    """Ask the configured model for the brief. Returns text plus what it cost."""
    settings = cfg.get("settings") or {}
    provider = settings.get("provider") or "anthropic"
    if provider not in PROVIDERS:
        raise AIError(f"unknown provider: {provider}")
    model = settings.get("model") or DEFAULT_MODELS[provider]
    lang = "Spanish" if language == "es" else "English"
    system = SYSTEM_PROMPT.format(language=lang)

    if provider == "anthropic":
        return await _anthropic(cfg, model, system, snapshot)
    return await _openai_compatible(cfg, provider, model, system, snapshot)


async def _anthropic(cfg: Dict[str, Any], model: str, system: str, snapshot: str) -> Dict[str, Any]:
    # The official SDK, not raw HTTP: it owns retries, timeouts and typed errors.
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - dependencia declarada
        raise AIError("the anthropic package is not installed") from exc

    key = cfg.get("secret") or ""
    if not key:
        raise AIError("no API key configured")

    client = anthropic.AsyncAnthropic(api_key=key, timeout=TIMEOUT)
    try:
        resp = await client.messages.create(
            model=model,
            max_tokens=16000,
            system=system,
            # Adaptive thinking: deciding what to patch first is a judgement call
            # over competing signals, not a formatting task.
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": snapshot}],
        )
    except anthropic.AuthenticationError as exc:
        raise AIError("the API key was rejected") from exc
    except anthropic.RateLimitError as exc:
        raise AIError("rate limited by Anthropic; try again shortly") from exc
    except anthropic.APIStatusError as exc:
        raise AIError(f"Anthropic returned {exc.status_code}") from exc
    except anthropic.APIConnectionError as exc:
        raise AIError(f"cannot reach Anthropic: {exc}") from exc

    if resp.stop_reason == "refusal":
        raise AIError("the model declined to answer this request")

    text = "".join(b.text for b in resp.content if b.type == "text").strip()
    if not text:
        raise AIError("the model returned no text")
    return {
        "text": text,
        "model": resp.model,
        "provider": "anthropic",
        "input_tokens": resp.usage.input_tokens,
        "output_tokens": resp.usage.output_tokens,
    }


async def _openai_compatible(
    cfg: Dict[str, Any], provider: str, model: str, system: str, snapshot: str
) -> Dict[str, Any]:
    """OpenAI and any OpenAI-compatible endpoint, Ollama included."""
    settings = cfg.get("settings") or {}
    base = (settings.get("base_url") or "").rstrip("/")
    if not base:
        base = "https://api.openai.com/v1" if provider == "openai" else "http://localhost:11434/v1"

    headers = {"Content-Type": "application/json"}
    key = cfg.get("secret") or ""
    if key:
        headers["Authorization"] = f"Bearer {key}"
    elif provider == "openai":
        raise AIError("no API key configured")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": snapshot},
        ],
        "max_tokens": 2000,
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(f"{base}/chat/completions", json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPStatusError as exc:
        raise AIError(
            f"{provider} returned {exc.response.status_code}: {exc.response.text[:200]}"
        ) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise AIError(f"cannot reach {provider}: {exc}") from exc

    try:
        text = data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError) as exc:
        raise AIError("unexpected response shape from the model") from exc
    if not text:
        raise AIError("the model returned no text")

    usage = data.get("usage") or {}
    return {
        "text": text,
        "model": data.get("model") or model,
        "provider": provider,
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
    }
