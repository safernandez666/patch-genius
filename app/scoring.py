"""Cálculo de severidad y priorización — funciones puras, sin dependencias."""

from __future__ import annotations

from typing import Optional

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "untriaged": 0}


def sev_rank(sev: Optional[str]) -> int:
    return SEV_RANK.get((sev or "").lower(), 0)


def priority_score(
    cvss: Optional[float],
    epss: Optional[float],
    kev: bool,
    cvss_weight: float,
    epss_weight: float,
    kev_weight: float,
) -> float:
    """Score único 0-100: CVSS*peso + EPSS*peso + bonus si está en KEV.

    Sin EPSS disponible degrada a CVSS*peso.
    """
    score = (cvss or 0.0) * cvss_weight
    if epss is not None:
        score += epss * epss_weight
    if kev:
        score += kev_weight
    return min(100.0, round(score, 1))
