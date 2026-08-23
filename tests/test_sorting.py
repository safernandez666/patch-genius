"""The CVE table must always lead with the highest priority."""

from __future__ import annotations

from app.main import _sort_by_priority


def row(cve, score, sev="High", kev=False, dias=0):
    return {
        "cve": cve,
        "priority_score": score,
        "severidad": sev,
        "kev": kev,
        "dias_detectado": dias,
    }


def test_highest_score_comes_first():
    out = _sort_by_priority([row("CVE-1", 15.6), row("CVE-2", 99.0), row("CVE-3", 40.6)])
    assert [r["cve"] for r in out] == ["CVE-2", "CVE-3", "CVE-1"]


def test_order_is_monotonically_descending():
    scores = [3.0, 91.2, 0.0, 55.5, 12.1, 88.8]
    out = _sort_by_priority([row(f"CVE-{i}", s) for i, s in enumerate(scores)])
    got = [r["priority_score"] for r in out]
    assert got == sorted(scores, reverse=True)


def test_unscored_rows_sink_below_scored_ones():
    # A missing score is "unknown", not "harmless" — but it must not outrank a
    # CVE we actually measured, however low that measurement is.
    out = _sort_by_priority([row("CVE-none", None, sev="Untriaged"), row("CVE-low", 0.1)])
    assert [r["cve"] for r in out] == ["CVE-low", "CVE-none"]


def test_kev_breaks_a_score_tie():
    out = _sort_by_priority([row("CVE-plain", 50.0), row("CVE-kev", 50.0, kev=True)])
    assert out[0]["cve"] == "CVE-kev"


def test_severity_breaks_a_tie_when_kev_matches():
    out = _sort_by_priority(
        [row("CVE-med", 50.0, sev="Medium"), row("CVE-crit", 50.0, sev="Critical")]
    )
    assert out[0]["cve"] == "CVE-crit"


def test_older_finding_wins_an_otherwise_exact_tie():
    out = _sort_by_priority([row("CVE-new", 50.0, dias=1), row("CVE-old", 50.0, dias=90)])
    assert out[0]["cve"] == "CVE-old"


def test_order_is_stable_across_calls():
    # Identical rows must not shuffle between reloads under the reader.
    rows = [row(f"CVE-{i}", 50.0) for i in range(6)]
    assert _sort_by_priority(rows) == _sort_by_priority(list(reversed(rows)))


def test_empty_input():
    assert _sort_by_priority([]) == []
