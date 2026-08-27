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


# --- Ordenamiento por columna --------------------------------------------
# La paginación es del servidor, así que ordenar en el navegador sólo ordenaría
# la página que ya está a la vista. La tabla ordena acá.

from app.main import _sort_rows  # noqa: E402


def col(cve, **kw):
    base = {
        "cve": cve,
        "priority_score": 50.0,
        "severidad": "High",
        "kev": False,
        "dias_detectado": 0,
        "cvss": None,
        "epss": None,
        "owner": None,
        "estado": None,
    }
    base.update(kw)
    return base


def test_no_column_keeps_the_priority_order():
    rows = [col("CVE-1", priority_score=10.0), col("CVE-2", priority_score=90.0)]
    assert [r["cve"] for r in _sort_rows(rows)] == ["CVE-2", "CVE-1"]


def test_an_unknown_column_falls_back_to_priority():
    # Una query mal escrita no puede vaciar la pantalla.
    rows = [col("CVE-1", priority_score=10.0), col("CVE-2", priority_score=90.0)]
    assert [r["cve"] for r in _sort_rows(rows, sort="nope")] == ["CVE-2", "CVE-1"]


def test_sorts_by_cvss_in_both_directions():
    rows = [col("CVE-a", cvss=4.0), col("CVE-b", cvss=9.8), col("CVE-c", cvss=7.5)]
    assert [r["cve"] for r in _sort_rows(rows, "cvss", "desc")] == ["CVE-b", "CVE-c", "CVE-a"]
    assert [r["cve"] for r in _sort_rows(rows, "cvss", "asc")] == ["CVE-a", "CVE-c", "CVE-b"]


def test_missing_values_sink_in_both_directions():
    # Ascendente, un None que ordenara como cero encabezaría la tabla con filas
    # en blanco: no es lo que pidió nadie.
    rows = [col("CVE-none"), col("CVE-low", cvss=2.0), col("CVE-high", cvss=9.0)]
    assert [r["cve"] for r in _sort_rows(rows, "cvss", "asc")][-1] == "CVE-none"
    assert [r["cve"] for r in _sort_rows(rows, "cvss", "desc")][-1] == "CVE-none"


def test_severity_sorts_by_rank_not_alphabetically():
    # "Critical" < "Low" < "Medium" alfabéticamente, que es exactamente el orden
    # equivocado.
    rows = [
        col("CVE-low", severidad="Low"),
        col("CVE-crit", severidad="Critical"),
        col("CVE-med", severidad="Medium"),
    ]
    assert [r["cve"] for r in _sort_rows(rows, "severity", "desc")] == [
        "CVE-crit",
        "CVE-med",
        "CVE-low",
    ]


def test_priority_breaks_a_tie_on_the_sorted_column():
    rows = [
        col("CVE-a", cvss=7.0, priority_score=20.0),
        col("CVE-b", cvss=7.0, priority_score=80.0),
    ]
    assert [r["cve"] for r in _sort_rows(rows, "cvss", "desc")] == ["CVE-b", "CVE-a"]


def test_owner_sorting_ignores_case():
    rows = [col("CVE-1", owner="zoe"), col("CVE-2", owner="Ana")]
    assert [r["cve"] for r in _sort_rows(rows, "owner", "asc")] == ["CVE-2", "CVE-1"]


def test_sorting_does_not_drop_or_duplicate_rows():
    rows = [col(f"CVE-{i}", cvss=(None if i % 3 == 0 else float(i))) for i in range(12)]
    for direction in ("asc", "desc"):
        out = _sort_rows(rows, "cvss", direction)
        assert sorted(r["cve"] for r in out) == sorted(r["cve"] for r in rows)
