"""Unit tests for the pure scoring helpers."""

from __future__ import annotations

import pytest

from app.scoring import priority_score, sev_rank

# Same defaults as app/settings.py.
CVSS_W = 5.0
EPSS_W = 30.0
KEV_W = 20.0


def score(cvss, epss, kev):
    return priority_score(cvss, epss, kev, CVSS_W, EPSS_W, KEV_W)


def test_combines_cvss_epss_and_kev_bonus():
    # 7.0*5 + 0.5*30 + 20 = 70.0
    assert score(7.0, 0.5, True) == 70.0


def test_without_kev_the_bonus_is_not_applied():
    # 7.0*5 + 0.5*30 = 50.0
    assert score(7.0, 0.5, False) == 50.0


def test_missing_epss_degrades_to_cvss_only():
    assert score(6.0, None, False) == 30.0


def test_epss_of_zero_is_not_treated_as_missing():
    # Distinct from None: 0.0 still takes the EPSS branch, contributing nothing.
    assert score(6.0, 0.0, False) == 30.0


def test_missing_cvss_counts_as_zero():
    assert score(None, None, False) == 0.0
    assert score(None, None, True) == KEV_W


def test_score_is_capped_at_100():
    assert score(10.0, 1.0, True) == 100.0


def test_score_is_rounded_to_one_decimal():
    # 3.3*5 + 0.123*30 = 16.5 + 3.69 = 20.19 -> 20.2
    assert score(3.3, 0.123, False) == 20.2


@pytest.mark.parametrize(
    ("sev", "expected"),
    [
        ("critical", 4),
        ("high", 3),
        ("medium", 2),
        ("low", 1),
        ("untriaged", 0),
        ("CRITICAL", 4),
        ("unknown-value", 0),
        ("", 0),
        (None, 0),
    ],
)
def test_sev_rank(sev, expected):
    assert sev_rank(sev) == expected
