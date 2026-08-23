"""Tests for the Wazuh -> dashboard mapping, using the real 4.14.6 record shape."""

from __future__ import annotations

from app.wazuh.mapper import (
    UNTRIAGED,
    aggregate_by_cve,
    normalize_score,
    normalize_severity,
    package_label,
    remediation_kind,
)


def win_doc(cve="CVE-2026-58640", sev="High", base=7.3, agent="DC01", agent_id="005"):
    """An OS-category record as Wazuh emits it for a Windows agent."""
    return {
        "agent": {"id": agent_id, "name": agent},
        "host": {
            "os": {
                "name": "Microsoft Windows Server 2022 Standard Evaluation",
                "platform": "windows",
                "version": "10.0.20348.587",
            }
        },
        "package": {
            "name": "Microsoft Windows Server 2022 Standard Evaluation 10.0.20348.587",
            "version": "10.0.20348.587",
            "type": "windows",
            "architecture": "x86_64",
        },
        "vulnerability": {
            "id": cve,
            "severity": sev,
            "score": {"base": base, "version": "3.1"},
            "description": "Heap-based buffer overflow in Windows NTFS.",
            "reference": "https://msrc.microsoft.com/...",
            "published_at": "2026-07-14T17:17:14Z",
            "category": "OS",
            "enumeration": "CVE",
        },
    }


def deb_doc(cve="CVE-2026-45232", sev="Low", base=3.1, agent="pve01", pkg="vim-common"):
    return {
        "agent": {"id": "001", "name": agent},
        "host": {"os": {"name": "Debian GNU/Linux", "platform": "debian", "version": "12"}},
        "package": {"name": pkg, "version": "2:9.0.1378", "type": "deb", "architecture": "amd64"},
        "vulnerability": {
            "id": cve,
            "severity": sev,
            "score": {"base": base, "version": "3.1"},
            "description": "vim issue.",
            "reference": "https://nvd.nist.gov/",
            "published_at": "2026-06-01T00:00:00Z",
            "category": "Packages",
            "enumeration": "CVE",
        },
    }


class TestNormalizeSeverity:
    def test_known_levels_pass_through(self):
        assert normalize_severity("Critical") == "Critical"
        assert normalize_severity("High") == "High"

    def test_wazuh_dash_becomes_untriaged(self):
        # ~12% of records on a real fleet carry "-" rather than null.
        assert normalize_severity("-") == UNTRIAGED

    def test_none_and_empty_become_untriaged(self):
        assert normalize_severity(None) == UNTRIAGED
        assert normalize_severity("") == UNTRIAGED

    def test_case_is_normalized(self):
        assert normalize_severity("high") == "High"

    def test_unrecognized_value_is_untriaged_not_dropped(self):
        assert normalize_severity("Severe") == UNTRIAGED


class TestNormalizeScore:
    def test_real_score_kept(self):
        assert normalize_score(7.3) == 7.3

    def test_wazuh_negative_one_sentinel_becomes_none(self):
        # Wazuh's FieldAlertHelper writes -1.0 (not null, not 0) when a CVE has no
        # score yet; it pairs with severity "-" and under_evaluation: true.
        # Verified against a live 4.14.6 index.
        assert normalize_score(-1.0) is None

    def test_zero_becomes_none_so_scoring_degrades(self):
        # None makes priority_score fall back to CVSS-only instead of ranking the
        # record as a genuine zero.
        assert normalize_score(0) is None

    def test_missing_or_garbage_is_none(self):
        assert normalize_score(None) is None
        assert normalize_score("-") is None


class TestPackageLabel:
    def test_os_finding_uses_stable_os_name_without_build(self):
        # package.name carries the build number, which would fragment the chart
        # into one bucket per patch level.
        assert package_label(win_doc()) == "Microsoft Windows Server 2022 Standard Evaluation"

    def test_package_finding_uses_package_name(self):
        assert package_label(deb_doc()) == "vim-common"


class TestRemediationKind:
    def test_windows_os_is_an_os_update(self):
        assert remediation_kind(win_doc()) == "os_update"

    def test_deb_is_a_distro_package(self):
        assert remediation_kind(deb_doc()) == "distro_package"

    def test_windows_program_is_an_application(self):
        doc = deb_doc()
        doc["package"] = {"name": "Microsoft Edge", "version": "1", "type": "win"}
        doc["vulnerability"]["category"] = "Packages"
        assert remediation_kind(doc) == "application"


class TestAggregateByCve:
    def test_one_row_per_cve(self):
        rows = aggregate_by_cve([win_doc(), deb_doc()])
        assert len(rows) == 2

    def test_same_cve_across_agents_collapses_into_one_row(self):
        rows = aggregate_by_cve(
            [
                deb_doc(agent="pve01"),
                deb_doc(agent="pve02"),
                deb_doc(agent="pve03"),
            ]
        )
        assert len(rows) == 1
        assert rows[0]["agentes"] == ["pve01", "pve02", "pve03"]
        assert rows[0]["instalaciones"] == 3

    def test_highest_severity_across_agents_wins(self):
        rows = aggregate_by_cve(
            [
                deb_doc(sev="Low", base=3.1, agent="pve01"),
                deb_doc(sev="Critical", base=9.8, agent="pve02"),
            ]
        )
        assert rows[0]["severidad"] == "Critical"
        assert rows[0]["cvss"] == 9.8

    def test_untriaged_record_yields_no_cvss(self):
        rows = aggregate_by_cve([deb_doc(sev="-", base=0)])
        assert rows[0]["severidad"] == UNTRIAGED
        assert rows[0]["cvss"] is None

    def test_records_without_a_cve_id_are_skipped(self):
        doc = deb_doc()
        doc["vulnerability"]["id"] = None
        assert aggregate_by_cve([doc]) == []

    def test_mixed_platform_cve_reports_both(self):
        rows = aggregate_by_cve(
            [
                deb_doc(agent="pve01"),
                {
                    **deb_doc(agent="lab-linux"),
                    "host": {"os": {"name": "Ubuntu", "platform": "ubuntu", "version": "24.04"}},
                },
            ]
        )
        assert rows[0]["plataformas"] == ["debian", "ubuntu"]

    def test_per_agent_detail_is_retained_for_assignment(self):
        # Assignment is tracked per (CVE, agent), so the aggregate must not lose
        # which agent carries which package.
        rows = aggregate_by_cve([deb_doc(agent="pve01"), deb_doc(agent="pve02")])
        detail = {a["agente"]: a for a in rows[0]["detalle_agentes"]}
        assert set(detail) == {"pve01", "pve02"}
        assert detail["pve01"]["plataforma"] == "debian"

    def test_epss_and_kev_are_attached(self):
        rows = aggregate_by_cve(
            [deb_doc(cve="CVE-2026-45232")],
            epss_by_cve={"CVE-2026-45232": 0.42},
            kev_by_cve={"CVE-2026-45232": {"vencimiento": "2026-09-01", "ransomware": True}},
        )
        assert rows[0]["epss"] == 0.42
        assert rows[0]["kev"] is True
        assert rows[0]["kev_info"]["ransomware"] is True

    def test_cve_absent_from_kev_is_not_flagged(self):
        rows = aggregate_by_cve([deb_doc()], kev_by_cve={"CVE-9999-1": {}})
        assert rows[0]["kev"] is False
        assert rows[0]["epss"] is None
