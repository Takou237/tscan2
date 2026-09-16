"""Tests unitaires du parseur Nessus/OpenVAS (.nessus XML, RF-01)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tscan_core.importers.nessus import NessusParseError, parse_nessus_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nessus_sample.nessus"


def test_parse_nessus_sample_returns_five_findings() -> None:
    findings = parse_nessus_xml(FIXTURE)
    assert len(findings) == 5


def test_parse_nessus_preserves_raw_xml() -> None:
    findings = parse_nessus_xml(FIXTURE)
    for finding in findings:
        assert finding.raw_result.strip().startswith("<")
        assert "ReportItem" in finding.raw_result


def test_parse_nessus_maps_fields() -> None:
    findings = parse_nessus_xml(FIXTURE)
    by_plugin = {f.external_id: f for f in findings}

    apache = by_plugin["10150"]
    assert apache.title == "HTTP Server Type and Version"
    assert apache.severity == "medium"  # gravité 2
    assert apache.matched_at == "http://example.test:80"
    assert apache.description
    assert apache.extra["cves"] == ["CVE-2021-44790", "CVE-2022-22719"]

    tls = by_plugin["104743"]
    assert tls.severity == "high"  # gravité 3
    assert tls.matched_at == "https://example.test:443"

    certificate = by_plugin["51192"]
    assert certificate.severity == "medium"
    assert certificate.title == "SSL Certificate Expiry"


def test_parse_nessus_severity_number_mapping() -> None:
    findings = parse_nessus_xml(FIXTURE)
    by_plugin = {f.external_id: f for f in findings}
    assert by_plugin["20000"].severity == "info"  # gravité 0
    assert by_plugin["10335"].severity == "low"  # gravité 1
    assert by_plugin["104743"].severity == "high"  # gravité 3


def test_parse_nessus_maps_category_from_text_hints() -> None:
    findings = parse_nessus_xml(FIXTURE)
    by_plugin = {f.external_id: f for f in findings}
    assert by_plugin["10335"].category == "sqli"
    assert by_plugin["104743"].category == "security_misconfiguration"
    assert by_plugin["10150"].category == "vulnerable_component"  # Cve/CVE- hint
    assert by_plugin["51192"].category == "security_misconfiguration"  # SSL/TLS hint


def test_parse_nessus_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        parse_nessus_xml(Path("does_not_exist.nessus"))


def test_parse_nessus_invalid_content_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "not_nessus.nessus"
    bad_file.write_text("ceci n'est pas du XML <", encoding="utf-8")
    with pytest.raises(NessusParseError):
        parse_nessus_xml(bad_file)


def test_parse_nessus_wrong_root_raises(tmp_path: Path) -> None:
    wrong_file = tmp_path / "wrong_root.nessus"
    wrong_file.write_text(
        '<?xml version="1.0" ?><NucleiReport><item /></NucleiReport>',
        encoding="utf-8",
    )
    with pytest.raises(NessusParseError):
        parse_nessus_xml(wrong_file)


def test_parse_nessus_no_report_items_raises(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.nessus"
    empty_file.write_text(
        '<?xml version="1.0" ?><NessusClientData_v2><Report /></NessusClientData_v2>',
        encoding="utf-8",
    )
    with pytest.raises(NessusParseError):
        parse_nessus_xml(empty_file)