"""Tests unitaires du parseur OWASP ZAP (RF-02)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tscan_core.importers.zap import ZapParseError, parse_zap_json

FIXTURE = Path(__file__).parent / "fixtures" / "zap_sample.json"


def test_parse_zap_sample_returns_two_findings() -> None:
    findings = parse_zap_json(FIXTURE)
    assert len(findings) == 2


def test_parse_zap_maps_category_and_severity() -> None:
    findings = parse_zap_json(FIXTURE)
    by_plugin = {f.external_id: f for f in findings}

    xss = by_plugin["40012"]
    assert xss.category == "xss"
    assert xss.severity == "high"
    assert xss.matched_at.startswith("http://example.test/search.jsp")

    csrf = by_plugin["10202"]
    assert csrf.category == "csrf"
    assert csrf.severity == "medium"


def test_parse_zap_strips_html_from_description() -> None:
    findings = parse_zap_json(FIXTURE)
    for finding in findings:
        assert "<p>" not in finding.description
        assert "<" not in finding.description


def test_parse_zap_preserves_raw_alert_as_json() -> None:
    findings = parse_zap_json(FIXTURE)
    for finding in findings:
        assert finding.raw_result.strip().startswith("{")
        assert '"pluginid"' in finding.raw_result


def test_parse_zap_invalid_json_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "not_zap.json"
    bad_file.write_text("ceci n'est pas du JSON", encoding="utf-8")
    with pytest.raises(ZapParseError):
        parse_zap_json(bad_file)


def test_parse_zap_missing_site_key_raises(tmp_path: Path) -> None:
    wrong_shape = tmp_path / "wrong_shape.json"
    wrong_shape.write_text('{"foo": "bar"}', encoding="utf-8")
    with pytest.raises(ZapParseError):
        parse_zap_json(wrong_shape)
