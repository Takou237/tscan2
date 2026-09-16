"""Tests unitaires du parseur OWASP ZAP (RF-02)."""

from __future__ import annotations

import json
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


def test_parse_zap_csp_alert_not_miscategorized_as_xss(tmp_path: Path) -> None:
    """Régression (27/09/2026) : la description ZAP des alertes CSP mentionne
    « Cross Site Scripting (XSS) » dans son texte générique. La catégorisation
    doit se fier au nom de l'alerte (CSP → `security_misconfiguration`) et non
    au texte libre, sinon la corroboration avec les constats du scan actif
    Tscan (même catégorie `security_misconfiguration`) échoue et
    `reproduced=0`."""
    data = {
        "site": [
            {
                "@name": "https://example.test",
                "alerts": [
                    {
                        "pluginid": "10055",
                        "alert": "CSP: Wildcard Directive",
                        "name": "CSP: Wildcard Directive",
                        "riskcode": "2",
                        "confidence": "3",
                        "riskdesc": "Moyen (Haut)",
                        "desc": (
                            "<p>Content Security Policy helps to detect and "
                            "mitigate certain types of attacks, including "
                            "Cross Site Scripting (XSS) and data injection "
                            "attacks.</p>"
                        ),
                        "instances": [{"uri": "https://example.test/?lang=fr"}],
                        "count": "1",
                        "cweid": "693",
                    }
                ],
            }
        ]
    }
    fixture = tmp_path / "csp_alert.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    findings = parse_zap_json(fixture)
    assert len(findings) == 1
    assert findings[0].title == "CSP: Wildcard Directive"
    assert findings[0].category == "security_misconfiguration"


def test_parse_zap_reflected_xss_remains_xss(tmp_path: Path) -> None:
    """Un vrai XSS (nom + description) reste rattaché à `xss` malgré la
    priorité au nom : la correction de priorité ne réécrit pas les catégories
    légitimes."""
    data = {
        "site": [
            {
                "@name": "https://example.test",
                "alerts": [
                    {
                        "pluginid": "40012",
                        "alert": "Cross Site Scripting (Reflected)",
                        "name": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "confidence": "2",
                        "riskdesc": "Haut",
                        "desc": "<p>Reflected XSS found in the response.</p>",
                        "instances": [
                            {"uri": "https://example.test/search.jsp?q=<script>"}
                        ],
                        "count": "1",
                    }
                ],
            }
        ]
    }
    fixture = tmp_path / "xss.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")

    findings = parse_zap_json(fixture)
    assert findings[0].category == "xss"
