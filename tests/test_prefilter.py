"""Tests du pré-filtrage contextuel (RF-08)."""

from __future__ import annotations

from tscan_core.correlation.prefilter import prefilter
from tscan_core.models import Finding, FindingStatus


def _make_finding(**overrides) -> Finding:
    defaults = {
        "scan_id": 1,
        "title": "Résultat de test",
        "category": "xss",
        "severity": "high",
        "status": FindingStatus.UNVALIDATED,
        "raw_result": '{"example": true}',
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_prefilter_clean_finding_has_no_issues() -> None:
    finding = _make_finding()
    result = prefilter(finding)
    assert result.is_consistent
    assert result.score_penalty == 0.0


def test_prefilter_flags_missing_title() -> None:
    finding = _make_finding(title="")
    result = prefilter(finding)
    assert not result.is_consistent
    assert any("Titre" in issue for issue in result.issues)
    assert result.score_penalty > 0


def test_prefilter_flags_unknown_severity() -> None:
    finding = _make_finding(severity="ultra-critique")
    result = prefilter(finding)
    assert any("Gravité" in issue for issue in result.issues)


def test_prefilter_flags_category_other() -> None:
    finding = _make_finding(category="other")
    result = prefilter(finding)
    assert any("non rattaché" in issue for issue in result.issues)


def test_prefilter_flags_missing_raw_result() -> None:
    finding = _make_finding(raw_result=None)
    result = prefilter(finding)
    assert any("ES-07" in issue for issue in result.issues)


def test_prefilter_accumulates_multiple_issues() -> None:
    finding = _make_finding(title="", severity="?", category="other", raw_result=None)
    result = prefilter(finding)
    assert len(result.issues) == 4
    assert result.score_penalty > 0.3
