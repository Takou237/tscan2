"""Tests du moteur de scoring de confiance (RF-10)."""

from __future__ import annotations

from tscan_core.correlation.matcher import CorrelationGroup
from tscan_core.correlation.scoring import PROBABLE_THRESHOLD, score_finding
from tscan_core.models import Finding, FindingStatus, Scan, ScanType
from tscan_core.rule_engine.schema import RuleDefinition


def _make_finding(scan_source: str = "nuclei", **overrides) -> Finding:
    scan = Scan(id=1, scan_type=ScanType.IMPORT, source=scan_source, target="example.test")
    defaults = {
        "scan_id": 1,
        "title": "Résultat de test",
        "category": "xss",
        "severity": "high",
        "status": FindingStatus.UNVALIDATED,
        "raw_result": '{"example": true}',
    }
    defaults.update(overrides)
    finding = Finding(**defaults)
    finding.scan = scan  # relation en mémoire, sans passer par la base
    return finding


def _xss_rule() -> RuleDefinition:
    return RuleDefinition(
        id="RULE-XSS-001",
        name="Cross-Site Scripting réfléchi",
        category="xss",
        severity="high",
        version="1.0.0",
        description="...",
        confidence_base=0.5,
        confidence_multi_source_bonus=0.3,
    )


def test_score_finding_without_correlation_uses_rule_base_score() -> None:
    finding = _make_finding()
    result = score_finding(finding, {"xss": _xss_rule()}, correlation_group=None)
    assert result.score == 0.5
    assert result.matched_rule_id == "RULE-XSS-001"
    assert any("Score de base" in line for line in result.explanation)


def test_score_finding_with_multi_source_correlation_gets_bonus() -> None:
    finding = _make_finding()
    other_finding = _make_finding(scan_source="zap")
    group = CorrelationGroup(
        category="xss", location="http://example.test/search.jsp", findings=[finding, other_finding]
    )

    result = score_finding(finding, {"xss": _xss_rule()}, correlation_group=group)
    assert result.score == 0.8  # 0.5 (base) + 0.3 (bonus multi-source)
    assert any("Corroboré par 2 sources" in line for line in result.explanation)


def test_score_finding_single_source_group_gets_no_bonus() -> None:
    finding = _make_finding()
    group = CorrelationGroup(category="xss", location="...", findings=[finding])  # une seule source

    result = score_finding(finding, {"xss": _xss_rule()}, correlation_group=group)
    assert result.score == 0.5  # pas de bonus, un seul scan dans le groupe


def test_score_finding_below_threshold_is_potential_false_positive() -> None:
    finding = _make_finding(category="other")
    result = score_finding(finding, rules_by_category={}, correlation_group=None)
    assert result.score < PROBABLE_THRESHOLD
    assert result.status == FindingStatus.POTENTIAL_FALSE_POSITIVE


def test_score_finding_above_threshold_is_probable() -> None:
    finding = _make_finding()
    other_finding = _make_finding(scan_source="zap")
    group = CorrelationGroup(category="xss", location="...", findings=[finding, other_finding])

    result = score_finding(finding, {"xss": _xss_rule()}, correlation_group=group)
    assert result.status == FindingStatus.PROBABLE


def test_score_finding_prefilter_penalty_is_applied_and_explained() -> None:
    finding = _make_finding(title="")  # déclenche une pénalité de pré-filtrage
    result = score_finding(finding, {"xss": _xss_rule()}, correlation_group=None)
    assert result.score < 0.5
    assert any("Pré-filtrage" in line for line in result.explanation)


def test_score_finding_never_exceeds_bounds() -> None:
    """Le score doit toujours rester dans [0, 1], même avec un bonus important."""
    finding = _make_finding()
    other_finding = _make_finding(scan_source="zap")
    group = CorrelationGroup(category="xss", location="...", findings=[finding, other_finding])

    generous_rule = RuleDefinition(
        id="RULE-X", name="x", category="xss", severity="high", version="1.0.0",
        description="...", confidence_base=0.9, confidence_multi_source_bonus=0.5,
    )
    result = score_finding(finding, {"xss": generous_rule}, correlation_group=group)
    assert result.score <= 1.0
