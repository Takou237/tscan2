"""Tests de la whitelist non destructive des constats.

Vérifie que `knowledge/finding_whitelist.yaml` est bien formé, que les règles
filtrent exactement le bruit déclaré (constat « info » de faible confiance,
titres de bruit) sans jamais écarter un constat solide, et que le filtrage est
bien branché sur la génération de rapport — en échec ouvert (fail-open) : un
fichier absent ou mal formé désactive le filtrage, il ne le renforce pas.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.knowledge_base.finding_whitelist import (
    DEFAULT_WHITELIST_FILE,
    Whitelist,
    WhitelistError,
    WhitelistRule,
    apply_whitelist,
    finding_matches_whitelist,
    load_whitelist,
)
from tscan_core.models import Finding, FindingStatus, Scan, ScanType
from tscan_core.reporting import generate_report


def _finding(
    *,
    severity: str = "info",
    confidence: float | None = 0.30,
    title: str = "Timestamp Disclosure",
    category: str = "information_disclosure",
) -> Finding:
    """Constat détaché (aucune session) : le filtrage ne lit que le titre,
    la gravité et le score de confiance."""
    return Finding(
        title=title,
        category=category,
        severity=severity,
        confidence_score=confidence,
        status=FindingStatus.UNVALIDATED,
        scan_id=1,
    )


def test_default_whitelist_file_exists_and_loads() -> None:
    assert DEFAULT_WHITELIST_FILE.exists()
    whitelist = load_whitelist()
    assert whitelist.enabled
    assert whitelist.rules
    ids = [rule.id for rule in whitelist.rules]
    assert len(ids) == len(set(ids)), "identifiants de règle dupliqués"
    for rule in whitelist.rules:
        assert rule.severities or rule.confidence_lt is not None or rule.title_contains


def test_shipped_yaml_is_a_mapping_with_enabled_flag() -> None:
    with DEFAULT_WHITELIST_FILE.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    assert isinstance(raw, dict)
    assert isinstance(raw.get("enabled"), bool)
    assert isinstance(raw.get("rules"), list)


def test_low_confidence_info_finding_is_filtered() -> None:
    whitelist = load_whitelist()
    matched, reason = finding_matches_whitelist(
        _finding(severity="info", confidence=0.20), whitelist
    )
    assert matched
    assert reason  # un motif lisible pour l'analyste


def test_high_severity_and_confidence_finding_is_kept() -> None:
    whitelist = load_whitelist()
    assert not finding_matches_whitelist(
        _finding(severity="critical", confidence=0.92, title="SQL Injection"), whitelist
    )[0]
    assert not finding_matches_whitelist(
        _finding(severity="info", confidence=0.90), whitelist
    )[0]


def test_missing_confidence_score_fails_open() -> None:
    """Score absent : le critère de confiance n'est pas vérifiable, le constat
    est conservé (le filtrage ouvre, il ne ferme jamais)."""
    whitelist = load_whitelist()
    assert not finding_matches_whitelist(
        _finding(severity="info", confidence=None), whitelist
    )[0]


def test_title_criterion_is_case_insensitive() -> None:
    whitelist = load_whitelist()
    assert finding_matches_whitelist(
        _finding(severity="info", confidence=0.50, title="TIMESTAMP DISCLOSURE"), whitelist
    )[0]


def test_disabled_rule_is_ignored() -> None:
    """La règle CSRF porte `enabled: false` : elle ne doit rien écarter."""
    whitelist = load_whitelist()
    csrf = next(rule for rule in whitelist.rules if rule.id == "csrf_very_low_conf")
    assert not csrf.enabled
    noisy = _finding(severity="low", confidence=0.30, title="Missing Anti-CSRF Token")
    assert not finding_matches_whitelist(noisy, whitelist)[0]


def test_globally_disabled_whitelist_filters_nothing() -> None:
    disabled = Whitelist(
        enabled=False,
        rules=(WhitelistRule(id="r", name="r", severities=("info",)),),
    )
    assert not finding_matches_whitelist(_finding(severity="info"), disabled)[0]


def test_criteria_are_combined_with_and() -> None:
    """La règle n'arbitre pas entre gravité et titre : les deux doivent tenir."""
    whitelist = Whitelist(
        rules=(
            WhitelistRule(
                id="noise",
                name="noise",
                severities=("info",),
                title_contains=("timestamp disclosure",),
            ),
        )
    )
    assert finding_matches_whitelist(_finding(severity="info"), whitelist)[0]
    # Bon titre mais gravité hors jeu : conservé.
    assert not finding_matches_whitelist(_finding(severity="high"), whitelist)[0]
    # Bonne gravité mais titre hors jeu : conservé.
    assert not finding_matches_whitelist(
        _finding(severity="info", title="Directory Listing"), whitelist
    )[0]


def test_load_rejects_rule_without_criteria(tmp_path: Path) -> None:
    bad = tmp_path / "wl.yaml"
    bad.write_text(
        "enabled: true\nrules:\n  - id: vide\n    match: {}\n",
        encoding="utf-8",
    )
    try:
        load_whitelist(bad)
    except WhitelistError as exc:
        assert "match" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("WhitelistError attendue pour une règle sans critère")


def test_load_rejects_unknown_criterion(tmp_path: Path) -> None:
    """Une faute de frappe sur un critère doit être signalée, pas ignorée."""
    bad = tmp_path / "wl.yaml"
    bad.write_text(
        "rules:\n  - id: faute\n    match:\n      confidence_lte: 0.4\n",
        encoding="utf-8",
    )
    try:
        load_whitelist(bad)
    except WhitelistError as exc:
        assert "confidence_lte" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("WhitelistError attendue pour un critère inconnu")


def test_load_rejects_missing_file(tmp_path: Path) -> None:
    try:
        load_whitelist(tmp_path / "absent.yaml")
    except WhitelistError:
        pass
    else:  # pragma: no cover
        raise AssertionError("WhitelistError attendue pour un fichier absent")


def test_apply_whitelist_fails_open_on_malformed_file(tmp_path: Path) -> None:
    bad = tmp_path / "wl.yaml"
    bad.write_text("rules: pas-une-liste\n", encoding="utf-8")
    findings = [_finding(), _finding(title="Directory Listing", confidence=0.9)]
    assert apply_whitelist(findings, bad) == findings


def test_apply_whitelist_filters_only_declared_noise() -> None:
    noisy = _finding(severity="info", confidence=0.20)
    solid = _finding(severity="critical", confidence=0.92, title="SQL Injection")
    assert apply_whitelist([noisy, solid]) == [solid]


def test_report_excludes_whitelisted_finding_but_keeps_the_rest() -> None:
    """Branche bout en bout : le rapport ignore le bruit whitelisted, le constat
    solide reste ; aucun constat n'est supprimé de la base (non destructif)."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scan = Scan(scan_type=ScanType.IMPORT, source="nuclei", target="example.test")
        session.add(scan)
        session.flush()
        session.add(
            Finding(
                scan=scan,
                title="Timestamp Disclosure",
                category="information_disclosure",
                severity="info",
                confidence_score=0.20,
                matched_at="https://example.test/",
                status=FindingStatus.UNVALIDATED,
            )
        )
        session.add(
            Finding(
                scan=scan,
                title="Injection SQL sur /login",
                category="sql_injection",
                severity="critical",
                confidence_score=0.92,
                matched_at="https://example.test/login",
                status=FindingStatus.PROBABLE,
            )
        )
        session.commit()

    with get_session(engine) as session:
        report = generate_report(session)
        assert report.total_findings == 1
        kept = report.targets[0].findings[0]
        assert kept.title == "Injection SQL sur /login"

        # Non destructif : les deux constats sont toujours en base.
        assert session.query(Finding).count() == 2
