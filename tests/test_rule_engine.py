"""Tests du chargeur de règles (RF-13)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Rule
from tscan_core.rule_engine import RuleLoadError, load_rules, sync_rules_to_db

REPO_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"

EXPECTED_CATEGORIES = {
    "security_misconfiguration",
    "vulnerable_component",
    "xss",
    "broken_access_control",
    "csrf",
    "sqli",
    "information_disclosure",
    "path-traversal",
    "open-redirect",
    "cmd-injection",
    "ssti",
    "ssrf",
    "header-injection",
}


def test_load_rules_finds_all_mvp_rules() -> None:
    rules = load_rules(REPO_RULES_DIR)
    assert len(rules) == 54  # 6 règles 7b + détections S8 + WAF/cookies/CSP/SRI/xdomain/timestamp + security-headers/big-redirect + zap-passives (20) + xss-attribut + auth/session/sensitive-url/cross-domain/charset
    categories = {r.category for r in rules}
    assert categories == EXPECTED_CATEGORIES


def test_declarative_checks_are_loaded() -> None:
    """La section `checks:` (semaine 7b) doit être chargée telle quelle."""
    rules = load_rules(REPO_RULES_DIR)
    by_id = {r.id: r for r in rules}

    misconfig = by_id["RULE-MISCONFIG-001"]
    assert any(c["type"] == "header_absent" for c in misconfig.checks)

    clickjacking = by_id["RULE-CLICKJACKING-001"]
    assert len(clickjacking.checks) == 1
    assert clickjacking.checks[0]["id"] == "clickjacking"
    assert clickjacking.checks[0]["type"] == "clickjacking"

    bac = by_id["RULE-BAC-001"]
    assert any(c["type"] == "path_status" and c["path"] == "/wp-admin/" for c in bac.checks)


def test_each_rule_has_required_fields_populated() -> None:
    rules = load_rules(REPO_RULES_DIR)
    for rule in rules:
        assert rule.id
        assert rule.name
        assert rule.description
        assert rule.recommendation
        assert 0.0 <= rule.confidence_base <= 1.0
        assert 0.0 <= rule.confidence_multi_source_bonus <= 1.0


def test_load_rules_raises_on_malformed_file(tmp_path: Path) -> None:
    bad_dir = tmp_path / "rules"
    bad_dir.mkdir()
    (bad_dir / "broken.yaml").write_text("id: ONLY-ID-NO-OTHER-FIELDS\n", encoding="utf-8")

    with pytest.raises(RuleLoadError):
        load_rules(bad_dir)


def test_sync_rules_to_db_creates_metadata_rows() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    rules = load_rules(REPO_RULES_DIR)

    with get_session(engine) as session:
        sync_rules_to_db(session, rules)
        db_rules = session.query(Rule).all()
        assert len(db_rules) == 54  # 6 règles 7b + détections S8 + WAF/cookies/CSP/SRI/xdomain/timestamp + security-headers/big-redirect + zap-passives (20) + xss-attribut + auth/session/sensitive-url/cross-domain/charset
        # La table ne stocke que des métadonnées, pas le contenu complet.
        sample = session.get(Rule, "RULE-XSS-001")
        assert sample is not None
        assert sample.category == "xss"
        assert sample.file_path.endswith("xss_reflected.yaml")


def test_sync_rules_to_db_is_idempotent() -> None:
    """Recharger les mêmes règles deux fois ne doit pas créer de doublons."""
    engine = get_engine(":memory:")
    init_db(engine)
    rules = load_rules(REPO_RULES_DIR)

    with get_session(engine) as session:
        sync_rules_to_db(session, rules)
        sync_rules_to_db(session, rules)
        assert session.query(Rule).count() == 54
