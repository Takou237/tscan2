"""Tests de la table de référence CWE statique (RF-33)."""

from __future__ import annotations

from pathlib import Path

from tscan_core.knowledge_base.cwe_reference import DEFAULT_CWE_FILE, load_cwe_reference

EXPECTED_CATEGORIES = {
    "xss",
    "csrf",
    "broken_access_control",
    "vulnerable_component",
    "security_misconfiguration",
    "sqli",
}


def test_default_cwe_file_exists() -> None:
    assert Path(DEFAULT_CWE_FILE).exists()


def test_load_cwe_reference_covers_all_mvp_categories() -> None:
    entries = load_cwe_reference()
    categories = {e.category for e in entries.values()}
    assert EXPECTED_CATEGORIES.issubset(categories)


def test_load_cwe_reference_indexed_by_id() -> None:
    entries = load_cwe_reference()
    assert "CWE-79" in entries
    assert entries["CWE-79"].category == "xss"
    assert "Cross-site Scripting" in entries["CWE-79"].name
