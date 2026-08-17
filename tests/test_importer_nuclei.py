"""Tests unitaires du parseur Nuclei (RF-01)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tscan_core.importers.nuclei import NucleiParseError, parse_nuclei_jsonl

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl"


def test_parse_nuclei_sample_returns_three_findings() -> None:
    findings = parse_nuclei_jsonl(FIXTURE)
    assert len(findings) == 3


def test_parse_nuclei_preserves_raw_result() -> None:
    findings = parse_nuclei_jsonl(FIXTURE)
    for finding in findings:
        assert finding.raw_result.strip().startswith("{")
        assert '"template-id"' in finding.raw_result


def test_parse_nuclei_maps_severity_and_category() -> None:
    findings = parse_nuclei_jsonl(FIXTURE)
    by_template = {f.external_id: f for f in findings}

    csp = by_template["missing-csp-header"]
    assert csp.severity == "info"
    assert csp.category == "security_misconfiguration"

    jquery = by_template["CVE-2023-12345"]
    assert jquery.severity == "medium"
    assert jquery.category == "vulnerable_component"
    assert jquery.matched_at == "http://example.test/js/jquery-1.11.0.min.js"

    admin = by_template["exposed-admin-panel"]
    assert admin.severity == "high"
    assert admin.category == "broken_access_control"


def test_parse_nuclei_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        parse_nuclei_jsonl(Path("does_not_exist.jsonl"))


def test_parse_nuclei_invalid_content_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "not_nuclei.jsonl"
    bad_file.write_text("ceci n'est pas du JSON\nni ça non plus\n", encoding="utf-8")
    with pytest.raises(NucleiParseError):
        parse_nuclei_jsonl(bad_file)


def test_parse_nuclei_skips_corrupted_lines_without_failing(tmp_path: Path) -> None:
    mixed_file = tmp_path / "mixed.jsonl"
    good_line = FIXTURE.read_text(encoding="utf-8").splitlines()[0]
    mixed_file.write_text(good_line + "\n{ligne corrompue non JSON\n", encoding="utf-8")

    findings = parse_nuclei_jsonl(mixed_file)
    assert len(findings) == 1
