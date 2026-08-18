"""Tests de la corrélation multi-sources (RF-09)."""

from __future__ import annotations

from pathlib import Path

from tscan_core.correlation.matcher import correlate, group_multi_source_only, normalize_location
from tscan_core.db import get_engine, get_session, init_db
from tscan_core.importers import import_file
from tscan_core.models import Finding

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_location_ignores_query_string_and_trailing_slash() -> None:
    a = normalize_location("http://example.test/search.jsp?q=test", "example.test")
    b = normalize_location("http://example.test/search.jsp?q=autre-chose", "example.test")
    c = normalize_location("http://EXAMPLE.test/search.jsp/", "example.test")
    assert a == b == c


def test_normalize_location_falls_back_to_target_when_no_url() -> None:
    assert normalize_location(None, "example.test") == "example.test"


def test_correlate_groups_single_source_findings_separately() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    with get_session(engine) as session:
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_sample.jsonl")
        findings = session.query(Finding).all()
        groups = correlate(findings)

        # 3 résultats Nuclei à 3 emplacements distincts -> 3 groupes, aucun multi-source.
        assert len(groups) == 3
        assert group_multi_source_only(groups) == []


def test_correlate_detects_multi_source_corroboration() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    with get_session(engine) as session:
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_xss_overlap.jsonl")
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")

        findings = session.query(Finding).all()
        groups = correlate(findings)
        multi_source = group_multi_source_only(groups)

        assert len(multi_source) == 1
        xss_group = multi_source[0]
        assert xss_group.category == "xss"
        assert xss_group.sources == {"nuclei", "zap"}
        assert len(xss_group.findings) == 2
