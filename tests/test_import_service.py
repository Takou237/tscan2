"""Test d'intégration du service d'import (RF-01, RF-02, RF-04, RF-05).

Vérifie le chemin complet : fichier source -> parseur -> persistance -> lecture,
plutôt que chaque brique isolément (déjà couvertes par test_importer_nuclei.py
et test_importer_zap.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.importers import SUPPORTED_FORMATS, UnsupportedFormatError, import_file
from tscan_core.models import Finding, ScanType

FIXTURES = Path(__file__).parent / "fixtures"


def test_supported_formats_contains_nuclei_and_zap() -> None:
    assert "nuclei" in SUPPORTED_FORMATS
    assert "zap" in SUPPORTED_FORMATS


def test_import_nuclei_file_end_to_end() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scan = import_file(
            session, source="nuclei", target="example.test", file_path=FIXTURES / "nuclei_sample.jsonl"
        )
        assert scan.id is not None
        assert scan.scan_type == ScanType.IMPORT
        assert scan.source == "nuclei"

        findings = session.query(Finding).filter_by(scan_id=scan.id).all()
        assert len(findings) == 3
        # Le résultat brut d'origine doit être conservé sans modification (RF-05).
        assert all(f.raw_result for f in findings)


def test_import_zap_file_end_to_end() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scan = import_file(
            session, source="zap", target="example.test", file_path=FIXTURES / "zap_sample.json"
        )
        findings = session.query(Finding).filter_by(scan_id=scan.id).all()
        assert len(findings) == 2
        categories = {f.category for f in findings}
        assert categories == {"xss", "csrf"}


def test_import_two_sources_on_same_target_are_both_queryable() -> None:
    """Prépare le terrain du bloc corrélation (semaines 5-6, RF-09) : deux
    scans de sources différentes sur la même cible doivent coexister sans
    se marcher dessus, chacun avec ses propres findings rattachés."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scan_nuclei = import_file(
            session, source="nuclei", target="example.test", file_path=FIXTURES / "nuclei_sample.jsonl"
        )
        scan_zap = import_file(
            session, source="zap", target="example.test", file_path=FIXTURES / "zap_sample.json"
        )

        assert scan_nuclei.id != scan_zap.id
        total_findings = session.query(Finding).count()
        assert total_findings == 3 + 2


def test_import_unknown_format_raises() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session, pytest.raises(UnsupportedFormatError):
        import_file(session, source="nessus", target="example.test", file_path=FIXTURES / "nuclei_sample.jsonl")
