"""Test de fumée du squelette de projet (semaine 3).

Objectif : vérifier que les modèles de données peuvent être créés, qu'une
session fonctionne, et qu'un `Finding` peut être inséré et relu -- avant
d'écrire la moindre logique métier (parseurs, corrélation...).
"""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus, Scan, ScanType


def test_init_db_creates_tables_in_memory() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    # Si la création des tables échoue, cette ligne ne sera jamais atteinte.
    assert engine is not None


def test_create_scan_and_finding_round_trip() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scan = Scan(scan_type=ScanType.IMPORT, source="nuclei", target="https://example.test")
        session.add(scan)
        session.flush()  # attribue l'id du scan sans clore la transaction

        finding = Finding(
            scan_id=scan.id,
            title="En-tête Content-Security-Policy manquant",
            category="security_misconfiguration",
            severity="low",
            status=FindingStatus.UNVALIDATED,
            raw_result='{"example": "raw payload conservé tel quel"}',
        )
        session.add(finding)
        session.commit()

        retrieved = session.get(Finding, finding.id)
        assert retrieved is not None
        assert retrieved.title == "En-tête Content-Security-Policy manquant"
        assert retrieved.status == FindingStatus.UNVALIDATED
        assert retrieved.scan.source == "nuclei"
