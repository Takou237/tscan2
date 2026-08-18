"""Tests de la gestion des statuts avec historique (RF-12 / ES-06)."""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus, Scan, ScanType, StatusHistory
from tscan_core.status import AUTOMATIC_ACTOR, change_status


def test_change_status_updates_finding_and_creates_history_entry() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scan = Scan(scan_type=ScanType.IMPORT, source="nuclei", target="example.test")
        session.add(scan)
        session.flush()

        finding = Finding(
            scan_id=scan.id, title="Test", category="xss", severity="high",
            status=FindingStatus.UNVALIDATED, raw_result="{}",
        )
        session.add(finding)
        session.commit()

        change_status(session, finding, FindingStatus.PROBABLE, changed_by=AUTOMATIC_ACTOR)

        assert finding.status == FindingStatus.PROBABLE
        history = session.query(StatusHistory).filter_by(finding_id=finding.id).all()
        assert len(history) == 1
        assert history[0].old_status == FindingStatus.UNVALIDATED
        assert history[0].new_status == FindingStatus.PROBABLE
        assert history[0].changed_by == AUTOMATIC_ACTOR


def test_manual_correction_after_automatic_scoring_keeps_full_history() -> None:
    """Simule le scénario réel : le moteur pose un statut automatique, puis
    un analyste le corrige manuellement (RF-12) -- les deux doivent rester
    visibles dans l'historique, pas seulement le dernier."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scan = Scan(scan_type=ScanType.IMPORT, source="zap", target="example.test")
        session.add(scan)
        session.flush()

        finding = Finding(
            scan_id=scan.id, title="Test", category="csrf", severity="medium",
            status=FindingStatus.UNVALIDATED, raw_result="{}",
        )
        session.add(finding)
        session.commit()

        change_status(session, finding, FindingStatus.POTENTIAL_FALSE_POSITIVE, changed_by=AUTOMATIC_ACTOR)
        change_status(
            session, finding, FindingStatus.CONFIRMED,
            changed_by="analyste_jordan", reason="Vérifié manuellement sur la cible, formulaire bien vulnérable.",
        )

        assert finding.status == FindingStatus.CONFIRMED
        history = (
            session.query(StatusHistory)
            .filter_by(finding_id=finding.id)
            .order_by(StatusHistory.changed_at)
            .all()
        )
        assert len(history) == 2
        assert history[0].changed_by == AUTOMATIC_ACTOR
        assert history[1].changed_by == "analyste_jordan"
        assert history[1].old_status == FindingStatus.POTENTIAL_FALSE_POSITIVE
        assert history[1].new_status == FindingStatus.CONFIRMED
        assert "manuellement" in history[1].reason
