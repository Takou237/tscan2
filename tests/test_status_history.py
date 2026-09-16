"""Tests de la gestion des statuts avec historique (RF-12 / ES-06)."""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus, Scan, ScanType, StatusHistory
from tscan_core.status import AUTOMATIC_ACTOR, change_status, correct_status_manually


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
def _make_finding(session) -> Finding:
    """Crée un constat non validé lié à un scan d'import (pour les tests de
    la correction manuelle RF-12 / ES-06)."""
    scan = Scan(scan_type=ScanType.IMPORT, source="nuclei", target="example.test")
    session.add(scan)
    session.flush()

    finding = Finding(
        scan_id=scan.id,
        title="Test",
        category="xss",
        severity="high",
        status=FindingStatus.UNVALIDATED,
        raw_result="{}",
    )
    session.add(finding)
    session.commit()
    return finding


def test_correct_status_manually_confirmed_sets_high_score() -> None:
    """RF-12/ES-06 : confirmer manuellement porte la confiance à 0,95 (signature
    de la décision humaine) et trace la décision dans le score et l'historique."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        finding = _make_finding(session)
        correct_status_manually(
            session,
            finding,
            FindingStatus.CONFIRMED,
            changed_by="analyste",
            reason="Preuve d'exploitation directe relevée sur la cible.",
        )

        assert finding.status == FindingStatus.CONFIRMED
        assert finding.confidence_score == 0.95
        assert "RF-12" in finding.score_explanation
        history = session.query(StatusHistory).filter_by(finding_id=finding.id).one()
        assert history.new_status == FindingStatus.CONFIRMED
        assert history.changed_by == "analyste"


def test_correct_status_manually_false_positive_nullifies_score() -> None:
    """RF-12/ES-06 : marquer un faux positif manuellement annule la confiance
    (0,00) pour sortir le constat du classement."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        finding = _make_finding(session)
        correct_status_manually(
            session,
            finding,
            FindingStatus.FALSE_POSITIVE,
            changed_by="analyste",
            reason="Résultat non reproductible en environnement de test.",
        )

        assert finding.status == FindingStatus.FALSE_POSITIVE
        assert finding.confidence_score == 0.0


def test_correct_status_manually_potential_false_positive_lowers_score() -> None:
    """RF-12/ES-06 : signaler un potentiel faux positif baisse la confiance à
    0,20 pour une revue analytique prioritaire."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        finding = _make_finding(session)
        correct_status_manually(
            session,
            finding,
            FindingStatus.POTENTIAL_FALSE_POSITIVE,
            changed_by="analyste",
            reason="Contexte observé contradictoire.",
        )

        assert finding.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
        assert finding.confidence_score == 0.20


def test_correct_status_manually_other_status_keeps_score() -> None:
    """RF-12 : un statut sans score manuel défini (ex : probable) conserve le
    score courant du constat."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        finding = _make_finding(session)
        finding.confidence_score = 0.70
        session.commit()

        correct_status_manually(
            session,
            finding,
            FindingStatus.PROBABLE,
            changed_by="analyste",
            reason="À re-traiter après complément de preuve.",
        )

        assert finding.status == FindingStatus.PROBABLE
        assert finding.confidence_score == 0.70
