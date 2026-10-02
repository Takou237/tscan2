"""Tests de la logique de présentation de l'interface desktop (S10).

Couvre la partie « viewmodel » de `tscan_gui` -- la portion de la couche de
présentation qui est testable sans écran Qt (c'est le choix d'architecture
décrit dans `tscan_gui/viewmodel.py`) :

- `list_findings` : filtres (statut, gravité, cible, texte) et tri par gravité
  (UC2) ;
- `list_targets` : cibles distinctes triées ;
- `get_finding_detail` : assemblage du détail (preuves, historique, score).

Les tests construisent une base SQLite en mémoire, donc n'écrivent rien sur la
base de l'utilisateur et ne dépendent d'aucune ressource externe (aucun
réseau, aucun scan actif).
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import (
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Scan,
    ScanType,
    StatusHistory,
)
from tscan_gui.viewmodel import (
    SEVERITY_ORDER,
    VALID_STATUSES,
    get_finding_detail,
    list_findings,
    list_targets,
)


@pytest.fixture
def session() -> Session:
    """Session sur une base SQLite en mémoire, peuplée de données de test."""
    engine = get_engine(":memory:")
    init_db(engine)
    with get_session(engine) as sess:
        scan_a = Scan(scan_type=ScanType.IMPORT, source="nuclei", target="https://a.test")
        scan_b = Scan(scan_type=ScanType.IMPORT, source="zap", target="https://b.test")
        sess.add_all([scan_a, scan_b])
        sess.flush()

        f_high = Finding(
            scan_id=scan_a.id,
            title="XSS réfléchi",
            category="xss_reflected",
            severity="high",
            status=FindingStatus.CONFIRMED,
            confidence_score=0.95,
            score_explanation='["Signal détecté et reporté reproductible."]',
        )
        f_medium = Finding(
            scan_id=scan_a.id,
            title="Clickjacking",
            category="clickjacking",
            severity="medium",
            status=FindingStatus.PROBABLE,
            confidence_score=0.60,
        )
        f_low = Finding(
            scan_id=scan_b.id,
            title="CORS permissif",
            category="cors",
            severity="low",
            status=FindingStatus.FALSE_POSITIVE,
            confidence_score=0.30,
        )
        sess.add_all([f_high, f_medium, f_low])
        sess.flush()

        sess.add(
            Evidence(
                finding_id=f_high.id,
                evidence_type=EvidenceType.REQUEST_RESPONSE,
                content_text="GET /p?=<script> --> 200 OK",
            )
        )
        sess.add(
            StatusHistory(
                finding_id=f_high.id,
                old_status=FindingStatus.UNVALIDATED,
                new_status=FindingStatus.CONFIRMED,
                changed_by="analyste",
                reason="Re-vérification manuelle",
            )
        )
        sess.commit()
        yield sess


def test_statuses_and_severity_order(session: Session) -> None:
    assert set(VALID_STATUSES) == {s.value for s in FindingStatus}
    assert SEVERITY_ORDER == ["critical", "high", "medium", "low", "info"]


def test_list_findings_all_sorted_by_severity(session: Session) -> None:
    rows = list_findings(session)
    severities = [r.severity for r in rows]
    # Tri descendant : high avant medium avant low.
    assert severities == ["high", "medium", "low"]
    assert rows[0].title == "XSS réfléchi"


def test_list_findings_filter_status(session: Session) -> None:
    rows = list_findings(session, status=FindingStatus.CONFIRMED.value)
    assert len(rows) == 1
    assert rows[0].status == "confirmed"


def test_list_findings_filter_severity(session: Session) -> None:
    rows = list_findings(session, severity="low")
    assert len(rows) == 1
    assert rows[0].severity == "low"


def test_list_findings_filter_target(session: Session) -> None:
    rows = list_findings(session, target="https://a.test")
    assert {r.title for r in rows} == {"XSS réfléchi", "Clickjacking"}


def test_list_findings_filter_text(session: Session) -> None:
    rows = list_findings(session, query_text="click")
    assert len(rows) == 1
    assert rows[0].category == "clickjacking"


def test_list_findings_groups_instances_by_vulnerability() -> None:
    """Une seule ligne par vulnérabilité (même cible + titre + catégorie) :
    les instances sont regroupées et comptées, `matched_at` porte la première
    (demande utilisateur 26/09/2026 : pas de répétitions dans l'affichage)."""
    engine = get_engine(":memory:")
    init_db(engine)
    with get_session(engine) as session:
        scan = Scan(
            scan_type=ScanType.IMPORT, source="nuclei", target="https://a.test"
        )
        session.add(scan)
        session.flush()
        first = Finding(
            scan_id=scan.id,
            title="XSS réfléchi",
            category="xss_reflected",
            severity="high",
            status=FindingStatus.PROBABLE,
            matched_at="https://a.test/p?q=1",
        )
        second = Finding(
            scan_id=scan.id,
            title="XSS réfléchi",
            category="xss_reflected",
            severity="high",
            status=FindingStatus.PROBABLE,
            matched_at="https://a.test/p?q=2",
        )
        stored = Finding(
            scan_id=scan.id,
            title="XSS stocké",
            category="xss_stored",
            severity="high",
            status=FindingStatus.UNVALIDATED,
            matched_at="https://a.test/profile",
        )
        session.add_all([first, second, stored])
        session.commit()

        rows = list_findings(session)
        # 2 vulnérabilités distinctes (titre/catégorie différents) → 2 lignes.
        assert len(rows) == 2
        assert {r.category for r in rows} == {"xss_reflected", "xss_stored"}

        reflected = next(r for r in rows if r.category == "xss_reflected")
        assert reflected.instance_count == 2
        assert reflected.title == "XSS réfléchi"
        assert reflected.matched_at == "https://a.test/p?q=1"  # première instance
        assert reflected.status == "probable"

        stored_row = next(r for r in rows if r.category == "xss_stored")
        assert stored_row.instance_count == 1


def test_list_targets(session: Session) -> None:
    assert list_targets(session) == ["https://a.test", "https://b.test"]


def test_get_finding_detail(session: Session) -> None:
    rows = list_findings(session)
    first_id = rows[0].id
    detail = get_finding_detail(session, first_id)
    assert detail is not None
    assert detail.severity == "high"
    assert detail.score == 0.95
    assert any("200 OK" in ev for ev in detail.evidences)
    assert any("Re-vérification manuelle" in h for h in detail.history)


def test_get_finding_detail_missing(session: Session) -> None:
    assert get_finding_detail(session, 9999) is None


def test_manual_correction_updates_history(session: Session) -> None:
    """Parcours UC3 (S10) : corriger le statut depuis le panneau de détail
    doit produire un nouvel enregistrement d'historique (RF-12 / ES-06) et le
    score correspondant à la décision humaine, puis l'affichage du détail doit
    refléter le nouveau statut."""
    from tscan_core.status import correct_status_manually

    rows = list_findings(session, status=FindingStatus.PROBABLE.value)
    assert len(rows) == 1
    finding_id = rows[0].id
    old_history_count = len(get_finding_detail(session, finding_id).history)

    # Ce que fait le bouton « Appliquer » : correct_status_manually + relecture.
    finding = session.get(Finding, finding_id)
    correct_status_manually(
        session,
        finding,
        FindingStatus.FALSE_POSITIVE,
        changed_by="analyste_gui",
        reason="Examiné sur le site de démonstration",
    )

    detail = get_finding_detail(session, finding_id)
    assert detail.status == "false_positive"
    assert detail.score == 0.0  # un faux positif manuel annule la confiance
    assert len(detail.history) == old_history_count + 1
    assert any("analyste_gui" in h for h in detail.history)


# --- Bilan des actions longues affiché à l'analyste ------------------------
#
# `workers.py` renvoie des indicateurs numériques ; `_summarize_task` les
# traduit en une ligne lisible pour la boîte de dialogue de l'interface.
# Sans cela, un scan se concluait par « Opération terminée. » sans indiquer le
# nombre de constats trouvés.


def test_summarize_scan_reports_finding_count() -> None:
    from tscan_gui.main import _summarize_task

    summary = _summarize_task({"findings": 46, "target": "http://127.0.0.1:8080/"})
    assert "46 constat(s)" in summary
    assert "http://127.0.0.1:8080/" in summary


def test_summarize_scan_mentions_manual_interrupt() -> None:
    from tscan_gui.main import _summarize_task

    summary = _summarize_task(
        {"findings": 12, "target": "http://127.0.0.1:8080/", "interrupted": True}
    )
    assert "conservés" in summary


def test_summarize_report_reports_path_and_count() -> None:
    from tscan_gui.main import _summarize_task

    summary = _summarize_task({"path": "rapport.html", "chars": 4096, "count": 46})
    assert "rapport.html" in summary
    assert "46 constat(s)" in summary


def test_summarize_correlate_reports_status_breakers() -> None:
    from tscan_gui.main import _summarize_task

    summary = _summarize_task(
        {"count": 19, "probable": 12, "potential_false_positives": 4}
    )
    assert "4 potentiel(s) faux positif(s)" in summary
    assert "12 probable(s)" in summary


def test_summarize_ignores_unknown_or_missing_detail() -> None:
    """Une tâche sans indicateur exploitable ne doit rien ajouter au message."""
    from tscan_gui.main import _summarize_task

    assert _summarize_task(None) == ""
    assert _summarize_task("pas un dict") == ""
    assert _summarize_task({"inconnu": 1}) == ""