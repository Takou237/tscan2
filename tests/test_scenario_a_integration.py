"""Test d'intégration du bloc corrélation/validation/scoring (semaines 5-6).

Rejoue le scénario A du chapitre 14 (critères de réussite du MVP) de bout en
bout : import de résultats de deux sources différentes sur une même cible,
corrélation, scoring, attribution de statuts, consultation des preuves
(l'explication du score tenant lieu de preuve de raisonnement, RF-11).
"""

from __future__ import annotations

import json
from pathlib import Path

from tscan_core.correlation import run_correlation
from tscan_core.db import get_engine, get_session, init_db
from tscan_core.importers import import_file
from tscan_core.models import Finding, FindingStatus, Scan, ScanType
from tscan_core.status import change_status

FIXTURES = Path(__file__).parent / "fixtures"


def test_scenario_a_end_to_end() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        # 1. Import de deux sources différentes sur la même cible.
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_xss_overlap.jsonl")
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_sample.jsonl")
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")

        total_before = session.query(Finding).count()
        assert total_before == 1 + 3 + 2  # 6 résultats importés au total

        # 2. Corrélation + scoring.
        updated = run_correlation(session, target="example.test")
        assert len(updated) == 6

        # 3. Tous les résultats ont un score et un statut Probable (upgrade
        #    auto, score ≥ seuil) — le scoring ne dégrade JAMAIS vers
        #    Potentiel faux positif (RF-12/RF-23).
        for finding in updated:
            assert finding.confidence_score is not None
            assert 0.0 <= finding.confidence_score <= 1.0
            assert finding.status == FindingStatus.PROBABLE
            assert finding.score_explanation is not None

        # 4. Le résultat XSS corroboré par 2 sources doit ressortir avec un
        #    score plus élevé et un statut Probable, et son explication doit
        #    mentionner la corroboration multi-sources (preuve du raisonnement).
        xss_findings = [f for f in updated if f.category == "xss"]
        assert len(xss_findings) == 2
        for f in xss_findings:
            assert f.status == FindingStatus.PROBABLE
            explanation = json.loads(f.score_explanation)
            assert any("Corroboré par 2 sources" in line for line in explanation)
            assert f.rule_id == "RULE-XSS-001"

        # 5. Le résultat CSRF (source unique, score 0.6 ≥ seuil) est Probable
        #    sans bonus multi-source.
        csrf = next(f for f in updated if f.category == "csrf")
        assert csrf.status == FindingStatus.PROBABLE
        explanation = json.loads(csrf.score_explanation)
        assert not any("Corroboré par" in line for line in explanation)

        # 6. Un résultat à source unique (ex : en-tête manquant, uniquement Nuclei)
        #    doit exister sans le bonus multi-source dans son explication.
        misconfig = next(f for f in updated if f.category == "security_misconfiguration")
        explanation = json.loads(misconfig.score_explanation)
        assert not any("Corroboré par" in line for line in explanation)


def test_scenario_a_is_idempotent_and_keeps_history() -> None:
    """Relancer la corrélation ne doit pas dupliquer les Finding, et doit
    conserver l'historique des statuts plutôt que l'écraser. Seuls les
    upgrades vers PROBABLE créent des entrées d'historique."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        # Import nuclei_sample (3 constats) + nuclei_xss_overlap (1 XSS) :
        # le XSS de nuclei_xss_overlap est corroboré par celui de nuclei_sample
        # (pas de overlap dans ce jeu, mais le BAC score 0.65 > 0.55 est upgrade).
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_sample.jsonl")

        run_correlation(session, target="example.test")
        run_correlation(session, target="example.test")

        assert session.query(Finding).count() == 3
        # Seuls les constats dont le score ≥ 0.55 ont été upgrade vers
        # PROBABLE (BAC 0.65, CSP 0.6, jQuery 0.55) → 3 entrées d'historique.
        findings = session.query(Finding).all()
        for f in findings:
            assert f.status == FindingStatus.PROBABLE
            assert len(f.status_history) == 1  # un seul upgrade par finding


def test_correlation_does_not_downgrade_active_scan_findings() -> None:
    """Régression (semaine 11) : la corrélation ne doit PAS re-scorer les
    résultats du scan actif (source `tscan_engine`) ni ceux déjà Confirmés.

    Sans cette exclusion, corréler après un scan rétrogradait les constats
    Confirmée (0,90, posés par la re-vérification RF-23) vers Probable avec
    un score de règle 0,60-0,70 — incohérent avec le design (chapitres 6/15 :
    la corrélation ne s'applique qu'aux résultats importés en attente de
    validation). Depuis le correctif RF-12 de la semaine 11, une confirmation
    vaut désormais 0,95 (décision d'analyste) et reste intouchable.
    """
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        # Import des résultats externes (source nuclei) : éligibles à la corrélation.
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_sample.jsonl")
        imported_list = session.query(Finding).all()
        assert len(imported_list) == 3

        # Résultat du scan actif Tscan déjà doté d'un verdict d'analyste
        # (Confirmé, RF-12) : la corrélation ne doit jamais le re-scorer.
        scan_engine = Scan(
            scan_type=ScanType.ACTIVE_SCAN,
            source="tscan_engine",
            target="example.test",
            authorized=True,
        )
        session.add(scan_engine)
        session.flush()
        session.add(
            Finding(
                scan_id=scan_engine.id,
                title="En-tête Content-Security-Policy absent",
                category="security_misconfiguration",
                severity="info",
                status=FindingStatus.CONFIRMED,
                confidence_score=0.95,
            )
        )
        session.commit()

        # Les résultats importés sont volontairement Confirmés manuellement
        # (RF-12), avec le score 0,95 que pose `correct_status_manually` :
        # aucune exécution de corrélation ne doit toucher ni statut ni score.
        for imported in imported_list:
            imported.confidence_score = 0.95
            change_status(
                session,
                imported,
                FindingStatus.CONFIRMED,
                changed_by="analyste",
                reason="Vérifié manuellement sur la cible.",
            )

        updated = run_correlation(session, target="example.test")

        # La corrélation n'a rien à traiter : aucun re-scoring des Confirmée.
        assert updated == []

        for finding in session.query(Finding).all():
            assert finding.status == FindingStatus.CONFIRMED
            assert finding.confidence_score == 0.95


def test_correlation_excludes_active_scan_source_from_updated_count() -> None:
    """Un résultat du scan actif au statut Probable (non encore confirmé)
    reste hors périmètre de la corrélation : elle ne concerne que les
    résultats importés de scanners externes."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")
        scan_engine = Scan(
            scan_type=ScanType.ACTIVE_SCAN,
            source="tscan_engine",
            target="example.test",
            authorized=True,
        )
        session.add(scan_engine)
        session.flush()
        session.add(
            Finding(
                scan_id=scan_engine.id,
                title="Résultat du scan Tscan",
                category="xss",
                severity="high",
                status=FindingStatus.PROBABLE,
            )
        )
        session.commit()

        updated = run_correlation(session, target="example.test")

        # Seuls les 2 résultats ZAP importés sont traités, pas le scan actif.
        assert len(updated) == 2
        assert all(f.scan.source != "tscan_engine" for f in updated)
