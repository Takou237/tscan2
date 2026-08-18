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
from tscan_core.models import Finding, FindingStatus

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

        # 3. Tous les résultats ont désormais un score et un statut décidés
        #    automatiquement (Probable ou Potentiel faux positif -- jamais
        #    Confirmée/Faux positif sans confirmation active ou correction
        #    manuelle, cf. chapitre 15).
        for finding in updated:
            assert finding.confidence_score is not None
            assert 0.0 <= finding.confidence_score <= 1.0
            assert finding.status in (FindingStatus.PROBABLE, FindingStatus.POTENTIAL_FALSE_POSITIVE)
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

        # 5. Un résultat à source unique (ex : en-tête manquant, uniquement Nuclei)
        #    doit exister sans le bonus multi-source dans son explication.
        misconfig = next(f for f in updated if f.category == "security_misconfiguration")
        explanation = json.loads(misconfig.score_explanation)
        assert not any("Corroboré par" in line for line in explanation)


def test_scenario_a_is_idempotent_and_keeps_history() -> None:
    """Relancer la corrélation ne doit pas dupliquer les Finding, et doit
    conserver l'historique des statuts plutôt que l'écraser."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")

        run_correlation(session, target="example.test")
        run_correlation(session, target="example.test")

        assert session.query(Finding).count() == 2
        finding = session.query(Finding).first()
        assert len(finding.status_history) == 2  # une entrée par exécution
