"""Service d'orchestration du bloc corrélation/validation/scoring (semaines 5-6).

`run_correlation` est le point d'entrée unique appelé par la CLI (commande
`tscan correlate`) : il assemble dans l'ordre les briques déjà testées
séparément (chargement des règles, corrélation multi-sources, scoring,
changement de statut avec historique), et persiste le résultat sur chaque
`Finding` concerné.

Comme pour `importers/service.py`, c'est volontairement le seul module qui
connaît à la fois les règles, la corrélation, le scoring et la persistance :
chaque brique individuelle (`rule_engine`, `correlation.matcher`,
`correlation.scoring`, `status`) reste utilisable et testable indépendamment.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from tscan_core.correlation.matcher import CorrelationGroup, correlate
from tscan_core.correlation.scoring import score_finding
from tscan_core.models import Finding
from tscan_core.rule_engine import load_rules, sync_rules_to_db
from tscan_core.status import AUTOMATIC_ACTOR, change_status


def run_correlation(session: Session, target: str | None = None) -> list[Finding]:
    """Exécute la corrélation et le scoring sur les résultats en base.

    Si `target` est fourni, seuls les résultats des scans portant sur cette
    cible sont traités ; sinon, tous les résultats non encore corrélés sont
    repris. Retourne la liste des `Finding` mis à jour.

    Ré-exécuter cette fonction sur des résultats déjà traités est sans
    risque : chaque exécution recalcule le score à partir de l'état actuel
    des règles et de la corrélation, et journalise un nouveau changement de
    statut dans l'historique plutôt que d'écraser silencieusement le
    précédent (RF-12 / ES-06).
    """
    rules = load_rules()
    sync_rules_to_db(session, rules)
    rules_by_category = {rule.category: rule for rule in rules}

    query = session.query(Finding)
    if target is not None:
        query = query.join(Finding.scan).filter_by(target=target)
    findings = query.all()

    correlation_groups = correlate(findings)
    group_by_finding_id = _index_groups_by_finding(correlation_groups)

    updated: list[Finding] = []
    for finding in findings:
        group = group_by_finding_id.get(finding.id)
        result = score_finding(finding, rules_by_category, correlation_group=group)

        finding.confidence_score = result.score
        finding.score_explanation = json.dumps(result.explanation, ensure_ascii=False)
        if result.matched_rule_id is not None:
            finding.rule_id = result.matched_rule_id

        change_status(session, finding, result.status, changed_by=AUTOMATIC_ACTOR)
        updated.append(finding)

    return updated


def _index_groups_by_finding(groups: list[CorrelationGroup]) -> dict[int, CorrelationGroup]:
    index: dict[int, CorrelationGroup] = {}
    for group in groups:
        for finding in group.findings:
            index[finding.id] = group
    return index
