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

Semaine 12 — Corrections comportementales :
- Les résultats du scan actif Tscan (`tscan_engine`) sont inclus dans les
  groupes de corrélation pour la détection multi-source (RF-09), mais ne
  sont pas re-scorés : ils conservent leur score issu de la détection et
  de la re-vérification active (RF-23).
- Le scoring ne dégrade jamais un constat vers « Potentiel faux positif » :
  un constat `unvalidated` avec un score bas reste en attente de revue
  analyste. Seul un upgrade vers `PROBABLE` (score ≥ seuil) est appliqué.
  PFP requiert une preuve de contradiction (ré-observation RF-23, re-
  vérification active, ou décision analyste RF-12).
- Option `reobserve=True` : la corrélation déclenche, en plus du scoring,
  une ré-observation ciblée par URL des constats importés **non corroborés**
  par un constat du scan actif présent en base. Une ressource introuvable
  (404/410) — preuve de contradiction (RF-23) — place le constat en
  « potentiel faux positif » avant tout scoring. L'opération est best-effort :
  une panne réseau laisse le constat tel quel (note en base) et le scoring
  statique reprend normalement.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from tscan_core.correlation.matcher import CorrelationGroup, correlate
from tscan_core.correlation.scoring import score_finding
from tscan_core.models import Finding, FindingStatus
from tscan_core.rule_engine import load_rules, sync_rules_to_db
from tscan_core.rule_engine.schema import RuleDefinition
from tscan_core.status import AUTOMATIC_ACTOR, change_status

# Source du moteur de scan actif : les résultats qu'il produit sont
# déjà validés par la confirmation active non destructive (RF-23) dans le scan
# lui-même. La corrélation ne s'applique qu'aux résultats importés de scanners
# externes (Nuclei, ZAP, Nessus/OpenVAS), qui n'ont aucune validation active.
ENGINE_SCAN_SOURCE = "tscan_engine"


def run_correlation(
    session: Session,
    target: str | None = None,
    reobserve: bool = False,
    http_client=None,
) -> list[Finding]:
    """Exécute la corrélation et le scoring sur les résultats importés en base.

    Si `target` est fourni, seuls les résultats des scans portant sur cette
    cible sont traités ; sinon, tous les résultats éligibles sont repris.

    `reobserve=True` déclenche en plus une **ré-observation ciblée par URL**
    des constats importés non corroborés : la disponibilité de la ressource
    (404/410 → contradiction, constat placé en « potentiel faux positif »)
    fait foi avant le scoring statique. L'opération est best-effort : une
    panne réseau laisse le constat tel quel (note en base) et le scoring
    reprend. `http_client` sert aux tests (client HTTPS simulé) ; sans lui,
    un client réseau standard est créé.

    Retourne la liste des `Finding` mis à jour.

    Périmètre (semaine 12, correctif rapport d'essai 11/09/2026) :
    - les résultats du **scan actif Tscan** (source `tscan_engine`) ne sont
      pas re-scorés — ils conservent leur score issu de la détection et de la
      re-vérification non destructive (RF-23). Ils sont cependant inclus dans
      les groupes de corrélation pour la détection multi-source (RF-09) :
      si un constat importé est corroboré par un constat du scan actif sur la
      même vulnérabilité, il bénéficie du bonus multi-source ;
    - un résultat portant déjà un **verdict** n'est jamais re-scoré ni changé
      de statut : `Confirmée` ou `Faux positif` (décision d'analyste, RF-12) et
      `Potentiel faux positif` (contradiction prouvée par la ré-observation
      RF-23, la re-vérification active, ou une décision d'analyste). La
      corrélation classe des résultats **en attente de validation** — elle ne
      retire jamais un verdict acquis ;
    - le scoring ne dégrade jamais un constat vers « Potentiel faux positif » :
      un constat `unvalidated` dont le score est inférieur au seuil reste
      `unvalidated` (en attente de revue analyste). **Seul un constat
      `unvalidated`** dont le score est ≥ seuil est upgradé vers `PROBABLE`.
      FFP / PFP requièrent une preuve (ré-observation, re-vérification active,
      ou décision analyste — RF-12 / RF-23) ;
    - avec `reobserve=True`, un constat importé non corroboré dont la
      ressource a disparu (404/410) est placé en « potentiel faux positif »
      par la ré-observation ciblée (preuve de contradiction, RF-23).

    Ré-exécuter cette fonction sur des résultats déjà traités est sans
    risque : chaque exécution recalcule le score à partir de l'état actuel
    des règles et de la corrélation, et journalise un nouveau changement de
    statut dans l'historique plutôt que d'écraser silencieusement le
    précédent (RF-12 / ES-06).
    """
    rules = load_rules()
    sync_rules_to_db(session, rules)
    rules_by_category: dict[str, list[RuleDefinition]] = {}
    for rule in rules:
        rules_by_category.setdefault(rule.category, []).append(rule)
    rules_by_id = {rule.id: rule for rule in rules}

    query = session.query(Finding)
    if target is not None:
        query = query.join(Finding.scan).filter_by(target=target)
    all_findings = query.all()

    # Exclusion des verdicts (RF-07, RF-12, RF-23) : « Confirmée », « Faux
    # positif » et « Potentiel faux positif » sont des décisions — humaines pour
    # les deux premières, fondées sur une contradiction démontrée pour la
    # troisième. Aucune n'est jamais retirée ni re-scorée par un calcul
    # automatique : la corrélation ne classe que ce qui attend encore une
    # validation (`unvalidated` ou `probable` sans verdict).
    eligible = [
        f
        for f in all_findings
        if f.status
        not in {
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.POTENTIAL_FALSE_POSITIVE,
        }
    ]

    # Séparation importés / scan actif : les importés seront scorés, les
    # résultats du scan actif servent uniquement à la détection multi-source.
    non_engine = [
        f for f in eligible if f.scan is None or f.scan.source != ENGINE_SCAN_SOURCE
    ]
    engine = [
        f
        for f in eligible
        if f.scan is not None and f.scan.source == ENGINE_SCAN_SOURCE
    ]

    # Corrélation multi-source (RF-09) : les deux ensembles sont mélangés
    # pour la formation des groupes, afin qu'un constat importé corroboré par
    # un constat du scan actif sur la même vulnérabilité bénéficie du bonus
    # de confiance multi-source.
    correlation_groups = correlate(non_engine + engine)
    group_by_finding_id = _index_groups_by_finding(correlation_groups)
    engine_ids = {f.id for f in engine}

    # Client réseau de la ré-observation ciblée par URL (`reobserve=True`).
    # Sa création est différée dans le corps car la ré-observation est
    # optionnelle ; les tests injectent un client HTTPS simulé.
    client = None
    if reobserve:
        from tscan_core.recon.client import create_http_client

        client = http_client or create_http_client(verify_tls=True, request_delay=0.0)

    updated: list[Finding] = []
    for finding in non_engine:
        group = group_by_finding_id.get(finding.id)

        # Ré-observation ciblée (option `reobserve`) : pour un constat importé
        # NON corroboré par un constat du scan actif présent en base, la
        # disponibilité de la ressource fait foi avant le scoring statique.
        # Une ressource disparue (404/410) est une contradiction prouvée
        # (RF-23) : le constat passe en « potentiel faux positif » et échappe
        # au scoring. Best-effort : une panne réseau laisse le constat tel
        # quel (note en base) et le scoring reprend normalement.
        if (
            reobserve
            and not _group_has_active_scan_finding(group, engine_ids)
            and _reobserve_and_flag(session, finding, client)
        ):
            updated.append(finding)
            continue

        result = score_finding(
            finding, rules_by_category, correlation_group=group, rules_by_id=rules_by_id
        )

        finding.confidence_score = result.score
        finding.score_explanation = json.dumps(result.explanation, ensure_ascii=False)
        if result.matched_rule_id is not None:
            finding.rule_id = result.matched_rule_id
        session.add(finding)

        # Upgrade UNIQUEMENT les constats encore en attente de validation
        # (`unvalidated`) vers PROBABLE — jamais un constat déjà `probable`
        # (aucun changement d'état nécessaire) ni un constat porteur d'un
        # verdict (`PFP`/`Confirmée`/`Faux positif`, exclus ci-dessus). Un
        # constat `unvalidated` dont le score est bas reste en attente de
        # revue analyste ; les verdicts de contradiction ne sont jamais
        # rétrogradés ni annulés par un calcul (RF-12 / RF-23).
        if (
            result.status == FindingStatus.PROBABLE
            and finding.status == FindingStatus.UNVALIDATED
        ):
            change_status(
                session, finding, FindingStatus.PROBABLE, changed_by=AUTOMATIC_ACTOR
            )
        updated.append(finding)

    session.commit()
    return updated


def _index_groups_by_finding(groups: list[CorrelationGroup]) -> dict[int, CorrelationGroup]:
    index: dict[int, CorrelationGroup] = {}
    for group in groups:
        for finding in group.findings:
            index[finding.id] = group
    return index


def _group_has_active_scan_finding(
    group: CorrelationGroup | None, engine_ids: set[int]
) -> bool:
    """Un constat importé est corroboré par le scan actif si son groupe de
    corrélation contient un constat de source `tscan_engine`. Dans ce cas, sa
    reproduction par le scan actif est déjà établie : inutile de le
    ré-observer par URL pendant la corrélation."""
    if group is None:
        return False
    return any(f.id in engine_ids for f in group.findings)


def _reobserve_and_flag(session: Session, finding: Finding, client) -> bool:
    """Ré-observation ciblée par URL d'un constat importé non corroboré.

    Retourne `True` si le fait décisif est CONTREDIT (ressource introuvable
    404/410) et que le constat a été placé en « potentiel faux positif » ; le
    constat échappe alors au scoring. Import différé au corps de fonction pour
    éviter le cycle d'import réciproque entre `correlation.service` et
    `importers.reobserve_service`.
    """
    from tscan_core.importers.reobserve_service import (  # import différé
        flag_potential_false_positive,
        targeted_reobserve,
    )

    contradicted = targeted_reobserve(session, finding, client)
    if contradicted:
        flag_potential_false_positive(session, finding)
    return contradicted
