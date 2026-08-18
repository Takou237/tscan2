"""Moteur de scoring de confiance (RF-10).

Calcule un score de confiance entre 0 et 1 pour un `Finding`, à partir de
trois facteurs, chacun consigné en texte dans l'explication retournée :

1. le score de base de la règle qui correspond à la catégorie du résultat
   (`confidence.base_score` du fichier YAML) ;
2. un bonus si le résultat est corroboré par plusieurs sources indépendantes
   (RF-09), dont l'ampleur est définie par la règle elle-même
   (`confidence.multi_source_bonus`) ;
3. une pénalité si le pré-filtrage contextuel (RF-08) a détecté des
   anomalies.

Le score, une fois calculé, est traduit en statut de validation (RF-07).
Décision assumée pour le MVP (documentée au chapitre 15, limites explicites) :
un résultat importé ne peut pas se voir attribuer automatiquement le statut
"Confirmée" ni "Faux positif" -- ces deux statuts nécessitent soit une
confirmation active (moteur de scan, semaines 7-8), soit une décision
humaine explicite (RF-12). Le scoring automatique se limite donc à
distinguer "Probable" de "Potentiel faux positif".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tscan_core.correlation.matcher import CorrelationGroup
from tscan_core.correlation.prefilter import prefilter
from tscan_core.models import Finding, FindingStatus
from tscan_core.rule_engine.schema import RuleDefinition

# Seuil au-delà duquel un résultat est jugé suffisamment plausible pour
# mériter une revue humaine prioritaire plutôt qu'un tri en fin de liste.
PROBABLE_THRESHOLD = 0.55


@dataclass
class ScoringResult:
    score: float
    status: FindingStatus
    explanation: list[str] = field(default_factory=list)
    matched_rule_id: str | None = None


def score_finding(
    finding: Finding,
    rules_by_category: dict[str, RuleDefinition],
    correlation_group: CorrelationGroup | None,
) -> ScoringResult:
    """Calcule le score de confiance d'un résultat et le statut qui en découle.

    `rules_by_category` permet de retrouver la règle applicable à la
    catégorie du résultat. `correlation_group` est le groupe de corrélation
    (RF-09) auquel ce résultat appartient, s'il en existe un.
    """
    explanation: list[str] = []
    rule = rules_by_category.get(finding.category)

    if rule is not None:
        score = rule.confidence_base
        explanation.append(
            f"Score de base de la règle {rule.id} ({rule.name}) : {rule.confidence_base:.2f}"
        )
    else:
        score = 0.3
        explanation.append(
            "Aucune règle ne correspond à cette catégorie : score de base prudent (0.30)"
        )

    if correlation_group is not None and correlation_group.is_multi_source:
        bonus = rule.confidence_multi_source_bonus if rule is not None else 0.2
        score += bonus
        sources = ", ".join(sorted(correlation_group.sources))
        explanation.append(
            f"Corroboré par {len(correlation_group.sources)} sources indépendantes "
            f"({sources}) : bonus de {bonus:.2f}"
        )

    prefilter_result = prefilter(finding)
    if prefilter_result.score_penalty:
        score -= prefilter_result.score_penalty
        for issue in prefilter_result.issues:
            explanation.append(f"Pré-filtrage : {issue} (pénalité appliquée)")

    score = max(0.0, min(1.0, score))

    status = FindingStatus.PROBABLE if score >= PROBABLE_THRESHOLD else FindingStatus.POTENTIAL_FALSE_POSITIVE
    explanation.append(
        f"Score final {score:.2f} -> statut "
        f"{'Probable' if status == FindingStatus.PROBABLE else 'Potentiel faux positif'} "
        f"(seuil : {PROBABLE_THRESHOLD})"
    )

    return ScoringResult(
        score=score,
        status=status,
        explanation=explanation,
        matched_rule_id=rule.id if rule is not None else None,
    )
