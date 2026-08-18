"""Pré-filtrage contextuel (RF-08).

Ce module applique des vérifications de cohérence sur un `Finding` avant
toute corrélation ou tout scoring, afin d'écarter tôt les indices
manifestement peu fiables plutôt que de les faire remonter tels quels dans
le score de confiance final.

Portée assumée pour ce bloc (semaines 5-6) : uniquement des vérifications
hors-ligne, applicables à des résultats importés. Le pré-filtrage complet
imaginé au chapitre 4 de l'étude de l'existant (vérifier qu'un service est
réellement actif, comparer une version observée en direct) suppose une
requête réseau vers la cible ; cette capacité n'existe pas avant le bloc
reconnaissance du scan actif (semaines 7-8). L'exiger maintenant violerait
l'exigence de fonctionnement hors-ligne des fonctions d'import et de
corrélation (RNF-14). Ce module sera étendu, pas réécrit, une fois la
reconnaissance active disponible.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tscan_core.models import Finding

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_CATEGORIES = {
    "security_misconfiguration",
    "vulnerable_component",
    "xss",
    "broken_access_control",
    "csrf",
    "sqli",
    "other",
}


@dataclass
class PrefilterResult:
    """Résultat du pré-filtrage : les anomalies constatées, et un ajustement
    de score (négatif) à appliquer par le moteur de scoring en conséquence."""

    issues: list[str] = field(default_factory=list)
    score_penalty: float = 0.0

    @property
    def is_consistent(self) -> bool:
        return not self.issues


def prefilter(finding: Finding) -> PrefilterResult:
    """Applique les vérifications de cohérence à un résultat.

    Chaque anomalie détectée est à la fois consignée en texte (pour
    l'explication du score, RF-10) et traduite en une pénalité chiffrée
    modeste : une seule anomalie mineure ne doit pas suffire à écarter un
    résultat par ailleurs plausible, mais doit peser dans le score final.
    """
    result = PrefilterResult()

    if not finding.title or not finding.title.strip():
        result.issues.append("Titre du résultat vide ou manquant")
        result.score_penalty += 0.2

    if finding.severity not in _VALID_SEVERITIES:
        result.issues.append(f"Gravité non reconnue : {finding.severity!r}")
        result.score_penalty += 0.1

    if finding.category not in _VALID_CATEGORIES:
        result.issues.append(f"Catégorie non reconnue : {finding.category!r}")
        result.score_penalty += 0.1

    if finding.category == "other":
        result.issues.append(
            "Résultat non rattaché à une famille du MVP : aucune règle ne s'y applique"
        )
        result.score_penalty += 0.15

    if not finding.raw_result:
        result.issues.append("Résultat brut d'origine absent (contrevient à ES-07)")
        result.score_penalty += 0.1

    return result
