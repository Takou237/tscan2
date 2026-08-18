"""Corrélation multi-sources (RF-09).

Rapproche les résultats provenant de scans différents (donc potentiellement
de sources/outils différents) portant sur la même cible, lorsqu'ils
désignent probablement la même vulnérabilité sous-jacente : même catégorie,
et même emplacement observé (URL/endpoint), une fois cet emplacement
normalisé pour ignorer les différences insignifiantes (paramètres de requête,
barre oblique finale...).

Une corroboration par plusieurs sources indépendantes est un signal de
confiance fort (chapitre 4 : c'est précisément ce que les plateformes
d'agrégation étudiées ne font qu'à moitié). Ce module ne calcule pas de
score : il se contente d'identifier les groupes de résultats corroborés,
laissant au moteur de scoring (`scoring.py`) le soin de traduire cette
information en une valeur chiffrée.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from tscan_core.models import Finding


def normalize_location(matched_at: str | None, fallback_target: str) -> str:
    """Ramène une URL à une forme comparable : sans requête ni fragment, sans
    barre oblique finale, en minuscules. Utilisée uniquement pour regrouper
    des résultats probablement liés au même endroit, pas pour l'affichage.
    """
    value = matched_at or fallback_target
    parts = urlsplit(value)
    if not parts.scheme and not parts.netloc:
        # Pas une URL complète (ex: simple libellé de cible) : on la garde telle quelle.
        return value.strip().rstrip("/").lower()

    path = parts.path.rstrip("/")
    normalized = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "", ""))
    return normalized


@dataclass
class CorrelationGroup:
    """Un ensemble de `Finding` probablement liés à la même vulnérabilité
    sous-jacente, observés par une ou plusieurs sources."""

    category: str
    location: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def sources(self) -> set[str]:
        return {f.scan.source for f in self.findings if f.scan is not None}

    @property
    def is_multi_source(self) -> bool:
        return len(self.sources) > 1


def correlate(findings: list[Finding]) -> list[CorrelationGroup]:
    """Regroupe une liste de `Finding` (typiquement : tous ceux d'une même
    cible) par catégorie + emplacement normalisé."""
    groups: dict[tuple[str, str], CorrelationGroup] = {}

    for finding in findings:
        target = finding.scan.target if finding.scan is not None else ""
        location = normalize_location(finding.matched_at, target)
        key = (finding.category, location)

        if key not in groups:
            groups[key] = CorrelationGroup(category=finding.category, location=location)
        groups[key].findings.append(finding)

    return list(groups.values())


def group_multi_source_only(groups: list[CorrelationGroup]) -> list[CorrelationGroup]:
    """Filtre pour ne garder que les groupes corroborés par plusieurs sources
    distinctes -- pratique pour l'inspection manuelle ou les tests."""
    return [g for g in groups if g.is_multi_source]
