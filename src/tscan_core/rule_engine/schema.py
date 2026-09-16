"""Schéma des règles de détection et de validation (chapitre 7, RF-13).

`RuleDefinition` est la représentation en mémoire d'une règle chargée depuis
un fichier YAML du dossier `rules/` (à la racine du dépôt, distincte du
paquet Python `tscan_core.rule_engine`). Cette séparation entre le fichier
source (YAML, modifiable sans toucher au code), sa représentation en mémoire
(cette classe) et sa trace en base (`tscan_core.models.Rule`, métadonnées
seulement) est ce qui matérialise la décision d'architecture du chapitre 10 :
Moteur ≠ Règles.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RuleDefinition:
    id: str
    name: str
    category: str
    severity: str
    version: str
    description: str

    detection_keywords: list[str] = field(default_factory=list)

    validation_method: str = "passive"
    validation_description: str = ""

    evidence_expected: list[str] = field(default_factory=list)
    recommendation: str = ""
    references: list[str] = field(default_factory=list)

    confidence_base: float = 0.5
    confidence_multi_source_bonus: float = 0.2

    checks: list[dict] = field(default_factory=list)
    """Checks déclaratifs de la règle (section `checks:` du YAML, semaine 7b) :
    conditions simples évaluées par le moteur de scan sur les réponses HTTP
    (header_absent, clickjacking, path_status). Vide si la règle ne porte
    aucun check (ex : XSS/CSRF, évalués en code à partir de la semaine 8)."""

    source_file: str = ""
    """Chemin du fichier YAML d'origine, renseigné par le chargeur."""
