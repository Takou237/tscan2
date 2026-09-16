"""Chargeur des règles de détection et de validation (RF-13).

Lit tous les fichiers YAML d'un dossier de règles et les convertit en
`RuleDefinition`. La synchronisation avec la table `Rule` de la base ne
copie que des métadonnées (identifiant, nom, catégorie, gravité, version,
chemin du fichier) : le contenu complet de la règle continue de vivre
uniquement dans le fichier YAML, conformément à la décision d'architecture
du chapitre 10.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from tscan_core.models import Rule
from tscan_core.rule_engine.schema import RuleDefinition

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"


class RuleLoadError(Exception):
    """Levée lorsqu'un fichier de règle est présent mais mal formé."""


def load_rules(rules_dir: Path | str = DEFAULT_RULES_DIR) -> list[RuleDefinition]:
    """Charge toutes les règles `*.yaml` d'un dossier.

    Un fichier de règle mal formé interrompt le chargement avec une erreur
    explicite plutôt que d'être silencieusement ignoré : une règle de
    détection de sécurité qui échoue à se charger sans que personne ne le
    remarque est un risque, pas un détail.
    """
    rules_dir = Path(rules_dir)
    rules: list[RuleDefinition] = []

    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        try:
            with yaml_file.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            rules.append(_to_rule_definition(data, yaml_file))
        except (yaml.YAMLError, KeyError, TypeError) as exc:
            raise RuleLoadError(f"Règle mal formée dans {yaml_file} : {exc}") from exc

    return rules


def _to_rule_definition(data: dict, source_file: Path) -> RuleDefinition:
    detection = data.get("detection", {}) or {}
    validation = data.get("validation", {}) or {}
    confidence = data.get("confidence", {}) or {}

    return RuleDefinition(
        id=data["id"],
        name=data["name"],
        category=data["category"],
        severity=data["severity"],
        version=data["version"],
        description=data.get("description", "").strip(),
        detection_keywords=list(detection.get("keywords", [])),
        validation_method=validation.get("method", "passive"),
        validation_description=validation.get("description", "").strip(),
        evidence_expected=list(data.get("evidence_expected", [])),
        recommendation=data.get("recommendation", "").strip(),
        references=list(data.get("references", [])),
        confidence_base=float(confidence.get("base_score", 0.5)),
        confidence_multi_source_bonus=float(confidence.get("multi_source_bonus", 0.2)),
        checks=list(data.get("checks", []) or []),
        source_file=str(source_file),
    )


def sync_rules_to_db(session: Session, rules: list[RuleDefinition]) -> None:
    """Met à jour la table `Rule` (métadonnées uniquement) à partir des
    règles chargées en mémoire. Insère les règles nouvelles, met à jour
    celles déjà connues, sans jamais dupliquer le contenu de la règle."""
    for rule_def in rules:
        existing = session.get(Rule, rule_def.id)
        if existing is None:
            session.add(
                Rule(
                    id=rule_def.id,
                    name=rule_def.name,
                    category=rule_def.category,
                    severity=rule_def.severity,
                    version=rule_def.version,
                    file_path=rule_def.source_file,
                )
            )
        else:
            existing.name = rule_def.name
            existing.category = rule_def.category
            existing.severity = rule_def.severity
            existing.version = rule_def.version
            existing.file_path = rule_def.source_file
    session.commit()
