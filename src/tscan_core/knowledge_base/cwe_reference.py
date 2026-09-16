"""Chargement de la table de référence CWE minimale (RF-33).

Contrairement à `nvd_client` et `kev_client`, ce module ne fait aucun appel
réseau : la table est un petit fichier YAML statique versionné dans le dépôt
(`knowledge/cwe_reference.yaml`), au même principe que les règles de
détection (`rules/`), mais pour des données de référence plutôt que des
règles.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_CWE_FILE = Path(__file__).resolve().parents[3] / "knowledge" / "cwe_reference.yaml"


@dataclass
class CweEntry:
    id: str
    name: str
    category: str


def load_cwe_reference(cwe_file: Path | str = DEFAULT_CWE_FILE) -> dict[str, CweEntry]:
    """Charge la table de référence CWE, indexée par identifiant (ex: 'CWE-79')."""
    with Path(cwe_file).open("r", encoding="utf-8") as handle:
        raw_entries = yaml.safe_load(handle) or []

    return {
        entry["id"]: CweEntry(id=entry["id"], name=entry["name"], category=entry["category"])
        for entry in raw_entries
    }
