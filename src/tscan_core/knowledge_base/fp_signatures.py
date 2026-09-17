"""Signatures de reconnaissance des faux positifs (RF-12, validation croisée).

Un constat automatique peut être trompé par des réponses HTTP légitimes qui
ressemblent à une vulnérabilité : la plus classique est la ressource sensible
protégée par une redirection vers une page de connexion (WordPress répond
302 /wp-admin/ -> /wp-login.php — le vérificateur `is_path_exposed` du bloc
checks consulte ces signatures pour ne pas la compter comme une exposition).

Les signatures vivent dans le fichier versionné `knowledge/fp_signatures.yaml`,
au même principe que les tables d'alias CPE (`cpe.py`) et de référence CWE
(`cwe_reference.py`) : elles s'étendent sans toucher au code. Ce module ne
fait aucun appel réseau.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_FP_SIGNATURES_FILE = (
    Path(__file__).resolve().parents[3] / "knowledge" / "fp_signatures.yaml"
)


class FpSignaturesError(Exception):
    """Levée lorsque le fichier de signatures de faux positifs est mal formé.

    Au même principe que les autres chargeurs du cœur : une table de
    connaissances invalide doit interrompre l'évaluation avec une erreur
    explicite, pas être ignorée en silence (un check de sécurité qui échoue
    en silence est un risque, pas un détail).
    """


@dataclass(frozen=True)
class FpSignatureCategory:
    """Une catégorie de signatures (ex : pages d'authentification).

    `path_markers` est une liste de fragments (minuscules) recherchés en
    sous-chaîne du chemin de la page de destination.
    """

    id: str
    label: str
    description: str = ""
    path_markers: tuple[str, ...] = ()


def load_fp_signatures(
    signatures_file: Path | str = DEFAULT_FP_SIGNATURES_FILE,
) -> dict[str, FpSignatureCategory]:
    """Charge les catégories de signatures, indexées par identifiant.

    Lève `FpSignaturesError` si le fichier est mal formé : identifiant
    dupliqué, catégorie sans `id`/`label`, fragments vides ou non textuels.
    """
    with Path(signatures_file).open("r", encoding="utf-8") as handle:
        raw_entries = yaml.safe_load(handle) or []

    if not isinstance(raw_entries, list) or not all(
        isinstance(entry, dict) for entry in raw_entries
    ):
        raise FpSignaturesError(
            f"{signatures_file} : une liste de catégories (mappings) est attendue."
        )

    categories: dict[str, FpSignatureCategory] = {}
    for entry in raw_entries:
        category_id = entry.get("id")
        label = entry.get("label")
        if not isinstance(category_id, str) or not category_id.strip():
            raise FpSignaturesError(
                f"{signatures_file} : catégorie sans 'id' (label={label!r})."
            )
        if category_id in categories:
            raise FpSignaturesError(
                f"{signatures_file} : identifiant de catégorie dupliqué '{category_id}'."
            )
        if not isinstance(label, str) or not label.strip():
            raise FpSignaturesError(
                f"{signatures_file} : catégorie {category_id} sans 'label'."
            )
        markers = entry.get("path_markers") or []
        if not isinstance(markers, list) or not all(
            isinstance(marker, str) and marker.strip() for marker in markers
        ):
            raise FpSignaturesError(
                f"{signatures_file} : catégorie {category_id} : 'path_markers' "
                "doit être une liste de fragments non vides."
            )
        categories[category_id] = FpSignatureCategory(
            id=category_id,
            label=label,
            description=str(entry.get("description") or ""),
            path_markers=tuple(marker.lower() for marker in markers),
        )
    return categories


def get_category(
    signatures: dict[str, FpSignatureCategory], category_id: str
) -> FpSignatureCategory | None:
    """Retourne une catégorie par identifiant, ou None si absente.

    Une catégorie manquante (fichier restreint ou version ancienne) ne
    lève pas d'erreur : le consommateur conserve son comportement par
    défaut (aucune signature de la catégorie considérée).
    """
    return signatures.get(category_id)
