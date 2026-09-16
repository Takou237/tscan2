"""Traduction des noms de composants courants vers le référentiel CPE (RF-18).

La correspondance version -> CVE (RF-18 : composants logiciels vulnérables
connus) repose sur l'identifiant CPE (Common Platform Enumeration) : NVD
référence chaque produit sous un identifiant structuré
(ex : cpe:2.3:a:jquery:jquery:1.11.0), et chaque CVE est liée aux CPE
exactement concernés. La recherche NVD par mot-clé, utilisée en repli, ne
permet pas cette correspondance fiable : les descriptions de CVE ne
contiennent que rarement la chaîne exacte "produit version" (constat vérifié
contre l'API réelle, août 2026).

Ce module ne fait aucun appel réseau : il sépare la saisie de l'utilisateur
en (produit, version) et résout les alias via le fichier versionné
`knowledge/cpe_aliases.yaml`, au même principe que la table CWE
(`cwe_reference.py`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_ALIAS_FILE = Path(__file__).resolve().parents[3] / "knowledge" / "cpe_aliases.yaml"

_VERSION_START_RE = re.compile(r"^\d")


@dataclass(frozen=True)
class CpeAlias:
    """Référence CPE d'un produit : vendeur et produit (cpe:2.3:a:<vendor>:<product>)."""

    vendor: str
    product: str


def split_component_and_version(component_query: str) -> tuple[str, str | None]:
    """Sépare la saisie "produit version" (ex : "jquery 1.11.0").

    Le dernier jeton est considéré comme une version s'il commence par un
    chiffre ; sinon la saisie entière est traitée comme un nom de produit
    sans version (ex : "apache http server"). Le nom de produit est retourné
    en minuscules pour une résolution d'alias insensible à la casse.
    """
    stripped = component_query.strip()
    if not stripped:
        return "", None

    tokens = stripped.split()
    if len(tokens) > 1 and _VERSION_START_RE.match(tokens[-1]):
        return " ".join(tokens[:-1]).lower(), tokens[-1]

    return stripped.lower(), None


def load_cpe_aliases(alias_file: Path | str = DEFAULT_ALIAS_FILE) -> dict[str, CpeAlias]:
    """Charge la table d'alias, indexée par nom de produit courant."""
    with Path(alias_file).open("r", encoding="utf-8") as handle:
        raw_entries = yaml.safe_load(handle) or []

    return {
        entry["product"]: CpeAlias(
            vendor=entry["cpe"].split(":", 1)[0], product=entry["cpe"].split(":", 1)[1]
        )
        for entry in raw_entries
    }


def resolve_cpe_alias(product: str, aliases: dict[str, CpeAlias]) -> CpeAlias | None:
    """Retourne l'alias CPE d'un nom de produit, ou None s'il est inconnu."""
    return aliases.get(product.strip().lower())


def build_cpe_prefix(alias: CpeAlias, version: str) -> str:
    """Construit le préfixe CPE utilisé pour l'interrogation NVD.

    Le résultat (ex : cpe:2.3:a:jquery:jquery:1.11.0) correspond au paramètre
    `cpeName` de l'API cves/2.0 : NVD le fait correspondre aux CPE du
    dictionnaire et retourne les CVE liées à cette version exacte.
    """
    return f"cpe:2.3:a:{alias.vendor}:{alias.product}:{version}"
