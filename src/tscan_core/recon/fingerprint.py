"""Fingerprinting des technologies de la cible (RF-16).

Applique les signatures passives de `knowledge/technologies.yaml` à la
réponse de la cible (en-têtes et corps), sans aucun test actif. Le fichier de
signatures est versionné dans le dépôt et extensible sans toucher au code,
au même principe que les règles de détection et la table d'alias CPE.

Les technologies détectées alimentent ensuite la base de connaissances pour
la détection des composants vulnérables connus (RF-18, semaine 7) : une
fausse détection y produirait aussi un faux résultat, c'est pourquoi les
signatures sont volontairement restrictives (voir le fichier de signatures).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_TECHNOLOGIES_FILE = Path(__file__).resolve().parents[3] / "knowledge" / "technologies.yaml"


class FingerprintError(Exception):
    """Levée lorsque le fichier de signatures est présent mais mal formé."""


@dataclass(frozen=True)
class TechnologyMatcher:
    """Une signature de détection : en-tête HTTP ou motif dans le corps."""

    pattern: str
    header: str | None = None
    body: bool = False


@dataclass(frozen=True)
class Technology:
    """Une technologie détectable et ses signatures."""

    name: str
    label: str
    cpe_alias: str | None
    matchers: list[TechnologyMatcher] = field(default_factory=list)


@dataclass(frozen=True)
class TechnologyMatch:
    """Résultat d'une détection : une technologie et la preuve de détection."""

    name: str
    label: str
    version: str | None
    cpe_alias: str | None
    source: str


def load_technologies(
    technologies_file: Path | str = DEFAULT_TECHNOLOGIES_FILE,
) -> list[Technology]:
    """Charge le fichier de signatures et le convertit en technologies.

    Une entrée mal formée interrompt le chargement avec une erreur explicite
    (même principe que le chargeur de règles : une signature de sécurité qui
    échoue en silence est un risque, pas un détail).
    """
    with Path(technologies_file).open("r", encoding="utf-8") as handle:
        raw_entries = yaml.safe_load(handle) or []

    technologies = []
    for entry in raw_entries:
        try:
            matchers = [
                _to_matcher(matcher)
                for matcher in entry.get("matchers", [])
            ]
            technologies.append(
                Technology(
                    name=entry["name"],
                    label=entry.get("label", entry["name"]),
                    cpe_alias=entry.get("cpe_alias"),
                    matchers=matchers,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise FingerprintError(
                f"Signature de technologie mal formée dans {technologies_file} : {exc}"
            ) from exc

    return technologies


def _to_matcher(raw: dict) -> TechnologyMatcher:
    if "header" in raw:
        return TechnologyMatcher(pattern=raw["pattern"], header=raw["header"])
    if "body" in raw:
        return TechnologyMatcher(pattern=raw["body"], body=True)
    raise ValueError(f"matcher sans clé 'header' ni 'body' : {raw}")


def fingerprint_response(
    headers: dict[str, str],
    body: str,
    technologies: list[Technology],
) -> list[TechnologyMatch]:
    """Applique les signatures à une réponse de la cible.

    Une technologie est détectée dès qu'une de ses signatures matche ; la
    première version trouvée (groupe 1 de la regex) est conservée. Le résultat
    est ordonné selon l'ordre du fichier de signatures.
    """
    matches: list[TechnologyMatch] = []

    for technology in technologies:
        for matcher in technology.matchers:
            compiled = re.compile(matcher.pattern)
            if matcher.header is not None:
                value = headers.get(matcher.header.lower())
                if value is None:
                    continue
                match = compiled.search(value)
                source = f"header:{matcher.header}"
            else:
                match = compiled.search(body)
                source = "body"

            if match is None:
                continue

            version = match.group(1) if match.lastindex and match.group(1) is not None else None
            matches.append(
                TechnologyMatch(
                    name=technology.name,
                    label=technology.label,
                    version=version,
                    cpe_alias=technology.cpe_alias,
                    source=source,
                )
            )
            break  # une seule détection par technologie

    return matches
