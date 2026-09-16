"""Tests du fichier de signatures de fingerprinting (RF-16).

Vérifie que le fichier versionné `knowledge/technologies.yaml` est bien
formé et cohérent avec la table d'alias CPE : une signature qui référence un
alias absent produirait une technologie détectable mais non résolvable en
CVE lors de la détection des composants vulnérables (RF-18).
"""

from __future__ import annotations

import yaml

from tscan_core.knowledge_base.cpe import load_cpe_aliases
from tscan_core.recon.fingerprint import (
    DEFAULT_TECHNOLOGIES_FILE,
    load_technologies,
)


def test_default_technologies_file_exists_and_loads() -> None:
    assert DEFAULT_TECHNOLOGIES_FILE.exists()
    technologies = load_technologies()
    assert len(technologies) >= 10


def test_each_technology_has_required_fields() -> None:
    technologies = load_technologies()
    for technology in technologies:
        assert technology.name
        assert technology.label
        assert technology.matchers, f"{technology.name} n'a aucun matcher"
        for matcher in technology.matchers:
            assert matcher.pattern, f"{technology.name} : pattern vide"
            assert (matcher.header is not None) != matcher.body, (
                f"{technology.name} : matcher ni header ni body (ou les deux)"
            )


def test_matchers_are_valid_regexes() -> None:
    import re

    technologies = load_technologies()
    for technology in technologies:
        for matcher in technology.matchers:
            re.compile(matcher.pattern)  # lève re.error si invalide


def test_cpe_aliases_referenced_by_signatures_exist() -> None:
    aliases = load_cpe_aliases()
    technologies = load_technologies()
    referenced = {t.cpe_alias for t in technologies if t.cpe_alias}
    assert referenced <= set(aliases), f"Aliases CPE inconnus : {referenced - set(aliases)}"


def test_yaml_entries_are_list_of_mappings() -> None:
    with DEFAULT_TECHNOLOGIES_FILE.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    assert isinstance(raw, list) and all(isinstance(entry, dict) for entry in raw)