"""Tests de la translation produit/version -> CPE (RF-18).

Vérifie le parsing de la saisie utilisateur, le chargement de la table
d'alias versionnée et la construction du préfixe CPE. Aucun appel réseau
ici : l'interrogation NVD elle-même est testée dans test_nvd_client.py et
l'orchestration dans test_update_manager.py.
"""

from __future__ import annotations

from tscan_core.knowledge_base.cpe import (
    DEFAULT_ALIAS_FILE,
    build_cpe_prefix,
    load_cpe_aliases,
    resolve_cpe_alias,
    split_component_and_version,
)


def test_split_component_and_version_simple() -> None:
    assert split_component_and_version("jquery 1.11.0") == ("jquery", "1.11.0")


def test_split_component_and_version_product_with_spaces() -> None:
    assert split_component_and_version("apache http server 2.4.49") == (
        "apache http server",
        "2.4.49",
    )


def test_split_component_and_version_without_version() -> None:
    """Dernier jeton non numérique : pas de version (repli mot-clé)."""
    assert split_component_and_version("apache http server") == ("apache http server", None)


def test_split_component_and_version_lowercases_product() -> None:
    assert split_component_and_version("jQuery 1.11.0") == ("jquery", "1.11.0")


def test_split_component_and_version_empty_input() -> None:
    assert split_component_and_version("  ") == ("", None)


def test_split_component_and_version_single_token() -> None:
    assert split_component_and_version("wordpress") == ("wordpress", None)


def test_default_alias_file_exists_and_contains_verified_products() -> None:
    aliases = load_cpe_aliases()
    assert DEFAULT_ALIAS_FILE.exists()
    assert {"jquery", "apache", "wordpress", "nginx"} <= set(aliases)


def test_resolve_cpe_alias_known_product() -> None:
    aliases = load_cpe_aliases()
    alias = resolve_cpe_alias("jquery", aliases)
    assert alias is not None
    assert (alias.vendor, alias.product) == ("jquery", "jquery")


def test_resolve_cpe_alias_unknown_product_returns_none() -> None:
    aliases = load_cpe_aliases()
    assert resolve_cpe_alias("composant-inconnu", aliases) is None


def test_resolve_cpe_alias_joomla_escaped_name() -> None:
    """Le nom CPE officiel de Joomla contient un '!' littéral (vérifié contre
    l'API cpes/2.0) : il doit être conservé tel quel dans l'alias."""
    aliases = load_cpe_aliases()
    alias = resolve_cpe_alias("joomla", aliases)
    assert alias is not None
    assert (alias.vendor, alias.product) == ("joomla", "joomla\\!")


def test_build_cpe_prefix() -> None:
    aliases = load_cpe_aliases()
    alias = resolve_cpe_alias("jquery", aliases)
    assert alias is not None
    assert build_cpe_prefix(alias, "1.11.0") == "cpe:2.3:a:jquery:jquery:1.11.0"


def test_build_cpe_prefix_joomla_keeps_escaped_exclamation() -> None:
    aliases = load_cpe_aliases()
    alias = resolve_cpe_alias("joomla", aliases)
    assert alias is not None
    assert build_cpe_prefix(alias, "4.2.0") == "cpe:2.3:a:joomla:joomla\\!:4.2.0"
