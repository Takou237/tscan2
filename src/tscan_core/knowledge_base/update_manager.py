"""Gestionnaire de mise à jour (chapitre 10, RF-34).

C'est le seul composant du cœur Tscan autorisé à effectuer des appels réseau
vers les sources externes de connaissances (CVE/NVD, CISA KEV). Tout le reste
du cœur -- corrélation, scoring, reporting -- ne lit que le cache local
(`tscan_core.knowledge_base.cache`), ce qui garantit structurellement le
respect de l'exigence de fonctionnement hors-ligne (RNF-14, RNF-15) : ces
fonctions n'ont tout simplement pas la capacité d'appeler le réseau, plutôt
que de s'en abstenir par convention.
"""

from __future__ import annotations

import httpx
from sqlalchemy.orm import Session

from tscan_core.knowledge_base import cache, cpe
from tscan_core.knowledge_base.kev_client import KevClientError, fetch_kev_catalog
from tscan_core.knowledge_base.nvd_client import (
    CveRecord,
    NvdClientError,
    search_cve_by_cpe,
    search_cve_by_keyword,
)
from tscan_core.models import CachedCve, KevEntry

DEFAULT_TIMEOUT_SECONDS = 15.0


class UpdateManagerError(Exception):
    """Erreur remontée par le gestionnaire de mise à jour (réseau ou format)."""


def lookup_component(
    session: Session,
    component_query: str,
    http_client: httpx.Client | None = None,
    allow_network: bool = True,
) -> list[CachedCve]:
    """Recherche les CVE connues pour un composant (ex : "jquery 1.11.0").

    Deux chemins, selon que le produit est reconnu dans la table d'alias CPE
    (`knowledge/cpe_aliases.yaml`) avec une version détectée :

    * alias connu + version -> correspondance CPE version -> CVE (RF-18),
      fiable, mise en cache sous une clé dédiée `cpe|vendeur:produit|version`
      (les entrées de cache issues de l'ancienne recherche par mot-clé ne
      s'appliquent donc pas à ce chemin) ;
    * sinon -> repli sur la recherche NVD par mot-clé, mise en cache sous la
      clé égale à la saisie (comportement historique).

    Dans les deux cas : vérification du cache local d'abord (RNF-14 :
      disponible hors-ligne). Si la requête n'a jamais été faite et que
      `allow_network` est vrai, interroge l'API NVD et met le résultat en
      cache pour les prochains appels -- y compris hors-ligne. Si
      `allow_network` est faux (mode explicitement hors-ligne) et que rien
      n'est en cache, retourne une liste vide plutôt que d'échouer :
      l'absence de connaissance sur un composant ne doit pas interrompre un
      scan.
    """
    product, version = cpe.split_component_and_version(component_query)
    alias = cpe.resolve_cpe_alias(product, cpe.load_cpe_aliases())

    if alias is not None and version is not None:
        cache_key = f"cpe|{alias.vendor}:{alias.product}|{version}"
        search_arg = cpe.build_cpe_prefix(alias, version)
        search_fn = search_cve_by_cpe
    else:
        cache_key = component_query
        search_arg = component_query
        search_fn = search_cve_by_keyword

    if cache.has_cached_query(session, cache_key):
        return cache.get_cached_cves(session, cache_key)

    if not allow_network:
        return []

    records = _query_nvd(search_fn, search_arg, http_client)
    return cache.store_cve_results(session, cache_key, records)


def _query_nvd(search_fn, search_arg: str, http_client: httpx.Client | None) -> list[CveRecord]:
    """Exécute un client NVD et traduit ses erreurs en UpdateManagerError."""
    client = http_client or httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS)
    try:
        return search_fn(client, search_arg)
    except NvdClientError as exc:
        raise UpdateManagerError(str(exc)) from exc
    finally:
        if http_client is None:
            client.close()


def update_kev_catalog(
    session: Session,
    http_client: httpx.Client | None = None,
) -> int:
    """Synchronise intégralement le catalogue CISA KEV en local.

    Retourne le nombre d'entrées synchronisées. À appeler explicitement
    (commande CLI dédiée), pas automatiquement à chaque scan : c'est une
    mise à jour de fond, pas une dépendance bloquante pour scanner une cible.
    """
    client = http_client or httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS)
    try:
        records = fetch_kev_catalog(client)
    except KevClientError as exc:
        raise UpdateManagerError(str(exc)) from exc
    finally:
        if http_client is None:
            client.close()

    return cache.sync_kev_catalog(session, records)


def check_kev(session: Session, cve_id: str) -> KevEntry | None:
    """Vérifie si une CVE est dans le catalogue KEV local (aucun appel
    réseau : suppose une synchronisation déjà effectuée via
    `update_kev_catalog`)."""
    return cache.get_kev_entry(session, cve_id)
