"""Tests du gestionnaire de mise à jour (RF-34, chapitre 10).

Vérifie le comportement le plus important de ce bloc : un composant n'est
interrogé sur le réseau qu'une seule fois, les appels suivants doivent
provenir exclusivement du cache local (RNF-14, fonctionnement hors-ligne).
"""

from __future__ import annotations

import httpx
import pytest

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.knowledge_base import cache
from tscan_core.knowledge_base.update_manager import (
    UpdateManagerError,
    check_kev,
    lookup_component,
    update_kev_catalog,
)

_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2020-11022",
                "descriptions": [{"lang": "en", "value": "jQuery XSS via DOM manipulation."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM"}}]
                },
            }
        }
    ]
}

_KEV_RESPONSE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-41773",
            "vendorProject": "Apache",
            "vulnerabilityName": "Apache HTTP Server Path Traversal",
            "dateAdded": "2021-10-01",
            "knownRansomwareCampaignUse": "Unknown",
        }
    ]
}


def _counting_transport(json_body: dict) -> tuple[httpx.MockTransport, list[int]]:
    """Transport simulé qui compte le nombre d'appels réseau effectués, pour
    vérifier que le cache évite bien les appels redondants."""
    call_count = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        call_count[0] += 1
        return httpx.Response(200, json=json_body)

    return httpx.MockTransport(handler), call_count


def _routing_transport(events: list[str]) -> httpx.MockTransport:
    """Transport qui enregistre le chemin NVD utilisé (cpeName ou
    keywordSearch) et répond avec le même jeu de CVE dans les deux cas."""

    def handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        if "cpeName" in params:
            events.append(f"cpe:{params['cpeName']}")
            return httpx.Response(200, json=_NVD_RESPONSE)
        if "keywordSearch" in params:
            events.append(f"keyword:{params['keywordSearch']}")
            return httpx.Response(200, json=_NVD_RESPONSE)
        events.append("autre")
        return httpx.Response(500)

    return httpx.MockTransport(handler)


def test_lookup_component_queries_network_only_once() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    transport, call_count = _counting_transport(_NVD_RESPONSE)
    client = httpx.Client(transport=transport)

    with get_session(engine) as session:
        first = lookup_component(session, "jquery 1.11.0", http_client=client)
        second = lookup_component(session, "jquery 1.11.0", http_client=client)

    assert call_count[0] == 1  # un seul appel réseau, malgré deux interrogations
    assert len(first) == 1
    assert first[0].cve_id == "CVE-2020-11022"
    assert [c.cve_id for c in second] == [c.cve_id for c in first]


def test_lookup_component_offline_without_cache_returns_empty() -> None:
    """Si le réseau n'est pas autorisé et rien n'est en cache, la fonction
    doit renvoyer une liste vide plutôt que d'échouer (RNF-14/15) : un scan
    ne doit pas être bloqué par l'absence de connaissance sur un composant."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        result = lookup_component(session, "composant-jamais-vu", allow_network=False)

    assert result == []


def test_lookup_component_offline_uses_existing_cache() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    transport, _ = _counting_transport(_NVD_RESPONSE)
    client = httpx.Client(transport=transport)

    with get_session(engine) as session:
        lookup_component(session, "jquery 1.11.0", http_client=client)  # peuple le cache
        # Nouvel appel, réseau explicitement désactivé : doit tout de même réussir.
        offline_result = lookup_component(session, "jquery 1.11.0", allow_network=False)

    assert len(offline_result) == 1
    assert offline_result[0].cve_id == "CVE-2020-11022"


def test_lookup_component_network_error_raises_update_manager_error() -> None:
    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    engine = get_engine(":memory:")
    init_db(engine)
    client = httpx.Client(transport=httpx.MockTransport(failing_handler))

    with get_session(engine) as session, pytest.raises(UpdateManagerError):
        lookup_component(session, "composant-quelconque", http_client=client)


def test_lookup_component_recognized_alias_uses_cpe_route() -> None:
    """ "jquery 1.11.0" est reconnu dans la table d'alias : la requête NVD doit
    passer par `cpeName` (correspondance version -> CVE, RF-18) et non par
    mot-clé."""
    engine = get_engine(":memory:")
    init_db(engine)
    events: list[str] = []
    client = httpx.Client(transport=_routing_transport(events))

    with get_session(engine) as session:
        results = lookup_component(session, "jquery 1.11.0", http_client=client)
        assert events == ["cpe:cpe:2.3:a:jquery:jquery:1.11.0"]
        assert [r.cve_id for r in results] == ["CVE-2020-11022"]


def test_lookup_component_cpe_route_is_cached_and_offline_usable() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    events: list[str] = []
    client = httpx.Client(transport=_routing_transport(events))

    with get_session(engine) as session:
        lookup_component(session, "jquery 1.11.0", http_client=client)
        offline_results = lookup_component(session, "jquery 1.11.0", allow_network=False)
        assert events == ["cpe:cpe:2.3:a:jquery:jquery:1.11.0"]  # pas de second appel
        assert [r.cve_id for r in offline_results] == ["CVE-2020-11022"]


def test_lookup_component_old_keyword_sentinel_does_not_block_cpe_route() -> None:
    """Une entrée de cache issue de l'ancienne recherche par mot-clé
    (clé = saisie, ici une sentinelle "sans résultat") ne doit pas empêcher
    la nouvelle recherche CPE : les clés de cache sont distinctes."""
    engine = get_engine(":memory:")
    init_db(engine)
    events: list[str] = []
    client = httpx.Client(transport=_routing_transport(events))

    with get_session(engine) as session:
        cache.store_cve_results(session, "jquery 1.11.0", [])  # sentinelle mot-clé
        results = lookup_component(session, "jquery 1.11.0", http_client=client)
        assert events == ["cpe:cpe:2.3:a:jquery:jquery:1.11.0"]
        assert [r.cve_id for r in results] == ["CVE-2020-11022"]


def test_lookup_component_unknown_product_falls_back_to_keyword() -> None:
    """Produit inconnu de la table d'alias : repli sur la recherche par
    mot-clé, comme avant ce bloc."""
    engine = get_engine(":memory:")
    init_db(engine)
    events: list[str] = []
    client = httpx.Client(transport=_routing_transport(events))

    with get_session(engine) as session:
        results = lookup_component(session, "composant-quelconque 1.0", http_client=client)
        assert events == ["keyword:composant-quelconque 1.0"]
        assert [r.cve_id for r in results] == ["CVE-2020-11022"]


def test_update_kev_catalog_and_check_kev() -> None:
    engine = get_engine(":memory:")
    init_db(engine)
    client = httpx.Client(transport=_counting_transport(_KEV_RESPONSE)[0])

    with get_session(engine) as session:
        count = update_kev_catalog(session, http_client=client)
        assert count == 1

        entry = check_kev(session, "CVE-2021-41773")
        assert entry is not None
        assert entry.vendor_project == "Apache"

        assert check_kev(session, "CVE-non-exploitee") is None
