"""Tests du client NVD (RF-33), avec réponses HTTP simulées (httpx.MockTransport).

Aucun appel réseau réel n'est effectué ici -- conformément à la contrainte
signalée : l'environnement de développement n'a pas accès à
services.nvd.nist.gov. La structure des réponses simulées reproduit le
schéma réel de l'API NVD 2.0 (confirmé par recherche avant écriture du
client, même discipline que pour les parseurs Nuclei/ZAP).
"""

from __future__ import annotations

import json

import httpx
import pytest

from tscan_core.knowledge_base.nvd_client import (
    NvdClientError,
    search_cve_by_cpe,
    search_cve_by_keyword,
)

_SAMPLE_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2026-08-18T10:00:00.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2020-11022",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2020-04-29T00:15:00.000",
                "lastModified": "2021-07-21T11:39:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "In jQuery before 3.5.0, passing HTML from untrusted sources "
                        "to jQuery's DOM manipulation methods may execute untrusted code.",
                    },
                    {"lang": "fr", "value": "Description en français, ne doit pas être choisie."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 6.1,
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ]
                },
                "references": [{"url": "https://jquery.com/", "source": "cve@mitre.org"}],
            }
        }
    ],
}


def _mock_transport(json_body: dict, status_code: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body)

    return httpx.MockTransport(handler)


def test_search_cve_parses_sample_response() -> None:
    client = httpx.Client(transport=_mock_transport(_SAMPLE_NVD_RESPONSE))
    results = search_cve_by_keyword(client, "jquery 1.11.0")

    assert len(results) == 1
    record = results[0]
    assert record.cve_id == "CVE-2020-11022"
    assert "jQuery before 3.5.0" in record.description
    assert record.cvss_score == 6.1
    assert record.cvss_severity == "MEDIUM"
    assert record.published == "2020-04-29T00:15:00.000"
    assert json.loads(record.raw_json)["cve"]["id"] == "CVE-2020-11022"


def test_search_cve_prefers_english_description() -> None:
    client = httpx.Client(transport=_mock_transport(_SAMPLE_NVD_RESPONSE))
    results = search_cve_by_keyword(client, "jquery")
    assert "français" not in results[0].description


def test_search_cve_no_results_returns_empty_list() -> None:
    empty_response = {**_SAMPLE_NVD_RESPONSE, "vulnerabilities": [], "totalResults": 0}
    client = httpx.Client(transport=_mock_transport(empty_response))
    results = search_cve_by_keyword(client, "composant-totalement-inconnu-xyz")
    assert results == []


def test_search_cve_handles_missing_cvss_gracefully() -> None:
    response = {
        **_SAMPLE_NVD_RESPONSE,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-1999-0001",
                    "descriptions": [{"lang": "en", "value": "Vieille CVE sans score CVSS."}],
                    "metrics": {},
                }
            }
        ],
    }
    client = httpx.Client(transport=_mock_transport(response))
    results = search_cve_by_keyword(client, "vieux-composant")
    assert results[0].cvss_score is None
    assert results[0].cvss_severity is None


def test_search_cve_http_error_raises_nvd_client_error() -> None:
    client = httpx.Client(transport=_mock_transport({}, status_code=503))
    with pytest.raises(NvdClientError):
        search_cve_by_keyword(client, "jquery")


def test_search_cve_malformed_json_raises_nvd_client_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"ceci n'est pas du JSON")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(NvdClientError):
        search_cve_by_keyword(client, "jquery")


def test_search_cve_unexpected_structure_raises_nvd_client_error() -> None:
    client = httpx.Client(transport=_mock_transport({"vulnerabilities": [{"cve": {}}]}))
    with pytest.raises(NvdClientError):
        search_cve_by_keyword(client, "jquery")


def test_search_cve_by_cpe_sends_cpe_name_parameter() -> None:
    """Le paramètre `cpeName` doit être transmis tel quel à l'API (RF-18)."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["cpeName"] == "cpe:2.3:a:jquery:jquery:1.11.0"
        return httpx.Response(200, json=_SAMPLE_NVD_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    results = search_cve_by_cpe(client, "cpe:2.3:a:jquery:jquery:1.11.0")

    assert len(results) == 1
    assert results[0].cve_id == "CVE-2020-11022"


def test_search_cve_by_cpe_no_results_returns_empty_list() -> None:
    empty_response = {**_SAMPLE_NVD_RESPONSE, "vulnerabilities": [], "totalResults": 0}
    client = httpx.Client(transport=_mock_transport(empty_response))
    results = search_cve_by_cpe(client, "cpe:2.3:a:jquery:jquery:3.2.0")
    assert results == []


def test_search_cve_by_cpe_http_error_raises_nvd_client_error() -> None:
    client = httpx.Client(transport=_mock_transport({}, status_code=503))
    with pytest.raises(NvdClientError):
        search_cve_by_cpe(client, "cpe:2.3:a:jquery:jquery:1.11.0")


def test_search_cve_rejects_too_large_response() -> None:
    """ES-11 : une réponse dépassant la limite de taille est rejetée (garde
    anti-bombe / serveur compromis), sans mise en cache."""
    from tscan_core.knowledge_base.nvd_client import MAX_NVD_BYTES

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_NVD_BYTES + 1))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(NvdClientError, match="ES-11"):
        search_cve_by_keyword(client, "jquery")


def test_search_cve_rejects_invalid_cve_id() -> None:
    """ES-11 : une CVE dont l'identifiant ne respecte pas le format canonique
    invalide la réponse (aucune donnée intégrée)."""
    response = {
        **_SAMPLE_NVD_RESPONSE,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "NOT-A-CVE",
                    "descriptions": [{"lang": "en", "value": "Piégé"}],
                    "metrics": {},
                }
            }
        ],
    }
    client = httpx.Client(transport=_mock_transport(response))
    with pytest.raises(NvdClientError, match="CVE"):
        search_cve_by_keyword(client, "jquery")
