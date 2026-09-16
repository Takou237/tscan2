"""Tests du client CISA KEV (RF-33), avec réponses HTTP simulées.

Structure de réponse simulée conforme au schéma réel du flux KEV (confirmé
par recherche avant écriture du client)."""

from __future__ import annotations

import httpx
import pytest

from tscan_core.knowledge_base.kev_client import KevClientError, fetch_kev_catalog

_SAMPLE_KEV_RESPONSE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.08.18",
    "dateReleased": "2026-08-18T00:00:00.0000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        },
        {
            "cveID": "CVE-2021-41773",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
            "dateAdded": "2021-10-01",
            "shortDescription": "Path traversal vulnerability in Apache HTTP Server.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-10-15",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
    ],
}


def _mock_transport(json_body, status_code: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body)

    return httpx.MockTransport(handler)


def test_fetch_kev_catalog_parses_sample_response() -> None:
    client = httpx.Client(transport=_mock_transport(_SAMPLE_KEV_RESPONSE))
    records = fetch_kev_catalog(client)

    assert len(records) == 2
    log4j = next(r for r in records if r.cve_id == "CVE-2021-44228")
    assert log4j.vulnerability_name == "Apache Log4j2 Remote Code Execution Vulnerability"
    assert log4j.vendor_project == "Apache"
    assert log4j.date_added == "2021-12-10"
    assert log4j.known_ransomware_use == "Known"


def test_fetch_kev_catalog_http_error_raises() -> None:
    client = httpx.Client(transport=_mock_transport({}, status_code=500))
    with pytest.raises(KevClientError):
        fetch_kev_catalog(client)


def test_fetch_kev_catalog_missing_vulnerabilities_key_raises() -> None:
    client = httpx.Client(transport=_mock_transport({"title": "..."}))
    with pytest.raises(KevClientError):
        fetch_kev_catalog(client)


def test_fetch_kev_catalog_rejects_too_large_feed() -> None:
    """ES-11 : un flux dont le contenu dépasse la limite de taille est rejeté
    sans aucune intégration (garde anti-bombe / serveur compromis)."""
    from tscan_core.knowledge_base.kev_client import MAX_KEV_BYTES

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_KEV_BYTES + 1))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(KevClientError, match="ES-11"):
        fetch_kev_catalog(client)


def test_fetch_kev_catalog_rejects_invalid_cve_id() -> None:
    """ES-11 : une entrée dont l'identifiant CVE ne respecte pas le format
    canonique invalide l'ensemble de la synchronisation (aucune intégration)."""
    bad_response = {
        **_SAMPLE_KEV_RESPONSE,
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4j"},
            {"cveID": "not-a-cve", "vulnerabilityName": "Piégé"},
        ],
    }
    client = httpx.Client(transport=_mock_transport(bad_response))
    with pytest.raises(KevClientError, match="CVE"):
        fetch_kev_catalog(client)
