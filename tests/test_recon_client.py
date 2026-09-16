"""Tests du client HTTP de reconnaissance (RF-15), avec réponses simulées."""

from __future__ import annotations

import httpx
import pytest

from tscan_core.recon.client import (
    MAX_BODY_CHARS,
    ReconError,
    fetch_root,
)

_BODY_200 = "<html><body>page de test</body></html>"


def _transport_for(status: int = 200, headers: dict | None = None, body: str = _BODY_200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers or {}, text=body)

    return httpx.MockTransport(handler)


def test_fetch_root_collects_status_headers_and_body() -> None:
    client = httpx.Client(
        transport=_transport_for(
            headers={"Server": "Apache/2.4.53", "X-Powered-By": "PHP/7.4.33"}
        )
    )
    result = fetch_root(client, "http://example.test/")

    assert result.status_code == 200
    assert result.headers["server"] == "Apache/2.4.53"  # clés en minuscules
    assert result.headers["x-powered-by"] == "PHP/7.4.33"
    assert "page de test" in result.body
    assert result.final_url == "http://example.test/"
    assert result.body_truncated is False


def test_fetch_root_http_errors_are_not_errors() -> None:
    client = httpx.Client(transport=_transport_for(status=404))
    result = fetch_root(client, "http://example.test/absent")
    assert result.status_code == 404


def test_fetch_root_follows_redirects() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/landing":
            return httpx.Response(200, text="page d'arrivee")
        return httpx.Response(302, headers={"Location": "http://example.test/landing"}, text="")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    result = fetch_root(client, "http://example.test/")
    assert result.final_url == "http://example.test/landing"


def test_fetch_root_network_failure_raises_recon_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connexion refusée")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(ReconError, match="Impossible de joindre"):
        fetch_root(client, "http://example.test/")


def test_fetch_root_truncates_oversized_body() -> None:
    big_body = "x" * (MAX_BODY_CHARS + 10_000)
    client = httpx.Client(transport=_transport_for(body=big_body))
    result = fetch_root(client, "http://example.test/")

    assert result.body_truncated is True
    assert len(result.body) == MAX_BODY_CHARS