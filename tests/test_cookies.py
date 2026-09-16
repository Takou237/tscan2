"""Tests de l'analyse passive des cookies de session (HttpOnly, Secure,
SameSite) : un cookie sans drapeaux est constaté, un cookie correctement
protégé ne l'est pas."""

from __future__ import annotations

from tscan_core.recon.client import create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import cookies


def _config(lab_server, path="/") -> ScanConfig:
    return ScanConfig(
        target=f"{lab_server.base_url}{path}",
        authorized=True,
        max_duration_seconds=30,
    )


def test_cookie_without_security_flags_is_reported(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        config = _config(lab_server, "/login")
        root = fetch_root(client, config.target)
        results = cookies.run(config, client, root, {}, None)

        assert len(results) >= 1
        cookie = results[0]
        assert cookie.rule_id == "RULE-COOKIE-001"
        assert cookie.severity == "medium"
        assert "HttpOnly" in cookie.description
        assert "valeur masquée" in cookie.evidence_text
    finally:
        client.close()


def test_secured_cookie_is_not_reported(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        config = _config(lab_server, "/secure-login")
        root = fetch_root(client, config.target)
        results = cookies.run(config, client, root, {}, None)

        assert results == []
    finally:
        client.close()