"""Tests des détecteurs de parité OWASP ZAP ajoutés à la semaine augmentée :
en-têtes de sécurité (HSTS, X-Content-Type-Options, X-Powered-By) et
redirection géante (Big Redirect).

Chaque module `run(...)` est évalué contre le laboratoire local, qui fournit
des routes positives (racine `/`, `/big-redirect`) et leurs contre-exemples
(`/bare`, `/redirect`). Aucune ressource externe n'est contactée (ES-09).
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse, create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import big_redirect, security_headers


def _config(lab_server, path="/") -> ScanConfig:
    return ScanConfig(
        target=f"{lab_server.base_url}{path}",
        authorized=True,
        max_duration_seconds=60,
        allowed_tests=frozenset({"recon", "security-headers", "big-redirect"}),
    )


def _run(module, config, client, root: RootResponse, **kwargs):
    """Appelle `module.run` avec la signature commune des détections."""
    return module.run(config, client, root, {}, None, **kwargs)


def test_security_headers_on_root_report_hsts_xcto_xpoweredby(lab_server) -> None:
    """La racine du lab expédie `X-Powered-By: PHP/7.4.33` mais aucun en-tête
    HSTS/X-Content-Type-Options : les trois constats ZAP sortent, avec leurs
    titres exacts (parité 10035, 10038, 10037)."""
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run(security_headers, config, client, root)
        by_rule = {r.rule_id: r for r in results}
        assert set(by_rule) == {
            "RULE-HSTS-NOTSET-001",
            "RULE-XCTO-NOTSET-001",
            "RULE-XPOWEREDBY-001",
        }
        assert by_rule["RULE-HSTS-NOTSET-001"].title == "Strict-Transport-Security Header Not Set"
        assert by_rule["RULE-HSTS-NOTSET-001"].severity == "medium"
        assert by_rule["RULE-HSTS-NOTSET-001"].category == "security_misconfiguration"
        assert (
            by_rule["RULE-XCTO-NOTSET-001"].title == "X-Content-Type-Options Header Missing"
        )
        assert by_rule["RULE-XCTO-NOTSET-001"].severity == "medium"
        assert (
            by_rule["RULE-XPOWEREDBY-001"].title
            == 'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)'
        )
        assert by_rule["RULE-XPOWEREDBY-001"].severity == "low"
        assert "PHP/7.4.33" in by_rule["RULE-XPOWEREDBY-001"].evidence_text
        assert config.target in by_rule["RULE-HSTS-NOTSET-001"].evidence_text
    finally:
        client.close()


def test_security_headers_on_bare_hides_technology_header(lab_server) -> None:
    """Contre-exemple X-Powered-By : `/bare` ne porte aucune signature de
    technologie → uniquement les constats d'en-têtes manquants, aucun X-Powered-By."""
    client = create_http_client()
    config = _config(lab_server, path="/bare")
    try:
        root = fetch_root(client, config.target)
        results = _run(security_headers, config, client, root)
        by_rule = {r.rule_id for r in results}
        assert by_rule == {"RULE-HSTS-NOTSET-001", "RULE-XCTO-NOTSET-001"}
    finally:
        client.close()


def test_big_redirect_reports_long_location_with_query(lab_server, monkeypatch) -> None:
    """La route `/big-redirect` renvoie un 302 dont le `Location` (> 100
    caractères) porte une chaîne de requête : le constat Big Redirect sort
    (parité ZAP 10043)."""
    monkeypatch.setattr(big_redirect, "_PROBE_PATHS", ("/big-redirect",))
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run(big_redirect, config, client, root)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "RULE-BIG-REDIRECT-001"
        assert result.severity == "low"
        assert result.category == "information_disclosure"
        assert (
            result.title == "Big Redirect Detected (Potential Sensitive Information Leak)"
        )
        assert result.matched_at.endswith("/big-redirect")
        assert result.probe_info is not None
        assert result.probe_info["signal_type"] == "big_redirect"
        assert "/landing?" in result.probe_info["signal_value"]
    finally:
        client.close()


def test_big_redirect_ignores_short_location(lab_server, monkeypatch) -> None:
    """Contre-exemple : `/redirect` renvoie un 302 avec un `Location` court
    (`/`) : aucun constat."""
    monkeypatch.setattr(big_redirect, "_PROBE_PATHS", ("/redirect",))
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        assert _run(big_redirect, config, client, root) == []
    finally:
        client.close()


def test_big_redirect_needs_length_and_query() -> None:
    """La règle de décision exige les deux conditions : longueur > 100 ET une
    chaîne de requête (un URL long sans `?` n'est pas une fuite en clair)."""
    assert big_redirect._is_big_redirect("/landing?" + "k=v&" * 30) is True
    assert big_redirect._is_big_redirect("/landing/" + "x" * 200) is False  # sans requête
    assert big_redirect._is_big_redirect("/?k=v") is False  # trop court
    assert big_redirect._is_big_redirect("/") is False
    assert big_redirect._is_big_redirect("") is False