"""Tests du bundle de parité passive ZAP (`zap_passive`) et de la règle XSS
attribut (`RULE-XSS-ATTR-001`).

Chaque règle est testée contre le laboratoire local (cas positifs/contre-
exemples) ou contre des réponses synthétiques construites à la main (pour les
règles que le labo ne déclenche pas). Aucune ressource externe n'est contactée
(ES-09).
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse, create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import xss, zap_passive

_TITLES = {
    "RULE-CT-MISSING-001": "Content-Type Header Missing",
    "RULE-SUSPICOMM-001": "Information Disclosure - Suspicious Comments",
    "RULE-MODERN-APP-001": "Modern Web Application",
    "RULE-CACHE-CONTROL-001": "Re-examine Cache-control Directives",
    "RULE-RETRIEVED-CACHE-001": "Retrieved from Cache",
    "RULE-PERMISSIONS-NOTSET-001": "Permissions Policy Header Not Set",
    "RULE-XFO-NOTSET-001": "X-Frame-Options Header Not Set",
    "RULE-SERVER-HEADER-001": "Server Header Information Leak",
    "RULE-XASPNET-001": "X-AspNet-Version Response Header",
    "RULE-XCHROME-001": "X-ChromeLogger-Data Header Information Leak",
    "RULE-XDEBUG-001": "X-Debug-Token Information Leak",
    "RULE-TABNABBING-001": "Reverse Tabnabbing",
    "RULE-WEAK-AUTH-001": "Weak Authentication Method",
    "RULE-HASH-001": "Hash Disclosure",
    "RULE-BASE64-001": "Base64 Disclosure",
    "RULE-SOURCE-001": "Source Code Disclosure",
    "RULE-AUTH-REQ-001": "Authentication Request Identified",
    "RULE-SESSION-MGMT-001": "Session Management Response Identified",
    "RULE-SENSITIVE-URL-001": "Information Disclosure - Sensitive Information in URL",
    "RULE-CROSS-DOMAIN-001": "Cross-Domain Misconfiguration",
    "RULE-CHARSET-001": "Charset Mismatch",
}


def _config(lab_server, path="/") -> ScanConfig:
    return ScanConfig(
        target=f"{lab_server.base_url}{path}",
        authorized=True,
        max_duration_seconds=60,
        allowed_tests=frozenset({"recon", "zap-passives"}),
    )


def _page(url: str, headers: dict[str, str], body: str = "") -> RootResponse:
    return RootResponse(
        status_code=200,
        headers={k.lower(): v for k, v in headers.items()},
        body=body,
        final_url=url,
        body_truncated=False,
        reason="OK",
        request_url=url,
    )


def _run(module, config, client, root: RootResponse, pages=None):
    return module.run(config, client, root, {}, None, pages=pages)


def test_zap_passive_on_lab_root_reports_common_headers(lab_server) -> None:
    """La racine du lab porte un Server Apache/2.4.53, aucun Cache-Control,
    ni Permissions-Policy, ni X-Frame-Options : quatre constats attendus, sans
    faux positifs sur le content-type ni les commentaires."""
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run(zap_passive, config, client, root)
        by_rule = {r.rule_id for r in results}
        assert {
            "RULE-SERVER-HEADER-001",
            "RULE-CACHE-CONTROL-001",
            "RULE-PERMISSIONS-NOTSET-001",
            "RULE-XFO-NOTSET-001",
        } <= by_rule
        assert by_rule.isdisjoint(
            {"RULE-CT-MISSING-001", "RULE-SUSPICOMM-001", "RULE-HASH-001"}
        )
        server = next(r for r in results if r.rule_id == "RULE-SERVER-HEADER-001")
        assert "Apache/2.4.53" in server.evidence_text
    finally:
        client.close()


def test_zap_passive_synthetic_rules_trigger(lab_server) -> None:
    """Chaque règle restante se déclenche sur une réponse synthétique qui la
    caractérise (parité des alertes passives ZAP restantes)."""
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)

        def trigger(headers: dict[str, str], body: str, url="/x") -> dict[str, str]:
            page = _page(f"{config.target.rstrip('/')}{url}", headers, body)
            results = _run(zap_passive, config, client, root, pages={url: page})
            # Chaque constat doit porter EXACTEMENT le titre de l'alerte ZAP
            # correspondante (nécessaire à la corroboration par titre).
            assert all(
                r.title == _TITLES[r.rule_id] for r in results if r.rule_id in _TITLES
            ), [
                (r.rule_id, r.title, _TITLES.get(r.rule_id))
                for r in results
                if r.rule_id in _TITLES and r.title != _TITLES[r.rule_id]
            ]
            return {r.rule_id for r in results}

        # En-têtes révélateurs / état du cache.
        assert "RULE-CT-MISSING-001" in trigger({}, "<html>ct</html>", "/noct")
        assert "RULE-SUSPICOMM-001" in trigger(
            {"Content-Type": "text/html"}, "<!-- TODO: refactor -->", "/cmt"
        )
        assert "RULE-MODERN-APP-001" in trigger(
            {"Content-Type": "text/html"},
            "const load = () => fetch('/api/users');",
            "/spa",
        )
        assert "RULE-RETRIEVED-CACHE-001" in trigger({"Age": "120"}, "", "/cdn")
        assert "RULE-XASPNET-001" in trigger({"X-AspNet-Version": "4.0.30319"}, "", "/aspx")
        assert "RULE-XCHROME-001" in trigger({"X-ChromeLogger-Data": "e30="}, "", "/chrome")
        assert "RULE-XDEBUG-001" in trigger({"X-Debug-Token": "abc123"}, "", "/symfo")
        assert "RULE-TABNABBING-001" in trigger(
            {"Content-Type": "text/html"}, '<a href="/x" target="_blank">lien</a>', "/tab"
        )
        assert "RULE-WEAK-AUTH-001" in trigger({"WWW-Authenticate": 'Basic realm="x"'}, "", "/auth")
        assert "RULE-HASH-001" in trigger(
            {"Content-Type": "text/html"}, "hash=0123456789abcdef0123456789abcdef", "/md5"
        )
        assert "RULE-BASE64-001" in trigger(
            {"Content-Type": "text/html"},
            "blob: " + "VGhpcyBpcyBhIGxvbmcgYmFzZTY0IGJsb2Igd2l0aCBlbmNvZGVkIHNlY3JldHM=",
            "/b64",
        )
        assert "RULE-SOURCE-001" in trigger(
            {"Content-Type": "text/html"}, "<html><body><?php echo 1; ?></body></html>", "/src"
        )

        # Authentification : URL contenant 'login'.
        assert "RULE-AUTH-REQ-001" in trigger({}, "", "/login")

        # Gestion de session : Set-Cookie contenant un identifiant de session.
        assert "RULE-SESSION-MGMT-001" in trigger(
            {"set-cookie": "PHPSESSID=abc123; Path=/"}, "", "/sess"
        )

        # URL sensible : paramètre email dans l'URL finale.
        sensitive_url = f"{config.target.rstrip('/')}/?email=test@example.com"
        sensitive_page = _page(sensitive_url, {"Content-Type": "text/html"}, "<html>ok</html>")
        sensitive_results = _run(
            zap_passive, config, client, root, pages={"/?email=test@example.com": sensitive_page}
        )
        assert "RULE-SENSITIVE-URL-001" in {r.rule_id for r in sensitive_results}

        # CORS permissif : Access-Control-Allow-Origin sauvage.
        assert "RULE-CROSS-DOMAIN-001" in trigger(
            {"access-control-allow-origin": "*"}, "", "/cors"
        )

        # Charset mismatch : en-tête utf-8, meta iso-8859-1.
        assert "RULE-CHARSET-001" in trigger(
            {"content-type": "text/html; charset=utf-8"},
            '<html><head><meta charset="iso-8859-1"></head><body>ok</body></html>',
            "/charset",
        )
    finally:
        client.close()


def test_zap_passive_no_false_data_uri_base64(lab_server) -> None:
    """Les data URIs (images embarquées) ne déclenchent pas RULE-BASE64-001."""
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        data_uri = "data:image/png;base64," + "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
        page = _page(f"{config.target.rstrip('/')}/img", {"Content-Type": "text/html"}, f'<img src="{data_uri}">')
        results = _run(zap_passive, config, client, root, pages={"/img": page})
        assert "RULE-BASE64-001" not in {r.rule_id for r in results}
    finally:
        client.close()


def test_xss_attribute_reflection_reports_zap_10031(lab_server) -> None:
    """Parité ZAP 10031 : un paramètre de requête reflété dans un attribut HTML
    (ex. ?lang=fr -> <html lang=\"fr\">) produit le constat d'infos avec le
    titre exact de ZAP. Aucune charge d'attaque envoyée."""
    client = create_http_client()
    config = _config(lab_server)
    try:
        base = config.target.rstrip("/")
        root = fetch_root(client, config.target)
        page = _page(f"{base}/?lang=fr", {"Content-Type": "text/html"}, '<html lang="fr"><body>ok</body></html>')
        results = xss.run(config, client, root, {}, None, pages={"/?lang=fr": page})
        attr_results = [r for r in results if r.rule_id == "RULE-XSS-ATTR-001"]
        assert len(attr_results) == 1
        assert attr_results[0].title == "User Controllable HTML Element Attribute (Potential XSS)"
        assert attr_results[0].category == "xss"
        assert attr_results[0].severity == "info"
        assert "lang" in attr_results[0].evidence_text
    finally:
        client.close()