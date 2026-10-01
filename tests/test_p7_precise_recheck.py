"""Tests du câblage P7 : les règles de parité ZAP re-vérifiables précisément.

Deux familles passives de parité ZAP (Permissions-Policy absent, Modern Web
Application) deviennent des modules dédiés avec `probe_info` rejouable :
leur constat est re-vérifiable par une requête fraîche (RF-23 précise) au
lieu de rester éternellement « Probable / fait non reproduit ». Le bundle
agrégé `zap_passive` n'émet plus ces deux alertes (déduplication).

Aucune ressource externe n'est contactée (ES-09).
"""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import FindingStatus
from tscan_core.recon.client import RootResponse, create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import modern_web_app, permissions_policy, zap_passive
from tscan_core.scan.orchestrator import run_recon_scan


def _config(base_url: str, tests: frozenset[str]) -> ScanConfig:
    return ScanConfig(
        target=f"{base_url}/",
        authorized=True,
        max_duration_seconds=60,
        allowed_tests=tests,
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


# --- Détections dédiées : un constat par page, avec probe_info -------------


def test_permissions_policy_missing_reports_per_page(lab_server) -> None:
    """La racine du labo n'a pas d'en-tête Permissions-Policy : un constat
    avec probe_info `header_absent` rejouable."""
    client = create_http_client()
    config = _config(lab_server.base_url, frozenset({"recon", "permissions-policy"}))
    try:
        root = fetch_root(client, config.target)
        results = permissions_policy.run(config, client, root, {}, None)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-PERMISSIONS-NOTSET-001"
        assert results[0].title == "Permissions Policy Header Not Set"
        assert results[0].probe_info["signal_type"] == "header_absent"
        assert results[0].probe_info["signal_value"] == "permissions-policy"
        assert results[0].probe_info["request_url"] == root.final_url
    finally:
        client.close()


def test_permissions_policy_present_is_not_reported() -> None:
    """Une page portant l'en-tête ne produit aucun constat."""
    page = _page(
        "http://example.test/",
        {"Permissions-Policy": "camera=(), geolocation=()"},
        "<html>ok</html>",
    )
    config = _config("http://example.test", frozenset({"recon", "permissions-policy"}))
    results = permissions_policy.run(config, None, page, {}, None)
    assert results == []


def test_modern_web_app_reports_per_page_with_regex_probe() -> None:
    """Une page HTML avec marqueurs ES6 produit un constat avec probe_info
    `body_regex` portant la regex exacte (rejouable)."""
    page = _page(
        "http://example.test/spa",
        {"Content-Type": "text/html"},
        "<html><body><script>const load = () => fetch('/api/users');</script></body></html>",
    )
    config = _config("http://example.test", frozenset({"recon", "modern-web-app"}))
    results = modern_web_app.run(config, None, page, {}, None)
    assert len(results) == 1
    assert results[0].rule_id == "RULE-MODERN-APP-001"
    assert results[0].title == "Modern Web Application"
    assert results[0].probe_info["signal_type"] == "body_regex"
    assert "fetch" in results[0].probe_info["signal_value"]


def test_modern_web_app_static_resources_are_not_reported() -> None:
    """Une ressource CSS/JS (pas une page HTML) et une page sans marqueur
    moderne ne produisent aucun constat."""
    config = _config("http://example.test", frozenset({"recon", "modern-web-app"}))
    css = _page(
        "http://example.test/style.css",
        {"Content-Type": "text/css"},
        "a { color: red }",
    )
    plain = _page(
        "http://example.test/",
        {"Content-Type": "text/html"},
        "<html><body><p>page classique</p></body></html>",
    )
    assert modern_web_app.run(config, None, css, {}, None) == []
    assert modern_web_app.run(config, None, plain, {}, None) == []


# --- Déduplication : zap_passive n'émet plus ces deux alertes --------------


def test_zap_passive_no_longer_emits_the_two_dedicated_rules(lab_server) -> None:
    """Le bundle agrégé ne produit plus RULE-PERMISSIONS-NOTSET-001 ni
    RULE-MODERN-APP-001 (désormais émis par les modules dédiés) : plus de
    doublons dans les rapports."""
    client = create_http_client()
    config = _config(lab_server.base_url, frozenset({"recon", "zap-passives"}))
    try:
        root = fetch_root(client, config.target)
        page = _page(
            f"{config.target.rstrip('/')}/spa",
            {"Content-Type": "text/html"},
            "<html><body><script>fetch('/api/x')</script></body></html>",
        )
        results = zap_passive.run(config, client, root, {}, None, pages={"/spa": page})
        rules = {r.rule_id for r in results}
        assert "RULE-PERMISSIONS-NOTSET-001" not in rules
        assert "RULE-MODERN-APP-001" not in rules
        # Le reste du bundle continue de fonctionner (racine du labo : Server
        # Apache + aucun Cache-Control).
        assert "RULE-SERVER-HEADER-001" in rules
        assert "RULE-CACHE-CONTROL-001" in rules
    finally:
        client.close()


# --- Re-vérification précise : le fait reproduit renforce la confiance -----


def test_reverify_precise_boosts_dedicated_rules(lab_server) -> None:
    """Bout en bout : un scan du labo produit les constats des 2 familles
    dédiées, et la re-vérification RF-23 les REPRODUIT (la cible n'a toujours
    pas d'en-tête Permissions-Policy, la page racine reste « moderne » ou non
    — le verdict s'appuie sur le probe_info). Statut toujours Probable
    (RF-12), score renforcé quand reproduit."""
    tests = frozenset({"recon", "permissions-policy", "modern-web-app"})
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server.base_url, tests))

        # La racine du labo n'a ni Permissions-Policy ni marqueur moderne :
        # seul Permissions-Policy doit être présent (relu depuis la base).
        from tscan_core.models import Finding

        stored = (
            session.query(Finding)
            .filter(Finding.rule_id == "RULE-PERMISSIONS-NOTSET-001")
            .first()
        )
        assert stored is not None
        modern = (
            session.query(Finding)
            .filter(Finding.rule_id == "RULE-MODERN-APP-001")
            .count()
        )
        assert modern == 0

        # La re-vérification précise a re-produit le fait : le score dépasse
        # la base de la règle (0.50) et le statut reste Probable (RF-12 : le
        # moteur ne confirme pas).
        assert outcome.reproduced >= 1
        assert stored.confidence_score > 0.50
        assert stored.status == FindingStatus.PROBABLE
        assert stored.score_explanation is not None


# --- Mode soft-404 : la page générique ne produit pas de « moderne » -------


def test_modern_web_app_on_soft404_server(lab_server) -> None:
    """Sur le labo en mode soft-404, la page générique ne contient pas de
    marqueurs JS modernes : aucun constat RULE-MODERN-APP-001 (la re-vérification
    précise d'un constat antérieur y serait d'ailleurs contredite)."""
    lab_server.enable_soft404()
    client = create_http_client()
    config = _config(lab_server.base_url, frozenset({"recon", "modern-web-app"}))
    try:
        root = fetch_root(client, config.target)
        results = modern_web_app.run(config, client, root, {}, None)
        assert results == []
    finally:
        lab_server.disable_soft404()
        client.close()
