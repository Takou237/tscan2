"""Tests du correctif anti-bruit (dé-duplication et périmètre des pages).

Deux sources de bruit sont couvertes :

1. **Sondes de chemins analysées comme des pages** : la table `pages` mêle les
   pages servies par l'application et les sondes de chemins (BAC) qui peuvent
   répondre 403/404. Analyser ces dernières produit des constats d'en-têtes
   « absent » sur des pages d'erreur — du bruit. Le filtre `served_pages`
   (statut 2xx) corrige cela.
2. **Doublons d'en-têtes** : `RULE-MISCONFIG-001` (déclaratif, racine) et les
   familles dédiées (`RULE-*-NOTSET`, par page) signalaient le même en-tête.
   La dé-duplication (`superseded_headers`) retire le check déclaratif quand la
   famille dédiée est active.

Aucune ressource externe n'est contactée (ES-09).
"""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding
from tscan_core.recon.client import RootResponse
from tscan_core.rule_engine.schema import RuleDefinition
from tscan_core.scan.checks import evaluate_rule_checks, superseded_headers
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import csp, header_notset
from tscan_core.scan.detections.page_scope import is_served, served_pages
from tscan_core.scan.orchestrator import run_recon_scan

_ALL_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def _page(url: str, status: int, headers: dict[str, str] | None = None, body: str = "") -> RootResponse:
    return RootResponse(
        status_code=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body=body,
        final_url=url,
        body_truncated=False,
        reason="OK",
        request_url=url,
    )


def _config(base_url: str, tests: frozenset[str]) -> ScanConfig:
    return ScanConfig(
        target=f"{base_url}/",
        authorized=True,
        max_duration_seconds=60,
        allowed_tests=tests,
    )


# --- 1. Périmètre : seules les pages réellement servies sont analysées -------


def test_is_served_only_accepts_2xx() -> None:
    assert is_served(_page("http://t/", 200)) is True
    assert is_served(_page("http://t/", 204)) is True
    assert is_served(_page("http://t/", 301)) is False
    assert is_served(_page("http://t/", 403)) is False
    assert is_served(_page("http://t/", 404)) is False
    assert is_served(_page("http://t/", 500)) is False


def test_served_pages_excludes_error_probe_responses() -> None:
    root = _page("http://t/", 200, _ALL_HEADERS)
    real = _page("http://t/real", 200, _ALL_HEADERS)
    forbidden = _page("http://t/wp-admin/", 403)
    missing = _page("http://t/config/", 404)
    result = served_pages(root, {"a": real, "b": forbidden, "c": missing})
    assert [p.final_url for p in result] == ["http://t/", "http://t/real"]


def test_header_notset_ignores_error_probe_pages() -> None:
    """Une racine complète + des sondes 403/404 sans en-têtes : aucun constat."""
    root = _page("http://t/", 200, _ALL_HEADERS)
    config = _config("http://t", frozenset({"recon", "header-notset"}))
    results = header_notset.run(
        config,
        None,
        root,
        {},
        None,
        pages={"wp": _page("http://t/wp-admin/", 403), "cfg": _page("http://t/config/", 404)},
    )
    assert results == []


def test_header_notset_reports_on_served_pages_only() -> None:
    root = _page("http://t/", 200, _ALL_HEADERS)
    served = _page("http://t/page", 200, {})
    config = _config("http://t", frozenset({"recon", "header-notset"}))
    results = header_notset.run(config, None, root, {}, None, pages={"p": served})
    assert {r.matched_at for r in results} == {"http://t/page"}
    assert len(results) == 3


def test_csp_notset_not_triggered_by_error_page() -> None:
    """La racine porte une CSP : un 404 sans CSP ne doit pas déclencher
    « CSP Header Not Set » (c'était un faux positif : le constat était posé
    sur la racine à cause d'une page 404)."""
    root = _page(
        "http://t/",
        200,
        {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"},
    )
    config = _config("http://t", frozenset({"recon", "csp"}))
    results = csp.run(
        config, None, root, {}, None, pages={"e": _page("http://t/missing", 404)}
    )
    assert all(r.rule_id != "RULE-CSP-NOTSET-001" for r in results)


# --- 2. Dé-duplication RULE-MISCONFIG-001 vs familles dédiées ----------------


def test_superseded_headers_mapping() -> None:
    assert superseded_headers(frozenset({"headers", "header-notset"})) == {
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    }
    assert superseded_headers(frozenset({"headers", "csp", "permissions-policy"})) == {
        "content-security-policy",
        "permissions-policy",
    }
    assert superseded_headers(frozenset({"headers"})) == set()


def test_evaluate_rule_checks_skips_superseded_headers() -> None:
    rule = RuleDefinition(
        id="RULE-MISCONFIG-001",
        name="En-tête manquant",
        category="security_misconfiguration",
        severity="info",
        version="1.0.0",
        description="",
        checks=[
            {"id": "header-hsts", "type": "header_absent", "header": "Strict-Transport-Security"},
            {"id": "header-referrer", "type": "header_absent", "header": "Referrer-Policy"},
        ],
    )
    root = _page("http://t/", 200, {"Server": "nginx"})
    # Sans skips : les deux en-têtes sont signalés.
    assert {r.check_id for r in evaluate_rule_checks(rule, root)} == {
        "header-hsts",
        "header-referrer",
    }
    # Avec HSTS couvert par header-notset : seul Referrer-Policy subsiste.
    results = evaluate_rule_checks(rule, root, skip_headers={"strict-transport-security"})
    assert {r.check_id for r in results} == {"header-referrer"}


def _misconfig_check_ids(session) -> set[str]:
    return {
        f.check_id
        for f in session.query(Finding).filter(Finding.rule_id == "RULE-MISCONFIG-001").all()
    }


def test_scan_dedupes_misconfig_when_dedicated_family_active(lab_server) -> None:
    """Avec 'header-notset' actif, RULE-MISCONFIG-001 ne re-signale plus HSTS,
    XCTO ni XFO : ces en-têtes sont couverts par la famille dédiée."""
    engine = get_engine(":memory:")
    init_db(engine)
    with get_session(engine) as session:
        run_recon_scan(
            session,
            _config(lab_server.base_url, frozenset({"recon", "headers", "header-notset"})),
        )
        check_ids = _misconfig_check_ids(session)
        assert not ({"header-hsts", "header-content-type-options", "header-x-frame-options"} & check_ids)
        rules = {f.rule_id for f in session.query(Finding).all()}
        assert "RULE-HSTS-NOTSET-001" in rules  # émis par la famille dédiée


def test_scan_keeps_misconfig_headers_without_dedicated_family(lab_server) -> None:
    """Sans famille dédiée active, le déclaratif conserve ses six en-têtes."""
    engine = get_engine(":memory:")
    init_db(engine)
    with get_session(engine) as session:
        run_recon_scan(
            session,
            _config(lab_server.base_url, frozenset({"recon", "headers"})),
        )
        check_ids = _misconfig_check_ids(session)
        assert {
            "header-hsts",
            "header-content-type-options",
            "header-x-frame-options",
            "header-csp",
            "header-referrer-policy",
            "header-permissions-policy",
        } <= check_ids
