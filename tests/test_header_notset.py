"""Tests du module header_notset (suite P7) : les en-têtes de sécurité
absents (HSTS, X-Content-Type-Options, X-Frame-Options) deviennent un constat
par page avec probe_info `header_absent` rejouable — re-vérifiables
précisément par RF-23, au lieu de constats agrégés « fait non reproduit ».

Aucune ressource externe n'est contactée (ES-09).
"""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus
from tscan_core.recon.client import RootResponse, create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import header_notset, security_headers, zap_passive
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


def test_header_notset_reports_missing_headers_per_page(lab_server) -> None:
    """La racine du labo n'a ni HSTS, ni XCTO, ni XFO : trois constats, un
    par en-tête, chacun avec un probe_info `header_absent` rejouable."""
    client = create_http_client()
    config = _config(lab_server.base_url, frozenset({"recon", "header-notset"}))
    try:
        root = fetch_root(client, config.target)
        results = header_notset.run(config, client, root, {}, None)
        by_rule = {r.rule_id: r for r in results}
        assert set(by_rule) == {
            "RULE-HSTS-NOTSET-001",
            "RULE-XCTO-NOTSET-001",
            "RULE-XFO-NOTSET-001",
        }
        for rule_id, header in (
            ("RULE-HSTS-NOTSET-001", "strict-transport-security"),
            ("RULE-XCTO-NOTSET-001", "x-content-type-options"),
            ("RULE-XFO-NOTSET-001", "x-frame-options"),
        ):
            assert by_rule[rule_id].probe_info["signal_type"] == "header_absent"
            assert by_rule[rule_id].probe_info["signal_value"] == header
            assert by_rule[rule_id].probe_info["request_url"] == root.final_url
        # Titres exacts des alertes ZAP (corroboration par titre).
        assert (
            by_rule["RULE-HSTS-NOTSET-001"].title
            == "Strict-Transport-Security Header Not Set"
        )
        assert by_rule["RULE-XCTO-NOTSET-001"].severity == "medium"
        assert by_rule["RULE-XFO-NOTSET-001"].severity == "low"
    finally:
        client.close()


def test_header_notset_present_header_is_not_reported() -> None:
    """Une page portant les trois en-têtes ne produit aucun constat."""
    page = _page(
        "http://example.test/",
        {
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
        "<html>ok</html>",
    )
    config = _config("http://example.test", frozenset({"recon", "header-notset"}))
    assert header_notset.run(config, None, page, {}, None) == []


def test_header_notset_reports_per_page_not_aggregated(lab_server) -> None:
    """Une page sécurisée + une page sans en-têtes : le module ne signale que
    la page concernée (constat par page, plus de constat agrégé racine)."""
    client = create_http_client()
    config = _config(lab_server.base_url, frozenset({"recon", "header-notset"}))
    try:
        root = fetch_root(client, config.target)
        secure = _page(
            f"{config.target.rstrip('/')}/secure-page",
            {
                "Strict-Transport-Security": "max-age=63072000",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
            },
            "<html>ok</html>",
        )
        results = header_notset.run(
            config, client, root, {}, None, pages={"/secure-page": secure}
        )
        # La racine est signalée (3 constats), /secure-page ne l'est pas.
        matched = {r.matched_at for r in results}
        assert matched == {root.final_url}
        assert len(results) == 3
    finally:
        client.close()


def test_dedup_security_headers_and_zap_passive(lab_server) -> None:
    """Après éclatement : `security_headers` n'émet plus que X-Powered-By,
    `zap_passive` n'émet plus XFO (déplacé dans header_notset)."""
    client = create_http_client()
    config = _config(lab_server.base_url, frozenset({"recon", "security-headers", "zap-passives"}))
    try:
        root = fetch_root(client, config.target)

        sh = security_headers.run(config, client, root, {}, None)
        assert {r.rule_id for r in sh} == {"RULE-XPOWEREDBY-001"}

        zp = zap_passive.run(config, client, root, {}, None)
        rules = {r.rule_id for r in zp}
        assert "RULE-XFO-NOTSET-001" not in rules
        assert "RULE-SERVER-HEADER-001" in rules  # le reste du bundle tient
    finally:
        client.close()


def test_scan_reinforces_header_notset_findings(lab_server) -> None:
    """Bout en bout : la re-vérification précise RF-23 re-produit les faits
    (la racine du labo garde ses en-têtes absents) -> scores renforcés au-dessus
    de la base de la règle (0,60), statuts toujours Probable (RF-12)."""
    tests = frozenset({"recon", "header-notset"})
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server.base_url, tests))
        assert outcome.reproduced >= 3

        stored = (
            session.query(Finding)
            .filter(Finding.rule_id == "RULE-HSTS-NOTSET-001")
            .first()
        )
        assert stored is not None
        assert stored.confidence_score > 0.60  # base 0.60 + boost RF-23
        assert stored.status == FindingStatus.PROBABLE
