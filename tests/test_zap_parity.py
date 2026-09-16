"""Tests des détections passives de parité ZAP : CSP, SRI, inclusion JS
cross-domain et divulgation de timestamps Unix.

Le laboratoire expose une page faible (CSP permissive, script/link tiers sans
SRI, timestamp) et une page sécurisée (contre-exemple : aucun constat).
"""

from __future__ import annotations

from tscan_core.recon.client import create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import csp, sri, timestamp, xdomain_js


def _config(lab_server, path) -> ScanConfig:
    return ScanConfig(
        target=f"{lab_server.base_url}{path}",
        authorized=True,
        max_duration_seconds=30,
    )


def _run(client, lab_server, path, module):
    config = _config(lab_server, path)
    root = fetch_root(client, config.target)
    return module.run(config, client, root, {}, None)


# --- CSP -------------------------------------------------------------------

def test_csp_weak_page_reports_all_findings(lab_server) -> None:
    """La page faible déclenche : mise en garde wildcard, unsafe-inline
    script et style, directive sans fallback. Mais la CSP étant posée, pas de
    constat 'not set'."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/weak-page", csp)
        rule_ids = {r.rule_id for r in results}
        assert csp.RULE_WILDCARD in rule_ids
        assert csp.RULE_UNSAFE_SCRIPT in rule_ids
        assert csp.RULE_UNSAFE_STYLE in rule_ids
        assert csp.RULE_NO_FALLBACK in rule_ids
        assert csp.RULE_NOTSET not in rule_ids
    finally:
        client.close()


def test_csp_notset_reported(lab_server) -> None:
    """Une page sans CSP déclenche le constat 'Header Not Set'."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/login", csp)
        assert any(r.rule_id == csp.RULE_NOTSET for r in results)
    finally:
        client.close()


def test_csp_secure_page_no_finding(lab_server) -> None:
    """La CSP restrictive ne déclenche aucun constat CSP."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", csp)
        assert results == []
    finally:
        client.close()


# --- SRI -------------------------------------------------------------------

def test_sri_reports_missing_integrity_on_third_party(lab_server) -> None:
    """Les ressources tierces sans attribut integrity sont signalées."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/weak-page", sri)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-SRI-001"
        assert "cdn.example.com" in results[0].evidence_text
    finally:
        client.close()


def test_sri_secure_page_no_finding(lab_server) -> None:
    """Une page qui n'embarque que des ressources locales ne déclenche rien."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", sri)
        assert results == []
    finally:
        client.close()


# --- Cross-domain JS -------------------------------------------------------

def test_xdomain_js_reports_external_script(lab_server) -> None:
    """Un <script src> vers un domaine tiers est signalé."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/weak-page", xdomain_js)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-XDOMAIN-JS-001"
        assert "cdn.example.com" in results[0].evidence_text
    finally:
        client.close()


def test_xdomain_js_secure_page_no_finding(lab_server) -> None:
    """Les scripts locaux ne déclenchent pas de constat cross-domain."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", xdomain_js)
        assert results == []
    finally:
        client.close()


# --- Timestamp -------------------------------------------------------------

def test_timestamp_reports_unix_epoch(lab_server) -> None:
    """Un horodatage Unix plausible (1700000000) est signalé."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/weak-page", timestamp)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-TIMESTAMP-001"
        assert "1700000000" in results[0].evidence_text
    finally:
        client.close()


def test_timestamp_clean_page_no_finding(lab_server) -> None:
    """Une page sans timestamp ne déclenche rien."""
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", timestamp)
        assert results == []
    finally:
        client.close()