"""Tests des nouvelles familles de détection de parité ZAP.

Vérifie que chaque famille ajoutée (parité OWASP ZAP) détecte bien la
vulnérabilité simulée sur le laboratoire local, et qu'un contre-exemple
sécurisé ne produit aucun constat. Aucune ressource externe n'est contactée
(ES-09) : le laboratoire est la cible contrôlée et autorisée.
"""

from __future__ import annotations

from tscan_core.recon.client import create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import (
    cmd_injection,
    header_injection,
    open_redirect,
    path_traversal,
    ssrf,
    ssti,
    weak_hash,
)

RULE_IDS = {
    path_traversal.RULE_ID,
    open_redirect.RULE_ID,
    cmd_injection.RULE_ID,
    ssti.RULE_ID,
    ssrf.RULE_ID,
    header_injection.RULE_ID,
    weak_hash.RULE_ID,
}


def _config(lab_server, path) -> ScanConfig:
    return ScanConfig(
        target=f"{lab_server.base_url}{path}",
        authorized=True,
        max_duration_seconds=30,
    )


def _run(client, lab_server, path, module):
    config = _config(lab_server, path)
    root = fetch_root(client, config.target)
    return module.run(config, client, root, {}, None, {}, None)


# --- Traversée de répertoire ---------------------------------------------

def test_path_traversal_detected(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "", path_traversal)
        assert len(results) == 1
        assert results[0].rule_id == path_traversal.RULE_ID
        assert "root:x:0:0" in results[0].evidence_text
    finally:
        client.close()


def test_path_traversal_safe_route_no_finding(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", path_traversal)
        assert results == []
    finally:
        client.close()


# --- Redirection ouverte -------------------------------------------------

def test_open_redirect_detected(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "", open_redirect)
        assert any(r.rule_id == open_redirect.RULE_ID for r in results)
    finally:
        client.close()


def test_open_redirect_root_no_finding(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", open_redirect)
        assert results == []
    finally:
        client.close()


# --- Injection de commande ------------------------------------------------

def test_cmd_injection_detected(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "", cmd_injection)
        assert len(results) == 1
        assert results[0].rule_id == cmd_injection.RULE_ID
        assert "TSCAN-OK" in results[0].evidence_text
    finally:
        client.close()


def test_cmd_injection_safe_page_no_finding(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", cmd_injection)
        assert results == []
    finally:
        client.close()


# --- SSTI -----------------------------------------------------------------

def test_ssti_detected(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "", ssti)
        assert any(r.rule_id == ssti.RULE_ID for r in results)
    finally:
        client.close()


def test_ssti_safe_page_no_finding(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", ssti)
        assert results == []
    finally:
        client.close()


# --- SSRF -----------------------------------------------------------------

def test_ssrf_detected(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "", ssrf)
        assert len(results) == 1
        assert results[0].rule_id == ssrf.RULE_ID
    finally:
        client.close()


def test_ssrf_safe_page_no_finding(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", ssrf)
        assert results == []
    finally:
        client.close()


# --- Injection de headers -------------------------------------------------

def test_header_injection_detected(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "", header_injection)
        assert len(results) == 1
        assert results[0].rule_id == header_injection.RULE_ID
    finally:
        client.close()


def test_header_injection_no_reflect_route_no_finding(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "/secure-page", header_injection)
        assert results == []
    finally:
        client.close()


# --- Hachage faible -------------------------------------------------------

def test_weak_hash_detected_on_htpasswd(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        results = _run(client, lab_server, "", weak_hash)
        assert any(r.rule_id == weak_hash.RULE_ID for r in results)
    finally:
        client.close()


def test_weak_hash_strong_hash_ignored(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        # .htpasswd-strong n'embarque que des hachages Argon2 : aucun constat.
        results = _run(client, lab_server, "/.htpasswd-strong", weak_hash)
        assert results == []
    finally:
        client.close()


# --- Enregistrement complet ----------------------------------------------

def test_all_new_rules_registered_and_reach_default() -> None:
    """Chaque nouvel identifiant de règle appartient à la liste de types de
    tests par défaut (les familles sont activées sans option)."""
    from tscan_core.scan.config import TEST_TYPES

    assert {"path-traversal", "open-redirect", "cmd-injection", "ssti",
            "ssrf", "header-injection", "weak-hash"} <= TEST_TYPES
    assert RULE_IDS == {
        "RULE-PATH-TRAVERSAL-001",
        "RULE-OPEN-REDIRECT-001",
        "RULE-CMD-INJECTION-001",
        "RULE-SSTI-001",
        "RULE-SSRF-001",
        "RULE-HDR-INJECTION-001",
        "RULE-WEAK-HASH-001",
    }
