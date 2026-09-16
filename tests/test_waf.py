"""Tests de la détection de WAF (pare-feu applicatif) et de la classification
des réponses 412/403 comme blocages (feuille de route « Gestion WAF »).

Le laboratoire simule un WAF : la racine rejette (412 + X-WAF-Sim) les
charges de forme « agressive » (`<script>…` ou `OR 1=1`). Sans charge, la
racine répond normalement (contre-exemple : aucun faux positif).
"""

from __future__ import annotations

from tscan_core.recon.client import create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import waf


def _config(lab_server) -> ScanConfig:
    return ScanConfig(
        target=f"{lab_server.base_url}/",
        authorized=True,
        max_duration_seconds=30,
    )


def test_waf_detects_blocked_probe_on_root(lab_server) -> None:
    """La sonde portant une charge agressive est rejetée (412) avec une
    signature d'en-tête : le WAF est détecté et la sonde comptée comme bloquée."""
    client = create_http_client(request_delay=0.0)
    try:
        root = fetch_root(client, _config(lab_server).target)
        observations: dict = {}
        results = waf.run(_config(lab_server), client, root, observations, None)

        assert observations["waf"]["detected"] is True
        assert observations["waf"]["blocked_probes"] >= 1
        assert len(results) == 1
        assert results[0].rule_id == "RULE-WAF-001"
        assert "412" in results[0].evidence_text
    finally:
        client.close()


def test_waf_reports_encoded_bypass(lab_server) -> None:
    """La rotation des charges (ZAP) détecte un filtre contournable : les
    formes « brute » sont bloquées (412) mais les variantes encodées
    (double encodage URL, commentaire MySQL) atteignent l'application."""
    client = create_http_client(request_delay=0.0)
    try:
        root = fetch_root(client, _config(lab_server).target)
        observations: dict = {}
        results = waf.run(_config(lab_server), client, root, observations, None)

        assert observations["waf"]["bypassable"] is True
        assert "url-encode double" in observations["waf"]["encoded_passed"]
        assert "comment mysql" in observations["waf"]["encoded_passed"]
        assert "contournable par encodage" in results[0].evidence_text
    finally:
        client.close()


def test_waf_no_false_positive_on_clean_routes(lab_server) -> None:
    """Le contre-exemple : une cible sans WAF ne déclenche aucun constat."""
    client = create_http_client(request_delay=0.0)
    try:
        # /bare n'implémente aucun blocage ; on le sonde à la place de la racine.
        target = f"{lab_server.base_url}/bare"
        config = ScanConfig(target=target, authorized=True, max_duration_seconds=30)
        root = fetch_root(client, config.target)
        observations: dict = {}
        results = waf.run(config, client, root, observations, None)

        assert observations["waf"]["detected"] is False
        assert results == []
    finally:
        client.close()