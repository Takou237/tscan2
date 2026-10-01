"""Tests anti-faux-positifs (P1/P2/P6) : le labo sert un serveur qui fabrique
des réponses « tentantes » (marqueur SQL statique, soft-404 réfléchissant la
requête, faux « Index of », signature .env) et les détections doivent
S'ABSTENIR au lieu de produire des constats — ou, pour SQLi sur /search,
garder le constat car le verdict différentiel le valide.

Historiquement, un marqueur de corps sans contrôle produisait le constat :
ces tests verrouillent la nouvelle sémantique « en cas de doute, on ne
conclut pas » (RF-12), avec compteurs d'abstention (`observations["anti_fp"]`)
vérifiés pour le bilan anti-faux-positifs du rapport (P5). Aucune ressource
externe n'est contactée (ES-09).
"""

from __future__ import annotations

import pytest

from tscan_core.recon.client import create_http_client, fetch_root
from tscan_core.scan.detections import directory_listing, sensitive_files, sqli, xss
from tscan_core.scan.detections.sentinel import get_calibration, reset_calibration


def _config(base_url: str):
    from tscan_core.scan.config import ScanConfig

    return ScanConfig(
        target=f"{base_url}/",
        authorized=True,
        max_duration_seconds=60,
    )


def _pages(client, base_url: str, paths: tuple[str, ...]) -> dict:
    """Construit la table `pages` (parité run_active_detections) : elle place
    les routes cibles du test en tête de l'échantillon borné des sondes."""
    from tscan_core.recon.client import fetch_url

    pages = {}
    for path in paths:
        pages[f"{base_url}{path}"] = fetch_url(client, f"{base_url}{path}")
    return pages


@pytest.fixture(autouse=True)
def _fresh_sentinel():
    """Chaque test part avec un cache de sentinelle vierge (une calibration
    par scan : le cache mémoire ne doit jamais traverser deux tests)."""
    reset_calibration()
    yield
    reset_calibration()


# --- P1 : le verdict différentiel écarte le marqueur statique -------------


def test_sqli_abstains_on_static_sql_marker(lab_server) -> None:
    """/static-error contient « SQL syntax error » en contenu statique : la
    baseline (requête normale) porte le même marqueur, donc le verdict
    différentiel doit s'abstenir — aucun constat sur cette page."""
    client = create_http_client()
    config = _config(lab_server.base_url)
    try:
        root = fetch_root(client, config.target)
        # Pages limitées à /static-error : la détection s'arrête au premier
        # constat, on isole donc la page piège pour évaluer le verdict.
        pages = _pages(client, lab_server.base_url, ("/static-error",))
        observations: dict = {}
        results = sqli.run(config, client, root, observations, None, pages)
        assert all("/static-error" not in r.matched_at for r in results)
        # Le compteur d'abstention P5 prouve que le verdict a bien examiné la
        # page (abstention enregistrée) et non ignoré le chemin.
        abstained = observations["anti_fp"]["sondes_ecartees"]
        assert any("/static-error" in a["url"] for a in abstained)
    finally:
        client.close()


def test_sqli_keeps_finding_on_real_injection(lab_server) -> None:
    """La route /search est un modèle réaliste d'injection : erreur présente
    sous charge de rupture, ABSENTE de la baseline et DISPARAISSANT avec la
    charge corrigée (''). Le constat doit être produit, avec la trace
    différentielle complète (ES-08)."""
    client = create_http_client()
    config = _config(lab_server.base_url)
    try:
        root = fetch_root(client, config.target)
        pages = _pages(client, lab_server.base_url, ("/search",))
        observations: dict = {}
        results = sqli.run(config, client, root, observations, None, pages)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-SQLI-001"
        assert "/search" in results[0].matched_at
        differential = results[0].probe_info["differential"]
        assert differential["baseline_markers"] == []
        assert differential["sentinelle"] == "distincte"
        # Bilan P5 : une analyse différentielle validée est comptée.
        assert observations["anti_fp"]["differentielles_validees"]["sqli"] == 1
    finally:
        client.close()


# --- P2 : la sentinelle écarte les pages génériques (soft-404) ------------


def test_soft404_server_produces_no_findings(lab_server) -> None:
    """Le labo en mode soft-404 répond 200 générique (avec marqueurs SQL,
    « Index of » et signature DATABASE_URL) pour tout chemin : sqli,
    sensitive_files et directory_listing ne doivent produire AUCUN constat."""
    lab_server.enable_soft404()
    client = create_http_client()
    config = _config(lab_server.base_url)
    try:
        root = fetch_root(client, config.target)
        pages = _pages(client, lab_server.base_url, ("/files/", "/backup/"))
        observations: dict = {}
        for module, use_pages in (
            (sqli, True),
            (sensitive_files, False),  # signature sans paramètre `pages`
            (directory_listing, True),
        ):
            if use_pages:
                assert module.run(config, client, root, observations, None, pages) == []
            else:
                assert module.run(config, client, root, observations, None) == []

        abstained = observations["anti_fp"]["sondes_ecartees"]
        families = {a["famille"] for a in abstained}
        # Chacune des trois familles a au moins une sonde écartée : par la
        # sentinelle (P2) pour sensitive_files/listing, par la sentinelle ou
        # le verdict différentiel (P1) pour sqli.
        assert {"sqli", "sensitive_files", "directory_listing"} <= families
        assert len(abstained) >= 3
    finally:
        lab_server.disable_soft404()
        client.close()


def test_soft404_calibration_cached_single_request(lab_server) -> None:
    """La sentinelle ne dépasse jamais une requête de calibration par scan :
    plusieurs familles consécutives partagent le même contrôle négatif."""
    client = create_http_client()
    config = _config(lab_server.base_url)
    try:
        observations: dict = {}
        cal1, tok1 = get_calibration(config, client, observations)
        cal2, tok2 = get_calibration(config, client, observations)
        assert cal1 is cal2
        assert tok1 == tok2
        # Le labo normal répond 404 au chemin-sentinelle : la calibration est
        # bien enregistrée (une seule requête), quel que soit son statut.
        assert observations["sentinelle_meta"]["status_code"] == 404
    finally:
        client.close()


# --- P1 : l'écho global de la requête n'est pas une réflexion XSS ---------


def test_xss_abstains_on_global_request_echo() -> None:
    """Un serveur qui renvoie l'URL entière (miroir qui affiche les chemins
    récemment demandés, cache mal configuré) reflète aussi le nonce sur la
    requête normale suivante : la détection XSS doit s'abstenir au lieu de
    produire un constat sur cette « réflexion »."""
    mirror = _MirrorServer()
    client = create_http_client()
    config = _config(mirror.base_url)
    try:
        root = fetch_root(client, config.target)
        observations: dict = {}
        results = xss.run(config, client, root, observations, None)
        assert results == []
        abstained = observations["anti_fp"]["sondes_ecartees"]
        assert any(a["famille"] == "xss" for a in abstained)
    finally:
        mirror.stop()
        client.close()


class _MirrorServer:
    """Petit serveur miroir : chaque réponse affiche (brut, non échappé) la
    liste des chemins récemment demandés — simulation d'un écho global de
    requête (page « liens récents », cache mal configuré)."""

    def __init__(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import unquote

        history: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                history.append(unquote(self.path))
                echoed = "".join(f"<span>{h}</span>" for h in history)
                body = f"<html><body>{echoed}</body></html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        import threading

        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


# --- P5 : les compteurs alimentent le bilan anti-faux-positifs ------------


def test_anti_fp_counters_shape(lab_server) -> None:
    """Structure des compteurs `observations["anti_fp"]` (P5) : clés attendues
    par le bilan « méthodologie anti-faux positifs » du rapport."""
    client = create_http_client()
    config = _config(lab_server.base_url)
    try:
        root = fetch_root(client, config.target)
        pages = _pages(client, lab_server.base_url, ("/static-error",))
        observations: dict = {}
        sqli.run(config, client, root, observations, None, pages)
        stats = observations.get("anti_fp", {})
        assert "sondes_ecartees" in stats
        assert "total_ecartees" in stats
        assert "par_famille" in stats
        assert all(
            {"famille", "url", "raison"} <= set(a) for a in stats["sondes_ecartees"]
        )
    finally:
        client.close()


# --- P2 : sans calibration (échec réseau), les sondes ne sont pas écartées -


def test_calibration_network_failure_is_not_fatal(lab_server) -> None:
    """Un échec réseau de la sentinelle n'interrompt pas les détections : la
    calibration vaut None, les sondes sont évaluées normalement (même
    sémantique que le BAC)."""
    from unittest.mock import patch

    from tscan_core.recon.client import ReconError

    client = create_http_client()
    config = _config(lab_server.base_url)
    try:
        root = fetch_root(client, config.target)
        observations: dict = {}
        with patch(
            "tscan_core.scan.detections.sentinel.fetch_url",
            side_effect=ReconError("réseau indisponible"),
        ):
            cal, token = get_calibration(config, client, observations)
        assert cal is None
        assert token is not None
        assert observations["sondes"]["sentinelle"]
        assert observations["sentinelle_meta"]["status_code"] is None
        # Les détections continuent : le listing trouve /files/ normalement.
        results = directory_listing.run(config, client, root, observations, None)
        assert any("/files/" in r.matched_at for r in results)
    finally:
        client.close()
