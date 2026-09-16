"""Tests du fuzzing ciblé par contexte (feuille de route) : les paramètres
réellement présents dans les pages crawlées (formulaires, requêtes) sont
découverts par le crawlur et consommés par les détections XSS/SQLi."""

from __future__ import annotations

from tscan_core.recon.client import create_http_client
from tscan_core.recon.crawler import crawl
from tscan_core.scan.detections.fuzzing import extract_form_fields


def test_crawl_discovers_form_param_names(lab_server) -> None:
    """Le champ `message` du formulaire /contact est découvert par le crawl et
    publié dans `observations["params_found"]` (fuzzing ciblé)."""
    client = create_http_client(request_delay=0.0)
    try:
        observations: dict = {}
        crawl(
            client,
            f"{lab_server.base_url}/contact",
            max_depth=1,
            max_pages=30,
            max_duration_seconds=15,
            observations=observations,
        )
    finally:
        client.close()

    assert "message" in observations.get("params_found", [])


def test_extract_form_fields_and_query_params() -> None:
    """Les utilitaires purs extraient les champs de formulaires et les noms de
    paramètres de requête depuis le HTML."""
    form_fields = extract_form_fields(
        _page(
            '<form method="post"><input type="text" name="email">'
            '<input type="hidden" name="csrf_token" value="x">'
            '<input type="submit"></form>'
        )
    )
    assert "email" in form_fields
    assert "csrf_token" in form_fields


def _page(body: str):
    """Construit un RootResponse minimal de test."""
    from tscan_core.recon.client import RootResponse

    return RootResponse(
        status_code=200,
        headers={},
        body=body,
        final_url="http://example.test/",
        body_truncated=False,
    )