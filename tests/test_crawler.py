"""Tests du crawlur de pages web (RF-15, RF-24) : découverte par liens HTML,
robots.txt et sitemap.xml, bornes de profondeur/pages/durée."""

from __future__ import annotations

from tscan_core.recon.client import create_http_client
from tscan_core.recon.crawler import _extract_links, crawl


def test_crawl_discovers_pages_through_html_links(lab_server) -> None:
    client = create_http_client(request_delay=0.0)
    try:
        pages = crawl(
            client,
            f"{lab_server.base_url}/",
            max_depth=2,
            max_pages=20,
            max_duration_seconds=10,
        )
    finally:
        client.close()

    assert pages
    # La racine est toujours crawlee.
    assert any(p.final_url.rstrip("/") == lab_server.base_url for p in pages.values())


def test_crawl_parses_robots_txt_disallowed_path(lab_server) -> None:
    """Les chemins listés dans robots.txt (Allow/Disallow) sont découverts et
    ajoutés au périmètre crawlable."""
    client = create_http_client(request_delay=0.0)
    try:
        pages = crawl(
            client,
            f"{lab_server.base_url}/",
            max_depth=1,
            max_pages=30,
            max_duration_seconds=15,
        )
    finally:
        client.close()

    # /wp-admin/ est répertorié dans robots.txt ; la réponse 403 est une page
    # découverte légitime (le statut fait partie de l'information de recon).
    assert any("/wp-admin" in url for url in pages)


def test_extract_links_finds_forms_iframes_and_links() -> None:
    """Le crawl découvre aussi les actions de formulaires, les iframes et les
    liens <link href> (et pas seulement les <a href>)."""
    html = (
        '<a href="/page-a">A</a>'
        '<form method="get" action="/action"><input name="q"></form>'
        '<iframe src="/widget"></iframe>'
        '<link rel="alternate" href="/flux.rss">'
        '<a href="https://autre.exemple/hors-domaine">hors</a>'
        '<a href="mailto:x@y.z">mail</a>'
    )
    links = _extract_links(html, "https://example.test/", "example.test", "https")

    assert "https://example.test/page-a" in links
    assert "https://example.test/action" in links
    assert "https://example.test/widget" in links
    # /flux.rss a l'extension .rss (pas dans _SKIP_EXTENSIONS) : découvert.
    assert "https://example.test/flux.rss" in links
    # Hors domaine et mailto filtrés.
    assert "autre.exemple" not in " ".join(links)
