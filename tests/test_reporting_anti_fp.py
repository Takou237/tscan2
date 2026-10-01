"""Tests d'intégration de la section « Méthodologie anti-faux positifs » (P5).

Vérifie que le bilan des contrôles négatifs (sentinelle anti soft-404 P2,
verdicts différentiels P1) exécutés pendant un scan actif arrive jusqu'aux
rapports HTML et Markdown : le rapport prouve que la machine anti-faux
positifs a tourné, au lieu d'un « 0 faux positif » invérifiable.
"""

from __future__ import annotations

from tests.test_detections import ALL_S8_TESTS, _config

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.reporting import generate_report
from tscan_core.reporting.render_html import render_html
from tscan_core.reporting.render_markdown import render_markdown
from tscan_core.scan.orchestrator import run_recon_scan


def test_report_contains_anti_fp_section_after_scan(lab_server) -> None:
    """Après un scan actif réel sur le labo, le rapport comporte la section
    « Méthodologie anti-faux positifs » avec la sentinelle exécutée (P2)."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        run_recon_scan(session, _config(lab_server, allowed_tests=ALL_S8_TESTS))

        report = generate_report(session)
        target = report.targets[0]

        # Le bilan anti-FP du dernier scan actif est porté par la cible.
        assert target.anti_fp, "le bilan anti-faux positifs devrait exister"
        sentinelle = target.anti_fp.get("sentinelle")
        assert sentinelle is not None
        assert sentinelle["url"].startswith(lab_server.base_url)
        assert sentinelle["status_code"] == 404  # le labo normal renvoie 404

        html = render_html(report)
        assert "Méthodologie anti-faux positifs" in html
        assert "Sentinelle anti soft-404 exécutée" in html

        md = render_markdown(report)
        assert "Méthodologie anti-faux positifs" in md
        assert "Sentinelle anti soft-404 exécutée" in md


def test_report_without_active_scan_has_no_anti_fp_section(lab_server) -> None:
    """Sans scan actif (aucun constat, base vide), aucune section anti-FP
    n'est affichée : pas de bloc vide dans le rapport."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        report = generate_report(session)
        assert report.targets == []
        html = render_html(report)
        assert "Méthodologie anti-faux positifs" not in html
