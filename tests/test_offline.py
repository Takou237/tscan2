"""Vérification du fonctionnement hors-ligne — RNF-14 et RNF-15 (semaine 11).

L'import de résultats externes, la corrélation/scoring et le rapport doivent
fonctionner **sans aucune connectivité réseau** : ce sont des opérations
strictement locales (base SQLite + règles YAML + fichiers de résultats + caches.

Pour prouver la garantie, on remplace la couche réseau (`httpx`) par un
transport simulé qui **refuse bruyamment tout appel** : si une de ces
opérations tentait d'accéder au réseau, le test échouerait explicitement."
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from tscan_core.correlation import run_correlation
from tscan_core.db import get_engine, get_session, init_db
from tscan_core.importers import import_file
from tscan_core.reporting import generate_report
from tscan_core.reporting.render_html import render_html

FIXTURES = Path(__file__).parent / "fixtures"


def _refuse_network(*args, **kwargs) -> httpx.Response:
    raise AssertionError("Appel réseau interdit : l'opération doit être strictement hors-ligne (RNF-14/15)")


@pytest.fixture()
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Coupe le réseau (httpx) pour toute la durée du test."""
    monkeypatch.setattr(httpx.Client, "request", _refuse_network)
    monkeypatch.setattr(httpx, "get", _refuse_network)
    monkeypatch.setattr(httpx, "post", _refuse_network)


def test_import_correlation_report_are_fully_offline(offline) -> None:
    """L'import multi-sources + la corrélation + le rapport ne font AUCUN
    appel réseau : la chaîne complète du Scénario A fonctionne hors-ligne."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_sample.jsonl")
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")
        updated = run_correlation(session, target="example.test")
        assert len(updated) == 5

        report = generate_report(session)
        assert report.total_findings == 5
        html = render_html(report)
        assert "example.test" in html


def test_scan_without_network_raises_but_leaves_trace(offline, lab_server) -> None:
    """Le scan actif, lui, exige le réseau : en coupure, il échoue avec une
    erreur explicite MAIS laisse une trace de scan en base (ES-05 :
    journalisation systématique, même en cas d'échec réseau."
    """
    from tscan_core.models import Scan
    from tscan_core.scan.config import ScanConfig
    from tscan_core.scan.orchestrator import run_recon_scan

    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        with pytest.raises(Exception) as exc_info:
            run_recon_scan(
                session,
                ScanConfig(target=f"{lab_server.base_url}/", authorized=True, max_duration_seconds=15),
            )
        assert "réseau" in str(exc_info.value) or "httpx" in str(exc_info.value)

        # La trace du scan est conservée malgré l'échec (ES-05).
        scans = session.query(Scan).all()
        assert len(scans) == 1
        assert scans[0].finished_at is None  # scan non terminé, mais journalisé