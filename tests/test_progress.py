"""Tests des événements de progression du scan actif (semaine 11).

Vérifie que `run_recon_scan` émet une suite cohérente de `ScanProgressEvent`
via `on_event` : première étape `start` (0 %), étapes intermédiaires avec les
sondes GET affichées, dernière étape `done` (100 %), progression monotone.
Le cœur reste indépendant de Qt : on enregistre simplement les événements
dans une liste, comme le fait l'interface desktop via un signal.
"""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.orchestrator import run_recon_scan
from tscan_core.scan.progress import ScanProgressEvent


def _config(lab_server, allowed_tests: set[str]) -> ScanConfig:
    return ScanConfig(
        target=f"{lab_server.base_url}/",
        authorized=True,
        max_duration_seconds=60,
        allowed_tests=frozenset(allowed_tests),
    )


def test_scan_emits_progress_events_from_start_to_done(lab_server) -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    events: list[ScanProgressEvent] = []
    with get_session(engine) as session:
        run_recon_scan(
            session,
            _config(
                lab_server,
                {"recon", "headers", "clickjacking", "bac", "xss", "cors"},
            ),
            on_event=events.append,
        )

    assert events, "le scan doit émettre au moins un événement"
    assert events[0].stage == "start"
    assert events[0].percent == 0
    assert events[-1].stage == "done"
    assert events[-1].percent == 100

    # Au minimum la sonde racine (GET) doit être affichée.
    assert any("GET " in e.message for e in events)

    # La progression, quand elle est connue, ne doit jamais reculer.
    percents = [e.percent for e in events if e.percent is not None]
    assert percents == sorted(percents)

    # Les étapes clés d'un scan complet sont présentes.
    stages = {e.stage for e in events}
    assert stages.issuperset({"start", "recon", "crawl", "checks", "detect", "done"})


def test_detections_forward_individual_get_probes(lab_server) -> None:
    """Les sondes de détection (famille en code) doivent remonter des GET
    individuels dans le journal de progression, à la manière des requêtes
    visibles dans OWASP ZAP."""
    engine = get_engine(":memory:")
    init_db(engine)

    events: list[ScanProgressEvent] = []
    with get_session(engine) as session:
        run_recon_scan(
            session,
            _config(lab_server, {"recon", "cors"}),
            on_event=events.append,
        )

    detect_gets = [
        e for e in events if e.stage == "detect" and e.message.startswith("GET ")
    ]
    assert detect_gets, "les sondes CORS doivent être affichées dans le journal"


def test_scan_no_progress_listener_is_safe(lab_server) -> None:
    """Sans écouteur, le scan se comporte exactement comme avant (rétro-compat)."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(
            session,
            _config(lab_server, {"recon", "headers"}),
        )
        assert outcome.scan_id > 0