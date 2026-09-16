"""Tests de l'arrêt manuel du scan (RF-XX, parité OWASP ZAP).

Vérifie qu'un scan non borné peut être interrompu proprement via
``ScanInterrupt`` : le scan s'arrête au prochain point d'arrêt, le résultat
retourne ``interrupted=True``, et les constats déjà enregistrés sont conservés
(même comportement que le bouton « Arrêter » / Ctrl+C du CLI).

La cible est le serveur de laboratoire local (fixture ``lab_server``) : aucune
ressource externe n'est contactée (ES-09).
"""

from __future__ import annotations

import threading

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.interrupt import ScanInterrupt
from tscan_core.scan.orchestrator import run_recon_scan


def _config(lab_server, **overrides) -> ScanConfig:
    defaults = {
        "target": f"{lab_server.base_url}/",
        "authorized": True,
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


def test_scan_interrupt_reports_interrupted_and_keeps_findings(lab_server) -> None:
    """Un scan non borné interrompu en cours de route signale `interrupted` et
    conserve les constats déjà trouvés (parité ZAP : arrêt propre)."""
    interrupt = ScanInterrupt()
    outcome_holder = {}

    def on_event(event) -> None:
        # La détection active démarre APRÈS que les constats déclaratifs
        # (en-têtes, clickjacking, BAC) sont déjà persistés : demander l'arrêt
        # à ce stade garantit qu'au moins un constat est conservé, sans dépendre
        # d'un chronométrage fragile (le scan sur le laboratoire local est rapide).
        if event.stage == "detect":
            interrupt.stop()

    def run() -> None:
        # Base SQLite en mémoire : créée et utilisée uniquement dans ce thread
        # (une base `:memory:` n'est visible que de sa propre connexion).
        engine = get_engine(":memory:")
        init_db(engine)
        with get_session(engine) as session:
            outcome_holder["outcome"] = run_recon_scan(
                session,
                _config(lab_server),
                interrupt=interrupt,
                on_event=on_event,
            )
            outcome_holder["findings"] = len(session.query(Finding).all())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    # La demande d'arrêt est émise par `on_event` dès le début de la détection
    # active ; il ne reste qu'à attendre la fin du scan.
    thread.join(timeout=60)

    outcome = outcome_holder["outcome"]
    assert outcome.interrupted is True
    assert outcome_holder["findings"] >= 1
