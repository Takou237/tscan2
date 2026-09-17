"""Exécution asynchrone des opérations longues de l'interface desktop (RNF-03).

Ce module concentre tout ce qui touche aux opérations longues (import, scan,
corrélation, rapport) : un `TaskWorker` exécute une fonction métier dans un
fil séparé (`QThread`), de sorte que la boucle d'événements Qt reste libre et
que l'interface garde la main pendant l'opération -- c'est le critère RNF-03 de
la semaine 10.

Chaque tâche ouvre sa propre session sur la base locale, l'exécute toujours et
rattrape les exceptions pour les remonter à l'interface sans planter
l'application. Le résultat est émis via le signal `task_done(TaskResult)`.

Les fabriques (import_task, scan_task, correlate_task, report_task) construisent
la fonction de travail `(session) -> detail` ; le `main.py` enveloppe ensuite
cette fonction dans un `TaskWorker`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Signal

from tscan_core import db
from tscan_core.db import get_engine, init_db
from tscan_core.scan.blocking import detect_target_blocking


@dataclass
class TaskResult:
    """Résultat d'une opération longue remonté à l'interface."""

    ok: bool
    message: str
    detail: Any = None


class TaskWorker(QThread):
    """Exécute `run(session, emit)` dans un fil et émet `task_done(TaskResult)`.

    L'interface Qt ne bloque pas pendant l'exécution : la fonction est lancée
    dans un thread dédié et le résultat est renvoyé par signal (RNF-03). Toute
    exception est capturée et convertie en `TaskResult(ok=False, message=...)`.

    `progress_emitted` transporte les événements de progression (`ScanProgressEvent`,
    semaine 11) depuis le fil d'exécution vers l'interface : il est émis via le
    second argument `emit` passé à la fonction de travail, ce qui permet au scan
    actif de remonter ses opérations (GET, TLS, crawl…) en temps réel.
    """

    task_done = Signal(object)  # TaskResult
    progress_emitted = Signal(object)  # ScanProgressEvent
    request_emitted = Signal(object)  # RequestRecord (journal « History » ZAP)

    def __init__(
        self, run: Callable[[Any], Any], parent: Any | None = None
    ) -> None:
        super().__init__(parent)
        self._run = run

    def run(self) -> None:
        # Session dédiée à ce thread : la base locale est lue/écrite sans
        # partager la session du thread principal, ce qui évite les accès
        # concurrents à l'intérieur d'une même session SQLAlchemy.
        engine = get_engine(db.DEFAULT_DB_PATH)
        init_db(engine)
        try:
            with db.get_session(engine) as session:
                detail = self._run(
                    session,
                    self.progress_emitted.emit,
                    self.request_emitted.emit,
                )
        except Exception as exc:  # noqa: BLE001 - remonté à l'interface
            self.task_done.emit(
                TaskResult(ok=False, message=f"{type(exc).__name__}: {exc}")
            )
            return
        self.task_done.emit(TaskResult(ok=True, message="Opération terminée.", detail=detail))


# --- Fabriques de tâches ----------------------------------------------------


def import_task(
    path: str | Path, source: str, target: str, rex: bool = False
) -> Callable[[Any], dict]:
    """Construit une tâche d'import de fichier externe (RF-01).

    `rex=True` enrichit l'import d'une ré-observation active (détection de faux
    positifs) : un scan actif Tscan est relancé sur la cible, ses constats sont
    corrélés avec ceux de l'import, et les constats importés dont le fait
    décisif n'est plus reproduit sont placés en « potentiel faux positif ».
    """

    def run(session, emit=None, on_request=None) -> dict:
        from tscan_core.importers import import_file
        from tscan_core.importers.reobserve_service import reobserve_imported_scan

        scan = import_file(session, source=source, target=target, file_path=Path(path))
        payload = {"scan_id": scan.id, "count": len(scan.findings), "source": source}
        if rex:
            outcome = reobserve_imported_scan(
                session,
                scan.id,
                on_event=emit,
                on_request=on_request,
            )
            payload["rex"] = {
                "active_scan_id": outcome.active_scan_id,
                "total": outcome.total,
                "reproduced": outcome.reproduced,
                "potential_false_positives": outcome.potential_false_positives,
                "not_reproducible": outcome.not_reproducible,
                "flagged": outcome.flagged,
                "blocked": outcome.blocked,
                "blocked_reason": outcome.blocked_reason,
                "root_status_code": outcome.root_status_code,
                "pages_crawled": outcome.pages_crawled,
            }
        return payload

    return run


def correlate_task(
    target: str | None = None, rex: bool = False
) -> Callable[[Any], dict]:
    """Construit une tâche de corrélation/scoring (RF-08 à RF-10).

    `rex=True` déclenche, pendant la corrélation, une ré-observation ciblée
    par URL des constats importés non corroborés : une ressource introuvable
    (404/410) place le constat en « potentiel faux positif » (RF-23).
    L'opération est best-effort — une panne réseau laisse le constat tel quel.
    """

    def run(session, emit=None, on_request=None) -> dict:
        from tscan_core.correlation import run_correlation
        from tscan_core.models import FindingStatus

        updated = run_correlation(session, target=target, reobserve=rex)
        return {
            "count": len(updated),
            "probable": sum(
                1 for f in updated if f.status == FindingStatus.PROBABLE
            ),
            "potential_false_positives": sum(
                1
                for f in updated
                if f.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            ),
        }

    return run


def scan_task(scan_kwargs: dict) -> tuple[Callable[[Any], dict], Any]:
    """Construit une tâche de scan actif (RF-15 à RF-23).

    `scan_kwargs` contient les champs de `ScanConfig` (target, authorized,
    max_depth, max_duration_seconds, allowed_tests, safe_mode, verify_tls),
    déjà validés par le formulaire de l'interface.

    Retourne `(run, interrupt)` : l'interface garde le `ScanInterrupt` pour
    proposer un bouton « Arrêter » (parité OWASP ZAP) qui arrête le scan au
    prochain point d'arrêt sans perdre les constats déjà enregistrés.
    """
    from tscan_core.scan.interrupt import ScanInterrupt

    interrupt = ScanInterrupt()

    def run(session, emit=None, on_request=None) -> dict:
        from tscan_core.scan.config import ScanConfig
        from tscan_core.scan.orchestrator import run_recon_scan

        config = ScanConfig(**scan_kwargs)
        # `emit` remonte chaque `ScanProgressEvent` (GET, TLS, crawl,
        # détections, re-vérifications) vers le panneau de progression.
        # `on_request` remonte chaque requête HTTP structurée (journal
        # « History » ZAP) vers le tableau de requêtes.
        # `interrupt` permet l'arrêt manuel (bouton « Arrêter »).
        outcome = run_recon_scan(
            session,
            config,
            on_event=emit,
            on_request=on_request,
            interrupt=interrupt,
        )
        return {
            "scan_id": outcome.scan_id,
            "target": outcome.target,
            "findings": len(outcome.findings),
            "interrupted": outcome.interrupted,
            "blocked": _target_blocked(outcome.recon_observations),
        }

    return run, interrupt


def _target_blocked(recon: dict | None) -> dict | None:
    """Détecte qu'une cible a refusé le scan (racine 401/403/429, échec de la
    sonde racine) et retourne le détail de l'avertissement à afficher — None
    si le scan s'est déroulé normalement. S'appuie sur l'heuristique partagée
    `scan.blocking` (même source de vérité que la CLI et la ré-observation)."""
    blocked, reasons = detect_target_blocking(recon)
    if not blocked:
        return None
    return {"reasons": reasons}




def report_task(
    output_path: str | Path, fmt: str, target: str | None = None
) -> Callable[[Any], dict]:
    """Construit une tâche de génération de rapport (RF-27 à RF-29).

    `target` limite le rapport à une cible (la liste exhaustive par défaut).
    `fmt` vaut 'html' ou 'markdown'.
    """

    def run(session, emit=None, on_request=None) -> dict:
        from tscan_core.reporting import generate_report
        from tscan_core.reporting.render_html import render_html
        from tscan_core.reporting.render_markdown import render_markdown

        report = generate_report(session, target=target)
        rendered = render_html(report) if fmt == "html" else render_markdown(report)
        Path(output_path).write_text(rendered, encoding="utf-8")
        return {
            "path": str(output_path),
            "chars": len(rendered),
            "count": report.total_findings,
        }

    return run