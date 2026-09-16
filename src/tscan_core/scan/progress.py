"""Événements de progression du scan actif (semaine 11).

Le moteur de scan (`tscan_core.scan.orchestrator`) émet un
`ScanProgressEvent` à chaque étape observable d'un scan en cours : sondes
GET, contrôle TLS, fingerprinting, crawl, détections, re-vérifications.
Les interfaces (CLI, desktop) peuvent écouter ces événements pour afficher
une barre de progression et un journal des opérations en temps réel, à la
manière d'OWASP ZAP.

Le cœur reste totalement agnostique de Qt : l'événement est une simple
structure de données, et la fonction `notify` ne fait rien quand aucun
écouteur n'est fourni (comportement rétro-compatible : les appels
existants n'ont pas à passer `on_event`).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProgressEvent:
    """Une étape observable du scan, destinée à l'affichage.

    - `stage` : famille d'étape (`start`, `recon`, `tls`, `fingerprint`,
      `crawl`, `checks`, `detect`, `confirm`, `error`, `done`).
    - `message` : texte affichable tel quel (ex. « GET https://… -> 200 »).
    - `percent` : avancement global 0-100 quand il est connu, sinon `None`
      (l'interface garde alors sa position courante).
    """

    stage: str
    message: str
    percent: int | None = None


def notify(
    listener: Callable[[ScanProgressEvent], None] | None,
    stage: str,
    message: str,
    percent: int | None = None,
) -> None:
    """Émet `ScanProgressEvent` vers l'écouteur s'il en existe un.

    Le listener est toujours appelé depuis le fil qui exécute le scan ; les
    interfaces le transportent vers leur fil d'affichage (Qt : signal).
    """
    if listener is not None:
        listener(ScanProgressEvent(stage=stage, message=message, percent=percent))