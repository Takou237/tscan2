"""Interruption manuelle d'un scan actif (parité OWASP ZAP).

OWASP ZAP laisse l'utilisateur interrompre à tout moment un scan en cours
(bouton Stop) ; Tscan reproduit ce comportement : un `ScanInterrupt` est un
simple drapeau thread-safe que l'interface (bouton GUI, ou Ctrl+C en CLI)
peut lever pour demander au scan de s'arrêter proprement au prochain point
d'arrêt (« binding point » : chaque requête, chaque grande étape).

Le moteur de scan (`tscan_core.scan.orchestrator`) vérifie ce drapeau aux
mêmes endroits que `check_deadline` : dès qu'il est levé, il arrête le crawl
et les détections en cours et clôture le scan avec le statut interrompu, sans
perdre les constats déjà enregistrés — exactement comme un arrêt utilisateur
dans ZAP.
"""

from __future__ import annotations

import threading


class ScanCancelledError(Exception):
    """Levée lorsqu'un scan est interrompu manuellement par l'utilisateur."""


class ScanInterrupt:
    """Drapeau thread-safe d'interruption d'un scan.

    `stop()` est appelé depuis le fil de l'interface (GUI) ou un gestionnaire
    de signal (CLI) ; `is_set()` est vérifié depuis le fil du scan. Toutes les
    méthodes sont thread-safe.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def stop(self) -> None:
        """Demande l'arrêt du scan en cours."""
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def clear(self) -> None:
        """Réinitialise le drapeau (pour un scan ensuite)."""
        self._event.clear()
