"""Fixtures partagées de la suite de tests Tscan.

Le serveur de laboratoire (`lab_server`) est la cible de test locale,
contrôlée et autorisée, utilisée par les tests d'intégration du moteur de
scan actif (semaine 7 et suivantes) : aucune ressource externe n'est jamais
contactée par la suite de tests.
"""

from __future__ import annotations

import pytest
from lab_server import LabServer


@pytest.fixture(scope="session")
def lab_server() -> LabServer:
    server = LabServer()
    server.start()
    yield server
    server.stop()
