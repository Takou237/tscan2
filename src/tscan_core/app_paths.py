"""Résolution des chemins des données embarquées (règles, connaissances).

En développement, le dépôt contient `rules/` et `knowledge/` à sa racine ;
les modules concernés résolvent ces chemins relativement à `__file__`.

Dans un exécutable PyInstaller (mode « one-file » ou « one-dir »), les
fichiers de données déclarées dans le fichier `.spec` sont extraits à côté
du binaire (`sys._MEIPASS` en one-file) : la résolution par `__file__` ne
fonctionne plus. Cette fonction centrale donne le bon chemin dans les deux
cas, de sorte qu'ajouter une règle ou un fichier de connaissance ne demande
aucune modification du code (BNF-10).
"""

from __future__ import annotations

import sys
from pathlib import Path


def data_root() -> Path:
    """Racine contenant `rules/` et `knowledge/`.

    - Exécutable PyInstaller : dossier des données déclarées dans le `.spec`
      (`sys._MEIPASS` en one-file, dossier `_internal` en one-dir).
    - Environnement de développement : racine du dépôt (3 niveaux au-dessus
      de `src/tscan_core/`).
    """
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root is not None:
        return Path(frozen_root)
    return Path(__file__).resolve().parents[2]
