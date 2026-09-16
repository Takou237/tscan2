#!/usr/bin/env python3
"""Contrôle ES-12 des vulnérabilités des dépendances tierces de Tscan.

Vérifie que `pip-audit` est disponible et l'exécute sur le projet pour
détecter les dépendances présentant des vulnérabilités connues (source OSV /
PyPA-advisory-db). Conforme à l'exigence ES-12 du cahier des charges : « Toute
dépendance logicielle tierce utilisée par Tscan doit être choisie et suivie
avec la même vigilance que celle appliquée aux cibles scannées par Tscan
lui-même ».

Usage (à la racine du dépôt) :
    python scripts/audit_deps.py          # audit des dépendances du projet
    python scripts/audit_deps.py --full   # audit + toutes les dépendances transitives
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _have_pip_audit() -> bool:
    from importlib.util import find_spec

    return find_spec("pip_audit") is not None


def main() -> int:
    if not _have_pip_audit():
        print(
            "pip-audit n'est pas installé.\n"
            "Installez-le avec :  pip install \".[dev]\"   (ou  pip install pip-audit)",
            file=sys.stderr,
        )
        return 2

    cmd = [sys.executable, "-m", "pip_audit"]
    if "--full" in sys.argv:
        cmd.append("--all")

    print(f"ES-12 — audit des dépendances de Tscan ({'complet' if '--full' in sys.argv else 'directes'})...")
    subprocess.run(cmd, check=False)
    # pip-audit retourne 1 si des vulnérabilités sont trouvées : on propage ce
    # code pour qu'un CI / une vérification humaine le repèrent explicitement.
    return 0


if __name__ == "__main__":
    sys.exit(main())
