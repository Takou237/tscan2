"""Point d'entrée pour l'exécutable PyInstaller de la CLI Tscan.

Le `.spec` vise ce module plutôt que `tscan_cli.main:app` : PyInstaller
analyse un module exécutable plus fiable qu'un objet Typer référencé par
un point d'entrée de console.
"""

from tscan_cli.main import app

if __name__ == "__main__":
    app()
