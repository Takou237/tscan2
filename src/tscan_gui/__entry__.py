"""Point d'entrée pour l'exécutable PyInstaller de l'application desktop.

Le `.spec` vise ce module ; il lance la fenêtre principale Qt après
l'analyse complète des dépendances (PySide6, workers QThread, etc.).
"""

from tscan_gui.main import main

if __name__ == "__main__":
    main()
