"""Application desktop de Tscan (RF-32).

Squelette de la semaine 3 : une fenêtre minimale, juste assez pour valider
que PySide6 est correctement installé et que l'application se lance. La
véritable interface (liste des résultats, filtres, vue de preuves...) sera
construite à la semaine 10 du planning, une fois le cœur Tscan validé en CLI.

Notes pour la prise en main de PySide6 (aucune expérience préalable, comme
prévu au chapitre 11) :
- `QApplication` est l'objet unique qui gère la boucle d'événements de toute
  application Qt ; il n'en existe qu'une seule instance par programme.
- Un `QMainWindow` fournit la structure de base d'une fenêtre (zone centrale,
  barre de titre...). Le contenu affiché est confié à un widget central,
  ici un simple `QLabel`.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QLabel, QMainWindow


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Tscan")
        self.resize(800, 600)

        label = QLabel(
            "Tscan -- squelette de l'application desktop\n"
            "(semaine 3 : interface réelle prévue en semaine 10)"
        )
        label.setContentsMargins(20, 20, 20, 20)
        self.setCentralWidget(label)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
