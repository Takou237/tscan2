"""Dialogues de l'application desktop Tscan (S10).

`ImportDialog`, `ScanDialog` et `ReportDialog` collectent les paramètres
des actions longues (import, scan actif autorisé, rapport) ; chaque dialogue
expose `config_kwargs()` prêt pour la fabrique de tâche de `workers.py`.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


class ImportDialog(QDialog):
    """Fichier à importer (RF-01), source et cible concernée."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Importer un résultat de scanner")

        form = QFormLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setReadOnly(True)
        browse = QPushButton("Parcourir…")
        browse.clicked.connect(self._browse)
        file_row = QHBoxLayout()
        file_row.addWidget(self.file_edit, stretch=1)
        file_row.addWidget(browse)
        form.addRow("Fichier :", file_row)

        self.source_combo = QComboBox()
        for value in ("nuclei", "zap", "nessus", "openvas"):
            self.source_combo.addItem(value, value)
        form.addRow("Source :", self.source_combo)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("https://example.test/")
        form.addRow("Cible concernée :", self.target_edit)

        self.rex = QCheckBox("Lancer une ré-observation active (détecter d'éventuels faux positifs)")
        self.rex.setToolTip(
            "Après l'import, relance un scan actif Tscan sur la cible, corrèle les "
            "constats importés et place en « potentiel faux positif » ceux dont le "
            "fait décisif n'est plus reproduit (autorisation implicite)."
        )
        form.addRow(self.rex)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choisir un résultat de scanner")
        if path:
            self.file_edit.setText(path)

    def _on_accept(self) -> None:
        if not self.file_edit.text().strip():
            QMessageBox.warning(self, "Champ requis", "Sélectionnez un fichier à importer.")
            return
        if not self.target_edit.text().strip():
            QMessageBox.warning(self, "Champ requis", "Indiquez la cible concernée.")
            return
        self.accept()

    def config_kwargs(self) -> dict:
        return {
            "path": self.file_edit.text().strip(),
            "source": self.source_combo.currentData(),
            "target": self.target_edit.text().strip(),
            "rex": self.rex.isChecked(),
        }


class ScanDialog(QDialog):
    """Périmètre d'un scan actif : cible autorisée (ES-01), durée/profondeur/
    types de test (ES-02). Le mode sécurisé non destructif est le défaut (ES-03)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Lancer un scan actif (cible autorisée)")

        form = QFormLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("https://example.test/")
        form.addRow("Cible (autorisée, http/https) :", self.target_edit)

        self.authorized = QCheckBox("Je confirme explicitement que cette cible est autorisée")
        form.addRow(self.authorized)

        self.duration_spin = QSpinBox()
        # 0 = aucune limite (parité OWASP ZAP : le scan s'arrête à l'épuisement
        # du crawl ou quand l'utilisateur clique sur « Arrêter »).
        self.duration_spin.setRange(0, 3600)
        self.duration_spin.setValue(0)
        self.duration_spin.setSuffix(" s")
        self.duration_spin.setSpecialValueText("Aucune limite (défaut)")
        form.addRow("Durée maximale (0 = aucune) :", self.duration_spin)

        self.depth_spin = QSpinBox()
        # 0 = aucune profondeur maximale : le crawl explore toutes les pages
        # du site, comme le spider d'OWASP ZAP.
        self.depth_spin.setRange(0, 50)
        self.depth_spin.setValue(0)
        self.depth_spin.setSpecialValueText("Aucune limite (défaut)")
        form.addRow("Profondeur de crawl (0 = aucune) :", self.depth_spin)

        self.tests_edit = QLineEdit()
        self.tests_edit.setPlaceholderText("vide = toutes les détections (headers, xss, csrf, sqli…)")
        form.addRow(
            "Types de test (optionnel) :",
            self.tests_edit,
        )

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        if not self.target_edit.text().strip():
            QMessageBox.warning(self, "Champ requis", "Précisez une cible (URL http/https).")
            return
        if not self.authorized.isChecked():
            QMessageBox.warning(
                self,
                "Autorisation requise (ES-01)",
                "Confirmez explicitement que la cible est autorisée avant de scanner.",
            )
            return
        self.accept()

    def config_kwargs(self) -> dict:
        kwargs: dict = {
            "target": self.target_edit.text().strip(),
            "authorized": self.authorized.isChecked(),
        }
        if self.duration_spin.value() > 0:
            kwargs["max_duration_seconds"] = self.duration_spin.value()
        if self.depth_spin.value() > 0:
            kwargs["crawl_max_depth"] = self.depth_spin.value()
            kwargs["max_depth"] = self.depth_spin.value()
        tests = self.tests_edit.text().strip()
        if tests:
            kwargs["allowed_tests"] = frozenset(
                part.strip() for part in tests.split(",") if part.strip()
            )
        return kwargs
class CorrelateDialog(QDialog):
    """Corrélation des résultats importés : cible optionnelle et ré-observation
    ciblée par URL (détection de faux positifs pendant la corrélation, RF-23)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Corréler les résultats")

        form = QFormLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("(vide = toutes les cibles)")
        form.addRow("Cible (optionnel) :", self.target_edit)

        self.reobserve = QCheckBox(
            "Ré-observer les URLs des constats importés (détecter les faux positifs)"
        )
        self.reobserve.setChecked(True)
        self.reobserve.setToolTip(
            "Pendant la corrélation, vérifie la disponibilité des ressources des "
            "constats importés non corroborés : une ressource introuvable (404/410) "
            "place le constat en « potentiel faux positif ». Best-effort : en l'absence "
            "de réseau, les constats restent tels quels."
        )
        form.addRow(self.reobserve)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def config_kwargs(self) -> dict:
        return {
            "target": self.target_edit.text().strip() or None,
            "rex": self.reobserve.isChecked(),
        }


class ReportDialog(QDialog):
    """Génération d'un rapport : fichier de sortie (HTML/Markdown) et cible
    optionnelle (RF-27 à RF-29)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Générer un rapport")

        form = QFormLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setReadOnly(True)
        browse = QPushButton("Parcourir…")
        browse.clicked.connect(self._browse)
        file_row = QHBoxLayout()
        file_row.addWidget(self.file_edit, stretch=1)
        file_row.addWidget(browse)
        form.addRow("Fichier de sortie :", file_row)

        self.fmt_combo = QComboBox()
        self.fmt_combo.addItem("HTML", "html")
        self.fmt_combo.addItem("Markdown", "markdown")
        form.addRow("Format :", self.fmt_combo)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("(vide = toutes les cibles)")
        form.addRow("Cible (optionnel) :", self.target_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Enregistrer le rapport",
            "tscan_report.html",
            "Rapports (*.html *.md);;Tous les fichiers (*)",
        )
        if path:
            self.file_edit.setText(path)

    def _on_accept(self) -> None:
        if not self.file_edit.text().strip():
            QMessageBox.warning(self, "Champ requis", "Choisissez un fichier de sortie.")
            return
        self.accept()

    def config_kwargs(self) -> dict:
        return {
            "output_path": self.file_edit.text().strip(),
            "fmt": self.fmt_combo.currentData(),
            "target": self.target_edit.text().strip() or None,
        }
