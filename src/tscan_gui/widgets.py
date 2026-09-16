"""Widgets Qt de l'interface desktop Tscan (S10).

Cette couche fait le lien inverse du `viewmodel.py` : elle ne contient AUCUN
code métier (requêtes, filtrage, correction...), elle appelle simplement les
fonctions du viewmodel et traduit leurs résultats en éléments d'interface
Qt. C'est la séparation décrite au chapitre 10 (présentation découplée du
cœur) et détaillée dans le docstring de `viewmodel.py`.

Contenu :
- `FilterState` : état courant des filtres (recherche, statut, gravité, cible).
- `FilterBar` : bandeau de filtres au-dessus de la liste.
- `FindingsTable` : tableau des résultats (RF-11), triable et filtré.
- `FindingDetailPanel` : panneau de détail d'un résultat (preuves, score,
  historique de statut, correction manuelle RF-12).

Aucun de ces widgets n'exécute d'opération longue (import, scan) : ceux-là
seront confiés à `workers.py` (RNF-03) pour garder l'interface réactive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from tscan_gui.viewmodel import VALID_STATUSES, FindingDetail, FindingRow

# Couleurs d'arrière-plan ordonnées de la gravité la plus critique à la plus
# faible. Le tri de la table réordonne la liste, mais chaque ligne garde sa
# couleur, ce qui reste lisible quel que soit le tri.
_SEVERITY_PALETTE: dict[str, QColor] = {
    "critical": QColor("#d9534f"),
    "high": QColor("#f0ad4e"),
    "medium": QColor("#f7e200"),
    "low": QColor("#5cb85c"),
    "info": QColor("#5bc0de"),
}


@dataclass(frozen=True)
class FilterState:
    """Filtres actifs sur la liste des résultats.

    Tous les champs sont transitifs : `None` (ou texte vide pour la
    recherche) signifie « pas de filtre sur cette dimension ».
    """

    text: str | None = None
    status: str | None = None
    severity: str | None = None
    target: str | None = None

    def as_dict(self) -> dict:
        """Transforme l'état en arguments nommés pour `list_findings`."""
        return {
            "query_text": self.text or None,
            "status": self.status,
            "severity": self.severity,
            "target": self.target,
        }


class FilterBar(QWidget):
    """Bandeau des filtres (texte, statut, gravité, cible).

    Émet `filters_changed` dès qu'un filtre change, en emportant un
    `FilterState` récapitulant la sélection courante.
    """

    filters_changed = Signal(object)  # FilterState

    def __init__(self, targets: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)

        layout = QVBoxLayout(self)

        # Ligne 1 : recherche plein texte + bouton de réinitialisation.
        search_row = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Rechercher (titre, catégorie, URL)...")
        self.search_edit.textChanged.connect(self._on_change)
        reset_btn = QPushButton("Réinitialiser")
        reset_btn.clicked.connect(self.reset)
        search_row.addWidget(self.search_edit, stretch=1)
        search_row.addWidget(reset_btn)
        layout.addLayout(search_row)

        # Ligne 2 : statut, gravité et cible.
        from tscan_gui.viewmodel import status_label

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Statut :"))
        self.status_combo = QComboBox()
        self.status_combo.addItem("Tous", None)
        for value in VALID_STATUSES:
            self.status_combo.addItem(status_label(value), value)
        self.status_combo.currentIndexChanged.connect(self._on_change)
        filter_row.addWidget(self.status_combo)

        filter_row.addWidget(QLabel("Gravité :"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("Toutes", None)
        for value in ("critical", "high", "medium", "low", "info"):
            self.severity_combo.addItem(value, value)
        self.severity_combo.currentIndexChanged.connect(self._on_change)
        filter_row.addWidget(self.severity_combo)

        filter_row.addWidget(QLabel("Cible :"))
        self.target_combo = QComboBox()
        self.target_combo.addItem("Toutes", None)
        for target in targets:
            self.target_combo.addItem(target, target)
        self.target_combo.currentIndexChanged.connect(self._on_change)
        filter_row.addWidget(self.target_combo)

        filter_row.addStretch()
        layout.addLayout(filter_row)

    def state(self) -> FilterState:
        """Récupère l'état courant des filtres."""
        return FilterState(
            text=self.search_edit.text().strip(),
            status=self.status_combo.currentData(),
            severity=self.severity_combo.currentData(),
            target=self.target_combo.currentData(),
        )

    def refresh_targets(self, targets: list[str]) -> None:
        """Met à jour la liste des cibles sans casser la sélection courante."""
        selected = self.target_combo.currentData()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self.target_combo.addItem("Toutes", None)
        for target in targets:
            self.target_combo.addItem(target, target)
        idx = self.target_combo.findData(selected) if selected in targets else 0
        self.target_combo.setCurrentIndex(max(idx, 0))
        self.target_combo.blockSignals(False)

    def reset(self) -> None:
        """Réinitialise tous les filtres puis émet `filters_changed`."""
        self.search_edit.clear()
        self.status_combo.setCurrentIndex(0)
        self.severity_combo.setCurrentIndex(0)
        self.target_combo.setCurrentIndex(0)
        self._on_change()

    def _on_change(self) -> None:
        self.filters_changed.emit(self.state())


class FindingsTable(QTableWidget):
    """Table filtrable des résultats (RF-11).

    La table est en lecture seule et triable ; chaque sélection émet
    `finding_selected` avec l'identifiant du résultat concerné.
    """

    finding_selected = Signal(int)  # finding_id

    _HEADERS: ClassVar[list[str]] = ["ID", "Gravité", "Statut", "Catégorie", "Titre", "Instances", "Cible", "URL", "Score"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, len(self._HEADERS), parent)
        self.setHorizontalHeaderLabels(self._HEADERS)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSortingEnabled(True)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        self.itemSelectionChanged.connect(self._on_selection)

    def populate(self, rows: list[FindingRow]) -> None:
        """Remplit la table à partir de lignes fournies par le viewmodel."""
        from tscan_gui.viewmodel import status_label

        self.setSortingEnabled(False)  # évite le tri pendant le remplissage
        self.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            cells = (
                str(row.id),
                row.severity,
                status_label(row.status),
                row.category,
                row.title,
                str(row.instance_count),
                row.target,
                f"{row.matched_at or ''}".split("/")[-1] if row.matched_at else "",
                f"{row.score:.2f}" if row.score is not None else "--",
            )
            for col_idx, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col_idx == 1:  # gravité -> fond coloré
                    item.setBackground(self._palette(row.severity))
                self.setItem(row_idx, col_idx, item)
        self.setSortingEnabled(True)

    def _palette(self, severity: str) -> QColor:
        return _SEVERITY_PALETTE.get(severity.lower(), QColor("#ffffff"))

    def _on_selection(self) -> None:
        rows = self.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        id_item = self.item(row, 0)
        if id_item is not None:
            self.finding_selected.emit(int(id_item.text()))


class FindingDetailPanel(QGroupBox):
    """Détail d'un résultat : description, preuves, score, historique et
    correction manuelle de statut (RF-11, RF-12, ES-06)."""

    status_submitted = Signal(int, str, str)  # finding_id, new_status, reason

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Détail du résultat", parent)

        # Le panneau de détail ne doit jamais être écrasé par le splitter :
        # une largeur minimale lisible est garantie (description, preuves et
        # explication restent exploitables même en petite fenêtre).
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        self.title_label = QLabel("(aucun résultat sélectionné)")
        self.title_label.setWordWrap(True)
        layout.addWidget(self.title_label)

        self.meta_label = QLabel("")
        self.meta_label.setWordWrap(True)
        layout.addWidget(self.meta_label)

        self.description = QTextEdit()
        self.description.setReadOnly(True)
        self.description.setMaximumHeight(120)
        layout.addWidget(QLabel("Description :"))
        layout.addWidget(self.description)

        self.evidences_list = QTextEdit()
        self.evidences_list.setReadOnly(True)
        layout.addWidget(QLabel("Preuves :"))
        layout.addWidget(self.evidences_list)

        self.explanation_text = QTextEdit()
        self.explanation_text.setReadOnly(True)
        self.explanation_text.setMaximumHeight(100)
        layout.addWidget(QLabel("Explication du score :"))
        layout.addWidget(self.explanation_text)

        self.history_text = QTextEdit()
        self.history_text.setReadOnly(True)
        layout.addWidget(QLabel("Historique de statut :"))
        layout.addWidget(self.history_text)

        # Correction manuelle (RF-12).
        from tscan_gui.viewmodel import status_label as _status_label

        correct_row = QHBoxLayout()
        correct_row.addWidget(QLabel("Corriger le statut :"))
        self.status_combo = QComboBox()
        for value in VALID_STATUSES:
            self.status_combo.addItem(_status_label(value), value)
        correct_row.addWidget(self.status_combo)
        self.apply_btn = QPushButton("Appliquer")
        self.apply_btn.clicked.connect(self._submit_status)
        correct_row.addWidget(self.apply_btn)
        layout.addLayout(correct_row)

        # Raison du changement (ES-06) : consignée dans l'historique de statut.
        reason_row = QHBoxLayout()
        reason_row.addWidget(QLabel("Raison (optionnel) :"))
        self.reason_edit = QLineEdit()
        self.reason_edit.setPlaceholderText("Justification du changement de statut...")
        reason_row.addWidget(self.reason_edit, stretch=1)
        layout.addLayout(reason_row)

    def show_detail(self, detail: FindingDetail) -> None:
        """Affiche les informations d'un résultat (transformation présentation)."""
        self.title_label.setText(f"#{detail.id} — {detail.title}")
        self.meta_label.setText(self._format_meta(detail))
        self.description.setText(detail.description or "(aucune description)")
        self.evidences_list.setText(self._format_evidences(detail))
        self.explanation_text.setText(self._format_explanation(detail))
        self.history_text.setText(self._format_history(detail) or "(aucun historique)")
        self.status_combo.setCurrentIndex(self._status_index(detail.status))
        self.reason_edit.clear()

    def _format_meta(self, detail: FindingDetail) -> str:
        from tscan_gui.viewmodel import status_label

        parts = [
            f"Gravité : {detail.severity}",
            f"Statut : {status_label(detail.status)}",
            f"Score : {f'{detail.score:.2f}' if detail.score is not None else '--'}",
            f"Catégorie : {detail.category}",
            f"Cible : {detail.target}",
            f"Source : {detail.source}",
        ]
        if detail.external_id:
            parts.append(f"ID externe : {detail.external_id}")
        if detail.matched_at:
            parts.append(f"Détecté : {detail.matched_at}")
        return "\n".join(parts)

    def _format_evidences(self, detail: FindingDetail) -> str:
        if not detail.evidences:
            return "(aucune preuve)"
        return "\n---\n".join(detail.evidences)

    def _format_explanation(self, detail: FindingDetail) -> str:
        if not detail.score_explanation:
            return "(aucune explication)"
        return "\n".join(detail.score_explanation)

    def _format_history(self, detail: FindingDetail) -> str:
        return "\n".join(detail.history)

    def _status_index(self, current: str) -> int:
        for idx in range(self.status_combo.count()):
            if self.status_combo.itemData(idx) == current:
                return idx
        return 0

    def _submit_status(self) -> None:
        value = self.status_combo.currentData()
        if value is None or self._current_id is None:
            return
        reason = self.reason_edit.text().strip() or None
        self.status_submitted.emit(self._current_id, value, reason)

    @property
    def _current_id(self) -> int | None:
        text = self.title_label.text()
        if text.startswith("#") and " — " in text:
            try:
                return int(text.split(" ", 1)[0][1:])
            except ValueError:
                return None
        return None


class ScanProgressPanel(QGroupBox):
    """Panneau de suivi temps réel d'un scan actif (semaine 11).

    Affiché sous la liste des résultats : une barre de progression globale, un
    libellé d'étape et le journal des opérations effectuées (GET, sondes TLS,
    crawl, détections, re-vérifications). Chaque `ScanProgressEvent` émis par
    le moteur de scan (fil d'exécution) remonte ici via un signal Qt, ce qui
    garde la fenêtre vivante pendant un scan long (RNF-03), à la manière
    d'OWASP ZAP.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Progression du scan actif", parent)
        layout = QVBoxLayout(self)

        self.stage_label = QLabel("Prêt.")
        layout.addWidget(self.stage_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(4000)
        self.log.setMaximumHeight(140)
        self.log.setPlaceholderText(
            "Le déroulement du scan (GET /app, crawl, détections…) apparaîtra ici."
        )
        layout.addWidget(self.log)

    def reset(self) -> None:
        """Réinitialise le panneau avant le lancement d'un scan."""
        self.progress.setValue(0)
        self.stage_label.setText("Scan en cours…")
        self.log.clear()

    def append_event(self, event) -> None:
        """Consomme un `ScanProgressEvent` et actualise l'affichage."""
        if event.percent is not None:
            self.progress.setValue(event.percent)
        if event.stage == "start":
            self.log.clear()
            self.stage_label.setText("Scan en cours…")
        self.log.appendPlainText(event.message)
        if event.stage == "error":
            self.stage_label.setText("Échec du scan — voir le journal.")
            self.progress.setValue(0)
        elif event.stage == "done":
            self.stage_label.setText(event.message)
            self.progress.setValue(100)

    def notify_failure(self, message: str) -> None:
        """Affiche une erreur de scan dans le journal."""
        self.log.appendPlainText(f"[erreur] {message}")
        self.stage_label.setText("Échec du scan — voir le journal.")
        self.progress.setValue(0)


class RequestHistoryPanel(QGroupBox):
    """Tableau des requêtes HTTP d'un scan (format « History » d'OWASP ZAP).

    Chaque requête envoyée pendant le scan (crawl, détections, re-vérifications)
    est affichée sur une ligne : ID, horodatage d'envoi, horodatage de réception
    (fuseau WAT), méthode, URL, code de statut et raison de la réponse. Les
    entrées arrivent en temps réel via `append_record(RequestRecord)`.
    """

    _HEADERS = ("#", "Envoyé", "Reçu", "Méthode", "URL", "Code", "Raison")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Historique des requêtes (History)", parent)
        layout = QVBoxLayout(self)

        self.table = QTableWidget(0, len(self._HEADERS))
        self.table.setHorizontalHeaderLabels(self._HEADERS)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

    def reset(self) -> None:
        """Vide le tableau avant le lancement d'un nouveau scan."""
        self.table.setRowCount(0)

    def append_record(self, record) -> None:
        """Consomme un `RequestRecord` et l'affiche dans le tableau."""
        row = self.table.rowCount()
        self.table.insertRow(row)
        values = (
            str(record.id),
            record.sent_at,
            record.received_at,
            record.method,
            record.url,
            str(record.status_code) if record.status_code is not None else "—",
            record.reason or "",
        )
        for col, value in enumerate(values):
            self.table.setItem(row, col, QTableWidgetItem(value))
        self.table.scrollToBottom()