"""Widgets Qt de l'interface desktop Tscan (S10).

Cette couche fait le lien inverse du `viewmodel.py` : elle ne contient AUCUN
code métier (requêtes, filtrage, correction...), elle appelle simplement les
fonctions du viewmodel et traduit leurs résultats en éléments d'interface
Qt. C'est la séparation décrite au chapitre 10 (présentation découplée du
cœur) et détaillée dans le docstring de `viewmodel.py`.

Contenu :
- `FilterState` : état courant des filtres (recherche, statut, gravité, cible).
- `FilterBar` : bandeau de filtres au-dessus de la liste (avec compteur).
- `FindingsTable` : tableau des résultats (RF-11), triable et filtré.
- `FindingDetailPanel` : panneau de détail d'un résultat (preuves, score,
  historique de statut, correction manuelle RF-12).

Toutes les couleurs (pastilles de gravité/statut, couleurs de fond) viennent de
`tscan_gui.theme` : ce module ne contient aucune valeur de couleur en dur, ce
qui garantit la lisibilité dans les deux thèmes (clair / sombre).

Aucun de ces widgets n'exécute d'opération longue (import, scan) : ceux-là
seront confiés à `workers.py` (RNF-03) pour garder l'interface réactive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtGui import QColor, QResizeEvent
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
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from tscan_gui.theme import severity_badge, status_badge
from tscan_gui.viewmodel import (
    SEVERITY_ORDER,
    VALID_STATUSES,
    FindingDetail,
    FindingRow,
    severity_label,
    severity_rank,
    status_label,
    status_rank,
)


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

        # Ligne 1 : recherche plein texte + compteur + bouton de réinitialisation.
        search_row = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Rechercher (titre, catégorie, URL)...")
        self.search_edit.textChanged.connect(self._on_change)
        # Compteur de lignes affichées : l'analyste voit immédiatement si un
        # filtre a vidé la liste (« 0 constat ») sans avoir à le deviner.
        self.count_label = QLabel("")
        self.count_label.setObjectName("countLabel")
        reset_btn = QPushButton("Réinitialiser")
        reset_btn.clicked.connect(self.reset)
        search_row.addWidget(self.search_edit, stretch=1)
        search_row.addWidget(self.count_label)
        search_row.addWidget(reset_btn)
        layout.addLayout(search_row)

        # Ligne 2 : statut, gravité et cible.
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
        for value in SEVERITY_ORDER:
            # Libellé français affiché, valeur brute en donnée : `FilterState`
            # continue de porter « high », ce que `list_findings` attend.
            self.severity_combo.addItem(severity_label(value), value)
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

    def set_count(self, shown: int) -> None:
        """Met à jour le compteur de lignes affichées."""
        self.count_label.setText(f"{shown} constat{'s' if shown != 1 else ''}")

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


class _SortItem(QTableWidgetItem):
    """Cellule triable sur une clé typée plutôt que sur son texte.

    Qt trie les `QTableWidgetItem` par leur texte : « 10 » passerait avant
    « 9 », le score manquant (`--`) grimperait en tête, et la gravité serait
    ordonnée alphabétiquement (« Critique » avant « Élevée »…). Chaque
    cellule porte donc sa clé de tri réelle (identifiant entier, rang de
    gravité, rang de statut, score flottant).
    """

    def __init__(self, text: str, sort_key: int | float | str) -> None:
        super().__init__(text)
        self._sort_key = sort_key

    def __lt__(self, other: object) -> bool:
        if isinstance(other, _SortItem):
            return bool(self._sort_key < other._sort_key)
        return bool(super().__lt__(other))


def _centered(item: _SortItem) -> _SortItem:
    """Centre le texte des colonnes courtes (ID, badges, compteurs, score)."""
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    return item


def _paint_badge(
    item: _SortItem, badge_of, value: str, theme: str | None = None
) -> None:
    """Colore une cellule selon son vocabulaire et le thème courant.

    `badge_of` est `severity_badge` ou `status_badge` : il renvoie le couple
    (fond, texte) adapté au thème (texte blanc sur la table sombre, sombre
    sur la table claire). La pastille est repeinte à chaque commutation via
    `FindingsTable.set_theme`.
    """
    background, foreground = badge_of(value, theme)
    item.setBackground(QColor(background))
    item.setForeground(QColor(foreground))


class FindingsTable(QTableWidget):
    """Table filtrable des résultats (RF-11).

    La table est en lecture seule et triable ; chaque sélection émet
    `finding_selected` avec l'identifiant du résultat concerné. Les colonnes
    « Gravité » et « Statut » sont peintes en pastilles (fond + texte issus
    de `tscan_gui.theme`), et une liste vide affiche un message explicite
    plutôt qu'une table muette.
    """

    finding_selected = Signal(int)  # finding_id

    _HEADERS: ClassVar[list[str]] = ["ID", "Gravité", "Statut", "Catégorie", "Titre", "Instances", "Cible", "URL", "Score"]
    _COL_GRAVITY: ClassVar[int] = 1
    _COL_STATUS: ClassVar[int] = 2
    _COL_TITLE: ClassVar[int] = 4

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, len(self._HEADERS), parent)
        self.setHorizontalHeaderLabels(self._HEADERS)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)

        # Colonnes dimensionnées à leur contenu, sauf le titre qui absorbe la
        # largeur restante (le Score n'est plus étiré en dernier ressort).
        header = self.horizontalHeader()
        header.setStretchLastSection(False)
        for col in range(len(self._HEADERS)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(self._COL_TITLE, QHeaderView.ResizeMode.Stretch)
        header.setMinimumSectionSize(64)

        # État vide : message centré au lieu d'une table muette.
        self._empty_label = QLabel(self.viewport())
        self._empty_label.setObjectName("emptyStateLabel")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setWordWrap(True)
        self._empty_label.hide()

        # Thème courant : les pastilles de gravité/statut en dépendent (texte
        # blanc sur la table sombre). Mis à jour par `set_theme`.
        self._theme: str | None = None

        self.itemSelectionChanged.connect(self._on_selection)

    def set_theme(self, theme: str) -> None:
        """Applique le thème aux pastilles et repeint les lignes affichées.

        Appelé à la construction puis à chaque bascule clair/sombre : sans
        repeinte, les pastilles garderaient les couleurs de l'ancien thème
        (texte noir illisible sur la table sombre).
        """
        self._theme = theme
        self._repaint_badges()

    def _repaint_badges(self) -> None:
        """Repeint les pastilles des lignes affichées avec le thème courant."""
        if self._theme is None:
            return
        self.setSortingEnabled(False)  # évite un tri pendant la repeinte
        for row in range(self.rowCount()):
            for col, badge_of in (
                (self._COL_GRAVITY, severity_badge),
                (self._COL_STATUS, status_badge),
            ):
                item = self.item(row, col)
                if item is not None:
                    _paint_badge(item, badge_of, item.data(Qt.ItemDataRole.UserRole) or "", self._theme)
        self.setSortingEnabled(True)

    def populate(
        self,
        rows: list[FindingRow],
        *,
        select_id: int | None = None,
        empty_message: str = "Aucun constat.",
    ) -> None:
        """Remplit la table à partir de lignes fournies par le viewmodel.

        `select_id` re-sélectionne (silencieusement) la ligne affichée dans le
        panneau de détail : un rafraîchissement — pendant un scan par exemple
        — ne vide plus la sélection ni le formulaire de correction.
        """
        self.setSortingEnabled(False)  # évite le tri pendant le remplissage
        self.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            for col_idx, item in enumerate(self._make_items(row)):
                self.setItem(row_idx, col_idx, item)
        self._set_empty_state(None if rows else empty_message)
        self.setSortingEnabled(True)
        self._restore_selection(select_id)

    def _make_items(self, row: FindingRow) -> list[QTableWidgetItem]:
        score_text = f"{row.score:.2f}" if row.score is not None else "--"
        items: list[QTableWidgetItem] = [
            _centered(_SortItem(str(row.id), row.id)),
            _centered(_SortItem(severity_label(row.severity), severity_rank(row.severity))),
            _centered(_SortItem(status_label(row.status), status_rank(row.status))),
            QTableWidgetItem(row.category),
            QTableWidgetItem(row.title),
            _centered(_SortItem(str(row.instance_count), row.instance_count)),
            QTableWidgetItem(row.target),
            QTableWidgetItem(
                f"{row.matched_at or ''}".split("/")[-1] if row.matched_at else ""
            ),
            _centered(_SortItem(score_text, row.score if row.score is not None else -1.0)),
        ]
        # La pastille suit la ligne lors d'un tri (couleur par cellule, non par
        # position) : la colonne reste lisible dans les deux sens de tri. La
        # valeur brute est rangée en UserRole pour permettre la repeinte lors
        # d'une commutation de thème (`set_theme`).
        for col, badge_of, raw in (
            (self._COL_GRAVITY, severity_badge, row.severity),
            (self._COL_STATUS, status_badge, row.status),
        ):
            items[col].setData(Qt.ItemDataRole.UserRole, raw)
            _paint_badge(items[col], badge_of, raw, self._theme)
        return items

    def _set_empty_state(self, message: str | None) -> None:
        if message is None:
            self._empty_label.hide()
            return
        self._empty_label.setText(message)
        self._empty_label.show()
        self._center_empty_label()

    def _center_empty_label(self) -> None:
        rect = self.viewport().rect()
        self._empty_label.setGeometry(
            24, 24, max(rect.width() - 48, 0), max(rect.height() - 48, 0)
        )

    def _restore_selection(self, select_id: int | None) -> None:
        if select_id is None:
            return
        for row in range(self.rowCount()):
            item = self.item(row, 0)
            if item is not None and item.text().isdigit() and int(item.text()) == select_id:
                # Signaux bloqués : re-sélectionner ne doit pas recharger le
                # détail (et écraser la raison en cours de saisie).
                self.blockSignals(True)
                self.selectRow(row)
                self.blockSignals(False)
                return

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if self._empty_label.isVisible():
            self._center_empty_label()

    def _on_selection(self) -> None:
        rows = self.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        id_item = self.item(row, 0)
        if id_item is not None:
            self.finding_selected.emit(int(id_item.text()))


class FindingDetailPanel(QGroupBox):
    """Détail d'un résultat, organisé en onglets (RF-11, RF-12, ES-06).

    Six onglets, à l'image des onglets « Progression » / « Historique des
    requêtes » du bas de fenêtre : « Nom et infos » (titre, méta-données),
    « Description », « Preuves », « Explication du score », « Historique de
    statut » et « Corriger le statut » (correction manuelle RF-12). Les
    onglets portant des changements (nouvelle preuve, historique enrichi) le
    signalent par un marqueur « • » dans leur libellé.
    """

    status_submitted = Signal(int, str, str)  # finding_id, new_status, reason

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Détail du résultat", parent)

        # Le panneau de détail ne doit jamais être écrasé par le splitter :
        # une largeur minimale lisible est garantie (description, preuves et
        # explication restent exploitables même en petite fenêtre).
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Flèches de défilement natives du QTabBar (ScrollLeftButton /
        # ScrollRightButton) désactivées : elles restaient vides et donc
        # invisibles, et faisaient doublon. La navigation entre onglets se fait
        # désormais au clavier : Flèche gauche / droite sur la barre d'onglets,
        # avec rebouclage (voir `eventFilter`).
        tab_bar = self.tabs.tabBar()
        tab_bar.setUsesScrollButtons(False)
        tab_bar.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        tab_bar.installEventFilter(self)
        layout.addWidget(self.tabs)

        # --- Onglet 1 : Nom et infos -------------------------------------
        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)
        self.title_label = QLabel("(aucun résultat sélectionné)")
        self.title_label.setWordWrap(True)
        self.title_label.setTextFormat(Qt.TextFormat.PlainText)
        info_layout.addWidget(self.title_label)
        self.meta_label = QLabel("")
        self.meta_label.setObjectName("mutedLabel")
        self.meta_label.setWordWrap(True)
        info_layout.addWidget(self.meta_label)
        info_layout.addStretch()

        # --- Onglet 2 : Description ---------------------------------------
        description_tab = QWidget()
        description_layout = QVBoxLayout(description_tab)
        self.description = QTextEdit()
        self.description.setReadOnly(True)
        description_layout.addWidget(self.description)

        # --- Onglet 3 : Preuves --------------------------------------------
        evidences_tab = QWidget()
        evidences_layout = QVBoxLayout(evidences_tab)
        self.evidences_list = QTextEdit()
        self.evidences_list.setReadOnly(True)
        evidences_layout.addWidget(self.evidences_list)

        # --- Onglet 4 : Explication du score --------------------------------
        explanation_tab = QWidget()
        explanation_layout = QVBoxLayout(explanation_tab)
        self.explanation_text = QTextEdit()
        self.explanation_text.setReadOnly(True)
        explanation_layout.addWidget(self.explanation_text)

        # --- Onglet 5 : Historique de statut ---------------------------------
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        self.history_text = QTextEdit()
        self.history_text.setReadOnly(True)
        history_layout.addWidget(self.history_text)

        # --- Onglet 6 : Corriger le statut (RF-12) ---------------------------
        correct_tab = QWidget()
        correct_layout = QVBoxLayout(correct_tab)
        correct_layout.addWidget(QLabel("Nouveau statut :"))
        self.status_combo = QComboBox()
        for value in VALID_STATUSES:
            self.status_combo.addItem(status_label(value), value)
        correct_layout.addWidget(self.status_combo)
        correct_layout.addWidget(QLabel("Raison (optionnel) :"))
        self.reason_edit = QLineEdit()
        self.reason_edit.setPlaceholderText("Justification du changement de statut...")
        correct_layout.addWidget(self.reason_edit)
        self.apply_btn = QPushButton("Appliquer")
        self.apply_btn.setObjectName("primaryButton")
        self.apply_btn.clicked.connect(self._submit_status)
        correct_layout.addWidget(self.apply_btn)
        correct_layout.addStretch()

        self.tabs.addTab(info_tab, "Nom et infos")
        self.tabs.addTab(description_tab, "Description")
        self.tabs.addTab(evidences_tab, "Preuves")
        self.tabs.addTab(explanation_tab, "Explication du score")
        self.tabs.addTab(history_tab, "Historique de statut")
        self.tabs.addTab(correct_tab, "Corriger le statut")

        # Identifiant du résultat affiché, posé par `show_detail` : il servait
        # autrefois à reconstruire depuis le titre (« #12 — … »), ce qui cassait
        # dès que la forme du titre changeait.
        self.current_id: int | None = None

    def eventFilter(self, obj, event: QEvent) -> bool:
        """Flèche gauche / droite sur la barre d'onglets → onglet précédent /
        suivant, avec rebouclage.

        Le filtre n'est posé que sur la barre d'onglets (jamais sur le panneau
        entier) : les flèches restent donc libres pour déplacer le curseur dans
        les zones de texte (description, preuves, historique).
        """
        if obj is self.tabs.tabBar() and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Left:
                self._cycle_tab(-1)
                return True
            if event.key() == Qt.Key.Key_Right:
                self._cycle_tab(+1)
                return True
        return super().eventFilter(obj, event)

    def _cycle_tab(self, step: int) -> None:
        """Passe à l'onglet suivant (+1) ou précédent (-1), en boucle."""
        count = self.tabs.count()
        if count == 0:
            return
        current = self.tabs.currentIndex()
        self.tabs.setCurrentIndex((current + step) % count)

    def show_detail(self, detail: FindingDetail) -> None:
        """Affiche les informations d'un résultat (transformation présentation)."""
        self.current_id = detail.id
        self.title_label.setText(f"#{detail.id} — {detail.title}")
        self.meta_label.setText(self._format_meta(detail))
        self.description.setText(detail.description or "(aucune description)")
        self.evidences_list.setText(self._format_evidences(detail))
        self.explanation_text.setText(self._format_explanation(detail))
        self.history_text.setText(self._format_history(detail) or "(aucun historique)")
        self.status_combo.setCurrentIndex(self._status_index(detail.status))
        self.reason_edit.clear()

    def _format_meta(self, detail: FindingDetail) -> str:
        parts = [
            f"Gravité : {severity_label(detail.severity)}",
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
        if value is None or self.current_id is None:
            return
        reason = self.reason_edit.text().strip() or None
        self.status_submitted.emit(self.current_id, value, reason)


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