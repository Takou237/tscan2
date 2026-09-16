"""Application desktop de Tscan (S10) — fenêtre principale et point d'entrée.

Cette fenêtre assemble les briques de `tscan_gui` conformément au chapitre 10
du cahier des charges :
- `FilterBar` + `FindingsTable` + `FindingDetailPanel` (`widgets.py`) ;
- la logique de présentation `viewmodel.py` (testable sans écran) ;
- les opérations longues (import, scan, corrélation, rapport) exécutées en
  arrière-plan par `workers.py` (RNF-03).

Le lancement se fait via `python -m tscan_gui` ou en exécutant ce module.
"""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QMainWindow,
    QMessageBox,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from tscan_core.models import Finding, FindingStatus
from tscan_core.status import correct_status_manually
from tscan_gui.dialogs import CorrelateDialog, ImportDialog, ReportDialog, ScanDialog
from tscan_gui.viewmodel import (
    get_finding_detail,
    list_findings,
    list_targets,
    open_default_db,
)
from tscan_gui.widgets import (
    FilterBar,
    FindingDetailPanel,
    FindingsTable,
    RequestHistoryPanel,
    ScanProgressPanel,
)
from tscan_gui.workers import (
    TaskWorker,
    correlate_task,
    import_task,
    report_task,
    scan_task,
)


class MainWindow(QMainWindow):
    """Fenêtre principale : liste des résultats, filtres, détail, corrections
    et lancement des actions longues (import / scan / rapport)."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Tscan — Analyse de vulnérabilités")
        self.resize(1100, 630)

        # Session partagée pour les lectures rapides de l'interface.
        self._session = open_default_db()
        # Conservés explicitement pour éviter leur destruction (GC) pendant run.
        self._workers: list[TaskWorker] = []
        # Drapeau d'interruption du scan en cours (bouton « Arrêter », parité ZAP).
        self._current_interrupt = None
        # Empreinte des dernières lignes affichées : lors du rafraîchissement
        # périodique d'un scan, la table n'est reconstruite QUE si les constats
        # ont réellement changé (sinon l'affichage à l'identique provoque des
        # à-coups et perd la sélection/le défilement — S11).
        self._last_rows_signature: tuple | None = None

        # Pendant un scan (qui tourne dans un fil avec sa propre session), les
        # constats commités au fil de l'eau par le moteur (S11) sont relus
        # périodiquement : la liste s'enrichit à la volée, sans attendre la fin.
        self._scan_refresh_timer = QTimer(self)
        self._scan_refresh_timer.setInterval(2000)
        self._scan_refresh_timer.timeout.connect(self._scan_refresh)

        self._build_toolbar()
        self._build_central()

        self.filter_bar.filters_changed.connect(self._apply_filters)
        self.table.finding_selected.connect(self._show_detail)
        self.detail_panel.status_submitted.connect(self._correct_status)

        self.refresh()

    # --- Construction de l'interface ----------------------------------------

    def _build_toolbar(self) -> None:
        toolbar = self.addToolBar("Actions")
        toolbar.setMovable(False)
        toolbar.addAction("Importer…", self._on_import)
        toolbar.addAction("Scanner…", self._on_scan)
        toolbar.addAction("Corréler", self._on_correlate)
        toolbar.addAction("Rapport…", self._on_report)
        toolbar.addSeparator()
        self.stop_action = toolbar.addAction("Arrêter", self._on_stop)
        self.stop_action.setEnabled(False)
        toolbar.addSeparator()
        toolbar.addAction("Actualiser", self.refresh)

    def _build_central(self) -> None:
        self.filter_bar = FilterBar(list_targets(self._session))
        self.table = FindingsTable()
        self.detail_panel = FindingDetailPanel()
        self.progress_panel = ScanProgressPanel()
        self.history_panel = RequestHistoryPanel()

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        # Tailles initiales confortables : la liste et le détail restent
        # larges et lisibles à l'ouverture (le détail a par ailleurs sa propre
        # largeur minimale).
        splitter.setSizes([560, 480])
        # Tailles minimales : quand la fenêtre est réduite, le contenu ne doit
        # jamais disparaître — la zone est alors parcourue par des barres de
        # défilement (voir QScrollArea ci-dessous).
        splitter.setMinimumSize(620, 180)

        # Deux onglets en bas : progression temps réel et historique des
        # requêtes (« History » de ZAP), alimentés en direct pendant le scan.
        bottom_tabs = QTabWidget()
        bottom_tabs.addTab(self.progress_panel, "Progression")
        bottom_tabs.addTab(self.history_panel, "Historique des requêtes")
        bottom_tabs.setMinimumSize(620, 90)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self.filter_bar)
        layout.addWidget(splitter, stretch=2)
        # Onglets de bas : progression (barre + journal) et historique des
        # requêtes HTTP structuré (ID, horodatages WAT, méthode, URL, code,
        # raison) — le flux « History » de ZAP. Largement compressibles : la
        # plus grande part de hauteur revient à la liste et au détail.
        layout.addWidget(bottom_tabs, stretch=1)
        central.setMinimumSize(700, 380)

        # Contenu défilable : même fenêtre très réduite, aucun panneau n'est
        # amputé de ses informations (les barres de défilement apparaissent).
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(central)
        self.setCentralWidget(scroll)

    # --- Relecture des données ---------------------------------------------

    def refresh(self) -> None:
        """Recharge les cibles et réapplique les filtres courants.

        Un `rollback` clôt toute transaction de lecture en cours : sinon, une
        session qui a déjà lu garde le même instantané SQLite et ne verrait
        pas les constats commités ensuite par un autre fil (le scan lancé en
        arrière-plan, S11). Les écritures de l'interface sont toutes suivies
        d'un commit avant ce rafraîchissement, ce rollback ne perd rien.
        """
        self._session.rollback()
        self.filter_bar.refresh_targets(list_targets(self._session))
        self._apply_filters(self.filter_bar.state())

    def _scan_refresh(self) -> None:
        """Relit la base pendant un scan : les constats au fil de l'eau
        apparaissent dès leur commit sans attendre la fin du scan."""
        self.refresh()

    def _apply_filters(self, state) -> None:
        rows = list_findings(self._session, **state.as_dict())
        signature = tuple(
            (r.id, r.status, r.severity, r.category, r.title, r.matched_at, r.score)
            for r in rows
        )
        if signature == self._last_rows_signature:
            return  # rien de nouveau : pas de reconstruction (fluence S11)
        self._last_rows_signature = signature
        self.table.populate(rows)

    def _show_detail(self, finding_id: int) -> None:
        detail = get_finding_detail(self._session, finding_id)
        if detail is not None:
            self.detail_panel.show_detail(detail)

    def _correct_status(self, finding_id: int, new_status: str, reason: str) -> None:
        finding = self._session.get(Finding, finding_id)
        if finding is None:
            return
        # Décision humaine (RF-12 / ES-06) : ajuste le statut ET le score de
        # confiance (Confirmé = 0,95, Faux positif = 0,00, potentiel faux
        # positif = 0,20). Seule l'analyste confirme ; le moteur de scan ne le
        # fait jamais.
        correct_status_manually(
            self._session,
            finding,
            FindingStatus(new_status),
            changed_by="analyste_gui",
            reason=reason or None,
        )
        self._show_detail(finding_id)
        self.refresh()

    # --- Opérations longues (RNF-03) ---------------------------------------

    def _run_worker(self, worker: TaskWorker, success: str) -> None:
        def _on_done(result) -> None:
            self._on_task_done(result, success)

        # Les événements de progression du scan (GET, TLS, crawl…) alimentent le
        # panneau de progression en temps réel (semaine 11).
        worker.progress_emitted.connect(self.progress_panel.append_event)
        # Chaque requête HTTP du scan alimente le tableau « History » (format
        # ZAP), avec ID, horodatages WAT, méthode, URL, code et raison.
        worker.request_emitted.connect(self.history_panel.append_record)
        worker.task_done.connect(_on_done)
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker))
        worker.start()

    def _on_task_done(self, result, success: str) -> None:
        self._scan_refresh_timer.stop()
        self.stop_action.setEnabled(False)
        self._current_interrupt = None
        if result.ok:
            QMessageBox.information(self, "Tscan", f"{success}\n{result.message}")
            self.refresh()
        else:
            self.progress_panel.notify_failure(result.message)
            QMessageBox.critical(self, "Erreur", result.message)

    def _on_import(self) -> None:
        dialog = ImportDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        kwargs = dialog.config_kwargs()
        rex = kwargs.get("rex", False)
        if rex:
            # La ré-observation relance un scan actif : on nettoie les panneaux
            # de progression et d'historique des requêtes pour son déroulement.
            self.progress_panel.reset()
            self.history_panel.reset()

        def _on_done(result) -> None:
            if not result.ok:
                self._on_task_done(result, "Import.")
                return
            message = f"{result.message}\n{result.detail}"
            if result.detail and isinstance(result.detail, dict) and result.detail.get("rex"):
                rex_r = result.detail["rex"]
                message += (
                    f"\nRé-observation (scan actif #{rex_r['active_scan_id']}) : "
                    f"{rex_r['total']} constat(s) importé(s) — "
                    f"{rex_r['reproduced']} corroboré(s), "
                    f"{rex_r['potential_false_positives']} potentiel(s) faux positif(s), "
                    f"{rex_r['not_reproducible']} non concluant(s) (revue analytique, RF-12)."
                )
            QMessageBox.information(self, "Tscan", message)
            self.refresh()

        worker = TaskWorker(
            import_task(kwargs["path"], kwargs["source"], kwargs["target"], rex=rex),
            self,
        )
        worker.task_done.connect(_on_done)
        worker.progress_emitted.connect(self.progress_panel.append_event)
        worker.request_emitted.connect(self.history_panel.append_record)
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker))
        worker.start()

    def _on_scan(self) -> None:
        dialog = ScanDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.progress_panel.reset()
        self.history_panel.reset()
        run, interrupt = scan_task(dialog.config_kwargs())
        self._current_interrupt = interrupt
        self.stop_action.setEnabled(True)
        self._run_worker(TaskWorker(run, self), "Scan terminé.")
        # Rafraîchit la liste pendant le scan : les constats apparaissent au
        # fil de l'eau dès leur commit (S11). Arrêté dans `_on_task_done`.
        self._scan_refresh_timer.start()

    def _on_stop(self) -> None:
        """Arrête manuellement le scan en cours (parité OWASP ZAP)."""
        if self._current_interrupt is not None:
            self._current_interrupt.stop()
            self.stop_action.setEnabled(False)
            from tscan_core.scan.progress import ScanProgressEvent

            self.progress_panel.append_event(
                ScanProgressEvent(stage="start", message="Arrêt demandé — fin propre du scan…")
            )

    def _on_correlate(self) -> None:
        dialog = CorrelateDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._run_worker(
            TaskWorker(correlate_task(**dialog.config_kwargs()), self),
            "Corrélation terminée.",
        )

    def _on_report(self) -> None:
        dialog = ReportDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        kwargs = dialog.config_kwargs()
        self._run_worker(
            TaskWorker(
                report_task(kwargs["output_path"], kwargs["fmt"], kwargs["target"]),
                self,
            ),
            "Rapport généré.",
        )


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    # La fenêtre doit rester dans la zone de travail (au-dessus de la barre des
    # tâches) : on ajuste sa géométrie à la zone disponible de son écran, sans
    # quoi son bas finit masqué sous la barre des tâches sur les écrans peu
    # hauts. Les barres de défilement internes gardent alors le contenu complet
    # visible en cas de petite zone affichable.
    screen = window.screen()
    if screen is not None:
        avail = screen.availableGeometry()
        geo = window.frameGeometry()
        geo.setWidth(min(geo.width(), avail.width()))
        geo.setHeight(min(geo.height(), avail.height()))
        geo.moveCenter(avail.center())
        window.setGeometry(geo)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

