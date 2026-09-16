"""Paquet de l'application desktop Tscan (S10).

Découpage en couches conforme au chapitre 10 du cahier des charges :
- `viewmodel.py` : logique de présentation testable, indépendante de Qt ;
- `widgets.py` : widgets Qt qui traduisent les données du viewmodel en
  interface et n'exécutent aucune opération longue ;
- `workers.py` : exécution asynchrone des opérations longues (RNF-03) ;
- `main.py` : point d'entrée de l'application desktop (assemble le tout).
"""

from tscan_gui.main import MainWindow
from tscan_gui.viewmodel import (
    SEVERITY_ORDER,
    VALID_STATUSES,
    FindingDetail,
    FindingRow,
    get_finding_detail,
    list_findings,
    list_targets,
    open_default_db,
)
from tscan_gui.widgets import (
    FilterBar,
    FilterState,
    FindingDetailPanel,
    FindingsTable,
)
from tscan_gui.workers import TaskResult, TaskWorker

__all__ = [
    "SEVERITY_ORDER",
    "VALID_STATUSES",
    "FilterBar",
    "FilterState",
    "FindingDetail",
    "FindingDetailPanel",
    "FindingRow",
    "FindingsTable",
    "MainWindow",
    "TaskResult",
    "TaskWorker",
    "get_finding_detail",
    "list_findings",
    "list_targets",
    "open_default_db",
]