"""Logique de présentation de l'interface desktop (S10).

Ce module concentre tout le code « métier » de l'écran : requêtes vers le cœur
Tscan (lecture des résultats, cibles, filtrage) et transformation en structures
simples (dicts) prêtes à être affichées par les widgets Qt.

Le choix clé : ce module ne dépend d'aucun objet Qt. Il est donc testable sans
affichage (pytest), ce qui permet de couvrir la logique des parcours UC1 à UC5
sans dépendre d'un écran — conformément à la philosophie « cœur testé » du
projet. Les widgets de `widgets.py` ne font qu'appeler ces fonctions et
traduire le résultat en éléments d'interface.

Les opérations longues (import, scan) ne font PAS partie de ce module : elles
sont exécutées de façon asynchrone par `workers.py` pour satisfaire la
RNF-03 (interface réactive), et ce module ne contient que des lectures rapides
ou des transformations pures.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from tscan_core.db import DEFAULT_DB_PATH, get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus

# Séverités ordonnées de la plus critique à la plus faible (partagé avec le
# rapport). Permet de trier la liste des résultats.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Statuts affichables, dans un ordre lisible pour un filtre.
VALID_STATUSES: tuple[str, ...] = tuple(status.value for status in FindingStatus)

# Libellés français pour l'affichage dans la GUI (partagé avec le rapport).
STATUS_LABEL: dict[str, str] = {
    FindingStatus.UNVALIDATED.value: "Non validé",
    FindingStatus.CONFIRMED.value: "Confirmé",
    FindingStatus.PROBABLE.value: "Probable",
    FindingStatus.POTENTIAL_FALSE_POSITIVE.value: "Potentiel faux positif",
    FindingStatus.FALSE_POSITIVE.value: "Faux positif",
}


def status_label(value: str) -> str:
    """Retourne le libellé français d'un statut pour l'affichage GUI."""
    return STATUS_LABEL.get(value, value)


@dataclass
class FindingRow:
    """Une ligne de la table principale de résultats."""
    id: int
    severity: str
    status: str
    category: str
    title: str
    target: str
    matched_at: str | None
    score: float | None = None
    # Nombre d'instances de la même vulnérabilité (même cible + titre +
    # catégorie). Toujours ≥ 1 : une ligne regroupe toutes les instances.
    instance_count: int = 1


@dataclass
class FindingDetail:
    """Détail complet d'un résultat, pour le panneau de droite."""
    id: int
    title: str
    description: str | None
    severity: str
    status: str
    score: float | None
    category: str
    target: str
    source: str
    matched_at: str | None
    external_id: str | None
    score_explanation: list[str] = field(default_factory=list)
    evidences: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)


def open_default_db() -> Session:
    """Ouvre une session sur la base locale de Tscan, en l'initialisant au
    besoin. L'appelant est responsable de fermer la session."""
    engine = get_engine(DEFAULT_DB_PATH)
    init_db(engine)
    return get_session(engine)


def list_targets(session: Session) -> list[str]:
    """Retourne la liste triée des cibles présentes en base."""
    from tscan_core.models import Scan

    targets = {scan.target for scan in session.query(Scan).all()}
    return sorted(targets)

def list_findings(
    session: Session,
    *,
    target: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    query_text: str | None = None,
) -> list[FindingRow]:
    """Liste les résultats en base avec filtres optionnels (cible, statut,
    gravité, texte), triés de la gravité la plus critique à la plus faible.

    Une seule ligne est produite par vulnérabilité (même cible + titre +
    catégorie), regroupant toutes ses instances : `instance_count` comptabilise
    les occurrences, `matched_at` conserve celle de la première.

    Ne fait que des lectures rapides : convient à un appel synchrone depuis le
    fil de l'interface (RNF-03).
    """
    q = session.query(Finding)
    if target is not None:
        q = q.join(Finding.scan).filter_by(target=target)
    if status is not None:
        q = q.filter_by(status=FindingStatus(status))
    if severity is not None:
        q = q.filter_by(severity=severity)

    findings = q.all()

    if query_text:
        lowered = query_text.strip().lower()
        findings = [
            f
            for f in findings
            if lowered in (f.title or "").lower()
            or lowered in (f.category or "").lower()
            or lowered in (f.matched_at or "").lower()
        ]

    def _rank(f: Finding) -> int:
        try:
            return SEVERITY_ORDER.index(f.severity.lower())
        except ValueError:
            return len(SEVERITY_ORDER)

    findings.sort(key=lambda f: (_rank(f), f.id))

    # Regroupement par vulnérabilité : une seule ligne par (cible, titre,
    # catégorie), avec le nombre d'instances de la même vulnérabilité. Les
    # findings étant triés par gravité puis id, le premier occurrence de chaque
    # groupe sert de ligne représentative ; les lignes restent ainsi ordonnées
    # par gravité décroissante.
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        key = (f.scan.target if f.scan else "", f.title, f.category)
        groups.setdefault(key, []).append(f)

    rows: list[FindingRow] = []
    for members in groups.values():
        first = members[0]
        rows.append(
            FindingRow(
                id=first.id,
                severity=first.severity,
                status=first.status.value,
                category=first.category,
                title=first.title,
                target=first.scan.target if first.scan else "",
                matched_at=first.matched_at,
                score=first.confidence_score,
                instance_count=len(members),
            )
        )
    return rows


def get_finding_detail(session: Session, finding_id: int) -> FindingDetail | None:
    """Construit le détail d'un résultat à partir de ses preuves, de son
    explication de score et de son historique de statut (RF-11, ES-06)."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        return None

    score_explanation: list[str] = []
    if finding.score_explanation:
        try:
            score_explanation = json.loads(finding.score_explanation)
        except json.JSONDecodeError:
            score_explanation = [finding.score_explanation]

    evidences = [(ev.content_text or "") for ev in finding.evidences if ev.content_text]

    history: list[str] = []
    for entry in finding.status_history:
        old = status_label(entry.old_status.value) if entry.old_status else "(aucun)"
        new = status_label(entry.new_status.value)
        by = entry.changed_by
        reason = f" — {entry.reason}" if entry.reason else ""
        history.append(f"{old} → {new} par {by}{reason}")

    return FindingDetail(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status.value,
        score=finding.confidence_score,
        category=finding.category,
        target=finding.scan.target if finding.scan else "",
        source=finding.scan.source if finding.scan else "",
        matched_at=finding.matched_at,
        external_id=finding.external_id,
        score_explanation=score_explanation,
        evidences=evidences,
        history=history,
    )

