"""Gestion des changements de statut d'un `Finding`, avec historique (RF-12 / ES-06).

Point d'entrée unique pour toute modification de `Finding.status` : que le
changement vienne du moteur de scoring automatique ou d'une correction
manuelle (semaine 10, interface desktop, ou dès maintenant via la CLI), il
doit passer par `change_status` pour que l'historique reste complet et fiable.
Modifier `finding.status` directement ailleurs dans le code romprait cette
garantie -- c'est pourquoi ce module est volontairement le seul à écrire
dans `StatusHistory`.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from tscan_core.models import Finding, FindingStatus, StatusHistory

AUTOMATIC_ACTOR = "tscan_engine"


def change_status(
    session: Session,
    finding: Finding,
    new_status: FindingStatus,
    changed_by: str,
    reason: str | None = None,
) -> StatusHistory:
    """Change le statut d'un résultat et enregistre l'historique correspondant.

    Si `new_status` est identique au statut actuel, une entrée d'historique
    est tout de même créée : un analyste peut vouloir consigner qu'il a
    explicitement examiné et confirmé un statut existant, ce qui est une
    information différente d'une absence de revue.
    """
    history_entry = StatusHistory(
        finding_id=finding.id,
        old_status=finding.status,
        new_status=new_status,
        changed_by=changed_by,
        reason=reason,
    )
    finding.status = new_status
    session.add(history_entry)
    session.add(finding)
    session.commit()
    return history_entry


def correct_status_manually(
    session: Session,
    finding: Finding,
    new_status: FindingStatus,
    changed_by: str,
    reason: str | None = None,
) -> StatusHistory:
    """Correction manuelle d'un statut par un analyste (RF-12 / ES-06).

    Une décision humaine est la source de confiance la plus forte : c'est le
    seul chemin qui mène à « Confirmée » (score porté à 0,95), et marquer
    « Faux positif » annule la confiance (0,00) ; signaler un potentiel faux
    positif la baisse nettement (0,20). Les autres statuts (Probable…) gardent
    le score courant. L'historique est tracé par `change_status`.
    """
    manual_scores = {
        FindingStatus.CONFIRMED: 0.95,
        FindingStatus.POTENTIAL_FALSE_POSITIVE: 0.20,
        FindingStatus.FALSE_POSITIVE: 0.0,
    }
    history = change_status(session, finding, new_status, changed_by=changed_by, reason=reason)

    score = manual_scores.get(new_status)
    if score is None:
        return history

    finding.confidence_score = score
    explanation = _load_explanation(finding)
    explanation.append(
        f"Décision {changed_by} : statut « {new_status.value} » attribué "
        "manuellement après vérification (RF-12). Score de confiance fixé à "
        f"{score:.2f} par la décision humaine."
    )
    finding.score_explanation = json.dumps(explanation, ensure_ascii=False)
    session.commit()
    return history


def _load_explanation(finding: Finding) -> list[str]:
    """Reconstruit la liste d'explications de score d'un constat."""
    if not finding.score_explanation:
        return []
    try:
        value = json.loads(finding.score_explanation)
        return value if isinstance(value, list) else [str(value)]
    except json.JSONDecodeError:
        return [finding.score_explanation]
