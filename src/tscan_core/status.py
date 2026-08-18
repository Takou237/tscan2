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
