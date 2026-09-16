"""Service d'orchestration de l'import (RF-01, RF-02, RF-04, RF-05).

Ce module fait le lien entre un parseur (`nuclei.py`, `zap.py`) et la
persistance en base : il crée le `Scan` représentant le lot importé, convertit
chaque `ParsedFinding` en `Finding` du modèle pivot, et conserve le résultat
brut d'origine (RF-05 / ES-07).

C'est volontairement le seul endroit du cœur qui connaît à la fois le monde
des parseurs et celui des modèles SQLAlchemy : le reste du cœur (corrélation,
scoring, reporting) ne manipule que des `Finding`, jamais un format externe.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from tscan_core.importers.common import ParsedFinding
from tscan_core.importers.nessus import parse_nessus_xml
from tscan_core.importers.nuclei import parse_nuclei_jsonl
from tscan_core.importers.zap import parse_zap_json
from tscan_core.models import Finding, Scan, ScanType

_PARSERS = {
    "nuclei": parse_nuclei_jsonl,
    "zap": parse_zap_json,
    "nessus": parse_nessus_xml,
    "openvas": parse_nessus_xml,
}

SUPPORTED_FORMATS = tuple(_PARSERS.keys())


class UnsupportedFormatError(ValueError):
    """Levée lorsqu'un format d'import demandé n'a pas de parseur associé."""


def import_file(session: Session, source: str, target: str, file_path: str | Path) -> Scan:
    """Importe un fichier de résultats et retourne le `Scan` créé, avec ses
    `Finding` déjà rattachés et commités en base.

    `source` doit être l'une des clés de `SUPPORTED_FORMATS` ('nuclei', 'zap',
    'nessus', 'openvas').
    `target` est un libellé de cible fourni par l'utilisateur (RF-24), utile
    pour retrouver ce lot d'import parmi d'autres scans sur des cibles
    différentes.
    """
    parser = _PARSERS.get(source)
    if parser is None:
        raise UnsupportedFormatError(
            f"Format d'import inconnu : {source!r}. Formats supportés : {SUPPORTED_FORMATS}."
        )

    parsed_findings = parser(file_path)

    scan = Scan(scan_type=ScanType.IMPORT, source=source, target=target)
    session.add(scan)
    session.flush()  # attribue scan.id sans clore la transaction

    for parsed in parsed_findings:
        session.add(_to_finding(parsed, scan.id))

    session.commit()
    return scan


def _to_finding(parsed: ParsedFinding, scan_id: int) -> Finding:
    return Finding(
        scan_id=scan_id,
        title=parsed.title,
        description=parsed.description,
        category=parsed.category,
        severity=parsed.severity,
        external_id=parsed.external_id,
        matched_at=parsed.matched_at,
        raw_result=parsed.raw_result,
    )
