"""Parseur d'import pour les résultats Nuclei au format JSONL (RF-01).

Chaque ligne du fichier est un objet JSON indépendant. Les champs exploités
correspondent à la structure de sortie standard de Nuclei :
`template-id`, `info.{name,description,severity,tags}`, `host`, `matched-at`.

Une ligne illisible (JSON invalide) est signalée mais n'interrompt pas
l'import des lignes suivantes : un fichier de résultats volumineux ne doit
pas être perdu en entier à cause d'une seule ligne corrompue.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from tscan_core.importers.common import ParsedFinding, normalize_category, normalize_severity


class NucleiParseError(Exception):
    """Levée lorsque le fichier n'a l'air d'être un export Nuclei JSONL valide
    pour aucune de ses lignes (fichier probablement dans le mauvais format)."""


def parse_nuclei_jsonl(file_path: str | Path) -> list[ParsedFinding]:
    file_path = Path(file_path)
    findings: list[ParsedFinding] = []
    lines_ok = 0
    lines_failed = 0

    for raw_line in _read_nonempty_lines(file_path):
        try:
            findings.append(_parse_line(raw_line))
            lines_ok += 1
        except (json.JSONDecodeError, KeyError):
            lines_failed += 1
            continue

    if lines_ok == 0:
        raise NucleiParseError(
            f"Aucune ligne exploitable trouvée dans {file_path} : "
            "le fichier ne semble pas être un export Nuclei JSONL valide."
        )

    return findings


def _read_nonempty_lines(file_path: Path) -> Iterator[str]:
    with file_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield stripped


def _parse_line(raw_line: str) -> ParsedFinding:
    data = json.loads(raw_line)
    info = data.get("info", {})

    template_id = data.get("template-id", "")
    name = info.get("name", template_id or "Résultat Nuclei sans nom")
    tags = info.get("tags", [])
    tags_text = " ".join(tags) if isinstance(tags, list) else str(tags)

    category = normalize_category(name, info.get("description"), tags_text, template_id)
    severity = normalize_severity(info.get("severity"))

    return ParsedFinding(
        title=name,
        category=category,
        severity=severity,
        raw_result=raw_line,
        description=info.get("description"),
        external_id=template_id or None,
        matched_at=data.get("matched-at") or data.get("host"),
        extra={"classification": info.get("classification", {})},
    )
