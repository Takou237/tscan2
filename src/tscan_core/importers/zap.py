"""Parseur d'import pour les résultats OWASP ZAP au format JSON (RF-02).

Le rapport JSON "Traditional" de ZAP a la structure suivante :
`{"site": [{"@name": ..., "alerts": [{"pluginid", "alert"/"name", "riskcode",
"desc", "instances": [{"uri", ...}], ...}]}]}`.

ZAP regroupe par défaut toutes les instances d'une même alerte (par exemple
un en-tête manquant détecté sur cinquante pages) sous un seul objet `alert`
avec plusieurs `instances`. Pour le MVP, un `ParsedFinding` est créé par
alerte (pas par instance), avec l'URI de la première instance conservée comme
`matched_at` : multiplier les résultats par instance produirait un volume de
`Finding` peu exploitable pour un même problème sous-jacent, ce que l'étude
de l'existant (chapitre 4) identifie déjà comme une limite de ZAP brut.
"""

from __future__ import annotations

import json
from pathlib import Path

from tscan_core.importers.common import ParsedFinding, normalize_category, normalize_severity

# ZAP exprime la gravité par un code numérique (riskcode), pas par un mot.
_RISKCODE_TO_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}


class ZapParseError(Exception):
    """Levée lorsque le fichier ne correspond pas à la structure attendue
    d'un rapport JSON ZAP (clé 'site' absente ou de mauvais type)."""


def parse_zap_json(file_path: str | Path) -> list[ParsedFinding]:
    file_path = Path(file_path)

    try:
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ZapParseError(f"{file_path} n'est pas un fichier JSON valide.") from exc

    sites = data.get("site")
    if not isinstance(sites, list):
        raise ZapParseError(
            f"{file_path} ne contient pas de clé 'site' exploitable : "
            "ce n'est probablement pas un rapport JSON ZAP."
        )

    findings: list[ParsedFinding] = []
    for site in sites:
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            findings.append(_parse_alert(alert, site_name))

    return findings


def _parse_alert(alert: dict, site_name: str) -> ParsedFinding:
    name = alert.get("name") or alert.get("alert") or "Alerte ZAP sans nom"
    plugin_id = str(alert.get("pluginid", "")) or None
    description = _strip_html(alert.get("desc", ""))

    instances = alert.get("instances", [])
    first_instance = instances[0] if instances else {}
    matched_at = first_instance.get("uri", site_name)

    category = normalize_category(name, description, alert.get("cweid"))
    severity = normalize_severity(_RISKCODE_TO_SEVERITY.get(str(alert.get("riskcode")), "info"))

    return ParsedFinding(
        title=name,
        category=category,
        severity=severity,
        raw_result=json.dumps(alert, ensure_ascii=False),
        description=description,
        external_id=plugin_id,
        matched_at=matched_at,
        extra={
            "instance_count": len(instances),
            "cweid": alert.get("cweid"),
            "solution": _strip_html(alert.get("solution", "")),
        },
    )


def _strip_html(value: str) -> str:
    """Retire grossièrement les balises HTML présentes dans les champs texte
    de ZAP (`desc`, `solution`), qui sont fournis au format HTML par l'outil.
    Un nettoyage plus soigné pourra remplacer cette version simple si des cas
    réels y trouvent des limites."""
    import re

    return re.sub(r"<[^>]+>", " ", value or "").strip()
