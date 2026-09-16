"""Parseur d'import pour les résultats Nessus et OpenVAS au format XML `.nessus` (RF-01).

Nessus et OpenVAS (Greenbone) partagent ce format XML d'export : une racine
`NessusClientData`/`NessusClientData_v2`, un `Report`, des `ReportHost`, et
des `ReportItem` portant chacun un titre (`pluginName`), un identifiant de
plugin, une gravité de 0 à 4 et une description.

Les champs exploités correspondent à cette structure commune aux deux outils ;
la gravité numérique technique (0-4) est convertie vers le vocabulaire interne
(info, low, medium, high, critical) par `normalize_severity` après une
traduction numérique explicite (`_severity_from_number`), car les deux outils
partagent la même échelle.

Un fichier illisible (XML mal formé) lève `NessusParseError` : contrairement
aux fichiers JSONL, un XML invalide ne permet pas de récupérer des éléments
isolés de façon fiable.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from tscan_core.importers.common import ParsedFinding, normalize_category

_NAMESPACE = "{http://www.nessus.org/nessus_client_data_v2}"


class NessusParseError(Exception):
    """Levée lorsque le fichier n'est pas un export .nessus XML exploitable."""


def _walk_items(root: ET.Element, host: str | None) -> list[ParsedFinding]:
    """Parcourt l'arbre XML en propageant le nom de l'hôte courant.

    Le nom d'hôte est porté par `ReportHost` et n'apparaît pas dans les
    `ReportItem` : une promenade récursive est le moyen le plus lisible de le
    maintenir à jour sans passer par des accès au parent (que `xml.etree`
    n'offre pas nativement).
    """
    findings: list[ParsedFinding] = []
    local = _local_name(root.tag)
    if local == "ReportHost":
        host = root.get("name") or host
    elif local == "ReportItem":
        finding = _parse_report_item(root, host)
        if finding is not None:
            findings.append(finding)

    for child in root:
        findings.extend(_walk_items(child, host))
    return findings


def parse_nessus_xml(file_path: str | Path) -> list[ParsedFinding]:
    """Convertit un export Nessus/OpenVAS `.nessus` en `ParsedFinding`."""
    file_path = Path(file_path)
    try:
        root = ET.parse(file_path).getroot()
    except ET.ParseError as exc:
        raise NessusParseError(
            f"XML illisible dans {file_path} : {exc}. "
            "Le fichier ne semble pas être un export .nessus (XML) valide."
        ) from exc

    root_tag = root.tag.removeprefix(_NAMESPACE)
    if root_tag not in ("NessusClientData", "NessusClientData_v2"):
        raise NessusParseError(
            f"Racine inattendue {root.tag!r} dans {file_path} : "
            "le fichier ne semble pas être un export .nessus (XML) valide."
        )

    findings = _walk_items(root, host=None)
    if not findings:
        raise NessusParseError(
            f"Aucun ReportItem exploitable trouvé dans {file_path} : "
            "le fichier ne semble pas être un export .nessus (XML) valide."
        )
    return findings


def _parse_report_item(item: ET.Element, host: str | None) -> ParsedFinding | None:
    """Convertit un `ReportItem` en `ParsedFinding` (None si mal formé)."""
    plugin_name = item.get("pluginName") or item.get("name")
    plugin_id = item.get("pluginID") or item.get("pluginName")
    if not plugin_name:
        return None

    description = _text(item, "description")
    raw = ET.tostring(item, encoding="unicode")
    cves = [value for value in _collect_simple_texts(item, "cve") if value]

    return ParsedFinding(
        title=plugin_name,
        category=normalize_category(plugin_name, description, plugin_id, *cves),
        severity=_severity_from_number(item.get("severity")),
        raw_result=raw,
        description=description or None,
        external_id=plugin_id or None,
        matched_at=_matched_at(item, host),
        extra={
            "cves": cves,
            "plugin_output": _text(item, "plugin_output"),
            "svc_name": item.get("svc_name"),
            "port": item.get("port"),
            "proto": item.get("protocol"),
        },
    )


def _severity_from_number(number: str | None) -> str:
    """Échelle technique commune .nessus (0-4) -> vocabulaire interne.

    Toute valeur illisible retombe sur `info` par conservatisme : une gravité
    inconnue ne doit pas gonfler un résultat d'import.
    """
    mapping = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
    return mapping.get((number or "").strip(), "info")


def _matched_at(item: ET.Element, host: str | None) -> str | None:
    """Emplacement du constat : URL http(s) construite depuis hôte/port/service,
    sinon libellé brut hôte:port."""
    port = item.get("port")
    svc = (item.get("svc_name") or "").lower()

    if host and port and "http" in svc:
        scheme = "https" if svc in ("https", "https-alt") else "http"
        return f"{scheme}://{host}:{port}"
    if host and port:
        return f"{host}:{port}"
    return host if host else None


def _text(item: ET.Element, tag: str) -> str:
    """Texte du premier élément enfant du tag donné, sans le namespace."""
    for child in item:
        if _local_name(child.tag) == tag:
            return (child.text or "").strip()
    return ""


def _local_name(tag: str) -> str:
    """Nom local d'un tag XML, avec ou sans namespace (`{uri}local`)."""
    return tag.rsplit("}", 1)[-1]


def _collect_simple_texts(item: ET.Element, tag: str) -> list[str]:
    """Textes de tous les enfants du tag donné (ex : plusieurs <cve>)."""
    return [
        (child.text or "").strip()
        for child in item
        if _local_name(child.tag) == tag
    ]