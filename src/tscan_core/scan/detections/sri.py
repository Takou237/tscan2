"""Détection passive de l'absence d'intégrité SRI (Sub Resource Integrity) sur
les ressources externes (feuille de route : parité OWASP ZAP, alerte 90003).

Les balises `<script src>` ou `<link href>` servies par un domaine tiers
devraient porter l'attribut `integrity`. Sans `integrity`, un compromis de la
CDN ou du serveur tiers permettrait d'injecter un contenu malveillant dans la
page. Cette analyse est 100 % passive : on inspecte uniquement le HTML déjà
crawlée, aucune requête supplémentaire n'est émise vers la cible ou un tiers.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_ID = "RULE-SRI-001"
CATEGORY = "security_misconfiguration"
SEVERITY = "medium"

# Balises à inspecter : scripts et feuilles de style servis par un tiers.
_ANY_TAG_ATTR = re.compile(
    r"<(?P<tag>script|link)\b(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL
)
_ATTR = re.compile(r"\b(src|href|integrity)\s*=\s*(['\"])(.*?)\2", re.IGNORECASE)


def _attrs_map(attrs: str) -> dict[str, str]:
    """Extrait un dict {attribut: valeur} des attributs d'une balise."""
    result: dict[str, str] = {}
    for name, _quote, value in _ATTR.findall(attrs):
        result[name.lower()] = value
    return result

def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive : signale toute ressource externe sans attribut
    `integrity` (SRI)."""
    del config, client, started_at, on_event
    checked = [root]
    if pages:
        checked.extend(pages.values())

    missing: list[str] = []
    for page in checked:
        base_host = urlparse(page.final_url).netloc
        for match in _ANY_TAG_ATTR.finditer(page.body):
            tag = match.group("tag").lower()
            attrs_map = _attrs_map(match.group("attrs"))
            res_url = attrs_map.get("src") or attrs_map.get("href")
            if not res_url:
                continue
            # Ressource relative : servie par la cible, SRI non pertinent.
            if not res_url.startswith(("http://", "https://", "//")):
                continue
            # Normalise la résolution de l'hôte (//domaine marche aussi).
            host = urlparse(("https:" if res_url.startswith("//") else "") + res_url).netloc
            if not host or host == base_host:
                continue
            if "integrity" not in attrs_map:
                missing.append(
                    f"{'<script>' if tag == 'script' else '<link>'} {res_url} "
                    f"sur {page.final_url}"
                )

    if not missing:
        return []

    return [
        DetectionResult(
            rule_id=RULE_ID,
            category=CATEGORY,
            severity=SEVERITY,
            title="Sub Resource Integrity Attribute Missing",
            description=(
                "Une ressource servie par un domaine tiers (script ou lien) ne porte "
                "pas l'attribut 'integrity' (SRI). En cas de compromission du serveur "
                "tiers, un contenu malveillant pourrait être injecté dans la page "
                "sans détection par le navigateur."
            ),
            matched_at=root.final_url,
            evidence_text=" ; ".join(dict.fromkeys(missing)),
        )
    ]
