"""Détection passive de l'inclusion de scripts JavaScript issus d'un domaine
tiers (feuille de route : parité OWASP ZAP, alerte 10017).

Une page qui inclut un `<script src>` pointant vers un domaine tiers donne à
ce domaine la possibilité d'exécuter du code dans le contexte de la page
cible. C'est un signal de surface (dépendance tierce) : aucun appel réseau
supplémentaire, uniquement la lecture du HTML déjà crawlée.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_ID = "RULE-XDOMAIN-JS-001"
CATEGORY = "security_misconfiguration"
SEVERITY = "low"

_SCRIPT_SRC = re.compile(
    r"<script\b[^>]*?\bsrc\s*=\s*(['\"])(.*?)\1[^>]*?>", re.IGNORECASE | re.DOTALL
)


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive : signale tout `<script src>` pointant vers un domaine
    externe (cross-domain)."""
    del config, client, started_at, on_event
    checked = [root]
    if pages:
        checked.extend(pages.values())

    found: list[str] = []
    for page in checked:
        base_host = urlparse(page.final_url).netloc
        for match in _SCRIPT_SRC.finditer(page.body):
            script_url = match.group(2)
            if not script_url.startswith(("http://", "https://", "//")):
                continue
            script_url = ("https:" if script_url.startswith("//") else "") + script_url
            host = urlparse(script_url).netloc
            if not host or host == base_host:
                continue
            found.append(f"{script_url} dans {page.final_url}")

    if not found:
        return []

    return [
        DetectionResult(
            rule_id=RULE_ID,
            category=CATEGORY,
            severity=SEVERITY,
            title="Cross-Domain JavaScript Source File Inclusion",
            description=(
                "La page inclut un ou plusieurs fichiers JavaScript servis par un "
                "domaine tiers. Ces dépendances peuvent exécuter du code dans le "
                "contexte de la page ; leur compromission affecterait la cible. "
                "Charger les scripts uniquement depuis des sources de confiance."
            ),
            matched_at=root.final_url,
            evidence_text=" ; ".join(dict.fromkeys(found)),
        )
    ]
