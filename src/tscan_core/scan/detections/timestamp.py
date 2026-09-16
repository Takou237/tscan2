"""Détection passive de la divulgation de timestamps Unix (feuille de route :
parité OWASP ZAP, alerte 10096).

Les réponses HTML peuvent révéler des horodatages Unix (versions d'actifs,
commentaires de génération, dates de publication). C'est une fuite
d'informations de faible sévérité : elle aide un attaquant à dater des
événements internes (mises à jour, génération de la page). Analyse 100 %
passive sur le contenu déjà collecté.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_ID = "RULE-TIMESTAMP-001"
CATEGORY = "information_disclosure"
SEVERITY = "low"

# Un timestamp Unix plausible : 10 chiffres correspondant à des dates entre
# 2001 (978307200) et 2286 (9999999999). On exclut les plages déjà balayées.
_MIN_TS = 978307200  # 2001-01-01
_MAX_TS = 4102444799  # 2100-01-01

_TS = re.compile(r"(?<!\d)(\d{10})(?!\d)")


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive : signale uniquement les timestamps Unix dans une plage
    de dates plausibles (2001-2100), hors plages deversioning courantes (2^31
    ~ 2038 ne couvre pas l'absurde)."""
    del config, client, started_at, on_event
    checked = [root]
    if pages:
        checked.extend(pages.values())

    found: list[str] = []
    seen: set[int] = set()
    for page in checked:
        for match in _TS.finditer(page.body):
            value = int(match.group(1))
            if not (_MIN_TS <= value <= _MAX_TS):
                continue
            if value in seen:
                continue
            seen.add(value)
            try:
                human = datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d")
            except (OverflowError, OSError, ValueError):
                continue
            found.append(f"{match.group(1)} ({human}) dans {page.final_url}")

    if not found:
        return []

    return [
        DetectionResult(
            rule_id=RULE_ID,
            category=CATEGORY,
            severity=SEVERITY,
            title="Timestamp Disclosure - Unix",
            description=(
                "Des horodatages Unix ont été observés dans les réponses. Ils peuvent "
                "révéler des dates de génération ou de version, utiles à un attaquant "
                "pour dater des événements internes (fuite d'information)."
            ),
            matched_at=root.final_url,
            evidence_text=" ; ".join(dict.fromkeys(found)),
        )
    ]
