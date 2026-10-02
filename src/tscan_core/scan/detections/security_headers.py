"""Détection passive de l'en-tête révélateur X-Powered-By (parité OWASP ZAP,
alerte 10037 « Server Leaks Information »).

Les constats d'en-têtes de sécurité ABSENTS (HSTS, X-Content-Type-Options)
historiquement émis ici sont déplacés dans le module dédié
``header_notset.py`` (suite P7 : un constat par page avec ``probe_info``
rejouable pour la re-vérification précise RF-23 — cf. rapport du 01/10/2026,
#9 et #10 « fait non reproduit »).

Analyse 100 % passive des réponses déjà récoltées (racine + pages crawlées) :
aucune requête supplémentaire, en-têtes jamais modifiés. Un constat est émis
si au moins une page observée est concernée, avec la liste des pages (style
du module CSP).

Constat émis (parité d'alerte ZAP) :

* X-Powered-By présent              -> RULE-XPOWEREDBY-001 (faible)
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_XPOWEREDBY = "RULE-XPOWEREDBY-001"

CATEGORY_INFO = "information_disclosure"
SEVERITY_LOW = "low"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive des en-têtes de sécurité sur la racine et les pages
    crawlées."""
    del config, client, observations, started_at, on_event
    checked = [root]
    if pages:
        checked.extend(pages.values())

    xpoweredby: list[str] = []

    for page in checked:
        headers = {key.lower(): value for key, value in page.headers.items()}
        if "x-powered-by" in headers:
            xpoweredby.append(f"{page.final_url} : {headers['x-powered-by']}")

    results: list[DetectionResult] = []

    if xpoweredby:
        results.append(
            DetectionResult(
                rule_id=RULE_XPOWEREDBY,
                category=CATEGORY_INFO,
                severity=SEVERITY_LOW,
                title='Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)',
                description=(
                    "L'en-tête X-Powered-By révèle la technologie du serveur ou de "
                    "l'application (nom, version). Cette information aide un attaquant "
                    "à cibler des vulnérabilités connues de cette version."
                ),
                matched_at=root.final_url,
                evidence_text=" ; ".join(dict.fromkeys(xpoweredby)),
            )
        )

    return results