"""Détection passive d'en-têtes de sécurité HTTP absents ou révélateurs
(feuille de route : parité OWASP ZAP, alertes 10035 « Strict-Transport-Security
Header Not Set », 10038 « X-Content-Type-Options Header Missing », 10037
« Server Leaks Information »).

Analyse 100 % passive des réponses déjà récoltées (racine + pages crawlées) :
aucune requête supplémentaire, en-têtes jamais modifiés. Un constat est émis
par famille d'en-tête si au moins une page observée est concernée, avec la
liste des pages (style du module CSP).

Constats émis, chacun avec sa propre règle (parité d'alertes ZAP) :

* Strict-Transport-Security absent  -> RULE-HSTS-NOTSET-001 (moyenne)
* X-Content-Type-Options absent     -> RULE-XCTO-NOTSET-001 (moyenne)
* X-Powered-By présent              -> RULE-XPOWEREDBY-001 (faible)
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_HSTS_NOTSET = "RULE-HSTS-NOTSET-001"
RULE_XCTO_NOTSET = "RULE-XCTO-NOTSET-001"
RULE_XPOWEREDBY = "RULE-XPOWEREDBY-001"

CATEGORY_SECURITY = "security_misconfiguration"
CATEGORY_INFO = "information_disclosure"
SEVERITY_MEDIUM = "medium"
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

    hsts_urls: list[str] = []
    xcto_urls: list[str] = []
    xpoweredby: list[str] = []

    for page in checked:
        headers = {key.lower(): value for key, value in page.headers.items()}
        if "strict-transport-security" not in headers:
            hsts_urls.append(page.final_url)
        if "x-content-type-options" not in headers:
            xcto_urls.append(page.final_url)
        if "x-powered-by" in headers:
            xpoweredby.append(f"{page.final_url} : {headers['x-powered-by']}")

    results: list[DetectionResult] = []

    if hsts_urls:
        results.append(
            DetectionResult(
                rule_id=RULE_HSTS_NOTSET,
                category=CATEGORY_SECURITY,
                severity=SEVERITY_MEDIUM,
                title="Strict-Transport-Security Header Not Set",
                description=(
                    "L'en-tête Strict-Transport-Security (HSTS) est absent de la "
                    "réponse : le navigateur n'est pas invité à basculer sur HTTPS "
                    "ni à avertir l'utilisateur en cas de certificat invalide. Les "
                    "échanges peuvent être interceptés par une attaque de milieu."
                ),
                matched_at=root.final_url,
                evidence_text=" ; ".join(dict.fromkeys(hsts_urls)),
            )
        )

    if xcto_urls:
        results.append(
            DetectionResult(
                rule_id=RULE_XCTO_NOTSET,
                category=CATEGORY_SECURITY,
                severity=SEVERITY_MEDIUM,
                title="X-Content-Type-Options Header Missing",
                description=(
                    "L'en-tête X-Content-Type-Options est absent de la réponse : "
                    "le navigateur peut deviner le type MIME d'une ressource au lieu "
                    "de le respecter (MIME sniffing), ouvrant la porte à des attaques "
                    "de téléchargement ou d'exécution de contenu."
                ),
                matched_at=root.final_url,
                evidence_text=" ; ".join(dict.fromkeys(xcto_urls)),
            )
        )

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