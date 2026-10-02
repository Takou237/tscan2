"""Détections d'en-têtes de sécurité absents — parité OWASP ZAP 10020/10035/10038 (suite P7).

Historiquement émises par ``security_headers`` (HSTS, X-Content-Type-Options)
et ``zap_passive`` (X-Frame-Options) sous forme de constats agrégés sur la
racine, sans ``probe_info`` rejouable : la re-vérification RF-23 ne pouvait
ni les renforcer ni les contredire (cf. rapport du 01/10/2026, #9, #10, #13).

Désormais une famille en code à part entière : **un constat par page et par
en-tête**, avec un ``probe_info`` rejouable (``header_absent``) — la
re-vérification précise refait une requête fraîche et vérifie que l'en-tête
est toujours absent. Fait reproduit -> score renforcé (plafond 0,85) ;
fait contredit (en-tête apparu) -> potentiel faux positif (RF-23, RF-12).
"""

from __future__ import annotations

from dataclasses import dataclass

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult


@dataclass(frozen=True)
class HeaderSpec:
    """Spécification d'un en-tête de sécurité attendu (parité ZAP)."""

    header: str  # nom d'en-tête HTTP (minuscules pour la comparaison)
    rule_id: str
    title: str  # titre exact de l'alerte ZAP (corroboration par titre)
    severity: str
    description: str


# En-têtes couverts par cette famille (HSTS/XCTO : ex-security_headers ;
# XFO : ex-zap_passive). Les titres sont exactement ceux des alertes ZAP.
HEADER_SPECS: tuple[HeaderSpec, ...] = (
    HeaderSpec(
        header="strict-transport-security",
        rule_id="RULE-HSTS-NOTSET-001",
        title="Strict-Transport-Security Header Not Set",
        severity="medium",
        description=(
            "L'en-tête Strict-Transport-Security (HSTS) est absent de la "
            "réponse : le navigateur n'est pas invité à basculer sur HTTPS ni "
            "à avertir l'utilisateur en cas de certificat invalide. Les "
            "échanges peuvent être interceptés par une attaque de milieu."
        ),
    ),
    HeaderSpec(
        header="x-content-type-options",
        rule_id="RULE-XCTO-NOTSET-001",
        title="X-Content-Type-Options Header Missing",
        severity="medium",
        description=(
            "L'en-tête X-Content-Type-Options est absent de la réponse : le "
            "navigateur peut deviner le type MIME d'une ressource au lieu de "
            "le respecter (MIME sniffing), ouvrant la porte à des attaques de "
            "téléchargement ou d'exécution de contenu."
        ),
    ),
    HeaderSpec(
        header="x-frame-options",
        rule_id="RULE-XFO-NOTSET-001",
        title="X-Frame-Options Header Not Set",
        severity="low",
        description=(
            "L'en-tête X-Frame-Options n'est pas défini : la page peut être "
            "embarquée dans une frame d'un site tiers (clickjacking)."
        ),
    ),
)

CATEGORY = "security_misconfiguration"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive : un constat par (page, en-tête absent), avec
    ``probe_info`` rejouable (aucune requête supplémentaire)."""
    del config, client, observations, started_at, on_event

    checked = [root]
    if pages:
        checked.extend(pages.values())

    results: list[DetectionResult] = []
    seen: set[tuple[str, str]] = set()
    for page in checked:
        probe_url = page.final_url or page.request_url
        if not probe_url:
            continue
        headers = {key.lower() for key in page.headers}
        for spec in HEADER_SPECS:
            key = (probe_url, spec.rule_id)
            if key in seen:
                continue
            if spec.header in headers:
                continue
            seen.add(key)
            results.append(
                DetectionResult(
                    rule_id=spec.rule_id,
                    category=CATEGORY,
                    severity=spec.severity,
                    title=spec.title,
                    description=spec.description,
                    matched_at=probe_url,
                    evidence_text=f"En-tête {spec.header} absent de {probe_url}",
                    probe_info={
                        "request_url": probe_url,
                        "method": "GET",
                        "signal_type": "header_absent",
                        "signal_value": spec.header,
                    },
                )
            )
    return results
