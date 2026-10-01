"""Détection Permissions-Policy absent — parité OWASP ZAP 10063 (P7).

Historiquement émise par le bundle agrégé ``zap_passive`` (constat agrégé sur
la racine, sans ``probe_info``) : la re-vérification RF-23 ne pouvait pas la
rejouer, le constat restait éternellement « Probable 0,60 » avec la note
« fait non reproduit » (cf. rapport du 01/10/2026, #12).

Désormais une famille en code à part entière, **un constat par page** avec un
``probe_info`` rejouable (``header_absent``) : la re-vérification précise
refait une requête fraîche et vérifie que l'en-tête est toujours absent.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_ID = "RULE-PERMISSIONS-NOTSET-001"
CATEGORY = "security_misconfiguration"
SEVERITY = "info"
TITLE = "Permissions Policy Header Not Set"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive : un constat par page dont la réponse ne porte pas
    l'en-tête Permissions-Policy (aucune requête supplémentaire)."""
    del config, client, observations, started_at, on_event

    checked = [root]
    if pages:
        checked.extend(pages.values())

    results: list[DetectionResult] = []
    seen: set[str] = set()
    for page in checked:
        probe_url = page.final_url or page.request_url
        if not probe_url or probe_url in seen:
            continue
        if "permissions-policy" in {k.lower() for k in page.headers}:
            continue
        seen.add(probe_url)
        results.append(
            DetectionResult(
                rule_id=RULE_ID,
                category=CATEGORY,
                severity=SEVERITY,
                title=TITLE,
                description=(
                    "L'en-tête Permissions-Policy n'est pas défini : les "
                    "fonctionnalités navigateur (microphone, caméra, "
                    "géolocalisation...) ne sont pas restreintes par défaut pour "
                    "les cadres de tiers."
                ),
                matched_at=probe_url,
                evidence_text=f"En-tête Permissions-Policy absent de {probe_url}",
                probe_info={
                    "request_url": probe_url,
                    "method": "GET",
                    "signal_type": "header_absent",
                    "signal_value": "permissions-policy",
                },
            )
        )
    return results
