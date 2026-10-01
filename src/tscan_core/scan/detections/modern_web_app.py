"""Détection « Modern Web Application » — parité OWASP ZAP 10101 (P7).

Historiquement émise par le bundle agrégé ``zap_passive`` (constat agrégé sur
la racine, sans ``probe_info``) : la re-vérification RF-23 ne pouvait pas la
rejouer. Désormais une famille en code à part entière, **un constat par page**
avec un ``probe_info`` rejouable (``body_regex``) : la re-vérification précise
refait une requête fraîche et vérifie que les marqueurs JS modernes sont
toujours présents dans la page.
"""

from __future__ import annotations

import re

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_ID = "RULE-MODERN-APP-001"
CATEGORY = "information_disclosure"
SEVERITY = "info"
TITLE = "Modern Web Application"

# Marqueurs de code JavaScript moderne (même logique que zap_passive, posée
# en constante rejouable : la regex exacte voyage dans le probe_info, la
# re-vérification réévalue le même signal sur une réponse fraîche).
MODERN_JS = re.compile(
    r"async\s+function\b|=>\s*[{(\s]|"
    r"\bfetch\s*\(|\bWebSocket\s*\(|document\.querySelector\s*\(|"
    r"\.map\s*\(|localStorage|sessionStorage|navigator\.serviceWorker\s*"
)

# Les pages non HTML (CSS, JS brut servi comme ressource, JSON...) ne sont pas
# des « applications web » au sens de l'alerte ZAP 10101 : analyse du HTML seul.
_SKIP_CONTENT_TYPES = ("text/css", "application/javascript", "text/javascript")


def _is_html(headers: dict[str, str]) -> bool:
    ctype = (headers.get("content-type") or "").lower()
    if any(marker in ctype for marker in _SKIP_CONTENT_TYPES):
        return False
    return "html" in ctype or not ctype


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive : un constat par page HTML dont le corps porte des
    marqueurs d'API JavaScript modernes (aucune requête supplémentaire)."""
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
        if not _is_html(page.headers) or not page.body:
            continue
        match = MODERN_JS.search(page.body)
        if match is None:
            continue
        seen.add(probe_url)
        results.append(
            DetectionResult(
                rule_id=RULE_ID,
                category=CATEGORY,
                severity=SEVERITY,
                title=TITLE,
                description=(
                    "La page utilise des API JavaScript modernes (ES6, fetch, Web "
                    "Workers, localStorage...) : la surface d'attaque côté client "
                    "diffère d'un site classique et mérite une analyse ciblée."
                ),
                matched_at=probe_url,
                evidence_text=(
                    f"Marqueurs JS modernes ({match.group(0)!r}) dans la page "
                    f"{probe_url}"
                ),
                probe_info={
                    "request_url": probe_url,
                    "method": "GET",
                    "signal_type": "body_regex",
                    "signal_value": MODERN_JS.pattern,
                },
            )
        )
    return results
