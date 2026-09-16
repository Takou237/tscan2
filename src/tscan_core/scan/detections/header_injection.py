"""Détection d'injection de headers HTTP (CRLF injection) par sonde bénigne.

Sonde GET non destructive (ES-03) : la charge injecte un marqueur de détection
dans un paramètre qui peut être réfléchi dans un en-tête de réponse
(`X-Reflected` ou `X-Custom-Header`). Le probe vérifie que le marqueur
apparaît dans les headers de réponse (hors en-têtes HTTP standards) — signe
que le serveur ne filter pas les caractères spéciaux (CRLF) et autorise
l'injection d'en-têtes arbitraires.

La charge est inoffensive (ES-03) : le marqueur ne contient que des
caractères alphanumériques et n'a aucun effet de bord.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch

# Paramètres classiquement vulnérables à l'injection de headers.
HDR_INJECT_PARAMS = ("name", "value", "title", "q")

# Marqueur de détection bénin : si ce texte apparaît dans un header de
# réponse (hors en-têtes HTTP standards), le serveur reflète les headers.
DETECTION_MARKER = "TSCAN-CRLF-001"

# Chemins à sonder (le labo aura une route qui reflète le paramètre dans
# un header X-Custom-Header, simulant la vulnérabilité).
PROBE_PATHS = ("/header-reflect", "/reflect-header")

RULE_ID = "RULE-HDR-INJECTION-001"
SEVERITY = "high"
CATEGORY = "header-injection"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at=None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    del root, started_at, pages

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    for path in PROBE_PATHS:
        for param in HDR_INJECT_PARAMS:
            url = f"{base}{path}?{param}={DETECTION_MARKER}"
            page = probe_fetch(client, url, observations, on_event)
            if page is None:
                continue

            if page.status_code not in (200, 204):
                continue

            if _marker_in_non_standard_header(page):
                results.append(
                    DetectionResult(
                        rule_id=RULE_ID,
                        category=CATEGORY,
                        severity=SEVERITY,
                        title="Injection de header HTTP (CRLF) probable",
                        description=(
                            "Un paramètre d'URL est réfléchi dans un en-tête de réponse "
                            "personnalisé sans filtrage des caractères de contrôle (CRLF). "
                            "Un attaquant pourrait injecter des en-têtes arbitraires "
                            "(Set-Cookie, cache, authentification) via les paramètres d'URL."
                        ),
                        matched_at=page.final_url,
                        evidence_text=(
                            f"GET {page.final_url} -> {page.status_code} : "
                            f"marqueur {DETECTION_MARKER!r} reflété dans un en-tête "
                            f"personnalisé via le paramètre {param!r}"
                        ),
                        probe_info={
                            "request_url": url,
                            "method": "GET",
                            "signal_type": "header_injection_marker",
                            "signal_value": DETECTION_MARKER,
                        },
                    )
                )
                return results

    return results


# En-têtes HTTP standards qu'on ne considère pas comme « injectés » :
# si le marqueur apparaît dans ces en-têtes, c'est un artefact du serveur
# et non un signe d'injection.
_STANDARD_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "content-security-policy",
        "server",
        "date",
        "connection",
        "cache-control",
        "transfer-encoding",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "x-powered-by",
        "location",
        "set-cookie",
    }
)


def _marker_in_non_standard_header(page: RootResponse) -> bool:
    """Vrai si le marqueur apparaît dans un en-tête non standard de la réponse."""
    for header_name, header_value in page.headers.items():
        if header_name.lower() in _STANDARD_HEADERS:
            continue
        if DETECTION_MARKER.lower() in header_value.lower():
            return True
    return False